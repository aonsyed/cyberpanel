//go:build linux

package dns

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const LocalPowerDNSDatabasePath="/var/lib/cyberpanel/powerdns/authority.db"

const powerDNSSQLiteSchema=`
CREATE TABLE IF NOT EXISTS domains (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,master TEXT,last_check INTEGER,type TEXT NOT NULL,notified_serial INTEGER,account TEXT,options TEXT,catalog TEXT);
CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id INTEGER,name TEXT,type TEXT,content TEXT,ttl INTEGER,prio INTEGER,disabled INTEGER DEFAULT 0,ordername BLOB,auth INTEGER DEFAULT 1);
CREATE INDEX IF NOT EXISTS records_name_type_index ON records(name,type);CREATE INDEX IF NOT EXISTS records_domain_index ON records(domain_id);CREATE INDEX IF NOT EXISTS records_order_index ON records(auth,ordername);
CREATE TABLE IF NOT EXISTS supermasters (ip TEXT NOT NULL,nameserver TEXT NOT NULL,account TEXT NOT NULL,PRIMARY KEY(ip,nameserver));
CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id INTEGER NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL,modified_at INTEGER NOT NULL,account TEXT,comment TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS comments_name_type_index ON comments(name,type);CREATE INDEX IF NOT EXISTS comments_domain_index ON comments(domain_id);
CREATE TABLE IF NOT EXISTS domainmetadata (id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id INTEGER NOT NULL,kind TEXT,content TEXT);
CREATE INDEX IF NOT EXISTS domainmetadata_domain_kind_index ON domainmetadata(domain_id,kind);
CREATE TABLE IF NOT EXISTS cryptokeys (id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id INTEGER NOT NULL,flags INTEGER NOT NULL,active INTEGER NOT NULL,published INTEGER DEFAULT 1,content TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS cryptokeys_domain_index ON cryptokeys(domain_id);
CREATE TABLE IF NOT EXISTS tsigkeys (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,algorithm TEXT,secret TEXT,UNIQUE(name,algorithm));`

func LocalPowerDNSControlFingerprint()string{sum:=sha256.Sum256([]byte("cyberpanel-control-authority-v1"));return hex.EncodeToString(sum[:])}
func LocalPowerDNSDatabaseBinding()PowerDNSDatabaseBinding{binding:=PowerDNSDatabaseBinding{ID:"local-sqlite",Purpose:PowerDNSAuthoritativePurpose,Backend:PowerDNSBackendSQLite,Host:netip.IPv4Unspecified(),Database:"powerdns",Username:"powerdns",CredentialRef:"local-sqlite-no-secret"};binding.Fingerprint=binding.ExpectedFingerprint();return binding}
func LocalPowerDNSConfigSnapshot(generation uint64)PowerDNSConfigSnapshot{return PowerDNSConfigSnapshot{NodeID:"local",Generation:generation,ListenAddresses:[]netip.Addr{netip.IPv4Unspecified(),netip.IPv6Unspecified()},Port:53,Database:LocalPowerDNSDatabaseBinding(),ReceiverThreads:2,DistributorThreads:2,RetrievalThreads:2,MaximumTCPClients:1024}}

func OpenLocalSQLitePowerDNSAuthority(ctx context.Context,secrets PowerDNSTSIGSecretResolver)(PowerDNSAuthoritativeDatabase,*SecuredPowerDNSAuthority,error){
	if ctx==nil{return PowerDNSAuthoritativeDatabase{},nil,ErrPowerDNSDatabaseOpen};directory:=filepath.Dir(LocalPowerDNSDatabasePath);if err:=os.MkdirAll(directory,0700);err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err}
	// The shared generation store writer creates its root 0750. That exact
	// root-owned, ACL-less state is our own unwritten store, not foreign
	// configuration: normalize it to the 0700 pre-grant mode so native
	// access validation can admit it and install the serving ACL. Every
	// other state stays for validation to reject.
	if err:=normalizeFreshPowerDNSStoreRoot(directory);err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err}
	if err:=validatePowerDNSNativeDatabaseFiles();err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err}
	initial,createErr:=os.OpenFile(LocalPowerDNSDatabasePath,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600);if createErr==nil{if err:=initial.Close();err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err}}else if !errors.Is(createErr,os.ErrExist){return PowerDNSAuthoritativeDatabase{},nil,createErr}
	dsn:="file:"+LocalPowerDNSDatabasePath+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)";handle,err:=sql.Open("sqlite",dsn);if err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err};fail:=func(cause error)(PowerDNSAuthoritativeDatabase,*SecuredPowerDNSAuthority,error){_=handle.Close();return PowerDNSAuthoritativeDatabase{},nil,cause}
	handle.SetMaxOpenConns(1);handle.SetMaxIdleConns(1);if err=handle.PingContext(ctx);err!=nil{return fail(err)}
	if _,err=handle.ExecContext(ctx,powerDNSSQLiteSchema);err!=nil{return fail(err)};if err=preparePowerDNSNativeDatabaseAccess();err!=nil{return fail(err)};identity:=LocalPowerDNSDatabaseBinding().AuthoritativeIdentity();database,err:=newPowerDNSAuthoritativeDatabase(handle,identity,LocalPowerDNSControlFingerprint());if err!=nil{return fail(err)};authority,err:=NewSecuredPowerDNSAuthority(database,secrets);if err!=nil{_=database.Close();return PowerDNSAuthoritativeDatabase{},nil,err};return database,authority,nil
}

// normalizeFreshPowerDNSStoreRoot tightens the shared generation writer's
// 0750 root to the 0700 pre-grant mode when — and only when — the directory
// is root:root, exactly mode 0750 and carries no access ACL, and no
// authority database exists yet. Anything else is left untouched for the
// strict native-access validation to judge.
func normalizeFreshPowerDNSStoreRoot(directory string) error {
	if _, err := os.Lstat(LocalPowerDNSDatabasePath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 {
		return nil
	}
	var acl [256]byte
	if _, aclErr := unix.Lgetxattr(directory, "system.posix_acl_access", acl[:]); !errors.Is(aclErr, unix.ENODATA) {
		return nil
	}
	return os.Chmod(directory, 0700)
}
