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
	if ctx==nil{return PowerDNSAuthoritativeDatabase{},nil,ErrPowerDNSDatabaseOpen};directory:=filepath.Dir(LocalPowerDNSDatabasePath);if err:=os.MkdirAll(directory,0700);err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err};if err:=os.Chmod(directory,0700);err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err}
	dsn:="file:"+LocalPowerDNSDatabasePath+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)";handle,err:=sql.Open("sqlite",dsn);if err!=nil{return PowerDNSAuthoritativeDatabase{},nil,err};fail:=func(cause error)(PowerDNSAuthoritativeDatabase,*SecuredPowerDNSAuthority,error){_=handle.Close();return PowerDNSAuthoritativeDatabase{},nil,cause}
	handle.SetMaxOpenConns(1);handle.SetMaxIdleConns(1);if err=handle.PingContext(ctx);err!=nil{return fail(err)};if err=os.Chmod(LocalPowerDNSDatabasePath,0600);err!=nil{return fail(err)};info,err:=os.Lstat(LocalPowerDNSDatabasePath);if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Mode()&os.ModeSymlink!=0{return fail(errors.Join(ErrPowerDNSDatabaseOpen,err))};metadata,ok:=info.Sys().(*syscall.Stat_t);if !ok||metadata.Uid!=0{return fail(ErrPowerDNSDatabaseOpen)}
	if _,err=handle.ExecContext(ctx,powerDNSSQLiteSchema);err!=nil{return fail(err)};identity:=LocalPowerDNSDatabaseBinding().AuthoritativeIdentity();database,err:=newPowerDNSAuthoritativeDatabase(handle,identity,LocalPowerDNSControlFingerprint());if err!=nil{return fail(err)};authority,err:=NewSecuredPowerDNSAuthority(database,secrets);if err!=nil{_=database.Close();return PowerDNSAuthoritativeDatabase{},nil,err};return database,authority,nil
}
