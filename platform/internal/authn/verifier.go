// Package authn implements the protected local credential verifier. Control
// state keeps only opaque references; password hashes, API-key verifiers,
// encrypted TOTP seeds, recovery-code digests, lockouts, and replay counters
// remain in the verifier-owned database.
package authn

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalid      = errors.New("authn: invalid request")
	ErrNotFound     = errors.New("authn: verifier not found")
	ErrLocked       = errors.New("authn: verifier temporarily locked")
	ErrConflict     = errors.New("authn: verifier conflict")
	ErrUnavailable  = errors.New("authn: verifier unavailable")
	ErrReplay       = errors.New("authn: authenticator response replayed")
)

const schema = `
CREATE TABLE IF NOT EXISTS authn_verifiers_v1 (
 ref TEXT PRIMARY KEY,
 principal_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 state TEXT NOT NULL,
 version INTEGER NOT NULL,
 payload BLOB NOT NULL,
 created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 expires_at TIMESTAMP,
 failed_attempts INTEGER NOT NULL DEFAULT 0,
 locked_until TIMESTAMP,
 last_step INTEGER NOT NULL DEFAULT -1
);
CREATE INDEX IF NOT EXISTS authn_verifiers_v1_principal ON authn_verifiers_v1(principal_id,kind,state);
CREATE TABLE IF NOT EXISTS authn_api_index_v1 (
 lookup_digest BLOB PRIMARY KEY,
 ref TEXT NOT NULL UNIQUE,
 FOREIGN KEY(ref) REFERENCES authn_verifiers_v1(ref) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS authn_recovery_v1 (
 ref TEXT NOT NULL,
 code_digest BLOB NOT NULL,
 consumed_at TIMESTAMP,
 PRIMARY KEY(ref,code_digest),
 FOREIGN KEY(ref) REFERENCES authn_verifiers_v1(ref) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS authn_webauthn_index_v1 (
 credential_id BLOB PRIMARY KEY,
 ref TEXT NOT NULL UNIQUE,
 FOREIGN KEY(ref) REFERENCES authn_verifiers_v1(ref) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS authn_webauthn_challenges_v1 (
 id TEXT PRIMARY KEY,
 principal_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 rp_id TEXT NOT NULL,
 challenge BLOB NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 consumed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS authn_webauthn_challenges_v1_expiry ON authn_webauthn_challenges_v1(expires_at);
`

type Argon2Parameters struct {
	MemoryKiB uint32
	Passes    uint32
	Threads   uint8
	SaltBytes uint32
	KeyBytes  uint32
}

func (parameters Argon2Parameters) normalized() (Argon2Parameters, error) {
	if parameters.MemoryKiB == 0 { parameters.MemoryKiB = 64 * 1024 }
	if parameters.Passes == 0 { parameters.Passes = 3 }
	if parameters.Threads == 0 { parameters.Threads = 4 }
	if parameters.SaltBytes == 0 { parameters.SaltBytes = 16 }
	if parameters.KeyBytes == 0 { parameters.KeyBytes = 32 }
	if parameters.MemoryKiB < 32*1024 || parameters.MemoryKiB > 1024*1024 || parameters.Passes < 2 || parameters.Passes > 10 || parameters.Threads < 1 || parameters.Threads > 32 || parameters.SaltBytes < 16 || parameters.SaltBytes > 64 || parameters.KeyBytes < 32 || parameters.KeyBytes > 64 { return Argon2Parameters{}, ErrInvalid }
	return parameters, nil
}

type Config struct {
	Password             Argon2Parameters
	APIKey                Argon2Parameters
	MaximumFailures       uint32
	InitialLockout        time.Duration
	MaximumLockout        time.Duration
	TOTPPeriod            time.Duration
	TOTPDigits            uint8
	TOTPWindow            int
	RecoveryCodeCount     uint8
	RecoveryCodeBytes     uint8
	WebAuthnDisplayName   string
	WebAuthnOrigins       map[string][]string
	RequireUserVerification bool
	AllowUserPresenceOnly bool
	Clock                 func() time.Time
}

func (config Config) normalized() (Config, error) {
	var err error
	if config.Password, err = config.Password.normalized(); err != nil { return Config{}, err }
	if config.APIKey, err = config.APIKey.normalized(); err != nil { return Config{}, err }
	if config.MaximumFailures == 0 { config.MaximumFailures = 6 }
	if config.InitialLockout == 0 { config.InitialLockout = 30 * time.Second }
	if config.MaximumLockout == 0 { config.MaximumLockout = 30 * time.Minute }
	if config.TOTPPeriod == 0 { config.TOTPPeriod = 30 * time.Second }
	if config.TOTPDigits == 0 { config.TOTPDigits = 6 }
	if config.TOTPWindow == 0 { config.TOTPWindow = 1 }
	if config.RecoveryCodeCount == 0 { config.RecoveryCodeCount = 10 }
	if config.RecoveryCodeBytes == 0 { config.RecoveryCodeBytes = 10 }
	if strings.TrimSpace(config.WebAuthnDisplayName) == "" { config.WebAuthnDisplayName = "CyberPanel" }
	if len(config.WebAuthnDisplayName) > 100 || len(config.WebAuthnOrigins) > 128 { return Config{}, ErrInvalid }
	if config.WebAuthnOrigins == nil { config.WebAuthnOrigins = make(map[string][]string) }
	if !config.AllowUserPresenceOnly { config.RequireUserVerification = true }
	for rpID, origins := range config.WebAuthnOrigins { if !validRPID(rpID) || len(origins) == 0 || len(origins) > 16 { return Config{}, ErrInvalid }; seen:=map[string]bool{};for _,origin:=range origins{if !validOriginForRP(origin,rpID)||seen[origin]{return Config{},ErrInvalid};seen[origin]=true} }
	if config.MaximumFailures < 3 || config.MaximumFailures > 100 || config.InitialLockout < time.Second || config.MaximumLockout < config.InitialLockout || config.MaximumLockout > 24*time.Hour || config.TOTPPeriod < 15*time.Second || config.TOTPPeriod > 2*time.Minute || (config.TOTPDigits != 6 && config.TOTPDigits != 8) || config.TOTPWindow < 0 || config.TOTPWindow > 3 || config.RecoveryCodeCount < 5 || config.RecoveryCodeCount > 32 || config.RecoveryCodeBytes < 8 || config.RecoveryCodeBytes > 32 { return Config{}, ErrInvalid }
	if config.Clock == nil { config.Clock = time.Now }
	return config, nil
}

type Verifier struct {
	db       *sql.DB
	aead     cipher.AEAD
	pepper   [32]byte
	config   Config
	webauthn WebAuthnEngine
}

// New constructs the verifier from keys supplied by the protected process.
// wrappingKey and lookupPepper must come from distinct root-owned key files.
func New(db *sql.DB, wrappingKey, lookupPepper []byte, config Config, webauthn WebAuthnEngine) (*Verifier, error) {
	if db == nil || len(wrappingKey) != 32 || len(lookupPepper) != 32 { return nil, ErrInvalid }
	normalized, err := config.normalized(); if err != nil { return nil, err }
	block, err := aes.NewCipher(wrappingKey); if err != nil { return nil, err }
	aead, err := cipher.NewGCM(block); if err != nil { return nil, err }
	verifier := &Verifier{db:db,aead:aead,config:normalized,webauthn:webauthn}
	copy(verifier.pepper[:], lookupPepper)
	return verifier, nil
}

func (verifier *Verifier) Bootstrap(ctx context.Context) error {
	if verifier == nil || verifier.db == nil { return ErrUnavailable }
	_, err := verifier.db.ExecContext(ctx, schema)
	return err
}

type hashPayload struct { Algorithm string `json:"algorithm"`; Version uint8 `json:"version"`; MemoryKiB uint32 `json:"memory_kib"`; Passes uint32 `json:"passes"`; Threads uint8 `json:"threads"`; Salt string `json:"salt"`; Hash string `json:"hash"` }
type totpPayload struct { Algorithm string `json:"algorithm"`; Digits uint8 `json:"digits"`; PeriodSeconds uint32 `json:"period_seconds"`; Ciphertext string `json:"ciphertext"` }

func (verifier *Verifier) EnrollPassword(ctx context.Context, principal identity.ID, password []byte) (identity.ID, error) {
	defer wipe(password)
	if verifier == nil || !principal.Valid() || len(password) < 12 || len(password) > 4096 { return "", ErrInvalid }
	payload, err := hashSecret(password, verifier.config.Password); if err != nil { return "", err }
	ref, err := newReference("avp"); if err != nil { return "", err }
	now := verifier.now(); raw, _ := json.Marshal(payload)
	_, err = verifier.db.ExecContext(ctx, `INSERT INTO authn_verifiers_v1(ref,principal_id,kind,state,version,payload,created_at,updated_at,last_step) VALUES(?,?,'password','active',1,?,?,?,-1)`, ref, principal, raw, now, now)
	if err != nil { return "", err }
	return ref, nil
}

func (verifier *Verifier) VerifyPassword(ctx context.Context, ref identity.ID, password []byte) (bool, error) {
	defer wipe(password)
	if verifier == nil || !ref.Valid() || len(password) == 0 || len(password) > 4096 { return false, ErrInvalid }
	record, err := verifier.load(ctx, ref, "password"); if err != nil { return false, err }
	if err = verifier.checkUsable(record); err != nil { return false, err }
	var payload hashPayload; if err = strictJSON(record.payload, &payload); err != nil { return false, ErrUnavailable }
	valid := verifyHash(password, payload)
	if err = verifier.recordAttempt(ctx, record, valid); err != nil { return false, err }
	return valid, nil
}

func (verifier *Verifier) IssueAPIKey(ctx context.Context, principal identity.ID, scopes []identity.Permission, expires time.Time) (identity.ID, []byte, error) {
	if verifier == nil || !principal.Valid() || !expires.After(verifier.now()) || expires.After(verifier.now().Add(10*365*24*time.Hour)) { return "", nil, ErrInvalid }
	for _, scope := range scopes { if _, err := identity.NewPermission(string(scope)); err != nil { return "", nil, ErrInvalid } }
	random := make([]byte, 32); if _, err := rand.Read(random); err != nil { return "", nil, err }
	raw := []byte("cpk_" + base64.RawURLEncoding.EncodeToString(random)); wipe(random)
	payload, err := hashSecret(raw, verifier.config.APIKey); if err != nil { wipe(raw); return "", nil, err }
	ref, err := newReference("avk"); if err != nil { wipe(raw); return "", nil, err }
	lookup := verifier.lookupDigest(raw); serialized, _ := json.Marshal(payload); now := verifier.now()
	tx, err := verifier.db.BeginTx(ctx, nil); if err != nil { wipe(raw); return "", nil, err }; defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO authn_verifiers_v1(ref,principal_id,kind,state,version,payload,created_at,updated_at,expires_at,last_step) VALUES(?,?,'api_key','active',1,?,?,?,?, -1)`, ref, principal, serialized, now, now, expires.UTC()); err != nil { wipe(raw); return "", nil, err }
	if _, err = tx.ExecContext(ctx, `INSERT INTO authn_api_index_v1(lookup_digest,ref) VALUES(?,?)`, lookup, ref); err != nil { wipe(raw); return "", nil, err }
	if err = tx.Commit(); err != nil { wipe(raw); return "", nil, err }
	return ref, raw, nil
}

func (verifier *Verifier) VerifyAPIKey(ctx context.Context, raw []byte) (identity.ID, bool, error) {
	defer wipe(raw)
	if verifier == nil || len(raw) < 24 || len(raw) > 4096 || !strings.HasPrefix(string(raw), "cpk_") { return "", false, ErrInvalid }
	lookup := verifier.lookupDigest(raw); var ref identity.ID
	err := verifier.db.QueryRowContext(ctx, `SELECT ref FROM authn_api_index_v1 WHERE lookup_digest=?`, lookup).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) { dummy, _ := hashSecret(raw, verifier.config.APIKey); _ = verifyHash(raw, dummy); return "", false, nil }
	if err != nil { return "", false, err }
	record, err := verifier.load(ctx, ref, "api_key"); if err != nil { return "", false, err }
	if err = verifier.checkUsable(record); err != nil { return "", false, err }
	var payload hashPayload; if strictJSON(record.payload, &payload) != nil { return "", false, ErrUnavailable }
	valid := verifyHash(raw, payload)
	return ref, valid, nil
}

func (verifier *Verifier) BeginTOTPEnrollment(ctx context.Context, principal identity.ID) (identity.ID, []byte, []string, error) {
	if verifier == nil || !principal.Valid() { return "", nil, nil, ErrInvalid }
	seed := make([]byte, 20); if _, err := rand.Read(seed); err != nil { return "", nil, nil, err }
	ref, err := newReference("avt"); if err != nil { wipe(seed); return "", nil, nil, err }
	ciphertext, err := verifier.seal(ref, principal, "totp", 1, seed); if err != nil { wipe(seed); return "", nil, nil, err }
	payload := totpPayload{Algorithm:"SHA1",Digits:verifier.config.TOTPDigits,PeriodSeconds:uint32(verifier.config.TOTPPeriod/time.Second),Ciphertext:base64.RawStdEncoding.EncodeToString(ciphertext)}
	raw, _ := json.Marshal(payload); now := verifier.now(); codes, digests, err := verifier.recoveryCodes(); if err != nil { wipe(seed); return "", nil, nil, err }
	tx, err := verifier.db.BeginTx(ctx, nil); if err != nil { wipe(seed); return "", nil, nil, err }; defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO authn_verifiers_v1(ref,principal_id,kind,state,version,payload,created_at,updated_at,last_step) VALUES(?,?,'totp','pending',1,?,?,?,-1)`, ref, principal, raw, now, now); err != nil { wipe(seed); return "", nil, nil, err }
	for _, digest := range digests { if _, err = tx.ExecContext(ctx, `INSERT INTO authn_recovery_v1(ref,code_digest) VALUES(?,?)`, ref, digest); err != nil { wipe(seed); return "", nil, nil, err } }
	if err = tx.Commit(); err != nil { wipe(seed); return "", nil, nil, err }
	encoded := []byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)); wipe(seed)
	return ref, encoded, codes, nil
}

func (verifier *Verifier) ConfirmTOTPEnrollment(ctx context.Context, ref identity.ID, code string) error {
	if verifier == nil || !ref.Valid() { return ErrInvalid }
	record, err := verifier.load(ctx, ref, "totp"); if err != nil { return err }
	if record.state != "pending" { return ErrConflict }
	valid, _, err := verifier.verifyTOTP(record, code, false); if err != nil { return err }; if !valid { return ErrInvalid }
	result, err := verifier.db.ExecContext(ctx, `UPDATE authn_verifiers_v1 SET state='active',failed_attempts=0,locked_until=NULL,updated_at=? WHERE ref=? AND state='pending' AND version=?`, verifier.now(), ref, record.version)
	if err != nil { return err }; changed, _ := result.RowsAffected(); if changed != 1 { return ErrConflict }
	return nil
}

func (verifier *Verifier) VerifyTOTP(ctx context.Context, ref identity.ID, code string) (bool, error) {
	if verifier == nil || !ref.Valid() { return false, ErrInvalid }
	record, err := verifier.load(ctx, ref, "totp"); if err != nil { return false, err }
	if err = verifier.checkUsable(record); err != nil { return false, err }
	valid, step, err := verifier.verifyTOTP(record, code, true); if err != nil { return false, err }
	if !valid { _ = verifier.recordAttempt(ctx, record, false); return false, nil }
	result, err := verifier.db.ExecContext(ctx, `UPDATE authn_verifiers_v1 SET last_step=?,failed_attempts=0,locked_until=NULL,updated_at=? WHERE ref=? AND state='active' AND version=? AND last_step<?`, step, verifier.now(), ref, record.version, step)
	if err != nil { return false, err }; changed, _ := result.RowsAffected(); if changed != 1 { return false, ErrReplay }
	return true, nil
}

// VerifyRecoveryCode consumes one high-entropy recovery code atomically. The
// identity service may use it as an MFA recovery path without ever receiving
// the remaining code set from this verifier.
func (verifier *Verifier) VerifyRecoveryCode(ctx context.Context, ref identity.ID, code string) (bool, error) {
	if verifier == nil || !ref.Valid() || len(code) < 8 || len(code) > 128 { return false, ErrInvalid }
	digest := verifier.recoveryDigest(code); now := verifier.now()
	result, err := verifier.db.ExecContext(ctx, `UPDATE authn_recovery_v1 SET consumed_at=? WHERE ref=? AND code_digest=? AND consumed_at IS NULL`, now, ref, digest)
	if err != nil { return false, err }; changed, _ := result.RowsAffected(); return changed == 1, nil
}

func (verifier *Verifier) Revoke(ctx context.Context, ref identity.ID) error {
	if verifier == nil || !ref.Valid() { return ErrInvalid }
	result, err := verifier.db.ExecContext(ctx, `UPDATE authn_verifiers_v1 SET state='revoked',version=version+1,updated_at=? WHERE ref=? AND state!='revoked'`, verifier.now(), ref)
	if err != nil { return err }; changed, _ := result.RowsAffected(); if changed == 0 { return ErrNotFound }; return nil
}

type verifierRecord struct { ref identity.ID; principal identity.ID; kind, state string; version uint64; payload []byte; created, updated time.Time; expires sql.NullTime; failures uint32; locked sql.NullTime; lastStep int64 }
func (verifier *Verifier) load(ctx context.Context, ref identity.ID, kind string) (verifierRecord, error) { var record verifierRecord; err := verifier.db.QueryRowContext(ctx, `SELECT ref,principal_id,kind,state,version,payload,created_at,updated_at,expires_at,failed_attempts,locked_until,last_step FROM authn_verifiers_v1 WHERE ref=? AND kind=?`, ref, kind).Scan(&record.ref,&record.principal,&record.kind,&record.state,&record.version,&record.payload,&record.created,&record.updated,&record.expires,&record.failures,&record.locked,&record.lastStep); if errors.Is(err,sql.ErrNoRows){return record,ErrNotFound}; return record,err }
func (verifier *Verifier) checkUsable(record verifierRecord) error { now:=verifier.now();if record.state!="active"{return ErrNotFound};if record.expires.Valid&&!now.Before(record.expires.Time){return ErrNotFound};if record.locked.Valid&&now.Before(record.locked.Time){return ErrLocked};return nil }
func (verifier *Verifier) recordAttempt(ctx context.Context, record verifierRecord, valid bool) error { now:=verifier.now();if valid{_,err:=verifier.db.ExecContext(ctx,`UPDATE authn_verifiers_v1 SET failed_attempts=0,locked_until=NULL,updated_at=? WHERE ref=? AND version=?`,now,record.ref,record.version);return err};failures:=record.failures+1;var lock any;if failures>=verifier.config.MaximumFailures{exponent:=failures-verifier.config.MaximumFailures;if exponent>16{exponent=16};duration:=verifier.config.InitialLockout*time.Duration(uint64(1)<<exponent);if duration>verifier.config.MaximumLockout{duration=verifier.config.MaximumLockout};lock=now.Add(duration)};_,err:=verifier.db.ExecContext(ctx,`UPDATE authn_verifiers_v1 SET failed_attempts=?,locked_until=?,updated_at=? WHERE ref=? AND version=?`,failures,lock,now,record.ref,record.version);return err }
func (verifier *Verifier) verifyTOTP(record verifierRecord, code string, enforceReplay bool) (bool,int64,error) { var payload totpPayload;if strictJSON(record.payload,&payload)!=nil||payload.Algorithm!="SHA1"||payload.Digits!=verifier.config.TOTPDigits||payload.PeriodSeconds!=uint32(verifier.config.TOTPPeriod/time.Second){return false,0,ErrUnavailable};ciphertext,err:=base64.RawStdEncoding.DecodeString(payload.Ciphertext);if err!=nil{return false,0,ErrUnavailable};seed,err:=verifier.open(record.ref,record.principal,"totp",record.version,ciphertext);if err!=nil{return false,0,ErrUnavailable};defer wipe(seed);if len(code)!=int(payload.Digits){return false,0,nil};for _,character:=range code{if character<'0'||character>'9'{return false,0,nil}};current:=verifier.now().Unix()/int64(payload.PeriodSeconds);for offset:=-verifier.config.TOTPWindow;offset<=verifier.config.TOTPWindow;offset++{step:=current+int64(offset);if step<0||(enforceReplay&&step<=record.lastStep){continue};expected:=totp(seed,uint64(step),payload.Digits);if subtle.ConstantTimeCompare([]byte(expected),[]byte(code))==1{return true,step,nil}};return false,0,nil }
func (verifier *Verifier) seal(ref,principal identity.ID,kind string,version uint64,plaintext []byte)([]byte,error){nonce:=make([]byte,verifier.aead.NonceSize());if _,err:=rand.Read(nonce);err!=nil{return nil,err};aad:=associatedData(ref,principal,kind,version);result:=make([]byte,0,len(nonce)+len(plaintext)+verifier.aead.Overhead());result=append(result,nonce...);result=verifier.aead.Seal(result,nonce,plaintext,aad);return result,nil}
func (verifier *Verifier) open(ref,principal identity.ID,kind string,version uint64,ciphertext []byte)([]byte,error){size:=verifier.aead.NonceSize();if len(ciphertext)<size+verifier.aead.Overhead(){return nil,ErrUnavailable};return verifier.aead.Open(nil,ciphertext[:size],ciphertext[size:],associatedData(ref,principal,kind,version))}
func associatedData(ref,principal identity.ID,kind string,version uint64)[]byte{return []byte("cyberpanel-authn-v1\x00"+ref.String()+"\x00"+principal.String()+"\x00"+kind+"\x00"+strconv.FormatUint(version,10))}
func (verifier *Verifier) lookupDigest(raw []byte)[]byte{mac:=hmac.New(sha256.New,verifier.pepper[:]);_,_=mac.Write([]byte("api-key-index-v1\x00"));_,_=mac.Write(raw);return mac.Sum(nil)}
func (verifier *Verifier) recoveryDigest(code string)[]byte{normalized:=strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code),"-",""));mac:=hmac.New(sha256.New,verifier.pepper[:]);_,_=mac.Write([]byte("recovery-code-v1\x00"));_,_=mac.Write([]byte(normalized));return mac.Sum(nil)}
func (verifier *Verifier) recoveryCodes()([]string,[][]byte,error){codes:=make([]string,0,verifier.config.RecoveryCodeCount);digests:=make([][]byte,0,verifier.config.RecoveryCodeCount);for index:=0;index<int(verifier.config.RecoveryCodeCount);index++{raw:=make([]byte,verifier.config.RecoveryCodeBytes);if _,err:=rand.Read(raw);err!=nil{return nil,nil,err};encoded:=base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw);wipe(raw);split:=len(encoded)/2;code:=encoded[:split]+"-"+encoded[split:];codes=append(codes,code);digests=append(digests,verifier.recoveryDigest(code))};return codes,digests,nil}
func (verifier *Verifier) now()time.Time{if verifier==nil||verifier.config.Clock==nil{return time.Now().UTC()};return verifier.config.Clock().UTC()}

func hashSecret(secret []byte, parameters Argon2Parameters)(hashPayload,error){normalized,err:=parameters.normalized();if err!=nil{return hashPayload{},err};salt:=make([]byte,normalized.SaltBytes);if _,err=rand.Read(salt);err!=nil{return hashPayload{},err};derived:=argon2.IDKey(secret,salt,normalized.Passes,normalized.MemoryKiB,normalized.Threads,normalized.KeyBytes);payload:=hashPayload{Algorithm:"argon2id",Version:argon2.Version,MemoryKiB:normalized.MemoryKiB,Passes:normalized.Passes,Threads:normalized.Threads,Salt:base64.RawStdEncoding.EncodeToString(salt),Hash:base64.RawStdEncoding.EncodeToString(derived)};wipe(salt);wipe(derived);return payload,nil}
func verifyHash(secret []byte,payload hashPayload)bool{if payload.Algorithm!="argon2id"||payload.Version!=argon2.Version||payload.MemoryKiB<32*1024||payload.MemoryKiB>1024*1024||payload.Passes<2||payload.Passes>10||payload.Threads<1||payload.Threads>32{return false};salt,err:=base64.RawStdEncoding.DecodeString(payload.Salt);if err!=nil||len(salt)<16||len(salt)>64{return false};expected,err:=base64.RawStdEncoding.DecodeString(payload.Hash);if err!=nil||len(expected)<32||len(expected)>64{wipe(salt);return false};actual:=argon2.IDKey(secret,salt,payload.Passes,payload.MemoryKiB,payload.Threads,uint32(len(expected)));valid:=subtle.ConstantTimeCompare(actual,expected)==1;wipe(salt);wipe(expected);wipe(actual);return valid}
func totp(secret []byte,counter uint64,digits uint8)string{buffer:=make([]byte,8);binary.BigEndian.PutUint64(buffer,counter);mac:=hmac.New(sha1.New,secret);_,_=mac.Write(buffer);sum:=mac.Sum(nil);offset:=sum[len(sum)-1]&0x0f;binaryCode:=(uint32(sum[offset])&0x7f)<<24|(uint32(sum[offset+1])&0xff)<<16|(uint32(sum[offset+2])&0xff)<<8|uint32(sum[offset+3]);modulus:=uint32(1000000);if digits==8{modulus=100000000};return fmt.Sprintf("%0*d",digits,binaryCode%modulus)}
func newReference(prefix string)(identity.ID,error){raw:=make([]byte,20);if _,err:=rand.Read(raw);err!=nil{return "",err};encoded:=strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw));wipe(raw);return identity.NewID(prefix+"_"+encoded)}
func strictJSON(raw []byte,target any)error{if len(raw)==0||len(raw)>1<<20{return ErrUnavailable};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return err};if err:=decoder.Decode(&struct{}{});err!=io.EOF{return ErrUnavailable};canonical,err:=json.Marshal(target);if err!=nil{return err};if subtle.ConstantTimeCompare(canonical,raw)!=1{return ErrUnavailable};return nil}
func wipe(value []byte){for index:=range value{value[index]=0}}
func hexDigest(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}

var _ identity.AuthVerifier = (*Verifier)(nil)
