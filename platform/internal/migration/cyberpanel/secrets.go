package cyberpanel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const secretEnvelopeAlgorithm = "X25519-HKDF-SHA256-AES-256-GCM"

type X25519Sealer struct {
	keyID string
	publicKey *ecdh.PublicKey
	random io.Reader
}

func NewX25519Sealer(keyID string, targetPublicKey []byte) (*X25519Sealer, error) {
	if !validKeyID(keyID) || len(targetPublicKey) != 32 { return nil, ErrInvalid }
	publicKey, err := ecdh.X25519().NewPublicKey(append([]byte(nil), targetPublicKey...))
	if err != nil { return nil, ErrInvalid }
	return &X25519Sealer{keyID:keyID,publicKey:publicKey,random:rand.Reader},nil
}

func (s *X25519Sealer) Seal(ctx context.Context, migrationID migration.ID, material SecretMaterial, plaintext []byte) (migration.SecretEnvelope, error) {
	if s==nil||s.publicKey==nil||ctx==nil||!migrationID.Valid()||!material.Ref.Valid()||strings.TrimSpace(material.Purpose)==""||!isDigest(material.AudienceDigest)||len(plaintext)==0{return migration.SecretEnvelope{},ErrInvalid}
	select{case<-ctx.Done():return migration.SecretEnvelope{},ctx.Err();default:}
	ephemeral,err:=ecdh.X25519().GenerateKey(s.random);if err!=nil{return migration.SecretEnvelope{},err};shared,err:=ephemeral.ECDH(s.publicKey);if err!=nil{return migration.SecretEnvelope{},err};defer wipe(shared)
	salt:=sha256.Sum256([]byte("cyberpanel-migration-secret-v1\x00"+migrationID.String()+"\x00"+material.AudienceDigest))
	secretID:=secretEnvelopeID(migrationID,material.Ref)
	key:=hkdfSHA256(shared,salt[:],[]byte(material.Purpose+"\x00"+secretID),32);defer wipe(key)
	block,err:=aes.NewCipher(key);if err!=nil{return migration.SecretEnvelope{},err};var aead cipher.AEAD;aead,err=cipher.NewGCM(block);if err!=nil{return migration.SecretEnvelope{},err}
	nonce:=make([]byte,aead.NonceSize());if _,err:=io.ReadFull(s.random,nonce);err!=nil{return migration.SecretEnvelope{},err}
	aad,err:=json.Marshal(struct{Domain string `json:"domain"`;MigrationID string `json:"migration_id"`;SecretID string `json:"secret_id"`;Purpose string `json:"purpose"`;AudienceDigest string `json:"audience_digest"`;KeyID string `json:"key_id"`}{Domain:"cyberpanel-migration-secret-v1",MigrationID:migrationID.String(),SecretID:secretID,Purpose:material.Purpose,AudienceDigest:material.AudienceDigest,KeyID:s.keyID});if err!=nil{return migration.SecretEnvelope{},err}
	ciphertext:=aead.Seal(nil,nonce,plaintext,aad);ciphertext=append(nonce,ciphertext...)
	return migration.SecretEnvelope{SecretID:secretID,Purpose:material.Purpose,AudienceDigest:material.AudienceDigest,Algorithm:secretEnvelopeAlgorithm,KeyID:s.keyID,Version:1,EncapsulatedKey:append([]byte(nil),ephemeral.PublicKey().Bytes()...),Ciphertext:ciphertext},nil
}

func secretEnvelopeID(migrationID migration.ID,ref SecretRef)string{return "sec_"+digestText(migrationID.String()+"\x00"+string(ref))[:32]}

func hkdfSHA256(secret,salt,info []byte,size int)[]byte{extract:=hmac.New(sha256.New,salt);extract.Write(secret);pseudorandom:=extract.Sum(nil);defer wipe(pseudorandom);output:=make([]byte,0,size);previous:=[]byte{};for counter:=byte(1);len(output)<size;counter++{expand:=hmac.New(sha256.New,pseudorandom);expand.Write(previous);expand.Write(info);expand.Write([]byte{counter});previous=expand.Sum(nil);needed:=size-len(output);if needed>len(previous){needed=len(previous)};output=append(output,previous[:needed]...)};return output}

type SecretReader interface { Read(context.Context) ([]byte,error) }
type FixedSecretSource struct { readers map[SecretRef]SecretReader; mu sync.RWMutex }
func NewFixedSecretSource(readers map[SecretRef]SecretReader)(*FixedSecretSource,error){if len(readers)==0{return nil,ErrInvalid};copyReaders:=make(map[SecretRef]SecretReader,len(readers));for ref,reader:=range readers{if !ref.Valid()||reader==nil{return nil,ErrInvalid};copyReaders[ref]=reader};return &FixedSecretSource{readers:copyReaders},nil}
func(s *FixedSecretSource)ReadSecret(ctx context.Context,ref SecretRef)([]byte,error){if s==nil||ctx==nil||!ref.Valid(){return nil,ErrInvalid};s.mu.RLock();reader:=s.readers[ref];s.mu.RUnlock();if reader==nil{return nil,migration.ErrNotFound};value,err:=reader.Read(ctx);if err!=nil{return nil,err};if len(value)==0{return nil,ErrDenied};return append([]byte(nil),value...),nil}

type CompositeSecretSource struct { sources []SecretSource }
func NewCompositeSecretSource(sources ...SecretSource)(*CompositeSecretSource,error){filtered:=[]SecretSource{};for _,source:=range sources{if source!=nil{filtered=append(filtered,source)}};if len(filtered)==0{return nil,ErrInvalid};return &CompositeSecretSource{sources:filtered},nil}
func(s *CompositeSecretSource)ReadSecret(ctx context.Context,ref SecretRef)([]byte,error){if s==nil||ctx==nil||!ref.Valid(){return nil,ErrInvalid};var failures []error;for _,source:=range s.sources{value,err:=source.ReadSecret(ctx,ref);if err==nil{return value,nil};if !errors.Is(err,migration.ErrNotFound)&&!errors.Is(err,ErrDenied){failures=append(failures,err)}};if len(failures)>0{return nil,errors.Join(failures...)};return nil,migration.ErrNotFound}

type BytesSecretReader struct { value []byte }
func NewBytesSecretReader(value []byte)(*BytesSecretReader,error){if len(value)==0{return nil,ErrInvalid};return &BytesSecretReader{value:append([]byte(nil),value...)},nil}
func(r *BytesSecretReader)Read(ctx context.Context)([]byte,error){if r==nil||ctx==nil{return nil,ErrInvalid};select{case<-ctx.Done():return nil,ctx.Err();default:};return append([]byte(nil),r.value...),nil}

var _ SecretSealer=(*X25519Sealer)(nil)
var _ SecretSource=(*FixedSecretSource)(nil)
