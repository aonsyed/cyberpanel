package secrets

import(
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type KeyEncryptionKey interface{Epoch(context.Context) (uint64,error);Wrap(context.Context,uint64,[]byte,[]byte)([]byte,error);Unwrap(context.Context,uint64,[]byte,[]byte)([]byte,error)}
type ConsumerRegistry interface{Verify(context.Context,ConsumerIdentity)(bool,error)}
type Broker struct{store *Store;kek KeyEncryptionKey;consumers ConsumerRegistry;clock func()time.Time;mu sync.Mutex}
func NewBroker(store *Store,kek KeyEncryptionKey,consumers ConsumerRegistry)(*Broker,error){if store==nil||kek==nil||consumers==nil{return nil,ErrInvalid};return &Broker{store:store,kek:kek,consumers:consumers,clock:time.Now},nil}

type PutRequest struct{ID,OwnerTenantID ID;Purpose Purpose;Audience AudienceBinding;Plaintext []byte;ExpectedVersion uint64;ExpectedBindingDigest string}
func(b *Broker)Put(ctx context.Context,request PutRequest)(Metadata,error){b.mu.Lock();defer b.mu.Unlock();defer wipe(request.Plaintext);if !request.ID.Valid()||!request.OwnerTenantID.Valid()||!validPurpose(request.Purpose)||request.Audience.Validate()!=nil||len(request.Plaintext)==0||len(request.Plaintext)>16<<20||request.ExpectedVersion==0&&request.ExpectedBindingDigest!=""||request.ExpectedVersion>0&&len(request.ExpectedBindingDigest)!=64{return Metadata{},ErrInvalid};if request.ExpectedVersion>0{head,err:=b.store.Head(ctx,request.ID);if err!=nil{return Metadata{},err};if head.Version!=request.ExpectedVersion||head.BindingDigest!=request.ExpectedBindingDigest||head.OwnerTenantID!=request.OwnerTenantID||head.Purpose!=request.Purpose||head.Audience.ResourceID!=request.Audience.ResourceID||head.Audience.ResourceKind!=request.Audience.ResourceKind{return Metadata{},ErrConflict};if digestJSON(head.Audience)!=digestJSON(request.Audience){return Metadata{},fmt.Errorf("%w: audience changes require replacement authorization",ErrConflict)}};epoch,err:=b.kek.Epoch(ctx);if err!=nil{return Metadata{},err};dek:=make([]byte,32);if _,err=io.ReadFull(rand.Reader,dek);err!=nil{return Metadata{},err};defer wipe(dek);block,err:=aes.NewCipher(dek);if err!=nil{return Metadata{},err};aead,err:=cipher.NewGCM(block);if err!=nil{return Metadata{},err};nonce:=make([]byte,aead.NonceSize());if _,err=io.ReadFull(rand.Reader,nonce);err!=nil{return Metadata{},err};metadata:=Metadata{ID:request.ID,OwnerTenantID:request.OwnerTenantID,Purpose:request.Purpose,Version:request.ExpectedVersion+1,KeyEpoch:epoch,State:StateActive,Audience:request.Audience,Algorithm:"AES-256-GCM",CreatedAt:b.clock().UTC()};metadata.BindingDigest=digestJSON(bindingDTO(metadata));aad:=canonicalAAD(metadata);ciphertext:=aead.Seal(nil,nonce,request.Plaintext,aad);wrapped,err:=b.kek.Wrap(ctx,epoch,dek,aad);if err!=nil{return Metadata{},err};metadata.WrappedDEKDigest=digest(wrapped);metadata.CiphertextDigest=digest(ciphertext);record:=SecretRecord{Metadata:metadata,Nonce:nonce,WrappedDEK:wrapped,Ciphertext:ciphertext,AAD:aad};if err=b.store.Put(ctx,record,request.ExpectedVersion);err!=nil{return Metadata{},err};return metadata,nil}

type GrantRequest struct{ID,SecretID,TenantID ID;Version uint64;Operation Operation;Consumer ConsumerIdentity;RequestDigest string;TTL time.Duration}
func(b *Broker)Grant(ctx context.Context,request GrantRequest)(DeliveryGrant,error){if b==nil||request.Consumer.Validate()!=nil||request.TTL<=0||request.TTL>5*time.Minute{return DeliveryGrant{},ErrInvalid};record,err:=b.store.Record(ctx,request.SecretID,request.Version);if err!=nil{return DeliveryGrant{},err};if record.Metadata.OwnerTenantID!=request.TenantID||record.Metadata.State!=StateActive{return DeliveryGrant{},ErrForbidden};allowed,err:=b.audienceAllows(ctx,record.Metadata.Audience,request.Consumer,request.Operation);if err!=nil{return DeliveryGrant{},err};if !allowed{return DeliveryGrant{},ErrForbidden};verified,err:=b.consumers.Verify(ctx,request.Consumer);if err!=nil||!verified{return DeliveryGrant{},ErrForbidden};grant:=DeliveryGrant{ID:request.ID,SecretID:request.SecretID,TenantID:request.TenantID,SecretVersion:request.Version,Operation:request.Operation,Consumer:request.Consumer,AudienceDigest:record.Metadata.BindingDigest,RequestDigest:request.RequestDigest,ExpiresAt:b.clock().UTC().Add(request.TTL)};if err=b.store.IssueGrant(ctx,grant);err!=nil{return DeliveryGrant{},err};return grant,nil}

// Deliver decrypts exactly one consumed grant into a bounded pipe. The broker
// wipes its plaintext copy after the write; consumers must read once and close.
func(b *Broker)Deliver(ctx context.Context,grantID ID)(io.ReadCloser,Metadata,error){b.mu.Lock();defer b.mu.Unlock();grant,err:=b.store.ConsumeGrant(ctx,grantID,b.clock().UTC());if err!=nil{return nil,Metadata{},err};record,err:=b.store.Record(ctx,grant.SecretID,grant.SecretVersion);if err!=nil{_ = b.store.RecordDelivery(ctx,grant,"record_missing");return nil,Metadata{},err};allowed,err:=b.audienceAllows(ctx,record.Metadata.Audience,grant.Consumer,grant.Operation);if err!=nil{return nil,Metadata{},err};if record.Metadata.State!=StateActive||record.Metadata.BindingDigest!=grant.AudienceDigest||!allowed{_ = b.store.RecordDelivery(ctx,grant,"binding_rejected");return nil,Metadata{},ErrForbidden};verified,err:=b.consumers.Verify(ctx,grant.Consumer);if err!=nil||!verified{_ = b.store.RecordDelivery(ctx,grant,"consumer_rejected");return nil,Metadata{},ErrForbidden};if !hmac.Equal(record.AAD,canonicalAAD(record.Metadata))||digest(record.WrappedDEK)!=record.Metadata.WrappedDEKDigest||digest(record.Ciphertext)!=record.Metadata.CiphertextDigest{return nil,Metadata{},ErrConflict};dek,err:=b.kek.Unwrap(ctx,record.Metadata.KeyEpoch,record.WrappedDEK,record.AAD);if err!=nil{return nil,Metadata{},err};defer wipe(dek);block,err:=aes.NewCipher(dek);if err!=nil{return nil,Metadata{},err};aead,err:=cipher.NewGCM(block);if err!=nil{return nil,Metadata{},err};plaintext,err:=aead.Open(nil,record.Nonce,record.Ciphertext,record.AAD);if err!=nil{return nil,Metadata{},ErrConflict};reader,writer:=io.Pipe();go func(){defer wipe(plaintext);_,writeErr:=writer.Write(plaintext);_ = b.store.RecordDelivery(context.Background(),grant,deliveryOutcome(writeErr));_ = writer.CloseWithError(writeErr)}();return reader,record.Metadata,nil}

func(b *Broker)Revoke(ctx context.Context,id ID,version uint64,destroy bool)error{b.mu.Lock();defer b.mu.Unlock();state:=StateRevoked;if destroy{state=StateDestroyed};return b.store.UpdateState(ctx,id,version,state,b.clock().UTC())}
func audienceAllows(binding AudienceBinding,consumer ConsumerIdentity,operation Operation)bool{if binding.AdapterID!=consumer.AdapterID||binding.AdapterVersion!=consumer.AdapterVersion||binding.ConsumerReleaseDigest!=consumer.ReleaseDigest{return false};for _,allowed:=range binding.Operations{if allowed==operation{return true}};return false}
func bindingDTO(metadata Metadata)any{return struct{InstallationDomain string `json:"domain"`;ID ID `json:"id"`;Owner ID `json:"owner"`;Purpose Purpose `json:"purpose"`;Version uint64 `json:"version"`;KeyEpoch uint64 `json:"key_epoch"`;Audience AudienceBinding `json:"audience"`;Algorithm string `json:"algorithm"`}{"cyberpanel-secret-v1",metadata.ID,metadata.OwnerTenantID,metadata.Purpose,metadata.Version,metadata.KeyEpoch,metadata.Audience,metadata.Algorithm}}
func canonicalAAD(metadata Metadata)[]byte{raw,_:=json.Marshal(bindingDTO(metadata));return raw}
func digestJSON(value any)string{raw,_:=json.Marshal(value);return digest(raw)}
func digest(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}
func deliveryOutcome(err error)string{if err!=nil{return "consumer_closed"};return "delivered"}
func wipe(value []byte){for index:=range value{value[index]=0};runtime.KeepAlive(value)}

// FileKEK is the standalone fallback when TPM/HSM sealing is unavailable. The
// key file must be owned by the broker account and mode 0400.
type FileKEK struct{path string;epoch uint64;ownerUID int;systemdCredential bool}
func NewFileKEK(path string,epoch uint64,ownerUID int)(*FileKEK,error){return newFileKEK(path,epoch,ownerUID,false)}

// NewSystemdCredentialKEK accepts only the broker's registered credential mount.
// Ordinary key files retain the stricter owner/0400 contract above.
func NewSystemdCredentialKEK(path string, epoch uint64) (*FileKEK, error) {
	if path != "/run/credentials/panel-secretd.service/wrapping.key" { return nil, ErrInvalid }
	return newFileKEK(path, epoch, 0, true)
}

func newFileKEK(path string, epoch uint64, ownerUID int, systemdCredential bool) (*FileKEK, error) {
	if !strings.HasPrefix(path, "/") || epoch == 0 || ownerUID < 0 { return nil, ErrInvalid }
	key := &FileKEK{path:path, epoch:epoch, ownerUID:ownerUID, systemdCredential:systemdCredential}
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !key.validFile(info) { return nil, ErrForbidden }
	return key, nil
}

func (f *FileKEK) validFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(stat.Uid) != f.ownerUID { return false }
	if f.systemdCredential { return stat.Gid == 0 && (info.Mode().Perm() == 0400 || info.Mode().Perm() == 0440) }
	return info.Mode().Perm() == 0400
}
func(f *FileKEK)Epoch(context.Context)(uint64,error){if f==nil{return 0,ErrInvalid};return f.epoch,nil}
func(f *FileKEK)Wrap(ctx context.Context,epoch uint64,plaintext,aad []byte)([]byte,error){return f.seal(epoch,plaintext,aad)}
func(f *FileKEK)Unwrap(ctx context.Context,epoch uint64,ciphertext,aad []byte)([]byte,error){key,err:=f.key();if err!=nil{return nil,err};defer wipe(key);block,err:=aes.NewCipher(key);if err!=nil{return nil,err};aead,err:=cipher.NewGCM(block);if err!=nil{return nil,err};if len(ciphertext)<aead.NonceSize(){return nil,ErrInvalid};return aead.Open(nil,ciphertext[:aead.NonceSize()],ciphertext[aead.NonceSize():],wrapAAD(aad,epoch))}
func(f *FileKEK)seal(epoch uint64,plaintext,aad []byte)([]byte,error){if f==nil||epoch!=f.epoch{return nil,ErrRollback};key,err:=f.key();if err!=nil{return nil,err};defer wipe(key);block,err:=aes.NewCipher(key);if err!=nil{return nil,err};aead,err:=cipher.NewGCM(block);if err!=nil{return nil,err};nonce:=make([]byte,aead.NonceSize());if _,err=rand.Read(nonce);err!=nil{return nil,err};return aead.Seal(nonce,nonce,plaintext,wrapAAD(aad,epoch)),nil}
func wrapAAD(aad []byte,epoch uint64)[]byte{return append(append([]byte(nil),aad...),[]byte(fmt.Sprintf("\x00kek-epoch:%d",epoch))...)}
func (f *FileKEK) key() ([]byte, error) {
	if f == nil { return nil, ErrInvalid }
	info, err := os.Lstat(f.path)
	if err != nil { return nil, err }
	if !f.validFile(info) { return nil, ErrForbidden }
	file, err := os.Open(f.path)
	if err != nil { return nil, err }
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !f.validFile(opened) { return nil, ErrForbidden }
	raw, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(raw) != 32 { wipe(raw); return nil, ErrInvalid }
	return raw, nil
}
var _=errors.Is
