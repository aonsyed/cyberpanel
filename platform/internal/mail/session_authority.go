package mail

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const mailSessionVersion = "mail-session.v1"

type MailSessionAuthority struct {
	Key []byte
	Audience string
	Now func() time.Time
	MaximumLifetime time.Duration
}

type mailSessionClaims struct {
	Version string `json:"version"`
	Audience string `json:"audience"`
	ID string `json:"id"`
	TenantID string `json:"tenant_id"`
	MailboxID MailboxID `json:"mailbox_id"`
	PrincipalID string `json:"principal_id"`
	AuthzEpoch uint64 `json:"authz_epoch"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewMailSessionAuthority(key []byte,audience string)(*MailSessionAuthority,error){
	if len(key)!=32||!validOpaque(audience){return nil,fmt.Errorf("%w: mail session authority",ErrInvalidCommand)}
	copyKey:=append([]byte(nil),key...)
	return &MailSessionAuthority{Key:copyKey,Audience:audience,Now:time.Now,MaximumLifetime:30*time.Minute},nil
}

func (authority *MailSessionAuthority) IssueMailSession(ctx context.Context,session MailSession,lifetime time.Duration)(MailSession,error){
	if ctx==nil||authority==nil||len(authority.Key)!=32||!validOpaque(authority.Audience){return MailSession{},ErrInvalidCommand}
	if err:=ctx.Err();err!=nil{return MailSession{},err}
	maximum:=authority.MaximumLifetime;if maximum<=0||maximum>30*time.Minute{maximum=30*time.Minute}
	if lifetime<=0{lifetime=15*time.Minute};if lifetime<time.Minute||lifetime>maximum{return MailSession{},ErrInvalidCommand}
	if !validOpaque(session.TenantID)||session.MailboxID==""||!validOpaque(string(session.MailboxID))||!validOpaque(session.PrincipalID)||session.AuthzEpoch==0{return MailSession{},ErrInvalidCommand}
	now:=authority.now();idBytes:=make([]byte,24);if _,err:=io.ReadFull(rand.Reader,idBytes);err!=nil{return MailSession{},err}
	id:="wms_"+base64.RawURLEncoding.EncodeToString(idBytes)
	claims:=mailSessionClaims{Version:mailSessionVersion,Audience:authority.Audience,ID:id,TenantID:session.TenantID,MailboxID:session.MailboxID,PrincipalID:session.PrincipalID,AuthzEpoch:session.AuthzEpoch,IssuedAt:now,ExpiresAt:now.Add(lifetime)}
	plaintext,err:=json.Marshal(claims);if err!=nil{return MailSession{},err};defer clearSessionBytes(plaintext)
	block,err:=aes.NewCipher(authority.Key);if err!=nil{return MailSession{},err};aead,err:=cipher.NewGCM(block);if err!=nil{return MailSession{},err}
	nonce:=make([]byte,aead.NonceSize());if _,err=io.ReadFull(rand.Reader,nonce);err!=nil{return MailSession{},err}
	sealed:=aead.Seal(nil,nonce,plaintext,[]byte(mailSessionVersion+"\x00"+authority.Audience))
	tokenBytes:=append(nonce,sealed...);token:=base64.RawURLEncoding.EncodeToString(tokenBytes);clearSessionBytes(tokenBytes);clearSessionBytes(sealed);clearSessionBytes(idBytes)
	return MailSession{ID:id,Token:token,TenantID:claims.TenantID,MailboxID:claims.MailboxID,PrincipalID:claims.PrincipalID,AuthzEpoch:claims.AuthzEpoch,ExpiresAt:claims.ExpiresAt},nil
}

func (authority *MailSessionAuthority) ValidateMailSession(ctx context.Context,presented MailSession)(MailSession,error){
	if ctx==nil||authority==nil||len(authority.Key)!=32||!validOpaque(authority.Audience)||!validOpaque(presented.ID)||len(presented.Token)<64||len(presented.Token)>4096||strings.ContainsAny(presented.Token,"\r\n\t "){return MailSession{},ErrUnauthorized}
	if err:=ctx.Err();err!=nil{return MailSession{},err}
	raw,err:=base64.RawURLEncoding.DecodeString(presented.Token);if err!=nil{return MailSession{},ErrUnauthorized};defer clearSessionBytes(raw)
	block,err:=aes.NewCipher(authority.Key);if err!=nil{return MailSession{},ErrUnauthorized};aead,err:=cipher.NewGCM(block);if err!=nil||len(raw)<=aead.NonceSize(){return MailSession{},ErrUnauthorized}
	plaintext,err:=aead.Open(nil,raw[:aead.NonceSize()],raw[aead.NonceSize():],[]byte(mailSessionVersion+"\x00"+authority.Audience));if err!=nil{return MailSession{},ErrUnauthorized};defer clearSessionBytes(plaintext)
	decoder:=json.NewDecoder(bytes.NewReader(plaintext));decoder.DisallowUnknownFields();var claims mailSessionClaims
	if err=decoder.Decode(&claims);err!=nil{return MailSession{},ErrUnauthorized};var extra any;if err=decoder.Decode(&extra);!errors.Is(err,io.EOF){return MailSession{},ErrUnauthorized}
	now:=authority.now();maximum:=authority.MaximumLifetime;if maximum<=0||maximum>30*time.Minute{maximum=30*time.Minute}
	if claims.Version!=mailSessionVersion||claims.Audience!=authority.Audience||claims.ID!=presented.ID||!validOpaque(claims.TenantID)||!validOpaque(string(claims.MailboxID))||!validOpaque(claims.PrincipalID)||claims.AuthzEpoch==0||claims.IssuedAt.IsZero()||claims.ExpiresAt.IsZero()||claims.ExpiresAt.After(claims.IssuedAt.Add(maximum))||claims.IssuedAt.After(now.Add(30*time.Second))||!now.Before(claims.ExpiresAt){return MailSession{},ErrUnauthorized}
	if presented.TenantID!=""&&presented.TenantID!=claims.TenantID{return MailSession{},ErrUnauthorized}
	if presented.MailboxID!=""&&presented.MailboxID!=claims.MailboxID{return MailSession{},ErrUnauthorized}
	if presented.PrincipalID!=""&&presented.PrincipalID!=claims.PrincipalID{return MailSession{},ErrUnauthorized}
	if presented.AuthzEpoch!=0&&presented.AuthzEpoch!=claims.AuthzEpoch{return MailSession{},ErrUnauthorized}
	return MailSession{ID:claims.ID,Token:presented.Token,TenantID:claims.TenantID,MailboxID:claims.MailboxID,PrincipalID:claims.PrincipalID,AuthzEpoch:claims.AuthzEpoch,ExpiresAt:claims.ExpiresAt},nil
}

func (authority *MailSessionAuthority)now()time.Time{if authority.Now!=nil{return authority.Now().UTC()};return time.Now().UTC()}
func clearSessionBytes(value []byte){for index:=range value{value[index]=0}}
