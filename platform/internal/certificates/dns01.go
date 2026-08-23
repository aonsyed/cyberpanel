package certificates

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// DNSChallengeAuthority is the narrow provider-neutral mutation contract used
// by ACME. Implementations retain existing TXT values and commit using the DNS
// authority's generation/idempotency rules.
type DNSChallengeAuthority interface {
	PresentACMETXT(context.Context,string,string,string,string) error
	RemoveACMETXT(context.Context,string,string,string,string) error
}

type PowerDNSDNS01Presenter struct { Authority DNSChallengeAuthority }

func NewPowerDNSDNS01Presenter(authority DNSChallengeAuthority)(*PowerDNSDNS01Presenter,error){if authority==nil{return nil,ErrInvalidCertificate};return &PowerDNSDNS01Presenter{Authority:authority},nil}
func(presenter *PowerDNSDNS01Presenter)PresentDNS01(ctx context.Context,challenge Challenge)error{owner,value,effect,err:=validatedDNS01Challenge(challenge);if err!=nil{return err};return presenter.Authority.PresentACMETXT(ctx,challenge.TenantID,owner,value,effect)}
func(presenter *PowerDNSDNS01Presenter)RemoveDNS01(ctx context.Context,challenge Challenge)error{owner,value,effect,err:=validatedDNS01Challenge(challenge);if err!=nil{return err};return presenter.Authority.RemoveACMETXT(ctx,challenge.TenantID,owner,value,effect+"-remove")}
func validatedDNS01Challenge(challenge Challenge)(string,string,string,error){if challenge.Kind!=DNS01||challenge.ID==""||challenge.TenantID==""||!validCertificateName(challenge.Name)||challenge.DNSValue==""{return "","","",ErrInvalidCertificate};decoded,err:=base64.RawURLEncoding.DecodeString(challenge.DNSValue);if err!=nil||len(decoded)!=sha256.Size{return "","","",ErrInvalidCertificate};owner:="_acme-challenge."+strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(challenge.Name,".")),"*.");sum:=sha256.Sum256([]byte("acme-dns01-v1\x00"+challenge.TenantID+"\x00"+owner+"\x00"+challenge.DNSValue+"\x00"+string(challenge.ID)));return owner,challenge.DNSValue,"acme_"+hex.EncodeToString(sum[:])[:48],nil}

var _ DNS01Presenter = (*PowerDNSDNS01Presenter)(nil)
