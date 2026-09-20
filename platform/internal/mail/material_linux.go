//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	OpenDKIMMaterialAdapterID          = "mail.opendkim.private-key"
	OpenDKIMMaterialAdapterVersion     = "linux-opendkim-v1"
	PostfixRelayMaterialAdapterID      = "mail.postfix.relay"
	PostfixRelayMaterialAdapterVersion = "linux-postfix-relay-v1"
)

type MailMaterialResolver interface {
	ResolveDKIMPrivateKey(context.Context, string, string, string, string) ([]byte, error)
	ResolveRelayCredential(context.Context, string, string, string) (RelayCredential, error)
}

type RelayCredential struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
}

func (credential *RelayCredential) Wipe() {
	if credential == nil {
		return
	}
	wipeMailBytes(credential.Password)
	credential.Username = ""
	credential.Password = nil
}

// LocalMailMaterialResolver obtains DKIM key material only through the
// purpose-bound panel-secretd protocol. Tenant, domain, and selector are all
// included in the audience binding used for each one-time read.
type LocalMailMaterialResolver struct {
	client *secrets.MaterialClient
}

func NewLocalMailMaterialResolver() (*LocalMailMaterialResolver, error) {
	client, err := secrets.NewLocalMaterialClient()
	if err != nil {
		return nil, err
	}
	return NewMailMaterialResolver(client)
}

func NewMailMaterialResolver(client *secrets.MaterialClient) (*LocalMailMaterialResolver, error) {
	if client == nil {
		return nil, ErrInvalidCommand
	}
	return &LocalMailMaterialResolver{client: client}, nil
}

func (resolver *LocalMailMaterialResolver) ResolveDKIMPrivateKey(ctx context.Context, tenant string, privateKeyRef string, domain string, selector string) ([]byte, error) {
	if resolver == nil || resolver.client == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(privateKeyRef) || !validHostname(domain) || !validDKIMSelector(selector) {
		return nil, ErrInvalidCommand
	}
	secretID := mailMaterialID("dkimkey", privateKeyRef)
	if strings.HasPrefix(privateKeyRef, "migsecret_") {
		if exact, exactErr := secrets.NewID(privateKeyRef); exactErr == nil {
			secretID = exact
		}
	}
	response, err := resolver.client.Read(ctx, secrets.MaterialRequest{
		SecretID:       secretID,
		OwnerTenantID:  mailMaterialID("mailtenant", tenant),
		Purpose:        secrets.PurposeDKIMKey,
		Operation:      secrets.OperationRead,
		AdapterID:      OpenDKIMMaterialAdapterID,
		AdapterVersion: OpenDKIMMaterialAdapterVersion,
		ResourceID:     mailMaterialID("dkimaudience", tenant, domain, selector),
	})
	if err != nil || len(response.Material) == 0 || len(response.Material) > 128<<10 {
		wipeMailBytes(response.Material)
		return nil, ErrInvalidCommand
	}
	return response.Material, nil
}

func (resolver *LocalMailMaterialResolver) ResolveRelayCredential(ctx context.Context, tenant string, credentialRef string, domain string) (RelayCredential, error) {
	if resolver == nil || resolver.client == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(credentialRef) || !validHostname(domain) {
		return RelayCredential{}, ErrInvalidCommand
	}
	response, err := resolver.client.Read(ctx, secrets.MaterialRequest{
		SecretID:       mailMaterialID("relaycredential", credentialRef),
		OwnerTenantID:  mailMaterialID("mailtenant", tenant),
		Purpose:        secrets.PurposeMailRelay,
		Operation:      secrets.OperationAuthenticate,
		AdapterID:      PostfixRelayMaterialAdapterID,
		AdapterVersion: PostfixRelayMaterialAdapterVersion,
		ResourceID:     mailMaterialID("relayaudience", tenant, domain),
	})
	if err != nil || len(response.Material) == 0 || len(response.Material) > 16<<10 {
		wipeMailBytes(response.Material)
		return RelayCredential{}, ErrInvalidCommand
	}
	defer wipeMailBytes(response.Material)
	decoder := json.NewDecoder(bytes.NewReader(response.Material))
	decoder.DisallowUnknownFields()
	var material RelayCredential
	if decoder.Decode(&material) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validRelayUsername(material.Username) || !validRelayPassword(material.Password) {
		material.Wipe()
		return RelayCredential{}, ErrInvalidCommand
	}
	return material, nil
}

func validRelayUsername(value string) bool {
	if len(value) < 1 || len(value) > 254 {
		return false
	}
	for _, character := range value {
		if !(character == '@' || character == '.' || character == '_' || character == '+' || character == '-' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
			return false
		}
	}
	return true
}

func validRelayPassword(value []byte) bool {
	if len(value) < 24 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if !(character == '_' || character == '-' || character == '.' || character == '~' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
			return false
		}
	}
	return true
}

func mailMaterialID(prefix string, values ...string) secrets.ID {
	hash := sha256.New()
	_, _ = hash.Write([]byte(prefix))
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	identifier, _ := secrets.NewID(prefix + "_" + hex.EncodeToString(hash.Sum(nil))[:48])
	return identifier
}

func wipeMailBytes(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}

var _ MailMaterialResolver = (*LocalMailMaterialResolver)(nil)

const MailboxCredentialAdapterID = "mail.dovecot.mailbox-hash"
const MailboxCredentialAdapterVersion = "linux-dovecot-crypt-v1"

// Only the scheme explicitly emitted by supported legacy CyberPanel is
// accepted. Hash-looking plaintext, weak/unknown crypt schemes and excessive
// bcrypt cost are not promoted to credentials by shape guessing.
func ValidateMailboxCredentialHash(value []byte) error {
	if len(value) != 67 || !bytes.HasPrefix(value, []byte("{CRYPT}$2b$")) {
		return ErrInvalidCommand
	}
	if value[13] != '$' {
		return ErrInvalidCommand
	}
	cost, err := strconv.Atoi(string(value[11:13]))
	if err != nil || cost < 10 || cost > 14 {
		return ErrInvalidCommand
	}
	for _, character := range value[14:] {
		if !(character == '.' || character == '/' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return ErrInvalidCommand
		}
	}
	return nil
}

func MailboxCredentialAudience(tenant string, domain DomainID, mailbox MailboxID, release string) (secrets.ID, secrets.AudienceBinding, error) {
	if !validOpaque(tenant) || !validOpaque(string(domain)) || !validOpaque(string(mailbox)) {
		return "", secrets.AudienceBinding{}, ErrInvalidCommand
	}
	audience := secrets.AudienceBinding{AdapterID: MailboxCredentialAdapterID, AdapterVersion: MailboxCredentialAdapterVersion,
		Account: "local-dovecot", Origin: "local://panel-execd/dovecot", ResourceKind: "mailbox_crypt_bcrypt",
		ResourceID: mailMaterialID("mailboxaudience", tenant, string(domain), string(mailbox)), ResourceGeneration: 1,
		Operations: []secrets.Operation{secrets.OperationAuthenticate}, ConsumerReleaseDigest: release}
	if audience.Validate() != nil {
		return "", secrets.AudienceBinding{}, ErrInvalidCommand
	}
	return mailMaterialID("mailtenant", tenant), audience, nil
}

func DKIMCredentialAudience(tenant string, domain string, selector string, release string) (secrets.ID, secrets.AudienceBinding, error) {
	if !validOpaque(tenant) || !validHostname(domain) || !validDKIMSelector(selector) || !validMailEvidenceDigest(release) {
		return "", secrets.AudienceBinding{}, ErrInvalidCommand
	}
	audience := secrets.AudienceBinding{AdapterID: OpenDKIMMaterialAdapterID, AdapterVersion: OpenDKIMMaterialAdapterVersion,
		Account: "mail-domain", Origin: "local://panel-execd/opendkim", ResourceKind: "mail_domain_dkim",
		ResourceID: mailMaterialID("dkimaudience", tenant, domain, selector), ResourceGeneration: 1,
		Operations: []secrets.Operation{secrets.OperationRead}, ConsumerReleaseDigest: release}
	if audience.Validate() != nil {
		return "", secrets.AudienceBinding{}, ErrInvalidCommand
	}
	return mailMaterialID("mailtenant", tenant), audience, nil
}

// DKIMPublicBindingFromPrivateKey derives only public DNS material. The
// caller retains and wipes the private input; no private bytes are returned or
// persisted by this conversion.
func DKIMPublicBindingFromPrivateKey(value []byte) (string, error) {
	if len(value) == 0 || len(value) > 128<<10 {
		return "", ErrInvalidCommand
	}
	block, remainder := pem.Decode(value)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(remainder)) != 0 {
		return "", ErrInvalidCommand
	}
	defer wipeMailBytes(block.Bytes)
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", ErrInvalidCommand
		}
		privateKey = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", ErrInvalidCommand
		}
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return "", ErrInvalidCommand
		}
	default:
		return "", ErrInvalidCommand
	}
	if privateKey.Validate() != nil || privateKey.N.BitLen() < 2048 || privateKey.N.BitLen() > 8192 || privateKey.E != 65537 {
		return "", ErrInvalidCommand
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", ErrInvalidCommand
	}
	defer wipeMailBytes(publicDER)
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicDER), nil
}

func (resolver *LocalMailMaterialResolver) ResolveMailboxHash(ctx context.Context, tenant string, domain DomainID, mailbox MailboxID, reference MailboxCredentialRef) ([]byte, error) {
	identifier, err := secrets.NewID(string(reference))
	if err != nil || resolver == nil || resolver.client == nil || !validOpaque(tenant) || !validOpaque(string(domain)) || !validOpaque(string(mailbox)) || strings.TrimSpace(string(reference)) != string(reference) {
		return nil, ErrInvalidCommand
	}
	response, err := resolver.client.Read(ctx, secrets.MaterialRequest{SecretID: identifier, OwnerTenantID: mailMaterialID("mailtenant", tenant),
		Purpose: secrets.PurposeAuthentication, Operation: secrets.OperationAuthenticate, AdapterID: MailboxCredentialAdapterID, AdapterVersion: MailboxCredentialAdapterVersion,
		ResourceID: mailMaterialID("mailboxaudience", tenant, string(domain), string(mailbox))})
	if err != nil || ValidateMailboxCredentialHash(response.Material) != nil && ValidateMailboxPasswordHash(response.Material) != nil {
		wipeMailBytes(response.Material)
		return nil, ErrUnauthorized
	}
	return response.Material, nil
}
