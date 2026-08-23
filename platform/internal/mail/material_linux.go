//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	OpenDKIMMaterialAdapterID = "mail.opendkim.private-key"
	OpenDKIMMaterialAdapterVersion = "linux-opendkim-v1"
	PostfixRelayMaterialAdapterID = "mail.postfix.relay"
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
	response, err := resolver.client.Read(ctx, secrets.MaterialRequest{
		SecretID: mailMaterialID("dkimkey", privateKeyRef),
		OwnerTenantID: mailMaterialID("mailtenant", tenant),
		Purpose: secrets.PurposeDKIMKey,
		Operation: secrets.OperationRead,
		AdapterID: OpenDKIMMaterialAdapterID,
		AdapterVersion: OpenDKIMMaterialAdapterVersion,
		ResourceID: mailMaterialID("dkimaudience", tenant, domain, selector),
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
		SecretID: mailMaterialID("relaycredential", credentialRef),
		OwnerTenantID: mailMaterialID("mailtenant", tenant),
		Purpose: secrets.PurposeMailRelay,
		Operation: secrets.OperationAuthenticate,
		AdapterID: PostfixRelayMaterialAdapterID,
		AdapterVersion: PostfixRelayMaterialAdapterVersion,
		ResourceID: mailMaterialID("relayaudience", tenant, domain),
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
