//go:build linux

package apps

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// EnrollDatabaseClientIdentity stores an application-specific client identity.
// Exact retries repair the local lease journal without rotating broker material;
// changed identities require a separate explicit rotation operation.
func (issuer *ApplicationSecretIssuer) EnrollDatabaseClientIdentity(ctx context.Context, tenant TenantID, siteID SiteID, installation InstallationID, certificate, key []byte) (SecretRef, error) {
	if issuer == nil || issuer.Management == nil || issuer.Store.DB == nil || ctx == nil || !validID(string(tenant)) || !validID(string(siteID)) || !validID(string(installation)) {
		return "", ErrInvalid
	}
	if err := validateApplicationDatabaseClientIdentity(certificate, key, time.Now().UTC()); err != nil {
		return "", err
	}
	identifier := ApplicationManagedSecretID("database_tls", installation)
	audience := issuer.applicationAudience(siteID, installation, "database_tls")
	owner := ApplicationTenantOwnerID(string(tenant))
	if lease, err := issuer.Store.LoadApplicationSecretLease(ctx, identifier); err == nil {
		if lease.InstallationID != installation || lease.Purpose != "database_tls" || lease.Metadata.OwnerTenantID != owner || lease.Metadata.Purpose != secrets.PurposeAuthentication || !reflect.DeepEqual(lease.Metadata.Audience, audience) {
			return "", ErrPolicyDenied
		}
		if lease.Metadata.State != secrets.StateActive {
			return "", ErrConflict
		}
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	payload, err := json.Marshal(applicationDatabaseClientIdentity{CertificatePEM: certificate, KeyPEM: key})
	if err != nil {
		return "", err
	}
	defer wipeLinuxApplicationBytes(payload)
	metadata, err := issuer.Management.PutExact(ctx, secrets.PutRequest{ID: identifier, OwnerTenantID: owner, Purpose: secrets.PurposeAuthentication, Audience: audience, Plaintext: payload})
	if err != nil {
		return "", err
	}
	// If the local write fails, retain the broker's durable exact intent. A
	// retry can recover it; revocation here would make that retry impossible.
	if err := issuer.Store.SaveApplicationSecretLease(ctx, ApplicationSecretLease{InstallationID: installation, Purpose: "database_tls", Metadata: metadata, UpdatedAt: time.Now().UTC()}); err != nil {
		return "", err
	}
	return SecretRef(identifier.String()), nil
}

// ValidateApplicationDatabaseClientIdentity permits input validation before any
// site provisioning or secret enrollment side effects.
func ValidateApplicationDatabaseClientIdentity(certificate, key []byte, now time.Time) error {
	return validateApplicationDatabaseClientIdentity(certificate,key,now)
}

func validateApplicationDatabaseClientIdentity(certificate, key []byte, now time.Time) error {
	if len(certificate) == 0 || len(certificate) > 64<<10 || len(key) == 0 || len(key) > 64<<10 {
		return ErrInvalid
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) == 0 {
		return ErrInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ErrInvalid
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				return nil
			}
		}
		return ErrInvalid
	}
	return nil
}
