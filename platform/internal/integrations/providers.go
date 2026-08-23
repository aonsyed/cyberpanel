package integrations

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

type Provider interface {
	DiscoverCapabilities(context.Context, ProviderBinding) (CapabilitySet, error)
	Health(context.Context, ProviderBinding) (ProviderHealth, error)
	ValidateCredential(context.Context, ProviderBinding) error
	RevokeCredential(context.Context, ProviderBinding) error
}

type PageRequest struct { Limit uint16 `json:"limit"`; Cursor string `json:"cursor,omitempty"` }
func (page PageRequest) Validate() error { if page.Limit == 0 || page.Limit > 1000 || len(page.Cursor) > 2048 { return ErrInvalid }; return nil }

type ConcurrencyMode string
const ( ConcurrencyAtomicCAS ConcurrencyMode = "atomic_cas"; ConcurrencyObserveApply ConcurrencyMode = "observe_apply" )

type DNSOwnership string
const ( DNSOwnershipExclusive DNSOwnership = "exclusive"; DNSOwnershipManagedSet DNSOwnership = "managed_set"; DNSOwnershipCooperative DNSOwnership = "cooperative" )

type CloudflareBinding struct {
	BindingID BindingID `json:"binding_id"`
	AccountID string `json:"account_id,omitempty"`
	ZoneIDs []string `json:"zone_ids,omitempty"`
	Ownership DNSOwnership `json:"ownership"`
	Concurrency ConcurrencyMode `json:"concurrency"`
	ProxyDefault bool `json:"proxy_default"`
	InitialImportOnly bool `json:"initial_import_only"`
}

func (binding CloudflareBinding) Validate(capabilities CapabilitySet) error {
	if err := requireID("binding", string(binding.BindingID)); err != nil { return err }
	if binding.Ownership != DNSOwnershipExclusive && binding.Ownership != DNSOwnershipManagedSet && binding.Ownership != DNSOwnershipCooperative { return ErrInvalid }
	if binding.Concurrency == ConcurrencyAtomicCAS && !capabilities.Has(CapabilityAtomicCAS) { return ErrUnsupported }
	if binding.Concurrency == ConcurrencyObserveApply && !capabilities.Has(CapabilityObserveApply) { return ErrUnsupported }
	if binding.Concurrency != ConcurrencyAtomicCAS && binding.Concurrency != ConcurrencyObserveApply { return ErrInvalid }
	for _, zoneID := range binding.ZoneIDs { if !validID(zoneID) { return ErrInvalid } }
	return nil
}

type CloudflareZone struct { ID string `json:"id"`; Name string `json:"name"`; Status string `json:"status"`; Paused bool `json:"paused"`; Revision string `json:"revision"`; ObservedAt time.Time `json:"observed_at"` }

type RRType string
const ( RRTypeA RRType = "A"; RRTypeAAAA RRType = "AAAA"; RRTypeCNAME RRType = "CNAME"; RRTypeTXT RRType = "TXT"; RRTypeMX RRType = "MX"; RRTypeSRV RRType = "SRV"; RRTypeCAA RRType = "CAA"; RRTypeNS RRType = "NS"; RRTypeHTTPS RRType = "HTTPS"; RRTypeSVCB RRType = "SVCB" )

type CloudflareRRSet struct {
	ZoneID string `json:"zone_id"`
	Owner string `json:"owner"`
	Type RRType `json:"type"`
	TTL uint32 `json:"ttl"`
	Values []string `json:"values"`
	Priority *uint16 `json:"priority,omitempty"`
	Proxied bool `json:"proxied"`
	ProviderIDs []string `json:"provider_ids,omitempty"`
	Revision string `json:"revision"`
	Digest string `json:"digest"`
}

func (rrset CloudflareRRSet) Validate() error {
	if !validID(rrset.ZoneID) || rrset.Owner == "" || len(rrset.Owner) > 253 || rrset.TTL != 1 && rrset.TTL < 60 || len(rrset.Values) == 0 || !validDigest(rrset.Digest) { return ErrInvalid }
	values := append([]string(nil), rrset.Values...); sort.Strings(values); for index := 1; index < len(values); index++ { if values[index] == values[index-1] { return ErrInvalid } }
	if rrset.Proxied && rrset.Type != RRTypeA && rrset.Type != RRTypeAAAA && rrset.Type != RRTypeCNAME { return ErrUnsupported }
	return nil
}

type DNSMutationKind string
const ( DNSCreate DNSMutationKind = "create"; DNSReplace DNSMutationKind = "replace"; DNSDelete DNSMutationKind = "delete"; DNSSetProxy DNSMutationKind = "set_proxy" )

type CloudflareChange struct {
	Effect ProviderEffect `json:"effect"`
	Binding CloudflareBinding `json:"binding"`
	Kind DNSMutationKind `json:"kind"`
	Before *CloudflareRRSet `json:"before,omitempty"`
	Desired *CloudflareRRSet `json:"desired,omitempty"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
}

type DNSApplyReceipt struct { EffectID EffectID `json:"effect_id"`; BeforeDigest string `json:"before_digest,omitempty"`; OutputDigest string `json:"output_digest"`; ProviderRevision string `json:"provider_revision"`; ProviderReceipt string `json:"provider_receipt"`; AppliedAt time.Time `json:"applied_at"` }

type CloudflareProvider interface {
	Provider
	ListZones(context.Context, ProviderBinding, PageRequest) ([]CloudflareZone, string, error)
	ListRRsets(context.Context, ProviderBinding, string, PageRequest) ([]CloudflareRRSet, string, error)
	ObserveRRSet(context.Context, ProviderBinding, string, string, RRType) (*CloudflareRRSet, error)
	DryRun(context.Context, ProviderBinding, CloudflareChange) error
	Apply(context.Context, ProviderBinding, CloudflareChange) (DNSApplyReceipt, error)
	ApplyConditional(context.Context, ProviderBinding, CloudflareChange) (DNSApplyReceipt, error)
	CompensateConditional(context.Context, ProviderBinding, CloudflareChange, DNSApplyReceipt) (DNSApplyReceipt, error)
	PresentDNSChallenge(context.Context, ProviderBinding, string, string, string, time.Time) (DNSApplyReceipt, error)
	CleanDNSChallenge(context.Context, ProviderBinding, DNSApplyReceipt) error
}

type StoragePreset struct {
	Kind ProviderKind `json:"kind"`
	Endpoint string `json:"endpoint"`
	Region string `json:"region"`
	AddressingStyle string `json:"addressing_style"`
	SignatureVersion string `json:"signature_version"`
	RequiresTLS bool `json:"requires_tls"`
	SupportsObjectLock bool `json:"supports_object_lock"`
	SupportsVersioning bool `json:"supports_versioning"`
}

func NamedStoragePresets() map[ProviderKind]StoragePreset {
	return map[ProviderKind]StoragePreset{
		ProviderAWSS3: {Kind: ProviderAWSS3, Endpoint: "https://s3.amazonaws.com", Region: "provider_selected", AddressingStyle: "virtual_host", SignatureVersion: "sigv4", RequiresTLS: true, SupportsObjectLock: true, SupportsVersioning: true},
		ProviderWasabi: {Kind: ProviderWasabi, Endpoint: "https://s3.wasabisys.com", Region: "required", AddressingStyle: "virtual_host", SignatureVersion: "sigv4", RequiresTLS: true, SupportsObjectLock: true, SupportsVersioning: true},
		ProviderBackblaze: {Kind: ProviderBackblaze, Endpoint: "https://s3.us-west-004.backblazeb2.com", Region: "required", AddressingStyle: "virtual_host", SignatureVersion: "sigv4", RequiresTLS: true, SupportsObjectLock: true, SupportsVersioning: true},
		ProviderDigitalOcean: {Kind: ProviderDigitalOcean, Endpoint: "https://REGION.digitaloceanspaces.com", Region: "required", AddressingStyle: "virtual_host", SignatureVersion: "sigv4", RequiresTLS: true, SupportsVersioning: true},
		ProviderMinIO: {Kind: ProviderMinIO, Endpoint: "operator_supplied_https", Region: "optional", AddressingStyle: "path_or_virtual_host", SignatureVersion: "sigv4", RequiresTLS: true, SupportsObjectLock: true, SupportsVersioning: true},
		ProviderGenericS3: {Kind: ProviderGenericS3, Endpoint: "operator_supplied_https", Region: "required", AddressingStyle: "declared", SignatureVersion: "sigv4", RequiresTLS: true},
		ProviderGoogleDrive: {Kind: ProviderGoogleDrive, Endpoint: "https://www.googleapis.com", Region: "provider_managed", AddressingStyle: "drive_folder", SignatureVersion: "oauth2", RequiresTLS: true},
		ProviderSFTP: {Kind: ProviderSFTP, Endpoint: "operator_supplied_host", Region: "operator_managed", AddressingStyle: "chroot_relative", SignatureVersion: "ssh_hostkey_and_key", RequiresTLS: false},
	}
}

type StorageBinding struct {
	BindingID BindingID `json:"binding_id"`
	Preset ProviderKind `json:"preset"`
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix"`
	Region string `json:"region,omitempty"`
	Endpoint EndpointPolicy `json:"endpoint"`
	AddressingStyle string `json:"addressing_style"`
	PinnedHostKey string `json:"pinned_host_key,omitempty"`
	OAuthAccount string `json:"oauth_account,omitempty"`
	ObjectLockRequired bool `json:"object_lock_required"`
	VersioningRequired bool `json:"versioning_required"`
}

func (binding StorageBinding) Validate(capabilities CapabilitySet) error {
	if err := requireID("binding", string(binding.BindingID)); err != nil { return err }
	if _, exists := NamedStoragePresets()[binding.Preset]; !exists { return ErrUnsupported }
	if binding.Prefix == "" || strings.HasPrefix(binding.Prefix, "/") || strings.Contains(binding.Prefix, "..") || strings.ContainsAny(binding.Prefix, "\x00\r\n\\") { return ErrInvalid }
	if binding.Preset != ProviderGoogleDrive && binding.Preset != ProviderSFTP && !namePattern.MatchString(binding.Bucket) { return ErrInvalid }
	if binding.Preset == ProviderSFTP { if binding.PinnedHostKey == "" { return ErrPolicyDenied } } else if err := binding.Endpoint.Validate(); err != nil { return err }
	if binding.ObjectLockRequired && !capabilities.Has(CapabilityObjectLock) || binding.VersioningRequired && !capabilities.Has(CapabilityObjectVersioning) { return ErrUnsupported }
	return nil
}

type ObjectKey struct{ value string }
func ParseObjectKey(raw string) (ObjectKey, error) { if raw == "" || len(raw) > 2048 || strings.HasPrefix(raw, "/") || strings.Contains(raw, "..") || strings.ContainsAny(raw, "\x00\r\n\\") { return ObjectKey{}, ErrInvalid }; return ObjectKey{raw}, nil }
func (key ObjectKey) String() string { return key.value }

type ObjectMetadata struct { Key ObjectKey `json:"key"`; Size int64 `json:"size"`; Digest string `json:"digest"`; VersionID string `json:"version_id,omitempty"`; ETag string `json:"etag"`; ModifiedAt time.Time `json:"modified_at"` }
type MultipartSession struct { ID string `json:"id"`; Key ObjectKey `json:"key"`; UploadID string `json:"upload_id"`; PartSize int64 `json:"part_size"`; ExpiresAt time.Time `json:"expires_at"` }
type UploadedPart struct { Number uint32 `json:"number"`; Size int64 `json:"size"`; Digest string `json:"digest"`; ETag string `json:"etag"` }

type StorageProvider interface {
	Provider
	ListObjects(context.Context, ProviderBinding, StorageBinding, ObjectKey, PageRequest) ([]ObjectMetadata, string, error)
	StatObject(context.Context, ProviderBinding, StorageBinding, ObjectKey) (ObjectMetadata, error)
	BeginUpload(context.Context, ProviderBinding, StorageBinding, ObjectKey, int64, string, EffectID) (MultipartSession, error)
	UploadPart(context.Context, ProviderBinding, StorageBinding, MultipartSession, uint32, []byte, string) (UploadedPart, error)
	CompleteUpload(context.Context, ProviderBinding, StorageBinding, MultipartSession, []UploadedPart) (ObjectMetadata, error)
	AbortUpload(context.Context, ProviderBinding, StorageBinding, MultipartSession) error
	ReadRange(context.Context, ProviderBinding, StorageBinding, ObjectKey, string, int64, int64) ([]byte, error)
	DeleteVersion(context.Context, ProviderBinding, StorageBinding, ObjectKey, string, EffectID) error
	ApplyRetention(context.Context, ProviderBinding, StorageBinding, ObjectKey, string, time.Time, EffectID) error
}

type GoogleDriveAuthorization struct { BindingID BindingID `json:"binding_id"`; AccountID string `json:"account_id"`; AccountLabel string `json:"account_label"`; OAuthGrantRef SecretRef `json:"oauth_grant_ref"`; Scopes []string `json:"scopes"`; GrantedAt time.Time `json:"granted_at"`; ExpiresAt time.Time `json:"expires_at"`; Generation uint64 `json:"generation"` }
type GoogleDriveFolder struct { ID string `json:"id"`; Name string `json:"name"`; ParentID string `json:"parent_id,omitempty"`; DriveID string `json:"drive_id,omitempty"`; Trashed bool `json:"trashed"`; Revision string `json:"revision"` }
type DriveUploadSession struct { ID string `json:"id"`; FolderID string `json:"folder_id"`; Name string `json:"name"`; Size int64 `json:"size"`; Digest string `json:"digest"`; Offset int64 `json:"offset"`; ExpiresAt time.Time `json:"expires_at"` }
type GoogleDriveProvider interface {
	Provider
	ExchangeAuthorizationCode(context.Context, ProviderBinding, string, string, string) (GoogleDriveAuthorization, error)
	RefreshAuthorization(context.Context, ProviderBinding, GoogleDriveAuthorization) (GoogleDriveAuthorization, error)
	RevokeAuthorization(context.Context, ProviderBinding, GoogleDriveAuthorization) error
	ListFolders(context.Context, ProviderBinding, GoogleDriveAuthorization, string, PageRequest) ([]GoogleDriveFolder, string, error)
	BeginResumableUpload(context.Context, ProviderBinding, GoogleDriveAuthorization, GoogleDriveFolder, string, int64, string, EffectID) (DriveUploadSession, error)
	UploadRange(context.Context, ProviderBinding, GoogleDriveAuthorization, DriveUploadSession, int64, []byte, string) (DriveUploadSession, error)
	CommitResumableUpload(context.Context, ProviderBinding, GoogleDriveAuthorization, DriveUploadSession) (ObjectMetadata, error)
	ReadRange(context.Context, ProviderBinding, GoogleDriveAuthorization, string, string, int64, int64) ([]byte, error)
	DeleteFile(context.Context, ProviderBinding, GoogleDriveAuthorization, string, string, EffectID) error
}

type RelayTLSMode string
const ( RelayTLSRequired RelayTLSMode = "required"; RelayTLSImplicit RelayTLSMode = "implicit_tls" )
type MailRelayBinding struct { BindingID BindingID `json:"binding_id"`; Host string `json:"host"`; Port uint16 `json:"port"`; ServerName string `json:"server_name"`; TLS RelayTLSMode `json:"tls"`; EnvelopeDomains []string `json:"envelope_domains"`; DKIMMode string `json:"dkim_mode"`; DailyLimit uint64 `json:"daily_limit"`; PerSecond uint32 `json:"per_second"`; EventWebhookAudience string `json:"event_webhook_audience,omitempty"` }
func (binding MailRelayBinding) Validate() error { if !validID(string(binding.BindingID)) || net.ParseIP(binding.Host) != nil || binding.Host == "" || binding.ServerName == "" || binding.Port == 0 || binding.TLS != RelayTLSRequired && binding.TLS != RelayTLSImplicit || binding.DailyLimit == 0 || binding.PerSecond == 0 { return ErrInvalid }; return nil }

type RelayMessage struct { DeliveryID DeliveryID `json:"delivery_id"`; TenantID TenantID `json:"tenant_id"`; EnvelopeFrom string `json:"envelope_from"`; EnvelopeTo []string `json:"envelope_to"`; MessageArtifactRef string `json:"message_artifact_ref"`; MessageDigest string `json:"message_digest"`; Size int64 `json:"size"`; IdempotencyKey string `json:"idempotency_key"` }
type RelayReceipt struct { DeliveryID DeliveryID `json:"delivery_id"`; ProviderMessageID string `json:"provider_message_id"`; Accepted []string `json:"accepted"`; Rejected map[string]string `json:"rejected"`; ReceiptDigest string `json:"receipt_digest"`; AcceptedAt time.Time `json:"accepted_at"` }
type MailRelayProvider interface { Provider; Deliver(context.Context, ProviderBinding, MailRelayBinding, RelayMessage) (RelayReceipt, error); VerifyEvent(context.Context, ProviderBinding, []byte, map[string]string) (RelayEvent, error) }
type RelayEvent struct { ProviderMessageID string `json:"provider_message_id"`; Kind string `json:"kind"`; Recipient string `json:"recipient"`; DeliveryID DeliveryID `json:"delivery_id"`; OccurredAt time.Time `json:"occurred_at"`; EventID string `json:"event_id"`; Digest string `json:"digest"` }
