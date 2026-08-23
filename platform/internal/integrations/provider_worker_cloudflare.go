package integrations

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

const (
	ProviderWorkerCloudflareListZones             ProviderWorkerAction = "cloudflare.list_zones"
	ProviderWorkerCloudflareListRRsets            ProviderWorkerAction = "cloudflare.list_rrsets"
	ProviderWorkerCloudflareObserveRRSet           ProviderWorkerAction = "cloudflare.observe_rrset"
	ProviderWorkerCloudflareDryRun                 ProviderWorkerAction = "cloudflare.dry_run"
	ProviderWorkerCloudflareApply                  ProviderWorkerAction = "cloudflare.apply"
	ProviderWorkerCloudflareApplyConditional       ProviderWorkerAction = "cloudflare.apply_conditional"
	ProviderWorkerCloudflareCompensateConditional  ProviderWorkerAction = "cloudflare.compensate_conditional"
	ProviderWorkerCloudflarePresentDNS01           ProviderWorkerAction = "cloudflare.present_dns01"
	ProviderWorkerCloudflareCleanupDNS01           ProviderWorkerAction = "cloudflare.cleanup_dns01"
	providerWorkerCloudflareMaximumPage                                  = 500
	providerWorkerCloudflareMaximumRequest                               = 256 << 10
	providerWorkerCloudflareMaximumResponse                              = 768 << 10
)

type ProviderWorkerCloudflareRequest struct {
	ListZones            *ProviderWorkerCloudflareListZonesRequest            `json:"list_zones,omitempty"`
	ListRRsets           *ProviderWorkerCloudflareListRRsetsRequest           `json:"list_rrsets,omitempty"`
	ObserveRRSet          *ProviderWorkerCloudflareObserveRRSetRequest         `json:"observe_rrset,omitempty"`
	DryRun                *ProviderWorkerCloudflareChangeRequest               `json:"dry_run,omitempty"`
	Apply                 *ProviderWorkerCloudflareChangeRequest               `json:"apply,omitempty"`
	ApplyConditional      *ProviderWorkerCloudflareChangeRequest               `json:"apply_conditional,omitempty"`
	CompensateConditional *ProviderWorkerCloudflareCompensateRequest           `json:"compensate_conditional,omitempty"`
	PresentDNS01          *ProviderWorkerCloudflarePresentDNS01Request          `json:"present_dns01,omitempty"`
	CleanupDNS01          *ProviderWorkerCloudflareCleanupDNS01Request          `json:"cleanup_dns01,omitempty"`
}

type ProviderWorkerCloudflareListZonesRequest struct {
	Page PageRequest `json:"page"`
}

type ProviderWorkerCloudflareListRRsetsRequest struct {
	ZoneID string      `json:"zone_id"`
	Page   PageRequest `json:"page"`
}

type ProviderWorkerCloudflareObserveRRSetRequest struct {
	ZoneID string `json:"zone_id"`
	Owner  string `json:"owner"`
	Type   RRType `json:"type"`
}

type ProviderWorkerCloudflareChangeRequest struct {
	Change CloudflareChange `json:"change"`
}

type ProviderWorkerCloudflareCompensateRequest struct {
	Change  CloudflareChange `json:"change"`
	Receipt DNSApplyReceipt  `json:"receipt"`
}

type ProviderWorkerCloudflarePresentDNS01Request struct {
	ZoneID   string    `json:"zone_id"`
	Owner    string    `json:"owner"`
	Value    string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ProviderWorkerCloudflareCleanupDNS01Request struct {
	Receipt DNSApplyReceipt `json:"receipt"`
}

type ProviderWorkerCloudflareResponse struct {
	ListZones            *ProviderWorkerCloudflareListZonesResponse    `json:"list_zones,omitempty"`
	ListRRsets           *ProviderWorkerCloudflareListRRsetsResponse   `json:"list_rrsets,omitempty"`
	ObserveRRSet          *ProviderWorkerCloudflareObserveRRSetResponse `json:"observe_rrset,omitempty"`
	DryRun                *ProviderWorkerCloudflareAcknowledgement     `json:"dry_run,omitempty"`
	Apply                 *ProviderWorkerCloudflareReceiptResponse     `json:"apply,omitempty"`
	ApplyConditional      *ProviderWorkerCloudflareReceiptResponse     `json:"apply_conditional,omitempty"`
	CompensateConditional *ProviderWorkerCloudflareReceiptResponse     `json:"compensate_conditional,omitempty"`
	PresentDNS01          *ProviderWorkerCloudflareReceiptResponse     `json:"present_dns01,omitempty"`
	CleanupDNS01          *ProviderWorkerCloudflareAcknowledgement     `json:"cleanup_dns01,omitempty"`
}

type ProviderWorkerCloudflareListZonesResponse struct {
	Zones  []CloudflareZone `json:"zones"`
	Cursor string           `json:"cursor,omitempty"`
}

type ProviderWorkerCloudflareListRRsetsResponse struct {
	RRsets []CloudflareRRSet `json:"rrsets"`
	Cursor string            `json:"cursor,omitempty"`
}

type ProviderWorkerCloudflareObserveRRSetResponse struct {
	RRSet *CloudflareRRSet `json:"rrset,omitempty"`
}

type ProviderWorkerCloudflareAcknowledgement struct {
	Accepted bool `json:"accepted"`
}

type ProviderWorkerCloudflareReceiptResponse struct {
	Receipt DNSApplyReceipt `json:"receipt"`
}

func providerWorkerCloudflareAction(action ProviderWorkerAction) bool {
	switch action {
	case ProviderWorkerCloudflareListZones, ProviderWorkerCloudflareListRRsets, ProviderWorkerCloudflareObserveRRSet, ProviderWorkerCloudflareDryRun, ProviderWorkerCloudflareApply, ProviderWorkerCloudflareApplyConditional, ProviderWorkerCloudflareCompensateConditional, ProviderWorkerCloudflarePresentDNS01, ProviderWorkerCloudflareCleanupDNS01:
		return true
	default:
		return false
	}
}

func (payload ProviderWorkerCloudflareRequest) Validate(action ProviderWorkerAction, binding ProviderBinding, now time.Time) error {
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) == 0 || len(raw) > providerWorkerCloudflareMaximumRequest || payload.count() != 1 {
		return ErrInvalid
	}
	switch action {
	case ProviderWorkerCloudflareListZones:
		if payload.ListZones == nil || providerWorkerPageInvalid(payload.ListZones.Page) {
			return ErrInvalid
		}
	case ProviderWorkerCloudflareListRRsets:
		if payload.ListRRsets == nil || !validID(payload.ListRRsets.ZoneID) || providerWorkerPageInvalid(payload.ListRRsets.Page) {
			return ErrInvalid
		}
	case ProviderWorkerCloudflareObserveRRSet:
		if payload.ObserveRRSet == nil || !validID(payload.ObserveRRSet.ZoneID) || !providerWorkerOwnerValid(payload.ObserveRRSet.Owner) || !providerWorkerRRTypeValid(payload.ObserveRRSet.Type) {
			return ErrInvalid
		}
	case ProviderWorkerCloudflareDryRun:
		if payload.DryRun == nil {
			return ErrInvalid
		}
		return providerWorkerCloudflareChangeValidate(payload.DryRun.Change, binding, "", true)
	case ProviderWorkerCloudflareApply:
		if payload.Apply == nil {
			return ErrInvalid
		}
		return providerWorkerCloudflareChangeValidate(payload.Apply.Change, binding, ConcurrencyObserveApply, true)
	case ProviderWorkerCloudflareApplyConditional:
		if payload.ApplyConditional == nil {
			return ErrInvalid
		}
		return providerWorkerCloudflareChangeValidate(payload.ApplyConditional.Change, binding, ConcurrencyAtomicCAS, true)
	case ProviderWorkerCloudflareCompensateConditional:
		if payload.CompensateConditional == nil || providerWorkerCloudflareChangeValidate(payload.CompensateConditional.Change, binding, ConcurrencyAtomicCAS, false) != nil || providerWorkerReceiptValidate(payload.CompensateConditional.Receipt, false) != nil || payload.CompensateConditional.Receipt.EffectID != payload.CompensateConditional.Change.Effect.ID {
			return ErrInvalid
		}
	case ProviderWorkerCloudflarePresentDNS01:
		if payload.PresentDNS01 == nil || !validID(payload.PresentDNS01.ZoneID) || !providerWorkerOwnerValid(payload.PresentDNS01.Owner) || !providerWorkerWireString(payload.PresentDNS01.Value, 8192, true) || !payload.PresentDNS01.ExpiresAt.After(now) || payload.PresentDNS01.ExpiresAt.After(now.Add(24*time.Hour)) {
			return ErrInvalid
		}
	case ProviderWorkerCloudflareCleanupDNS01:
		if payload.CleanupDNS01 == nil || providerWorkerReceiptValidate(payload.CleanupDNS01.Receipt, false) != nil {
			return ErrInvalid
		}
	default:
		return ErrUnsupported
	}
	return nil
}

func (payload ProviderWorkerCloudflareRequest) count() int {
	count := 0
	for _, present := range []bool{payload.ListZones != nil, payload.ListRRsets != nil, payload.ObserveRRSet != nil, payload.DryRun != nil, payload.Apply != nil, payload.ApplyConditional != nil, payload.CompensateConditional != nil, payload.PresentDNS01 != nil, payload.CleanupDNS01 != nil} {
		if present {
			count++
		}
	}
	return count
}

func (response ProviderWorkerResponse) ValidateFor(request ProviderWorkerRequest) error {
	if response.Version != request.Version || response.RequestID != request.RequestID || response.Action != request.Action {
		return ErrIntegrity
	}
	if !response.Succeeded {
		if !providerWorkerErrorClassValid(response.Failure) || !providerWorkerWireString(response.FailureCode, 128, true) || response.Capabilities != nil || response.Health != nil || response.Cloudflare != nil {
			return ErrIntegrity
		}
		return nil
	}
	if response.Failure != "" || response.FailureCode != "" {
		return ErrIntegrity
	}
	switch request.Action {
	case ProviderWorkerDiscover:
		if response.Capabilities == nil || response.Health != nil || response.Cloudflare != nil || response.Capabilities.Validate() != nil || response.Capabilities.Digest != capabilityDigest(response.Capabilities.Capabilities) || !providerWorkerWireString(response.Capabilities.ProviderVersion, 256, true) || len(response.Capabilities.Capabilities) > 128 {
			return ErrIntegrity
		}
	case ProviderWorkerHealth:
		if response.Health == nil || response.Capabilities != nil || response.Cloudflare != nil || providerWorkerHealthValidate(*response.Health, request.Binding) != nil {
			return ErrIntegrity
		}
	case ProviderWorkerValidate, ProviderWorkerRevoke:
		if response.Capabilities != nil || response.Health != nil || response.Cloudflare != nil {
			return ErrIntegrity
		}
	default:
		if !providerWorkerCloudflareAction(request.Action) || response.Capabilities != nil || response.Health != nil || response.Cloudflare == nil || request.Cloudflare == nil {
			return ErrIntegrity
		}
		return response.Cloudflare.ValidateFor(request.Action, *request.Cloudflare)
	}
	return nil
}

func (payload ProviderWorkerCloudflareResponse) ValidateFor(action ProviderWorkerAction, request ProviderWorkerCloudflareRequest) error {
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) == 0 || len(raw) > providerWorkerCloudflareMaximumResponse || payload.count() != 1 {
		return ErrIntegrity
	}
	switch action {
	case ProviderWorkerCloudflareListZones:
		if payload.ListZones == nil || request.ListZones == nil || len(payload.ListZones.Zones) > int(request.ListZones.Page.Limit) || len(payload.ListZones.Zones) > providerWorkerCloudflareMaximumPage || !providerWorkerCursorValid(payload.ListZones.Cursor) {
			return ErrIntegrity
		}
		for _, zone := range payload.ListZones.Zones {
			if providerWorkerZoneValidate(zone) != nil {
				return ErrIntegrity
			}
		}
	case ProviderWorkerCloudflareListRRsets:
		if payload.ListRRsets == nil || request.ListRRsets == nil || len(payload.ListRRsets.RRsets) > int(request.ListRRsets.Page.Limit) || len(payload.ListRRsets.RRsets) > providerWorkerCloudflareMaximumPage || !providerWorkerCursorValid(payload.ListRRsets.Cursor) {
			return ErrIntegrity
		}
		for _, rrset := range payload.ListRRsets.RRsets {
			if rrset.ZoneID != request.ListRRsets.ZoneID || providerWorkerRRSetValidate(rrset) != nil {
				return ErrIntegrity
			}
		}
	case ProviderWorkerCloudflareObserveRRSet:
		if payload.ObserveRRSet == nil || request.ObserveRRSet == nil {
			return ErrIntegrity
		}
		if rrset := payload.ObserveRRSet.RRSet; rrset != nil && (providerWorkerRRSetValidate(*rrset) != nil || rrset.ZoneID != request.ObserveRRSet.ZoneID || rrset.Owner != request.ObserveRRSet.Owner || rrset.Type != request.ObserveRRSet.Type) {
			return ErrIntegrity
		}
	case ProviderWorkerCloudflareDryRun:
		if payload.DryRun == nil || !payload.DryRun.Accepted || request.DryRun == nil {
			return ErrIntegrity
		}
	case ProviderWorkerCloudflareApply:
		return providerWorkerReceiptResponseValidate(payload.Apply, request.Apply)
	case ProviderWorkerCloudflareApplyConditional:
		return providerWorkerReceiptResponseValidate(payload.ApplyConditional, request.ApplyConditional)
	case ProviderWorkerCloudflareCompensateConditional:
		if payload.CompensateConditional == nil || request.CompensateConditional == nil || providerWorkerReceiptValidate(payload.CompensateConditional.Receipt, true) != nil || payload.CompensateConditional.Receipt.EffectID != request.CompensateConditional.Receipt.EffectID {
			return ErrIntegrity
		}
	case ProviderWorkerCloudflarePresentDNS01:
		if payload.PresentDNS01 == nil || request.PresentDNS01 == nil || providerWorkerReceiptValidate(payload.PresentDNS01.Receipt, true) != nil {
			return ErrIntegrity
		}
	case ProviderWorkerCloudflareCleanupDNS01:
		if payload.CleanupDNS01 == nil || !payload.CleanupDNS01.Accepted || request.CleanupDNS01 == nil {
			return ErrIntegrity
		}
	default:
		return ErrUnsupported
	}
	return nil
}

func (payload ProviderWorkerCloudflareResponse) count() int {
	count := 0
	for _, present := range []bool{payload.ListZones != nil, payload.ListRRsets != nil, payload.ObserveRRSet != nil, payload.DryRun != nil, payload.Apply != nil, payload.ApplyConditional != nil, payload.CompensateConditional != nil, payload.PresentDNS01 != nil, payload.CleanupDNS01 != nil} {
		if present {
			count++
		}
	}
	return count
}

func providerWorkerReceiptResponseValidate(response *ProviderWorkerCloudflareReceiptResponse, request *ProviderWorkerCloudflareChangeRequest) error {
	if response == nil || request == nil || providerWorkerReceiptValidate(response.Receipt, true) != nil || response.Receipt.EffectID != request.Change.Effect.ID {
		return ErrIntegrity
	}
	return nil
}

func providerWorkerPageInvalid(page PageRequest) bool {
	return page.Validate() != nil || page.Limit > providerWorkerCloudflareMaximumPage || !providerWorkerCursorValid(page.Cursor)
}

func providerWorkerCursorValid(cursor string) bool {
	return providerWorkerWireString(cursor, 2048, false)
}

func providerWorkerWireString(value string, maximum int, required bool) bool {
	return (!required || value != "") && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func providerWorkerOwnerValid(owner string) bool {
	return providerWorkerWireString(owner, 253, true) && !strings.ContainsAny(owner, " \t")
}

func providerWorkerRRTypeValid(value RRType) bool {
	switch value {
	case RRTypeA, RRTypeAAAA, RRTypeCNAME, RRTypeTXT, RRTypeMX, RRTypeSRV, RRTypeCAA, RRTypeNS, RRTypeHTTPS, RRTypeSVCB:
		return true
	default:
		return false
	}
}

func providerWorkerCloudflareBindingValidate(binding CloudflareBinding, capabilities CapabilitySet) error {
	if binding.Validate(capabilities) != nil || !providerWorkerWireString(binding.AccountID, 128, false) || len(binding.ZoneIDs) > providerWorkerCloudflareMaximumPage {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(binding.ZoneIDs))
	for _, zoneID := range binding.ZoneIDs {
		if _, exists := seen[zoneID]; exists {
			return ErrInvalid
		}
		seen[zoneID] = struct{}{}
	}
	return nil
}

func providerWorkerCloudflareChangeValidate(change CloudflareChange, binding ProviderBinding, concurrency ConcurrencyMode, requireCompleteEffect bool) error {
	if !validID(string(change.Effect.ID)) || change.Effect.BindingID != binding.ID || change.Binding.BindingID != binding.ID || providerWorkerCloudflareBindingValidate(change.Binding, binding.Capabilities) != nil || concurrency != "" && change.Binding.Concurrency != concurrency || !providerWorkerWireString(change.ExpectedRevision, 512, false) || !providerWorkerWireString(change.Effect.Kind, 128, requireCompleteEffect) || !providerWorkerWireString(change.Effect.Resource, 4096, requireCompleteEffect) || !providerWorkerWireString(change.Effect.ExpectedRevision, 512, false) || !providerWorkerWireString(change.Effect.ProviderReceipt, 4096, false) || !providerWorkerWireString(change.Effect.Failure, 4096, false) {
		return ErrInvalid
	}
	if requireCompleteEffect && change.Effect.Validate() != nil {
		return ErrInvalid
	}
	if change.Before != nil && providerWorkerRRSetValidate(*change.Before) != nil || change.Desired != nil && providerWorkerRRSetValidate(*change.Desired) != nil {
		return ErrInvalid
	}
	switch change.Kind {
	case DNSCreate:
		if change.Before != nil || change.Desired == nil {
			return ErrInvalid
		}
	case DNSReplace, DNSSetProxy:
		if change.Before == nil || change.Desired == nil {
			return ErrInvalid
		}
	case DNSDelete:
		if change.Before == nil || change.Desired != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if change.Before != nil && change.Desired != nil && (change.Before.ZoneID != change.Desired.ZoneID || change.Before.Owner != change.Desired.Owner || change.Before.Type != change.Desired.Type) {
		return ErrInvalid
	}
	return nil
}

func providerWorkerRRSetValidate(rrset CloudflareRRSet) error {
	if rrset.Validate() != nil || !providerWorkerRRTypeValid(rrset.Type) || !providerWorkerOwnerValid(rrset.Owner) || !providerWorkerWireString(rrset.Revision, 512, true) || len(rrset.Values) > 1000 || len(rrset.ProviderIDs) > 1000 {
		return ErrInvalid
	}
	for _, value := range rrset.Values {
		if !providerWorkerWireString(value, 8192, true) {
			return ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(rrset.ProviderIDs))
	for _, providerID := range rrset.ProviderIDs {
		if !validID(providerID) {
			return ErrInvalid
		}
		if _, exists := seen[providerID]; exists {
			return ErrInvalid
		}
		seen[providerID] = struct{}{}
	}
	return nil
}

func providerWorkerZoneValidate(zone CloudflareZone) error {
	if !validID(zone.ID) || !providerWorkerOwnerValid(zone.Name) || !providerWorkerWireString(zone.Status, 64, true) || !providerWorkerWireString(zone.Revision, 512, true) || zone.ObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func providerWorkerReceiptValidate(receipt DNSApplyReceipt, requireAppliedAt bool) error {
	if !validID(string(receipt.EffectID)) || receipt.BeforeDigest != "" && !validDigest(receipt.BeforeDigest) || !validDigest(receipt.OutputDigest) || !providerWorkerWireString(receipt.ProviderRevision, 512, true) || !providerWorkerWireString(receipt.ProviderReceipt, 4096, true) || requireAppliedAt && receipt.AppliedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func providerWorkerHealthValidate(health ProviderHealth, binding ProviderBinding) error {
	if health.BindingID != binding.ID || health.Latency < 0 || !validDigest(health.CapabilitiesDigest) || health.CapabilitiesDigest != binding.Capabilities.Digest || health.ObservedAt.IsZero() || !health.StaleAfter.After(health.ObservedAt) || !providerWorkerWireString(health.Reason, 2048, false) {
		return ErrInvalid
	}
	switch health.State {
	case HealthUnknown, HealthHealthy, HealthDegraded, HealthUnavailable:
		return nil
	default:
		return ErrInvalid
	}
}

func providerWorkerErrorClassValid(class ErrorClass) bool {
	switch class {
	case ErrorInvalid, ErrorUnauthorized, ErrorRateLimited, ErrorUnavailable, ErrorConflict, ErrorPartial, ErrorAmbiguous, ErrorPermanent:
		return true
	default:
		return false
	}
}

func (client *ProviderWorkerClient) ListZones(ctx context.Context, binding ProviderBinding, page PageRequest) ([]CloudflareZone, string, error) {
	request := &ProviderWorkerCloudflareRequest{ListZones:&ProviderWorkerCloudflareListZonesRequest{Page:page}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareListZones, binding, request)
	if err != nil {
		return nil, "", err
	}
	return response.Cloudflare.ListZones.Zones, response.Cloudflare.ListZones.Cursor, nil
}

func (client *ProviderWorkerClient) ListRRsets(ctx context.Context, binding ProviderBinding, zoneID string, page PageRequest) ([]CloudflareRRSet, string, error) {
	request := &ProviderWorkerCloudflareRequest{ListRRsets:&ProviderWorkerCloudflareListRRsetsRequest{ZoneID:zoneID,Page:page}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareListRRsets, binding, request)
	if err != nil {
		return nil, "", err
	}
	return response.Cloudflare.ListRRsets.RRsets, response.Cloudflare.ListRRsets.Cursor, nil
}

func (client *ProviderWorkerClient) ObserveRRSet(ctx context.Context, binding ProviderBinding, zoneID, owner string, rrtype RRType) (*CloudflareRRSet, error) {
	request := &ProviderWorkerCloudflareRequest{ObserveRRSet:&ProviderWorkerCloudflareObserveRRSetRequest{ZoneID:zoneID,Owner:owner,Type:rrtype}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareObserveRRSet, binding, request)
	if err != nil {
		return nil, err
	}
	return response.Cloudflare.ObserveRRSet.RRSet, nil
}

func (client *ProviderWorkerClient) DryRun(ctx context.Context, binding ProviderBinding, change CloudflareChange) error {
	request := &ProviderWorkerCloudflareRequest{DryRun:&ProviderWorkerCloudflareChangeRequest{Change:change}}
	_, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareDryRun, binding, request)
	return err
}

func (client *ProviderWorkerClient) Apply(ctx context.Context, binding ProviderBinding, change CloudflareChange) (DNSApplyReceipt, error) {
	request := &ProviderWorkerCloudflareRequest{Apply:&ProviderWorkerCloudflareChangeRequest{Change:change}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareApply, binding, request)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	return response.Cloudflare.Apply.Receipt, nil
}

func (client *ProviderWorkerClient) ApplyConditional(ctx context.Context, binding ProviderBinding, change CloudflareChange) (DNSApplyReceipt, error) {
	request := &ProviderWorkerCloudflareRequest{ApplyConditional:&ProviderWorkerCloudflareChangeRequest{Change:change}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareApplyConditional, binding, request)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	return response.Cloudflare.ApplyConditional.Receipt, nil
}

func (client *ProviderWorkerClient) CompensateConditional(ctx context.Context, binding ProviderBinding, change CloudflareChange, receipt DNSApplyReceipt) (DNSApplyReceipt, error) {
	request := &ProviderWorkerCloudflareRequest{CompensateConditional:&ProviderWorkerCloudflareCompensateRequest{Change:change,Receipt:receipt}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareCompensateConditional, binding, request)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	return response.Cloudflare.CompensateConditional.Receipt, nil
}

func (client *ProviderWorkerClient) PresentDNSChallenge(ctx context.Context, binding ProviderBinding, zoneID, owner, value string, expiresAt time.Time) (DNSApplyReceipt, error) {
	request := &ProviderWorkerCloudflareRequest{PresentDNS01:&ProviderWorkerCloudflarePresentDNS01Request{ZoneID:zoneID,Owner:owner,Value:value,ExpiresAt:expiresAt}}
	response, err := client.requestCloudflare(ctx, ProviderWorkerCloudflarePresentDNS01, binding, request)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	return response.Cloudflare.PresentDNS01.Receipt, nil
}

func (client *ProviderWorkerClient) CleanDNSChallenge(ctx context.Context, binding ProviderBinding, receipt DNSApplyReceipt) error {
	request := &ProviderWorkerCloudflareRequest{CleanupDNS01:&ProviderWorkerCloudflareCleanupDNS01Request{Receipt:receipt}}
	_, err := client.requestCloudflare(ctx, ProviderWorkerCloudflareCleanupDNS01, binding, request)
	return err
}

func dispatchProviderWorkerCloudflare(ctx context.Context, provider CloudflareProvider, request ProviderWorkerRequest) (*ProviderWorkerCloudflareResponse, error) {
	payload := request.Cloudflare
	response := &ProviderWorkerCloudflareResponse{}
	switch request.Action {
	case ProviderWorkerCloudflareListZones:
		zones, cursor, err := provider.ListZones(ctx, request.Binding, payload.ListZones.Page)
		if err != nil {
			return nil, err
		}
		response.ListZones = &ProviderWorkerCloudflareListZonesResponse{Zones:zones,Cursor:cursor}
	case ProviderWorkerCloudflareListRRsets:
		rrsets, cursor, err := provider.ListRRsets(ctx, request.Binding, payload.ListRRsets.ZoneID, payload.ListRRsets.Page)
		if err != nil {
			return nil, err
		}
		response.ListRRsets = &ProviderWorkerCloudflareListRRsetsResponse{RRsets:rrsets,Cursor:cursor}
	case ProviderWorkerCloudflareObserveRRSet:
		rrset, err := provider.ObserveRRSet(ctx, request.Binding, payload.ObserveRRSet.ZoneID, payload.ObserveRRSet.Owner, payload.ObserveRRSet.Type)
		if err != nil {
			return nil, err
		}
		response.ObserveRRSet = &ProviderWorkerCloudflareObserveRRSetResponse{RRSet:rrset}
	case ProviderWorkerCloudflareDryRun:
		if err := provider.DryRun(ctx, request.Binding, payload.DryRun.Change); err != nil {
			return nil, err
		}
		response.DryRun = &ProviderWorkerCloudflareAcknowledgement{Accepted:true}
	case ProviderWorkerCloudflareApply:
		receipt, err := provider.Apply(ctx, request.Binding, payload.Apply.Change)
		if err != nil {
			return nil, err
		}
		response.Apply = &ProviderWorkerCloudflareReceiptResponse{Receipt:receipt}
	case ProviderWorkerCloudflareApplyConditional:
		receipt, err := provider.ApplyConditional(ctx, request.Binding, payload.ApplyConditional.Change)
		if err != nil {
			return nil, err
		}
		response.ApplyConditional = &ProviderWorkerCloudflareReceiptResponse{Receipt:receipt}
	case ProviderWorkerCloudflareCompensateConditional:
		receipt, err := provider.CompensateConditional(ctx, request.Binding, payload.CompensateConditional.Change, payload.CompensateConditional.Receipt)
		if err != nil {
			return nil, err
		}
		response.CompensateConditional = &ProviderWorkerCloudflareReceiptResponse{Receipt:receipt}
	case ProviderWorkerCloudflarePresentDNS01:
		receipt, err := provider.PresentDNSChallenge(ctx, request.Binding, payload.PresentDNS01.ZoneID, payload.PresentDNS01.Owner, payload.PresentDNS01.Value, payload.PresentDNS01.ExpiresAt)
		if err != nil {
			return nil, err
		}
		response.PresentDNS01 = &ProviderWorkerCloudflareReceiptResponse{Receipt:receipt}
	case ProviderWorkerCloudflareCleanupDNS01:
		if err := provider.CleanDNSChallenge(ctx, request.Binding, payload.CleanupDNS01.Receipt); err != nil {
			return nil, err
		}
		response.CleanupDNS01 = &ProviderWorkerCloudflareAcknowledgement{Accepted:true}
	default:
		return nil, ErrUnsupported
	}
	if response.ValidateFor(request.Action, *payload) != nil {
		return nil, ErrIntegrity
	}
	return response, nil
}

var _ CloudflareProvider = (*ProviderWorkerClient)(nil)
