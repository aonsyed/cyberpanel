//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

const haPromotionApprovalTrustPath = "/etc/cyberpanel/trust/ha-promotion-approval.pub"

// haPromotionApprovalAuthority verifies only the closed HA approval payload.
// The private key remains in the independently provisioned approval client.
type haPromotionApprovalAuthority struct {
	repository *ha.SQLRepository
	identities *identity.Store
	authorizer  *identity.Authorizer
	publicKey  ed25519.PublicKey
	now        func() time.Time
}

func newHAPromotionApprovalAuthority(repository *ha.SQLRepository, identities *identity.Store, now func() time.Time) (*haPromotionApprovalAuthority, error) {
	if repository == nil || repository.DB == nil || identities == nil {
		return nil, ha.ErrInvalid
	}
	key, err := loadHAPromotionApprovalKey(haPromotionApprovalTrustPath)
	if err != nil {
		return nil, err
	}
	authorizer, err := identity.NewAuthorizer(identities)
	if err != nil { return nil, err }
	if now == nil {
		now = time.Now
	}
	return &haPromotionApprovalAuthority{repository: repository, identities: identities, authorizer: authorizer, publicKey: key, now: now}, nil
}

func (authority *haPromotionApprovalAuthority) Admit(ctx context.Context, promotion ha.Promotion, admission ha.PromotionApprovalAdmission) (ha.PromotionApprovalAdmission, bool, error) {
	now := authority.current()
	if authority == nil || authority.repository == nil || authority.identities == nil || authority.authorizer == nil || len(authority.publicKey) != ed25519.PublicKeySize || ctx == nil || !admission.AcceptedAt.IsZero() || admission.FenceID != "" {
		return ha.PromotionApprovalAdmission{}, false, ha.ErrUnsupported
	}
	admission.AcceptedAt = now
	if admission.Validate(now) != nil || validateHAPromotionApprovalBinding(promotion, admission.Approval, admission.Approval.PlanDigest, true) != nil {
		return ha.PromotionApprovalAdmission{}, false, ha.ErrDataLossApproval
	}
	if err := authority.verifyCurrentIdentity(ctx, admission.Approval, now); err != nil {
		return ha.PromotionApprovalAdmission{}, false, err
	}
	if err := authority.verifySignature(admission.Approval); err != nil {
		return ha.PromotionApprovalAdmission{}, false, err
	}
	return authority.repository.AdmitPromotionApproval(ctx, admission)
}

func (authority *haPromotionApprovalAuthority) ApprovalsForPromotion(ctx context.Context, promotion ha.Promotion, planDigest string) ([]ha.Approval, error) {
	now := authority.current()
	if authority == nil || authority.repository == nil || authority.identities == nil || authority.authorizer == nil || len(authority.publicKey) != ed25519.PublicKeySize || ctx == nil || validateHAPromotionApprovalBinding(promotion, ha.Approval{PromotionID: promotion.ID, GroupID: promotion.GroupID, PromotionGeneration: promotion.Generation, PlanDigest: planDigest, FenceChallenge: planDigest}, planDigest, true) != nil {
		return nil, ha.ErrDataLossApproval
	}
	admissions, err := authority.repository.PromotionApprovalAdmissions(ctx, promotion.ID, planDigest, now)
	if err != nil {
		return nil, errors.Join(err, ha.ErrDataLossApproval)
	}
	if len(admissions) < 2 {
		return nil, ha.ErrDataLossApproval
	}
	approvals := make([]ha.Approval, 0, len(admissions))
	actors := make(map[string]struct{}, len(admissions))
	tenantID := ""
	for _, admission := range admissions {
		approval := admission.Approval
		if approval.Validate(now) != nil || validateHAPromotionApprovalBinding(promotion, approval, planDigest, true) != nil {
			return nil, ha.ErrDataLossApproval
		}
		if _, duplicate := actors[approval.ActorID]; duplicate {
			return nil, ha.ErrDataLossApproval
		}
		if tenantID == "" {
			tenantID = approval.TenantID
		} else if tenantID != approval.TenantID {
			return nil, ha.ErrDataLossApproval
		}
		if err = authority.verifyCurrentIdentity(ctx, approval, now); err != nil {
			return nil, err
		}
		if err = authority.verifySignature(approval); err != nil {
			return nil, err
		}
		actors[approval.ActorID] = struct{}{}
		approvals = append(approvals, approval)
	}
	sort.Slice(approvals, func(left, right int) bool {
		if approvals[left].ActorID == approvals[right].ActorID { return approvals[left].ID < approvals[right].ID }
		return approvals[left].ActorID < approvals[right].ActorID
	})
	return approvals, nil
}

func (authority *haPromotionApprovalAuthority) VerifyAdministrativeApproval(ctx context.Context, fence ha.Fence, approval ha.Approval) error {
	now := authority.current()
	if authority == nil || authority.repository == nil || authority.identities == nil || authority.authorizer == nil || len(authority.publicKey) != ed25519.PublicKeySize || ctx == nil || fence.Class != ha.FenceAdministrative || fence.State != ha.FencePlanned || fence.Challenge != approval.FenceChallenge || fence.Challenge != approval.PlanDigest || fence.GroupID != approval.GroupID || approval.Validate(now) != nil {
		return ha.ErrDataLossApproval
	}
	admission, err := authority.repository.PromotionApprovalAdmission(ctx, approval.ID)
	if err != nil || !sameHAPromotionApproval(admission.Approval, approval) || admission.FenceID != "" && admission.FenceID != fence.ID {
		return errors.Join(err, ha.ErrDataLossApproval)
	}
	promotion, err := authority.repository.LoadPromotion(ctx, approval.PromotionID)
	if err != nil || promotion.ID != approval.PromotionID || promotion.GroupID != approval.GroupID || promotion.PreviousWriter != fence.TargetNodeID || promotion.State != ha.PromotionFencing {
		return errors.Join(err, ha.ErrDataLossApproval)
	}
	if err = authority.verifyCurrentIdentity(ctx, approval, now); err != nil {
		return err
	}
	if err = authority.verifySignature(approval); err != nil {
		return err
	}
	if err = authority.repository.BindPromotionApprovalFence(ctx, approval.ID, fence.ID); err != nil {
		return errors.Join(err, ha.ErrDataLossApproval)
	}
	return nil
}

func validateHAPromotionApprovalBinding(promotion ha.Promotion, approval ha.Approval, planDigest string, requirePlanned bool) error {
	if promotion.ID == "" || promotion.GroupID == "" || promotion.Generation == 0 || promotion.ID != approval.PromotionID || promotion.GroupID != approval.GroupID || promotion.Generation != approval.PromotionGeneration || approval.PlanDigest != planDigest || approval.FenceChallenge != planDigest {
		return ha.ErrDataLossApproval
	}
	if requirePlanned && promotion.State != ha.PromotionPlanned {
		return ha.ErrDataLossApproval
	}
	digest, err := ha.PromotionPlanDigest(promotion)
	if err != nil || digest != planDigest {
		return errors.Join(err, ha.ErrDataLossApproval)
	}
	return nil
}

func (authority *haPromotionApprovalAuthority) verifyCurrentIdentity(ctx context.Context, approval ha.Approval, now time.Time) error {
	tenantID, tenantErr := identity.NewID(approval.TenantID)
	actorID, actorErr := identity.NewID(approval.ActorID)
	credentialID, credentialErr := identity.NewID(approval.CredentialID)
	sessionID, sessionErr := identity.NewID(approval.SessionID)
	if tenantErr != nil || actorErr != nil || credentialErr != nil || sessionErr != nil {
		return ha.ErrForbidden
	}
	tenant, err := authority.identities.Tenant(ctx, tenantID)
	if err != nil || tenant.Kind != identity.TenantOwner || tenant.State != identity.TenantActive || tenant.AuthzEpoch != approval.TenantAuthzEpoch {
		return errors.Join(err, ha.ErrForbidden)
	}
	principal, err := authority.identities.Principal(ctx, actorID)
	if err != nil || principal.Kind != identity.PrincipalHuman || principal.State != identity.PrincipalActive || principal.AuthzEpoch != approval.AuthzEpoch {
		return errors.Join(err, ha.ErrForbidden)
	}
	session, err := authority.identities.Session(ctx, sessionID)
	if err != nil || session.PrincipalID != actorID || session.CredentialID != credentialID || session.AuthzEpoch != approval.AuthzEpoch || session.CredentialEpoch != principal.CredentialEpoch || session.Assurance < identity.AssurancePhishingResistant || session.RevokedAt != nil || !now.Before(session.ExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || approval.IssuedAt.Before(session.CreatedAt) || approval.ExpiresAt.After(session.ExpiresAt) || approval.ExpiresAt.After(session.AbsoluteExpiresAt) {
		return errors.Join(err, ha.ErrForbidden)
	}
	memberships, err := authority.identities.Memberships(ctx, actorID)
	if err != nil {
		return errors.Join(err, ha.ErrForbidden)
	}
	member := false
	for _, membership := range memberships {
		if membership.TenantID == tenantID && membership.State == identity.MembershipActive { member = true; break }
	}
	if !member {
		return ha.ErrForbidden
	}
	decision, err := authority.authorizer.Decide(ctx, identity.AuthorizationRequest{PrincipalID:actorID,Permission:identity.MustPermission("ha:manage"),Scope:identity.Scope{Kind:identity.ScopeTenant,TenantID:tenantID},At:now,Assurance:identity.AssurancePhishingResistant})
	if err != nil || !decision.Allowed || decision.PrincipalEpoch != approval.AuthzEpoch || decision.TenantEpoch != approval.TenantAuthzEpoch {
		return errors.Join(err, ha.ErrForbidden)
	}
	return nil
}

func (authority *haPromotionApprovalAuthority) verifySignature(approval ha.Approval) error {
	signature, err := decodeHAPromotionApprovalSignature(approval.Signature)
	if err != nil {
		return ha.ErrForbidden
	}
	payload, err := haPromotionApprovalSignaturePayload(approval)
	if err != nil || !ed25519.Verify(authority.publicKey, payload, signature) {
		return errors.Join(err, ha.ErrForbidden)
	}
	return nil
}

func haPromotionApprovalSignaturePayload(approval ha.Approval) ([]byte, error) {
	payload, err := json.Marshal(struct {
		Version             uint32         `json:"version"`
		Purpose             string         `json:"purpose"`
		ID                  string         `json:"id"`
		TenantID            string         `json:"tenant_id"`
		PromotionID         ha.PromotionID `json:"promotion_id"`
		GroupID             ha.NodeGroupID `json:"group_id"`
		ActorID             string         `json:"actor_id"`
		CredentialID        string         `json:"credential_id"`
		SessionID           string         `json:"session_id"`
		AuthzEpoch          uint64         `json:"authz_epoch"`
		TenantAuthzEpoch    uint64         `json:"tenant_authz_epoch"`
		PromotionGeneration uint64         `json:"promotion_generation"`
		Kind                string         `json:"kind"`
		PlanDigest          string         `json:"plan_digest"`
		FenceChallenge      string         `json:"fence_challenge"`
		PhishingResistant   bool           `json:"phishing_resistant"`
		IssuedAt            time.Time      `json:"issued_at"`
		ExpiresAt           time.Time      `json:"expires_at"`
	}{1, "cyberpanel.ha.promotion-approval.v1", approval.ID, approval.TenantID, approval.PromotionID, approval.GroupID, approval.ActorID, approval.CredentialID, approval.SessionID, approval.AuthzEpoch, approval.TenantAuthzEpoch, approval.PromotionGeneration, approval.Kind, approval.PlanDigest, approval.FenceChallenge, approval.PhishingResistant, approval.IssuedAt.UTC(), approval.ExpiresAt.UTC()})
	if err != nil || len(payload) == 0 || len(payload) > 16<<10 {
		return nil, errors.Join(err, ha.ErrInvalid)
	}
	return payload, nil
}

func loadHAPromotionApprovalKey(path string) (ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ha.ErrUnsupported
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0022 != 0 || before.Size() != ed25519.PublicKeySize || haApprovalFileUID(before) != 0 {
		return nil, errors.Join(err, ha.ErrUnsupported)
	}
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) { return nil, ha.ErrUnsupported }
	key := make([]byte, ed25519.PublicKeySize)
	if _, err = io.ReadFull(file, key); err != nil { return nil, err }
	var trailing [1]byte
	if count, readErr := file.Read(trailing[:]); count != 0 || readErr != io.EOF { return nil, ha.ErrUnsupported }
	return ed25519.PublicKey(key), nil
}

func decodeHAPromotionApprovalSignature(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == ed25519.SignatureSize { return decoded, nil }
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize { return nil, ha.ErrDataLossApproval }
	return decoded, nil
}

func haApprovalFileUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok { return stat.Uid }
	return ^uint32(0)
}

func sameHAPromotionApproval(left, right ha.Approval) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.PromotionID == right.PromotionID && left.GroupID == right.GroupID && left.ActorID == right.ActorID && left.CredentialID == right.CredentialID && left.SessionID == right.SessionID && left.AuthzEpoch == right.AuthzEpoch && left.TenantAuthzEpoch == right.TenantAuthzEpoch && left.PromotionGeneration == right.PromotionGeneration && left.Kind == right.Kind && left.PlanDigest == right.PlanDigest && left.FenceChallenge == right.FenceChallenge && left.PhishingResistant == right.PhishingResistant && left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt) && left.Signature == right.Signature
}

func (authority *haPromotionApprovalAuthority) current() time.Time {
	if authority != nil && authority.now != nil { return authority.now().UTC() }
	return time.Now().UTC()
}

var _ ha.AdministrativeApprovalVerifier = (*haPromotionApprovalAuthority)(nil)
