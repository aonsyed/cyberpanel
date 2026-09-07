package ha

import (
	"encoding/json"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

// FederatedHAGrantDigest excludes the digest and signature themselves. Provisioning
// tools use this digest, then sign FederatedHAGrantSignaturePayload out of band.
func FederatedHAGrantDigest(grant federation.MutationGrant) (string, error) {
	grant.Digest, grant.Signature = "", nil
	raw, err := json.Marshal(grant)
	if err != nil { return "", err }
	return federatedHADigest(raw), nil
}

func FederatedHAGrantSignaturePayload(grant federation.MutationGrant) ([]byte, error) {
	digest, err := FederatedHAGrantDigest(grant)
	if err != nil || digest != grant.Digest { return nil, ErrForbidden }
	grant.Signature = nil
	return json.Marshal(struct { Domain string `json:"domain"`; Grant federation.MutationGrant `json:"grant"` }{"cyberpanel-ha-mutation-grant-v1", grant})
}

// The approval signature covers all approval metadata, including the immutable
// plan digest (tenant/node/grant/purpose/resource/generation/payload). It does not
// depend on the central-assigned intent/effect IDs, which do not yet exist when
// the independent approval client signs. This helper never signs or mints approval.
func FederatedHAApprovalSignaturePayload(approval federation.Approval) ([]byte, error) {
	if approval.PolicyVersion != FederatedHAApprovalPolicyVersion || approval.AuthorizationID == "" || approval.SigningKeyID == "" || !validDigest(approval.PlanDigest) || !validDigest(approval.DisplayDigest) || approval.ExpiresAt.IsZero() { return nil, ErrForbidden }
	approval.Signature = nil
	return json.Marshal(struct { Domain string `json:"domain"`; Approval federation.Approval `json:"approval"` }{"cyberpanel-ha-purpose-approval-v1", approval})
}
