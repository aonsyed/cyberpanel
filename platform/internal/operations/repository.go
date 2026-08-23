package operations

import (
	"context"
	"time"
)

type MutationKind string
const MutationUpsert MutationKind = "upsert"

type ResourceMutation struct {
	Kind MutationKind `json:"kind"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Resource ResourceEnvelope `json:"resource"`
}

type ObservedResource struct {
	Kind ResourceKind `json:"kind"`
	ID ResourceID `json:"id"`
	Generation uint64 `json:"generation"`
	Status ResourceStatus `json:"status"`
}

type OperationStatus string

const (
	OperationAccepted OperationStatus = "accepted"
	OperationApplied OperationStatus = "applied"
	OperationRejected OperationStatus = "rejected"
	OperationCompensated OperationStatus = "compensated"
	OperationAmbiguous OperationStatus = "ambiguous"
)

type OperationReceipt struct {
	CommandID string `json:"command_id"`
	CommandDigest string `json:"command_digest"`
	Scope OperationScope `json:"scope"`
	Status OperationStatus `json:"status"`
	AcceptedAt time.Time `json:"accepted_at"`
	Request EffectRequest `json:"request"`
	Mutations []ResourceMutation `json:"mutations,omitempty"`
	Rollback []ResourceMutation `json:"rollback,omitempty"`
	Success []ObservedResource `json:"success,omitempty"`
	Restored []ObservedResource `json:"restored,omitempty"`
	Effect EffectReceipt `json:"effect,omitempty"`
	Compensation CompensationReceipt `json:"compensation,omitempty"`
}

type Admission struct {
	CommandID string
	CommandDigest string
	Scope OperationScope
	AcceptedAt time.Time
	Request EffectRequest
	Mutations []ResourceMutation
	Rollback []ResourceMutation
	Success []ObservedResource
	Restored []ObservedResource
}

type AdmissionResultKind string
const (
	AdmissionNew AdmissionResultKind = "new"
	AdmissionExistingSame AdmissionResultKind = "existing_same"
	AdmissionConflict AdmissionResultKind = "conflict"
)
type AdmissionResult struct { Kind AdmissionResultKind; Receipt OperationReceipt }

type Completion struct {
	CommandID string
	CommandDigest string
	Scope OperationScope
	Status OperationStatus
	Effect EffectReceipt
	Compensation CompensationReceipt
	Observed []ObservedResource
}

// Repository is the single control.db writer. Admit persists desired state and
// the executable outbox request atomically. Complete persists observations,
// terminal evidence, and any proven rollback in the same transaction.
type Repository interface {
	LookupOperation(context.Context, OperationScope, string) (OperationReceipt, bool, error)
	LoadResource(context.Context, ResourceKind, ResourceID) (ResourceEnvelope, error)
	Admit(context.Context, Admission) (AdmissionResult, error)
	Complete(context.Context, Completion) (OperationReceipt, error)
}

type Clock interface { Now() time.Time }
type SystemClock struct{}
func (SystemClock) Now() time.Time { return time.Now() }

func cloneReceipt(receipt OperationReceipt) OperationReceipt {
	receipt.Mutations = cloneMutations(receipt.Mutations)
	receipt.Rollback = cloneMutations(receipt.Rollback)
	receipt.Success = append([]ObservedResource(nil), receipt.Success...)
	receipt.Restored = append([]ObservedResource(nil), receipt.Restored...)
	return receipt
}

func cloneMutations(source []ResourceMutation) []ResourceMutation {
	result := append([]ResourceMutation(nil), source...)
	for index := range result { result[index].Resource.Spec = append([]byte(nil), result[index].Resource.Spec...) }
	return result
}
