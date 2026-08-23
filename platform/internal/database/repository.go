package database

import (
	"context"
	"time"
)

type OperationStatus string

const (
	OperationAccepted    OperationStatus = "accepted"
	OperationApplied     OperationStatus = "applied"
	OperationCompensated OperationStatus = "compensated"
	OperationRejected    OperationStatus = "rejected"
	OperationAmbiguous   OperationStatus = "ambiguous"
)

type OperationReceipt struct {
	CommandID       string                `json:"command_id"`
	CommandDigest   string                `json:"command_digest"`
	Scope           OperationScope        `json:"scope"`
	Status          OperationStatus       `json:"status"`
	AcceptedAt      time.Time             `json:"accepted_at"`
	Request         EffectRequest         `json:"request"`
	Mutations       []ResourceMutation    `json:"mutations"`
	Rollback        []ResourceMutation    `json:"rollback"`
	Success         []ObservedResource    `json:"success"`
	Compensated     []ObservedResource    `json:"compensated"`
	Effect          EffectReceipt         `json:"effect,omitempty"`
	Compensation    CompensationReceipt   `json:"compensation,omitempty"`
}

type Admission struct {
	CommandID     string
	CommandDigest string
	Scope         OperationScope
	AcceptedAt    time.Time
	Request       EffectRequest
	Mutations     []ResourceMutation
	Rollback      []ResourceMutation
	Success       []ObservedResource
	Compensated   []ObservedResource
}

type AdmissionResultKind string

const (
	AdmissionNew          AdmissionResultKind = "new"
	AdmissionExistingSame AdmissionResultKind = "existing_same"
	AdmissionConflict     AdmissionResultKind = "conflict"
)

type AdmissionResult struct {
	Kind    AdmissionResultKind
	Receipt OperationReceipt
}

type Completion struct {
	CommandID     string
	CommandDigest string
	Scope         OperationScope
	Status        OperationStatus
	Effect        EffectReceipt
	Compensation  CompensationReceipt
	Observed      []ObservedResource
}

// Repository is the sole control.db authority used by Coordinator. Admit must
// apply resource CAS mutations and persist the accepted outbox request in one
// transaction. Complete must persist terminal evidence and observations in one
// transaction.
type Repository interface {
	LookupOperation(context.Context, OperationScope, string) (OperationReceipt, bool, error)
	LoadResource(context.Context, ResourceKind, ResourceID) (ResourceEnvelope, error)
	Admit(context.Context, Admission) (AdmissionResult, error)
	Complete(context.Context, Completion) (OperationReceipt, error)
}

type Clock interface { Now() time.Time }

func cloneOperation(receipt OperationReceipt) OperationReceipt {
	receipt.Mutations = append([]ResourceMutation(nil), receipt.Mutations...)
	receipt.Rollback = append([]ResourceMutation(nil), receipt.Rollback...)
	receipt.Success = append([]ObservedResource(nil), receipt.Success...)
	receipt.Compensated = append([]ObservedResource(nil), receipt.Compensated...)
	for index := range receipt.Mutations {
		receipt.Mutations[index].Resource.Spec = append([]byte(nil), receipt.Mutations[index].Resource.Spec...)
	}
	for index := range receipt.Rollback {
		receipt.Rollback[index].Resource.Spec = append([]byte(nil), receipt.Rollback[index].Resource.Spec...)
	}
	return receipt
}
