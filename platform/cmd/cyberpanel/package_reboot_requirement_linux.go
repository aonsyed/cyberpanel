//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/packagemaint"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// This adapter publishes passive evidence only. It has no reboot coordinator,
// executor, scheduling authority, or caller-controlled filesystem paths.
type packageRebootRequirementPublisher struct {
	repository *rebootcontrol.Repository
	database   *sql.DB
	nodeID     string
}

var packageRebootBootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var packageRebootKernelRelease = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func (publisher *packageRebootRequirementPublisher) BootIdentityForOperation(ctx context.Context, nodeID, operationID string, allowCreate bool) (packagemaint.RebootBootIdentity, error) {
	if publisher == nil || publisher.database == nil || ctx == nil || nodeID != publisher.nodeID || !validPackageMaintenanceRuntimeID(operationID) { return packagemaint.RebootBootIdentity{},packagemaint.ErrInvalid }
	load := func() (packagemaint.RebootBootIdentity,error) {
		var identity packagemaint.RebootBootIdentity; var storedNode,digest string
		err := publisher.database.QueryRowContext(ctx,`SELECT node_id,boot_id,kernel_release,kernel_digest,binding_digest FROM package_operation_boot_bindings WHERE operation_id=?`,operationID).Scan(&storedNode,&identity.BootID,&identity.KernelRelease,&identity.KernelDigest,&digest)
		if err != nil { return identity,err }
		if storedNode != nodeID || identity.Validate() != nil || !packageRebootBootID.MatchString(identity.BootID) || identity.BootID == "00000000-0000-0000-0000-000000000000" || !packageRebootKernelRelease.MatchString(identity.KernelRelease) || identity.KernelDigest != rebootRuntimeDigest("kernel_release",identity.KernelRelease) || digest != rebootRuntimeDigest("package-operation-boot",operationID,nodeID,identity.BootID,identity.KernelRelease,identity.KernelDigest) { return packagemaint.RebootBootIdentity{},rebootcontrol.ErrIntegrity }
		return identity,nil
	}
	identity,err := load()
	if errors.Is(err,sql.ErrNoRows) && allowCreate {
		identity,err = publisher.CurrentBootIdentity(ctx,nodeID); if err != nil { return identity,err }
		digest := rebootRuntimeDigest("package-operation-boot",operationID,nodeID,identity.BootID,identity.KernelRelease,identity.KernelDigest)
		_,err = publisher.database.ExecContext(ctx,`INSERT INTO package_operation_boot_bindings(operation_id,node_id,boot_id,kernel_release,kernel_digest,binding_digest) VALUES(?,?,?,?,?,?) ON CONFLICT(operation_id) DO NOTHING`,operationID,nodeID,identity.BootID,identity.KernelRelease,identity.KernelDigest,digest)
		if err != nil { return packagemaint.RebootBootIdentity{},err }; identity,err = load()
	}
	if err != nil { return packagemaint.RebootBootIdentity{},err }
	// Missing bindings on restart fail closed; old bindings are immutable and
	// may never be replaced with the current boot following an external reboot.
	current,err := publisher.CurrentBootIdentity(ctx,nodeID)
	if err != nil { return packagemaint.RebootBootIdentity{},err }
	if current != identity { return packagemaint.RebootBootIdentity{},rebootcontrol.ErrStaleBoot }
	return identity,nil
}

func (publisher *packageRebootRequirementPublisher) CurrentBootIdentity(ctx context.Context, nodeID string) (packagemaint.RebootBootIdentity, error) {
	if publisher == nil || publisher.repository == nil || ctx == nil || nodeID != publisher.nodeID || !validPackageMaintenanceRuntimeID(nodeID) {
		return packagemaint.RebootBootIdentity{}, packagemaint.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return packagemaint.RebootBootIdentity{}, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return packagemaint.RebootBootIdentity{}, err
	}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return packagemaint.RebootBootIdentity{}, err
	}
	// Remove only the proc record terminator. Never sanitize malformed bytes
	// into a plausible identity or truncate an overlong value.
	identity := packagemaint.RebootBootIdentity{BootID: strings.TrimSuffix(string(boot), "\n"), KernelRelease: strings.TrimSuffix(string(kernel), "\n")}
	if !packageRebootBootID.MatchString(identity.BootID) || identity.BootID == "00000000-0000-0000-0000-000000000000" || !packageRebootKernelRelease.MatchString(identity.KernelRelease) {
		return packagemaint.RebootBootIdentity{}, rebootcontrol.ErrIntegrity
	}
	identity.KernelDigest = rebootRuntimeDigest("kernel_release", identity.KernelRelease)
	if identity.Validate() != nil {
		return packagemaint.RebootBootIdentity{}, rebootcontrol.ErrIntegrity
	}
	return identity, nil
}

func (publisher *packageRebootRequirementPublisher) PublishRebootRequirement(ctx context.Context, value packagemaint.RebootRequirement) (packagemaint.RebootRequirementPublication, error) {
	if publisher == nil || publisher.repository == nil || ctx == nil || value.NodeID != publisher.nodeID || value.Digest == "" {
		return packagemaint.RebootRequirementPublication{}, packagemaint.ErrInvalid
	}
	requirement, err := packagemaint.CanonicalRebootRequirement(value)
	if err != nil {
		return packagemaint.RebootRequirementPublication{}, err
	}
	current, err := publisher.CurrentBootIdentity(ctx, requirement.NodeID)
	if err != nil {
		return packagemaint.RebootRequirementPublication{}, err
	}
	if current != requirement.CurrentBoot.RebootBootIdentity {
		return packagemaint.RebootRequirementPublication{}, rebootcontrol.ErrStaleBoot
	}
	// Keep the immutable package envelope digest, receipt timestamp and boot
	// evidence. A retry does not invent a new observation or change its digest.
	// Package evidence alone does not establish a kernel/security/recovery reason.
	durable, err := rebootcontrol.CanonicalRequirement(rebootcontrol.RebootRequirement{
		ID: requirement.ID, NodeID: requirement.NodeID, Reason: rebootcontrol.ReasonPackageUpdate,
		PackageOperationID: requirement.PackageOperationID, EvidenceDigest: requirement.Digest,
		SourceBoot: rebootcontrol.BootIdentity{BootID: current.BootID, KernelRelease: current.KernelRelease,
			KernelDigest: current.KernelDigest, ObservedAt: requirement.CurrentBoot.ObservedAt,
			EvidenceDigest: requirement.CurrentBoot.EvidenceDigest},
		ObservedAt: requirement.ObservedAt, Generation: 1,
	})
	if err != nil {
		return packagemaint.RebootRequirementPublication{}, err
	}
	if err = publisher.repository.UpsertRequirement(ctx, durable); err != nil {
		return packagemaint.RebootRequirementPublication{}, err
	}
	stored, err := publisher.repository.LoadRequirement(ctx, durable.ID)
	if err != nil {
		return packagemaint.RebootRequirementPublication{}, err
	}
	if stored != durable {
		return packagemaint.RebootRequirementPublication{}, rebootcontrol.ErrIntegrity
	}
	return packagemaint.RebootRequirementPublication{RequirementID: stored.ID, EvidenceDigest: stored.EvidenceDigest}, nil
}

var _ packagemaint.RebootRequirementPublisher = (*packageRebootRequirementPublisher)(nil)
