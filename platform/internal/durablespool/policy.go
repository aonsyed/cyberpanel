package durablespool

import "math"

func add(values ...uint64) (uint64, bool) {
	var result uint64
	for _, value := range values {
		if value > math.MaxUint64-result {
			return 0, false
		}
		result += value
	}
	return result, true
}

func remaining(capacity, used uint64) uint64 {
	if used >= capacity {
		return 0
	}
	return capacity - used
}

func belowBasisPoints(value, total uint64, basisPoints uint16) bool {
	if total == 0 {
		return true
	}
	whole := total / 10000
	remainder := total % 10000
	threshold := whole*uint64(basisPoints) + remainder*uint64(basisPoints)/10000
	return value <= threshold
}

func (policy WatermarkPolicy) validate() error {
	if policy.WarnFreeBasisPoints == 0 || policy.WarnFreeBasisPoints > 10000 || policy.RestrictFreeBasisPoints == 0 || policy.RestrictFreeBasisPoints >= policy.WarnFreeBasisPoints || policy.EmergencyFreeBasisPoints == 0 || policy.EmergencyFreeBasisPoints >= policy.RestrictFreeBasisPoints {
		return ErrInvalid
	}
	if _, ok := add(policy.AuditReserve.Bytes, policy.RecoveryReserve.Bytes, policy.RollbackReserve.Bytes); !ok {
		return ErrInvalid
	}
	if _, ok := add(policy.AuditReserve.Inodes, policy.RecoveryReserve.Inodes, policy.RollbackReserve.Inodes); !ok {
		return ErrInvalid
	}
	return nil
}

func (policy Policy) Validate() error {
	if err := policy.Watermarks.validate(); err != nil {
		return err
	}
	if policy.MaximumPayloadBytes == 0 || policy.MaximumPayloadBytes > AbsoluteMaximumSpoolBytes || policy.MaximumRecords == 0 || policy.MaximumRecords > AbsoluteMaximumRecords || policy.MaximumRecordBytes == 0 || policy.MaximumRecordBytes > AbsoluteMaximumRecordBytes || policy.MaximumRecordBytes > policy.MaximumPayloadBytes || policy.EssentialReserveBytes < policy.MaximumRecordBytes || policy.EssentialReserveBytes > policy.MaximumPayloadBytes || policy.EssentialReserveCount == 0 || policy.EssentialReserveCount > policy.MaximumRecords || policy.MinimumEssentialBytes < policy.MaximumRecordBytes || policy.MinimumEssentialBytes > policy.EssentialReserveBytes || policy.DefaultLease <= 0 || policy.MaximumLease < policy.DefaultLease || policy.MaximumLease > MaximumLeaseLimit {
		return ErrInvalid
	}
	for _, class := range []RecordClass{ClassTerminalReceipt, ClassAuditCheckpoint, ClassSecurityCheckpoint, ClassOrdinaryEvent} {
		limit := policy.Classes.For(class)
		if limit.MaximumPayloadBytes < policy.MaximumRecordBytes || limit.MaximumPayloadBytes > policy.MaximumPayloadBytes || limit.MaximumRecords == 0 || limit.MaximumRecords > policy.MaximumRecords {
			return ErrInvalid
		}
	}
	return nil
}

func (policy WatermarkPolicy) Evaluate(observation FilesystemPressure) (Watermark, uint64, uint64, error) {
	if err := policy.validate(); err != nil {
		return "", 0, 0, err
	}
	if err := observation.Validate(); err != nil {
		return "", 0, 0, err
	}
	protectedBytes, ok := add(observation.BytesReserved, policy.AuditReserve.Bytes, policy.RecoveryReserve.Bytes, policy.RollbackReserve.Bytes)
	if !ok {
		return "", 0, 0, ErrInvalid
	}
	protectedInodes, ok := add(observation.InodesReserved, policy.AuditReserve.Inodes, policy.RecoveryReserve.Inodes, policy.RollbackReserve.Inodes)
	if !ok {
		return "", 0, 0, ErrInvalid
	}
	effectiveBytes := remaining(observation.BytesFree, protectedBytes)
	effectiveInodes := remaining(observation.InodesFree, protectedInodes)
	if effectiveBytes == 0 || effectiveInodes == 0 || belowBasisPoints(effectiveBytes, observation.BytesTotal, policy.EmergencyFreeBasisPoints) || belowBasisPoints(effectiveInodes, observation.InodesTotal, policy.EmergencyFreeBasisPoints) {
		return WatermarkEmergency, effectiveBytes, effectiveInodes, nil
	}
	if belowBasisPoints(effectiveBytes, observation.BytesTotal, policy.RestrictFreeBasisPoints) || belowBasisPoints(effectiveInodes, observation.InodesTotal, policy.RestrictFreeBasisPoints) {
		return WatermarkRestrict, effectiveBytes, effectiveInodes, nil
	}
	if belowBasisPoints(effectiveBytes, observation.BytesTotal, policy.WarnFreeBasisPoints) || belowBasisPoints(effectiveInodes, observation.InodesTotal, policy.WarnFreeBasisPoints) {
		return WatermarkWarn, effectiveBytes, effectiveInodes, nil
	}
	return WatermarkNormal, effectiveBytes, effectiveInodes, nil
}

func (policy Policy) AdmissionFor(observation FilesystemPressure, usage Usage) (AdmissionState, error) {
	if err := policy.Validate(); err != nil {
		return AdmissionState{}, err
	}
	watermark, freeBytes, freeInodes, err := policy.Watermarks.Evaluate(observation)
	if err != nil {
		return AdmissionState{}, err
	}
	spoolBytes := remaining(policy.MaximumPayloadBytes, usage.TotalPayloadBytes)
	spoolRecords := remaining(policy.MaximumRecords, usage.TotalRecords)
	recoverableBytes, ok := add(spoolBytes, usage.EvictablePayloadBytes)
	if !ok {
		return AdmissionState{}, ErrInvalid
	}
	recoverableRecords, ok := add(spoolRecords, usage.EvictableRecords)
	if !ok {
		return AdmissionState{}, ErrInvalid
	}
	physicalBytes := remaining(observation.BytesFree, observation.BytesReserved)
	physicalInodes := remaining(observation.InodesFree, observation.InodesReserved)
	physicalRecoverableBytes, ok := add(physicalBytes, usage.EvictablePayloadBytes)
	if !ok || usage.EvictableRecords > math.MaxUint64/2 {
		return AdmissionState{}, ErrInvalid
	}
	physicalRecoverableInodes, ok := add(physicalInodes, usage.EvictableRecords*2)
	if !ok {
		return AdmissionState{}, ErrInvalid
	}
	exhausted := recoverableBytes < policy.MinimumEssentialBytes || recoverableRecords == 0 || physicalRecoverableBytes < policy.MinimumEssentialBytes || physicalRecoverableInodes == 0
	state := AdmissionState{
		Watermark: watermark, EssentialReserveExhausted: exhausted,
		AllowLocalRecovery: true, AllowLocalAudit: true,
		AllowEssentialSpool: !exhausted,
		EffectiveFreeBytes: freeBytes, EffectiveFreeInodes: freeInodes,
	}
	switch {
	case exhausted:
		state.ReasonCode = "essential_spool_reserve_exhausted"
	case watermark == WatermarkEmergency:
		state.ReasonCode = "filesystem_emergency_watermark"
	case watermark == WatermarkRestrict:
		state.ReasonCode = "filesystem_restrict_watermark"
	case watermark == WatermarkWarn:
		state.ReasonCode = "filesystem_warn_watermark"
	default:
		state.ReasonCode = "admission_normal"
	}
	state.AllowCentralMutations = !exhausted && (watermark == WatermarkNormal || watermark == WatermarkWarn)
	state.AllowOrdinaryEvents = state.AllowCentralMutations && spoolBytes > policy.EssentialReserveBytes && spoolRecords > policy.EssentialReserveCount
	return state, nil
}
