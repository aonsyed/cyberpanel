package redisservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	RedisPackageProfile = "managed-redis"
	configRoot          = "/etc/cyberpanel/redis"
	dataRoot            = "/var/lib/cyberpanel/redis"
	runRoot             = "/run/cyberpanel/redis"
)

type SecretResolver interface {
	Resolve(context.Context, SecretRef) ([]byte, error)
}

type SupportCatalog interface {
	Qualify(context.Context, SupportTuple) error
}

type RenderedGeneration struct {
	InstanceID       InstanceID  `json:"instance_id"`
	ConfigGeneration uint64      `json:"config_generation"`
	RedisConfig      []byte      `json:"-"`
	ACLConfig        []byte      `json:"-"`
	SystemdDropIn    []byte      `json:"-"`
	SecretRefs       []SecretRef `json:"secret_refs"`
	ConfigDigest     string      `json:"config_digest"`
}

func instanceConfigDirectory(id InstanceID) string {
	return configRoot + "/" + string(id)
}

func generationDirectory(id InstanceID, generation uint64) string {
	return instanceConfigDirectory(id) + "/generations/" + strconv.FormatUint(generation, 10)
}

func redisConfigPath(id InstanceID, generation uint64) string {
	return generationDirectory(id, generation) + "/redis.conf"
}

func aclConfigPath(id InstanceID, generation uint64) string {
	return generationDirectory(id, generation) + "/users.acl"
}

func systemdDropInPath(id InstanceID, generation uint64) string {
	return generationDirectory(id, generation) + "/resource.conf"
}

func unixSocketPath(id InstanceID) string {
	return runRoot + "/" + string(id) + "/redis.sock"
}

func instanceDataDirectory(id InstanceID) string {
	return dataRoot + "/" + string(id)
}

func tlsDirectory(reference string) string {
	return configRoot + "/tls/" + reference
}

func aclRules(purpose Purpose) (string, error) {
	switch purpose {
	case PurposeCache, PurposeObjectCache:
		return "~* +@connection +@read +@write +@keyspace -@dangerous -flushall -flushdb -config -module -shutdown -debug +info", nil
	case PurposeSession:
		return "~* +@connection +@read +@write +@keyspace +expire +pexpire -@dangerous -flushall -flushdb -config -module -shutdown -debug +info", nil
	case PurposeQueue:
		return "~* +@connection +@read +@write +@list +@stream +@scripting -@dangerous -flushall -flushdb -config -module -shutdown -debug +info", nil
	case PurposeRateLimit:
		return "~* +@connection +@read +@write +@scripting +expire +pexpire -@dangerous -flushall -flushdb -config -module -shutdown -debug +info", nil
	case PurposeInternal:
		return "~* +@connection +@read +@write +@keyspace +@list +@set +@sortedset +@hash +@stream +@scripting -@dangerous -flushall -flushdb -config -module -shutdown -debug +info", nil
	default:
		return "", fmt.Errorf("%w: ACL purpose", ErrInvalid)
	}
}

func secretHash(secret []byte) string {
	sum := sha256.Sum256(secret)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func RenderGeneration(ctx context.Context, spec InstanceSpec, resolver SecretResolver) (RenderedGeneration, error) {
	if resolver == nil {
		return RenderedGeneration{}, fmt.Errorf("%w: nil secret resolver", ErrInvalid)
	}
	sealed, err := SealInstanceSpec(spec)
	if err != nil || sealed.Digest != spec.Digest {
		return RenderedGeneration{}, fmt.Errorf("%w: unsealed instance spec", ErrInvalid)
	}
	var redisConfig strings.Builder
	redisConfig.Grow(4096)
	redisConfig.WriteString("daemonize no\n")
	redisConfig.WriteString("supervised systemd\n")
	redisConfig.WriteString("protected-mode yes\n")
	redisConfig.WriteString("aclfile " + aclConfigPath(spec.ID, spec.ConfigGeneration) + "\n")
	redisConfig.WriteString("dir " + instanceDataDirectory(spec.ID) + "\n")
	redisConfig.WriteString("dbfilename dump.rdb\n")
	redisConfig.WriteString("databases " + strconv.Itoa(int(spec.Databases)) + "\n")
	redisConfig.WriteString("maxmemory " + strconv.FormatUint(spec.MaxMemoryBytes, 10) + "\n")
	redisConfig.WriteString("maxmemory-policy " + string(spec.Eviction) + "\n")
	redisConfig.WriteString("logfile \"\"\n")
	redisConfig.WriteString("loglevel notice\n")
	redisConfig.WriteString("timeout 0\n")
	redisConfig.WriteString("tcp-keepalive 300\n")
	redisConfig.WriteString("stop-writes-on-bgsave-error yes\n")
	redisConfig.WriteString("rdbcompression yes\n")
	redisConfig.WriteString("rdbchecksum yes\n")
	redisConfig.WriteString("appendfilename \"appendonly.aof\"\n")
	redisConfig.WriteString("aof-use-rdb-preamble yes\n")
	redisConfig.WriteString("aof-load-truncated no\n")
	redisConfig.WriteString("pidfile " + runRoot + "/" + string(spec.ID) + "/redis.pid\n")
	switch spec.Listener.Mode {
	case ListenerUnix:
		redisConfig.WriteString("bind 127.0.0.1\n")
		redisConfig.WriteString("port 0\n")
		redisConfig.WriteString("unixsocket " + unixSocketPath(spec.ID) + "\n")
		redisConfig.WriteString("unixsocketperm " + strconv.FormatUint(uint64(spec.Listener.SocketMode), 8) + "\n")
	case ListenerLoopback:
		redisConfig.WriteString("bind " + spec.Listener.LoopbackAddress + "\n")
		if spec.Listener.TLS {
			redisConfig.WriteString("port 0\n")
			redisConfig.WriteString("tls-port " + strconv.Itoa(int(spec.Listener.Port)) + "\n")
			redisConfig.WriteString("tls-protocols \"TLSv1.2 TLSv1.3\"\n")
			redisConfig.WriteString("tls-cert-file " + tlsDirectory(spec.Listener.CertificateRef) + "/server.crt\n")
			redisConfig.WriteString("tls-key-file " + tlsDirectory(spec.Listener.CertificateRef) + "/server.key\n")
			redisConfig.WriteString("tls-ca-cert-file " + tlsDirectory(spec.Listener.ClientCARef) + "/ca.crt\n")
			redisConfig.WriteString("tls-auth-clients yes\n")
		} else {
			redisConfig.WriteString("port " + strconv.Itoa(int(spec.Listener.Port)) + "\n")
			redisConfig.WriteString("tls-port 0\n")
		}
	default:
		return RenderedGeneration{}, fmt.Errorf("%w: listener mode", ErrInvalid)
	}
	switch spec.Persistence.RDB {
	case RDBDisabled:
		redisConfig.WriteString("save \"\"\n")
	case RDBBalanced:
		redisConfig.WriteString("save 900 1\n")
		redisConfig.WriteString("save 300 10\n")
		redisConfig.WriteString("save 60 10000\n")
	case RDBDurable:
		redisConfig.WriteString("save 300 1\n")
		redisConfig.WriteString("save 60 100\n")
	}
	switch spec.Persistence.AOF {
	case AOFDisabled:
		redisConfig.WriteString("appendonly no\n")
	case AOFEverySec:
		redisConfig.WriteString("appendonly yes\n")
		redisConfig.WriteString("appendfsync everysec\n")
	case AOFAlways:
		redisConfig.WriteString("appendonly yes\n")
		redisConfig.WriteString("appendfsync always\n")
	}

	var aclConfig strings.Builder
	aclConfig.Grow(2048)
	aclConfig.WriteString("user default off resetpass resetkeys -@all\n")
	secretRefs := make([]SecretRef, 0, len(spec.ACLUsers))
	for _, user := range spec.ACLUsers {
		secret, resolveErr := resolver.Resolve(ctx, user.SecretRef)
		if resolveErr != nil {
			return RenderedGeneration{}, fmt.Errorf("%w: ACL secret reference unavailable", ErrInvalid)
		}
		if len(secret) < 32 || len(secret) > 256 || secretHash(secret) != user.SecretRef.Digest {
			zeroBytes(secret)
			return RenderedGeneration{}, fmt.Errorf("%w: ACL secret material does not match reference", ErrInvalid)
		}
		rules, rulesErr := aclRules(user.Purpose)
		if rulesErr != nil {
			zeroBytes(secret)
			return RenderedGeneration{}, rulesErr
		}
		hash := strings.TrimPrefix(secretHash(secret), "sha256:")
		zeroBytes(secret)
		aclConfig.WriteString("user " + user.Name + " on resetpass #" + hash + " " + rules + "\n")
		secretRefs = append(secretRefs, user.SecretRef)
	}
	profile := spec.ResourceProfile
	var dropIn strings.Builder
	dropIn.WriteString("[Service]\n")
	dropIn.WriteString("UMask=0077\n")
	dropIn.WriteString("MemoryMax=" + strconv.FormatUint(profile.MemoryLimitBytes, 10) + "\n")
	dropIn.WriteString("CPUQuota=" + strconv.FormatUint(uint64(profile.CPUQuotaMilli/10), 10) + "%\n")
	dropIn.WriteString("LimitNOFILE=" + strconv.FormatUint(uint64(profile.FileLimit), 10) + "\n")
	dropIn.WriteString("IOWeight=" + strconv.FormatUint(uint64(profile.IOWeight), 10) + "\n")
	if redisConfig.Len() > MaxConfigBytes || aclConfig.Len() > MaxConfigBytes || dropIn.Len() > MaxConfigBytes {
		return RenderedGeneration{}, fmt.Errorf("%w: rendered generation exceeds bounds", ErrInvalid)
	}
	sort.Slice(secretRefs, func(i, j int) bool { return secretRefs[i].ID < secretRefs[j].ID })
	rendered := RenderedGeneration{
		InstanceID: spec.ID, ConfigGeneration: spec.ConfigGeneration,
		RedisConfig: []byte(redisConfig.String()), ACLConfig: []byte(aclConfig.String()), SystemdDropIn: []byte(dropIn.String()), SecretRefs: secretRefs,
	}
	rendered.ConfigDigest, err = digestValue(struct {
		InstanceID       InstanceID  `json:"instance_id"`
		ConfigGeneration uint64      `json:"config_generation"`
		RedisConfig      []byte      `json:"redis_config"`
		ACLConfig        []byte      `json:"acl_config"`
		SystemdDropIn    []byte      `json:"systemd_drop_in"`
	}{rendered.InstanceID, rendered.ConfigGeneration, rendered.RedisConfig, rendered.ACLConfig, rendered.SystemdDropIn})
	if err != nil {
		return RenderedGeneration{}, err
	}
	return rendered, nil
}

type PlanRequest struct {
	ID                     string
	Action                 PlanAction
	PlanGeneration         uint64
	Target                 InstanceSpec
	Current                *InstanceSpec
	Observed               InstanceObservation
	Consumers              ConsumerSnapshot
	Artifact               *ArtifactDescriptor
	Remap                  *RemapPlan
	RecoveryArtifactRef    string
	PackageInstalled       bool
	CreatedAt              time.Time
	TTL                    time.Duration
}

type Planner struct {
	support SupportCatalog
}

func validatePlanShape(plan LifecyclePlan) error {
	allowed := func(kinds ...StepKind) map[StepKind]bool {
		set := make(map[StepKind]bool, len(kinds))
		for _, kind := range kinds {
			set[kind] = true
		}
		return set
	}
	var permitted map[StepKind]bool
	switch plan.Action {
	case ActionApply:
		permitted = allowed(StepQualify, StepInstall, StepRender, StepStage, StepValidate, StepSwitchConfig, StepEnable, StepDisable, StepActivate, StepReload, StepRestart, StepStop, StepProbe)
		qualifyIndex := 0
		if plan.Steps[0].Kind == StepInstall {
			qualifyIndex = 1
		}
		if qualifyIndex >= len(plan.Steps) || plan.Steps[qualifyIndex].Kind != StepQualify || !plan.RequiresStepUp || plan.Artifact != nil || plan.Remap != nil {
			return fmt.Errorf("%w: invalid apply plan shape", ErrInvalid)
		}
	case ActionRemove:
		permitted = allowed(StepStop, StepDisable, StepRemovePackage)
		if plan.Steps[len(plan.Steps)-1].Kind != StepRemovePackage || !plan.RequiresMaintenance || !plan.RequiresStepUp || !plan.Recovery.Eligible || plan.Recovery.RecoveryArtifactRef == "" || plan.Artifact != nil || plan.Remap != nil {
			return fmt.Errorf("%w: invalid remove plan shape", ErrInvalid)
		}
		removeRank := map[StepKind]int{StepStop: 0, StepDisable: 1, StepRemovePackage: 2}
		lastRank := -1
		for _, step := range plan.Steps {
			if removeRank[step.Kind] < lastRank {
				return fmt.Errorf("%w: invalid remove ordering", ErrInvalid)
			}
			lastRank = removeRank[step.Kind]
		}
	case ActionBackup:
		permitted = allowed(StepBackupStream)
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != StepBackupStream || plan.RequiresMaintenance || plan.RequiresStepUp || plan.Artifact != nil || plan.Remap != nil {
			return fmt.Errorf("%w: invalid backup plan shape", ErrInvalid)
		}
	case ActionRestore:
		permitted = allowed(StepRestoreStage, StepRestoreVerify, StepStop, StepRestoreSwitch, StepActivate, StepProbe)
		if plan.Artifact == nil || !plan.RequiresMaintenance || !plan.RequiresStepUp || !plan.Recovery.Eligible || plan.Recovery.RecoveryArtifactRef == "" {
			return fmt.Errorf("%w: invalid restore plan shape", ErrInvalid)
		}
		expected := []StepKind{StepRestoreStage, StepRestoreVerify, StepRestoreSwitch, StepActivate, StepProbe}
		if len(plan.Steps) == 6 {
			expected = []StepKind{StepRestoreStage, StepRestoreVerify, StepStop, StepRestoreSwitch, StepActivate, StepProbe}
		}
		if len(plan.Steps) != len(expected) {
			return fmt.Errorf("%w: restore step cardinality", ErrInvalid)
		}
		for index, kind := range expected {
			if plan.Steps[index].Kind != kind {
				return fmt.Errorf("%w: restore ordering", ErrInvalid)
			}
		}
	default:
		return fmt.Errorf("%w: unknown plan action", ErrInvalid)
	}
	seen := make(map[StepKind]bool, len(plan.Steps))
	for _, step := range plan.Steps {
		if !permitted[step.Kind] || seen[step.Kind] {
			return fmt.Errorf("%w: duplicate or unsupported plan step", ErrInvalid)
		}
		seen[step.Kind] = true
		shouldBeIrreversible := step.Kind == StepInstall || step.Kind == StepRemovePackage || step.Kind == StepRestoreSwitch
		if step.Irreversible != shouldBeIrreversible {
			return fmt.Errorf("%w: step irreversible classification", ErrInvalid)
		}
	}
	if plan.Action == ActionApply {
		positions := make(map[StepKind]int, len(plan.Steps))
		for index, step := range plan.Steps {
			positions[step.Kind] = index
		}
		if installPosition, present := positions[StepInstall]; present && (installPosition != 0 || positions[StepQualify] != 1) {
			return fmt.Errorf("%w: package install ordering", ErrInvalid)
		}
		renderPosition, rendered := positions[StepRender]
		stagePosition, staged := positions[StepStage]
		validatePosition, validated := positions[StepValidate]
		if rendered != staged || staged != validated || (rendered && !(renderPosition < stagePosition && stagePosition < validatePosition)) {
			return fmt.Errorf("%w: render, stage, and validation ordering", ErrInvalid)
		}
		if probePosition, present := positions[StepProbe]; present && probePosition != len(plan.Steps)-1 {
			return fmt.Errorf("%w: health probe must be final", ErrInvalid)
		}
	}
	return nil
}

func NewPlanner(support SupportCatalog) (*Planner, error) {
	if support == nil {
		return nil, fmt.Errorf("%w: nil support catalog", ErrInvalid)
	}
	return &Planner{support: support}, nil
}

func sameNonACLConfig(left, right InstanceSpec) bool {
	left.ACLUsers = nil
	right.ACLUsers = nil
	left.DesiredLifecycle, right.DesiredLifecycle = "", ""
	left.Generation, right.Generation = 0, 0
	left.ConfigGeneration, right.ConfigGeneration = 0, 0
	left.Digest, right.Digest = "", ""
	left.UpdatedAt, right.UpdatedAt = time.Time{}, time.Time{}
	leftDigest, _ := digestValue(left)
	rightDigest, _ := digestValue(right)
	return leftDigest == rightDigest
}

func sameConfiguration(left, right InstanceSpec) bool {
	left.DesiredLifecycle, right.DesiredLifecycle = "", ""
	left.Generation, right.Generation = 0, 0
	left.ConfigGeneration, right.ConfigGeneration = 0, 0
	left.Digest, right.Digest = "", ""
	left.UpdatedAt, right.UpdatedAt = time.Time{}, time.Time{}
	leftDigest, _ := digestValue(left)
	rightDigest, _ := digestValue(right)
	return leftDigest == rightDigest
}

func validateConsumerSnapshot(snapshot ConsumerSnapshot, spec InstanceSpec, now time.Time) (ConsumerSnapshot, error) {
	sealed, err := SealConsumerSnapshot(snapshot)
	if err != nil || sealed.EvidenceDigest != snapshot.EvidenceDigest || snapshot.InstanceID != spec.ID || snapshot.ObservedAt.After(now) || now.Sub(snapshot.ObservedAt) > 5*time.Minute {
		return ConsumerSnapshot{}, fmt.Errorf("%w: recent complete consumer snapshot required", ErrStale)
	}
	users := make(map[string]bool, len(spec.ACLUsers))
	for _, user := range spec.ACLUsers {
		users[user.Name] = true
	}
	for _, consumer := range snapshot.Consumers {
		if consumer.Purpose != spec.Purpose || !users[consumer.ACLUser] || consumer.Database >= spec.Databases {
			return ConsumerSnapshot{}, fmt.Errorf("%w: consumer is outside instance purpose or database policy", ErrInvalid)
		}
	}
	return sealed, nil
}

func compatibleArtifact(spec InstanceSpec, artifact ArtifactDescriptor) error {
	if err := validateArtifact(artifact); err != nil {
		return err
	}
	if artifact.InstanceID != spec.ID || artifact.RedisVersion != spec.Support.RedisVersion {
		return fmt.Errorf("%w: artifact instance or Redis version differs", ErrUnsupported)
	}
	if spec.Persistence.AOF != AOFDisabled && artifact.Kind != ArtifactAOF {
		return fmt.Errorf("%w: AOF-enabled target requires AOF artifact", ErrUnsupported)
	}
	if spec.Persistence.AOF == AOFDisabled && artifact.Kind != ArtifactRDB {
		return fmt.Errorf("%w: RDB target requires RDB artifact", ErrUnsupported)
	}
	return nil
}

func (p *Planner) Build(ctx context.Context, request PlanRequest) (LifecyclePlan, error) {
	if !validID(request.ID) || !validGeneration(request.PlanGeneration) || request.CreatedAt.IsZero() || request.TTL <= 0 || request.TTL > 30*time.Minute {
		return LifecyclePlan{}, fmt.Errorf("%w: plan request metadata", ErrInvalid)
	}
	sealedTarget, err := SealInstanceSpec(request.Target)
	if err != nil || sealedTarget.Digest != request.Target.Digest {
		return LifecyclePlan{}, fmt.Errorf("%w: target spec digest", ErrInvalid)
	}
	if err := p.support.Qualify(ctx, request.Target.Support); err != nil {
		return LifecyclePlan{}, fmt.Errorf("%w: support tuple not qualified", ErrUnsupported)
	}
	sealedObserved, err := SealObservation(request.Observed)
	if err != nil || sealedObserved.EvidenceDigest != request.Observed.EvidenceDigest || request.Observed.InstanceID != request.Target.ID || request.Observed.NodeID != request.Target.NodeID {
		return LifecyclePlan{}, fmt.Errorf("%w: observed state binding", ErrStale)
	}
	if request.Current != nil {
		sealedCurrent, sealErr := SealInstanceSpec(*request.Current)
		expectedGeneration := request.Current.Generation
		if request.Action == ActionApply || request.Action == ActionRemove {
			if expectedGeneration == MaxGeneration {
				return LifecyclePlan{}, fmt.Errorf("%w: instance generation exhausted", ErrConflict)
			}
			expectedGeneration++
		}
		expectedConfigGeneration := request.Current.ConfigGeneration
		if request.Action == ActionApply && !sameConfiguration(*request.Current, request.Target) {
			if expectedConfigGeneration == MaxGeneration {
				return LifecyclePlan{}, fmt.Errorf("%w: config generation exhausted", ErrConflict)
			}
			expectedConfigGeneration++
		}
		if sealErr != nil || sealedCurrent.Digest != request.Current.Digest || request.Current.ID != request.Target.ID || request.Current.NodeID != request.Target.NodeID || request.Target.Generation != expectedGeneration || request.Target.ConfigGeneration != expectedConfigGeneration {
			return LifecyclePlan{}, fmt.Errorf("%w: current and target generation binding", ErrStale)
		}
		if (request.Action == ActionBackup || request.Action == ActionRestore) && request.Target.Digest != request.Current.Digest {
			return LifecyclePlan{}, fmt.Errorf("%w: read/data operation cannot change desired spec", ErrInvalid)
		}
	} else if request.Action != ActionApply || request.Target.Generation != 1 || request.Target.ConfigGeneration != 1 {
		return LifecyclePlan{}, fmt.Errorf("%w: only apply may create first instance generation", ErrStale)
	}
	if request.Action == ActionRemove && request.Target.DesiredLifecycle != LifecycleRemoved {
		return LifecyclePlan{}, fmt.Errorf("%w: removal target lifecycle", ErrInvalid)
	}
	if request.Action != ActionRemove && request.Target.DesiredLifecycle == LifecycleRemoved {
		return LifecyclePlan{}, fmt.Errorf("%w: removed target cannot serve this action", ErrInvalid)
	}
	consumerRequired := request.Action == ActionRemove || request.Action == ActionRestore || (request.Action == ActionApply && request.Observed.Lifecycle == LifecycleRunning)
	var consumers ConsumerSnapshot
	if consumerRequired {
		consumers, err = validateConsumerSnapshot(request.Consumers, request.Target, request.CreatedAt)
		if err != nil {
			return LifecyclePlan{}, err
		}
	} else if request.Consumers.Generation != 0 || len(request.Consumers.Consumers) != 0 || request.Consumers.EvidenceDigest != "" {
		return LifecyclePlan{}, fmt.Errorf("%w: consumer snapshot not used by action", ErrInvalid)
	}
	plan := LifecyclePlan{
		ID: request.ID, InstanceID: request.Target.ID, NodeID: request.Target.NodeID, Action: request.Action,
		Generation: request.PlanGeneration, ExpectedSpecGeneration: request.Target.Generation,
		ExpectedObservedGeneration: request.Observed.Generation, ExpectedConfigGeneration: request.Observed.ConfigGeneration,
		TargetSpecDigest: request.Target.Digest, RequiresStepUp: true, IrreversibleFrontier: -1,
		CreatedAt: request.CreatedAt.UTC(), ExpiresAt: request.CreatedAt.UTC().Add(request.TTL),
	}
	if consumerRequired {
		plan.ConsumerSnapshotGeneration = consumers.Generation
		plan.ConsumerSnapshotDigest = consumers.EvidenceDigest
	}
	appendStep := func(kind StepKind, irreversible bool, recovery string) {
		step := PlanStep{Index: len(plan.Steps), Kind: kind, Irreversible: irreversible, Recovery: recovery}
		if irreversible && plan.IrreversibleFrontier < 0 {
			plan.IrreversibleFrontier = step.Index
		}
		plan.Steps = append(plan.Steps, step)
	}
	activeConsumers := make([]Consumer, 0, len(consumers.Consumers))
	for _, consumer := range consumers.Consumers {
		if consumer.Active {
			activeConsumers = append(activeConsumers, consumer)
		}
	}
	switch request.Action {
	case ActionApply:
		if !request.PackageInstalled {
			appendStep(StepInstall, true, "package-maintenance recovery")
		}
		appendStep(StepQualify, false, "none")
		configurationChanged := request.Current == nil || !sameConfiguration(*request.Current, request.Target)
		if configurationChanged {
			appendStep(StepRender, false, "discard staged generation")
			appendStep(StepStage, false, "discard staged generation")
			appendStep(StepValidate, false, "discard staged generation")
		}
		wantRunning := request.Target.DesiredLifecycle == LifecycleRunning
		wantEnabled := request.Target.DesiredLifecycle == LifecycleRunning || request.Target.DesiredLifecycle == LifecycleStopped
		wasRunning := request.Observed.Lifecycle == LifecycleRunning
		if wantEnabled && !request.Observed.Enabled {
			appendStep(StepEnable, false, "restore prior unit enablement")
		}
		if !wantEnabled && request.Observed.Enabled {
			appendStep(StepDisable, false, "restore prior unit enablement")
		}
		if wantRunning {
			if wasRunning && configurationChanged {
				plan.RequiresMaintenance = true
				if request.Current != nil && sameNonACLConfig(*request.Current, request.Target) {
					appendStep(StepReload, false, "restore prior generation and reload")
				} else {
					appendStep(StepRestart, false, "restore prior generation and restart")
				}
			} else if !wasRunning {
				appendStep(StepActivate, false, "restore prior service state")
			}
			appendStep(StepProbe, false, "rollback generation and service state")
		} else {
			if wasRunning {
				plan.RequiresMaintenance = true
				appendStep(StepStop, false, "restore prior generation and restart")
			}
			if configurationChanged {
				appendStep(StepSwitchConfig, false, "restore prior generation")
			}
		}
		if plan.RequiresMaintenance {
			for _, consumer := range activeConsumers {
				plan.Impacts = append(plan.Impacts, Impact{ConsumerID: consumer.ID, Kind: "consumer", Availability: "bounded interruption", Reason: "configuration or lifecycle activation"})
			}
		}
		plan.Recovery = RecoveryPlan{Eligible: request.Observed.ActualConfigDigest != "", PriorConfigGeneration: request.Observed.ConfigGeneration, PriorConfigDigest: request.Observed.ActualConfigDigest, Reason: "prior immutable generation"}
	case ActionRemove:
		if len(consumers.Consumers) != 0 {
			return LifecyclePlan{}, ErrConsumersPresent
		}
		if request.RecoveryArtifactRef == "" {
			return LifecyclePlan{}, fmt.Errorf("%w: removal requires an immutable recovery artifact", ErrInvalid)
		}
		plan.RequiresMaintenance = true
		if request.Observed.Lifecycle == LifecycleRunning {
			appendStep(StepStop, false, "restart prior generation")
		}
		if request.Observed.Enabled {
			appendStep(StepDisable, false, "restore prior unit enablement")
		}
		appendStep(StepRemovePackage, true, "restore from package and recovery artifact")
		plan.Recovery = RecoveryPlan{Eligible: true, PriorConfigGeneration: request.Observed.ConfigGeneration, PriorConfigDigest: request.Observed.ActualConfigDigest, RecoveryArtifactRef: request.RecoveryArtifactRef, Reason: "explicit recovery artifact required after removal"}
	case ActionBackup:
		if request.Target.Persistence.RDB == RDBDisabled && request.Target.Persistence.AOF == AOFDisabled {
			return LifecyclePlan{}, fmt.Errorf("%w: no persistent data to back up", ErrUnsupported)
		}
		if request.Observed.Lifecycle != LifecycleRunning || request.Observed.Health != HealthHealthy {
			return LifecyclePlan{}, fmt.Errorf("%w: backup source is not healthy and running", ErrStale)
		}
		appendStep(StepBackupStream, false, "discard incomplete artifact")
		plan.RequiresStepUp = false
		plan.Recovery = RecoveryPlan{Eligible: true, PriorConfigGeneration: request.Observed.ConfigGeneration, PriorConfigDigest: request.Observed.ActualConfigDigest, Reason: "read-only backup"}
	case ActionRestore:
		if request.Artifact == nil {
			return LifecyclePlan{}, fmt.Errorf("%w: restore artifact required", ErrInvalid)
		}
		if err := compatibleArtifact(request.Target, *request.Artifact); err != nil {
			return LifecyclePlan{}, err
		}
		plan.Artifact = request.Artifact
		if len(activeConsumers) != 0 {
			if request.Remap == nil {
				return LifecyclePlan{}, ErrConsumersPresent
			}
			sealedRemap, remapErr := SealRemapPlan(*request.Remap)
			if remapErr != nil || sealedRemap.Digest != request.Remap.Digest || request.Remap.SourceInstanceID != request.Target.ID || request.Remap.Generation != consumers.Generation {
				return LifecyclePlan{}, fmt.Errorf("%w: invalid consumer remap", ErrInvalid)
			}
			expectedIDs := make([]string, 0, len(activeConsumers))
			for _, consumer := range activeConsumers {
				expectedIDs = append(expectedIDs, consumer.ID)
			}
			sort.Strings(expectedIDs)
			if strings.Join(expectedIDs, "\x00") != strings.Join(sealedRemap.ConsumerIDs, "\x00") {
				return LifecyclePlan{}, fmt.Errorf("%w: remap does not cover every live consumer", ErrConsumersPresent)
			}
			plan.Remap = request.Remap
		}
		if request.RecoveryArtifactRef == "" || request.RecoveryArtifactRef == request.Artifact.ID {
			return LifecyclePlan{}, fmt.Errorf("%w: restore requires pre-restore recovery artifact", ErrInvalid)
		}
		plan.RequiresMaintenance = true
		appendStep(StepRestoreStage, false, "discard isolated restore staging")
		appendStep(StepRestoreVerify, false, "discard isolated restore staging")
		if request.Observed.Lifecycle == LifecycleRunning {
			appendStep(StepStop, false, "restart unchanged live dataset")
		}
		appendStep(StepRestoreSwitch, true, "restore pre-restore recovery artifact")
		appendStep(StepActivate, false, "restore pre-restore dataset")
		appendStep(StepProbe, false, "restore pre-restore dataset and restart")
		plan.Recovery = RecoveryPlan{Eligible: true, PriorConfigGeneration: request.Observed.ConfigGeneration, PriorConfigDigest: request.Observed.ActualConfigDigest, RecoveryArtifactRef: request.RecoveryArtifactRef, Reason: "required pre-restore recovery artifact"}
		for _, consumer := range activeConsumers {
			plan.Impacts = append(plan.Impacts, Impact{ConsumerID: consumer.ID, Kind: "remapped_consumer", Availability: "remapped before restore", Reason: "live dataset is never overwritten while consumer remains attached"})
		}
	default:
		return LifecyclePlan{}, fmt.Errorf("%w: plan action", ErrUnsupported)
	}
	return SealLifecyclePlan(plan)
}
