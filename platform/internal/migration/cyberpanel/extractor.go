package cyberpanel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type ExtractorConfig struct {
	SourceKind migration.SourceKind
	PlanStore PlanStore
	PlanVerifier PlanVerifier
	Collector Collector
	Artifacts ArtifactCatalog
	Secrets SecretSource
	Sealer SecretSealer
	Chunks *migration.ChunkStore
	SigningKeyID string
	SigningKey ed25519.PrivateKey
	ExtractorVersion string
	Clock func() time.Time
}

type Extractor struct {
	sourceKind migration.SourceKind
	plans PlanStore
	verifier PlanVerifier
	collector Collector
	artifacts ArtifactCatalog
	secrets SecretSource
	sealer SecretSealer
	chunks *migration.ChunkStore
	signingKeyID string
	signingKey ed25519.PrivateKey
	version string
	clock func() time.Time
	operationMu sync.Mutex
	mu sync.RWMutex
	allowedChunks map[string]allowedChunk
}

type allowedChunk struct { descriptor migration.Chunk; approvals map[migration.ID]string }
const maximumMigrationSecretBytes=900<<10

func NewExtractor(config ExtractorConfig) (*Extractor, error) {
	if config.PlanStore == nil || config.PlanVerifier == nil || config.Collector == nil || config.Artifacts == nil || config.Chunks == nil || !validKeyID(config.SigningKeyID) || len(config.SigningKey) != ed25519.PrivateKeySize || strings.TrimSpace(config.ExtractorVersion) == "" {
		return nil, ErrInvalid
	}
	if (config.Secrets == nil) != (config.Sealer == nil) {
		return nil, ErrInvalid
	}
	if config.SourceKind == "" { config.SourceKind = migration.SourceCyberPanel }
	if config.SourceKind != migration.SourceCyberPanel && config.SourceKind != migration.SourceCPanel { return nil, ErrInvalid }
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Extractor{
		sourceKind: config.SourceKind,
		plans: config.PlanStore,
		verifier: config.PlanVerifier,
		collector: config.Collector,
		artifacts: config.Artifacts,
		secrets: config.Secrets,
		sealer: config.Sealer,
		chunks: config.Chunks,
		signingKeyID: config.SigningKeyID,
		signingKey: append(ed25519.PrivateKey(nil), config.SigningKey...),
		version: config.ExtractorVersion,
		clock: config.Clock,
		allowedChunks: map[string]allowedChunk{},
	}, nil
}

func(e *Extractor)Close()error{if e==nil{return nil};e.operationMu.Lock();defer e.operationMu.Unlock();e.mu.Lock();defer e.mu.Unlock();wipe(e.signingKey);e.signingKey=nil;clear(e.allowedChunks);return nil}

func (e *Extractor) Discover(ctx context.Context, migrationID migration.ID) (migration.Manifest, error) {
	if e == nil || ctx == nil || !migrationID.Valid() {
		return migration.Manifest{}, ErrInvalid
	}
	e.operationMu.Lock()
	defer e.operationMu.Unlock()
	approved, snapshot, descriptors, secretDigests, generation, err := e.inventory(ctx, migrationID)
	if err != nil {
		return migration.Manifest{}, err
	}
	for artifactID, descriptor := range descriptors {
		reader, openErr := e.artifacts.Open(ctx, artifactID)
		if openErr != nil {
			return migration.Manifest{}, openErr
		}
		putErr := e.chunks.Put(ctx, descriptor, reader)
		closeErr := reader.Close()
		if putErr != nil {
			return migration.Manifest{}, errors.Join(ErrChanged, putErr, closeErr)
		}
		if closeErr != nil {
			return migration.Manifest{}, closeErr
		}
	}
	secretEnvelopes, secretIDs, err := e.sealSecrets(ctx, approved.Plan, snapshot,secretDigests)
	if err != nil {
		return migration.Manifest{}, err
	}
	manifest, err := e.manifest(approved.Plan, snapshot, descriptors, secretEnvelopes, secretIDs, generation)
	if err != nil {
		return migration.Manifest{}, err
	}
	manifest, err = migration.SignManifest(manifest, e.signingKeyID, e.signingKey)
	if err != nil {
		return migration.Manifest{}, err
	}
	approvalDigest,err:=approvedPlanDigest(approved)
	if err!=nil{return migration.Manifest{},err}
	e.mu.Lock()
	for _, descriptor := range manifest.Chunks {
		allowed:=e.allowedChunks[descriptor.Digest]
		if allowed.approvals==nil{allowed=allowedChunk{descriptor:descriptor,approvals:map[migration.ID]string{}}}
		if allowed.descriptor!=descriptor{e.mu.Unlock();return migration.Manifest{},ErrChanged}
		allowed.approvals[manifest.MigrationID]=approvalDigest
		e.allowedChunks[descriptor.Digest]=allowed
	}
	e.mu.Unlock()
	return manifest, nil
}

func (e *Extractor) OpenChunk(ctx context.Context, digest string, offset, length uint64) ([]byte, error) {
	if e == nil || ctx == nil || !isDigest(digest) || length == 0 {
		return nil, ErrInvalid
	}
	e.mu.RLock()
	allowedChunk, allowed := e.allowedChunks[digest]
	approvals:=make(map[migration.ID]string,len(allowedChunk.approvals))
	for migrationID,approvalDigest:=range allowedChunk.approvals{approvals[migrationID]=approvalDigest}
	e.mu.RUnlock()
	if !allowed || offset > allowedChunk.descriptor.Size || length > allowedChunk.descriptor.Size-offset {
		return nil, ErrDenied
	}
	approved:=false
	for migrationID,approvalDigest:=range approvals{
		if err:=e.approvedChunkScope(ctx,migrationID,approvalDigest);err==nil{approved=true;break}else if errors.Is(err,context.Canceled)||errors.Is(err,context.DeadlineExceeded){return nil,err}
	}
	if !approved{return nil,ErrDenied}
	return e.chunks.ReadRange(ctx, digest, offset, length)
}

func(e *Extractor)OpenChunkForMigration(ctx context.Context,migrationID migration.ID,digest string,offset,length uint64)([]byte,error){if e==nil||ctx==nil||!migrationID.Valid()||!isDigest(digest)||length==0{return nil,ErrInvalid};e.mu.RLock();allowed,exists:=e.allowedChunks[digest];approvalDigest,scoped:=allowed.approvals[migrationID];e.mu.RUnlock();if !exists||!scoped||offset>allowed.descriptor.Size||length>allowed.descriptor.Size-offset{return nil,ErrDenied};if err:=e.approvedChunkScope(ctx,migrationID,approvalDigest);err!=nil{return nil,err};return e.chunks.ReadRange(ctx,digest,offset,length)}

func(e *Extractor)approvedChunkScope(ctx context.Context,migrationID migration.ID,expectedDigest string)error{approved,err:=e.plans.ApprovedPlan(ctx,migrationID);if err!=nil{return err};if approved.Plan.MigrationID!=migrationID{return ErrDenied};if err:=e.verifier.VerifyApprovedPlan(ctx,approved,e.clock().UTC());err!=nil{return err};digest,err:=approvedPlanDigest(approved);if err!=nil{return err};if digest!=expectedDigest{return ErrDenied};return nil}

func (e *Extractor) Generation(ctx context.Context, migrationID migration.ID) (uint64, error) {
	if e == nil || ctx == nil || !migrationID.Valid() {
		return 0, ErrInvalid
	}
	e.operationMu.Lock()
	defer e.operationMu.Unlock()
	_, _, _, _, generation, err := e.inventory(ctx, migrationID)
	return generation, err
}

func (e *Extractor) inventory(ctx context.Context, migrationID migration.ID) (ApprovedPlan, Snapshot, map[ArtifactID]migration.Chunk, map[SecretRef]string,uint64, error) {
	approved, err := e.plans.ApprovedPlan(ctx, migrationID)
	if err != nil {
		return ApprovedPlan{}, Snapshot{}, nil,nil, 0, err
	}
	now := e.clock().UTC()
	if err := e.verifier.VerifyApprovedPlan(ctx, approved, now); err != nil {
		return ApprovedPlan{}, Snapshot{}, nil,nil, 0, err
	}
	request := CollectRequest{MigrationID: migrationID, SiteSourceIDs: append([]string(nil), approved.Plan.SiteSourceIDs...), Selection: approved.Plan.Selection}
	snapshot, err := e.collector.Collect(ctx, request)
	if err != nil {
		return ApprovedPlan{}, Snapshot{}, nil,nil, 0, err
	}
	if err := snapshot.validate(approved.Plan); err != nil {
		return ApprovedPlan{}, Snapshot{}, nil,nil, 0, err
	}
	descriptors := make(map[ArtifactID]migration.Chunk)
	digests := make(map[string]migration.Chunk)
	for _, artifactID := range snapshot.artifactIDs(approved.Plan) {
		descriptor, describeErr := e.artifacts.Describe(ctx, artifactID)
		if describeErr != nil {
			return ApprovedPlan{}, Snapshot{}, nil,nil, 0, describeErr
		}
		if !validChunk(descriptor) {
			return ApprovedPlan{}, Snapshot{}, nil,nil, 0, ErrInvalid
		}
		if existing, exists := digests[descriptor.Digest]; exists && existing != descriptor {
			return ApprovedPlan{}, Snapshot{}, nil,nil, 0, ErrChanged
		}
		descriptors[artifactID] = descriptor
		digests[descriptor.Digest] = descriptor
	}
	secretDigests:=map[SecretRef]string{}
	materials:=snapshot.secrets(approved.Plan)
	for _,material:=range materials{
		if e.secrets==nil{if resettableCredentialPurpose(material.Purpose){continue};return ApprovedPlan{},Snapshot{},nil,nil,0,ErrDenied}
		plaintext,readErr:=e.secrets.ReadSecret(ctx,material.Ref)
		if readErr!=nil{if resettableCredentialPurpose(material.Purpose)&&(errors.Is(readErr,migration.ErrNotFound)||errors.Is(readErr,ErrDenied)){continue};return ApprovedPlan{},Snapshot{},nil,nil,0,readErr}
		if len(plaintext)==0||len(plaintext)>maximumMigrationSecretBytes{wipe(plaintext);return ApprovedPlan{},Snapshot{},nil,nil,0,ErrInvalid}
		secretDigests[material.Ref]=digestBytes(plaintext)
		wipe(plaintext)
	}
	generation, err := sourceGeneration(snapshot, descriptors,secretDigests)
	if err != nil {
		return ApprovedPlan{}, Snapshot{}, nil,nil, 0, err
	}
	return approved, snapshot, descriptors,secretDigests, generation, nil
}

func (e *Extractor) sealSecrets(ctx context.Context, plan SourcePlan, snapshot Snapshot,expectedDigests map[SecretRef]string) ([]migration.SecretEnvelope, map[SecretRef]string, error) {
	materials := snapshot.secrets(plan)
	if len(materials) == 0 || len(expectedDigests) == 0 {
		return nil, map[SecretRef]string{}, nil
	}
	if e.secrets == nil || e.sealer == nil {
		return nil, nil, ErrDenied
	}
	envelopes := make([]migration.SecretEnvelope, 0, len(materials))
	secretIDs := make(map[SecretRef]string, len(materials))
	for _, material := range materials {
		expectedDigest,available:=expectedDigests[material.Ref]
		if !available{continue}
		material.AudienceDigest = audienceDigest(plan, material)
		plaintext, err := e.secrets.ReadSecret(ctx, material.Ref)
		if err != nil {
			if resettableCredentialPurpose(material.Purpose)&&(errors.Is(err,migration.ErrNotFound)||errors.Is(err,ErrDenied)){return nil,nil,ErrChanged}
			return nil, nil, err
		}
		if len(plaintext) == 0 || len(plaintext) > maximumMigrationSecretBytes {
			wipe(plaintext)
			return nil, nil, ErrInvalid
		}
		if digestBytes(plaintext)!=expectedDigest{wipe(plaintext);return nil,nil,ErrChanged}
		envelope, sealErr := e.sealer.Seal(ctx, plan.MigrationID, material, plaintext)
		wipe(plaintext)
		if sealErr != nil {
			return nil, nil, sealErr
		}
		if envelope.SecretID == "" || envelope.Purpose != material.Purpose || envelope.AudienceDigest != material.AudienceDigest || envelope.Algorithm == "" || envelope.KeyID == "" || envelope.Version == 0 || len(envelope.Ciphertext) == 0 {
			return nil, nil, ErrInvalid
		}
		if _, duplicate := secretIDs[material.Ref]; duplicate {
			return nil, nil, ErrInvalid
		}
		secretIDs[material.Ref] = envelope.SecretID
		envelopes = append(envelopes, envelope)
	}
	return envelopes, secretIDs, nil
}

func (e *Extractor) manifest(plan SourcePlan, snapshot Snapshot, descriptors map[ArtifactID]migration.Chunk, secrets []migration.SecretEnvelope, secretIDs map[SecretRef]string, generation uint64) (migration.Manifest, error) {
	manifest := migration.Manifest{
		SchemaVersion: 1,
		MigrationID: plan.MigrationID,
		Source: e.sourceKind,
		SourceInstallationID: snapshot.InstallationID,
		TargetInstallationID: plan.TargetInstallationID,
		SourceGeneration: generation,
		CreatedAt: e.clock().UTC(),
		SchemaHash: plan.SchemaHash,
		Secrets: secrets,
	}
	chunksByDigest := make(map[string]migration.Chunk, len(descriptors))
	for _, descriptor := range descriptors { chunksByDigest[descriptor.Digest] = descriptor }
	for _, descriptor := range chunksByDigest { manifest.Chunks = append(manifest.Chunks, descriptor) }
	provenance := func(kind, sourceID string) []migration.Provenance {
		return []migration.Provenance{{SourceKind: string(e.sourceKind), SourceLocation: string(e.sourceKind)+":"+kind+":"+sourceID, ExtractorVersion: e.version, ObservedAt: snapshot.ObservedAt.UTC(), Digest: digestText(snapshot.Revision+"\x00"+kind+"\x00"+sourceID), Confidence: "authoritative", Authoritative: true}}
	}
	if plan.Selection.Sites {
		databaseIDs := idsBySite(snapshot.Databases, func(value DatabaseRecord) string { return value.SiteSourceID }, func(value DatabaseRecord) migration.ID { return mappedID("db", value.SourceID) })
		mailIDs := idsBySite(snapshot.MailDomains, func(value MailDomainRecord) string { return value.SiteSourceID }, func(value MailDomainRecord) migration.ID { return mappedID("mail", value.SourceID) })
		credentialIDs := idsBySite(snapshot.Credentials, func(value CredentialRecord) string { return value.SiteSourceID }, func(value CredentialRecord) migration.ID { return mappedID("cred", value.SourceID) })
		cronIDs := idsBySite(snapshot.Schedules, func(value ScheduleRecord) string { return value.SiteSourceID }, func(value ScheduleRecord) migration.ID { return mappedID("cron", value.SourceID) })
		repositoryIDs := idsBySite(snapshot.Repositories, func(value RepositoryRecord) string { return value.SiteSourceID }, func(value RepositoryRecord) migration.ID { return mappedID("repo", value.SourceID) })
		containerIDs := idsBySite(snapshot.Containers, func(value ContainerRecord) string { return value.SiteSourceID }, func(value ContainerRecord) migration.ID { return mappedID("app", value.SourceID) })
		for _, value := range snapshot.Sites {
			runtimeKind := value.RuntimeKind
			if runtimeKind == "" { runtimeKind = "php_lsapi" }
			site := migration.Site{
				SourceID: mappedID("site", value.SourceID),
				PrimaryHostname: normalizeHostname(value.PrimaryHostname),
				Aliases: normalizedHostnames(value.Aliases),
				Redirects: append([]string(nil), value.Redirects...),
				Children: normalizedHostnames(value.ChildHostnames),
				PHPVersion: value.PHPVersion,
				DocumentRootRelative: value.DocumentRootRelative,
				RuntimeKind: runtimeKind,
				ResourceProfile: map[string]uint64{"disk_bytes": value.DiskBytes, "transfer_bytes": value.TransferBytes, "memory_bytes": value.MemoryBytes, "cpu_milli": value.CPUMilli, "io_bytes_per_second": value.IOBytesPerSecond, "max_connections": value.MaxConnections,"enabled":boolUint64(value.Enabled)},
				DatabaseIDs: databaseIDs[value.SourceID],
				MailDomainIDs: mailIDs[value.SourceID],
				CredentialIDs: credentialIDs[value.SourceID],
				CronIDs: cronIDs[value.SourceID],
				RepositoryIDs: repositoryIDs[value.SourceID],
				ContainerApplicationIDs: containerIDs[value.SourceID],
				Provenance: provenance("site", value.SourceID),
			}
			if descriptor, exists := descriptors[value.ContentArtifact]; exists { site.Content = []migration.Chunk{descriptor} }
			manifest.Sites = append(manifest.Sites, site)
		}
	}
	if plan.Selection.Databases {
		for _, value := range snapshot.Databases {
			database := migration.Database{SourceID: mappedID("db", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), Name: value.Name, Charset: value.Charset, Collation: value.Collation, Provenance: provenance("database", value.SourceID)}
			if descriptor, exists := descriptors[value.DumpArtifact]; exists { database.Dump = []migration.Chunk{descriptor} }
			for _, principal := range value.Principals {
				secretID:=secretIDs[principal.Password]
				disposition:=migration.CredentialResetRequired
				if secretID!=""{disposition=migration.CredentialPreserved}
				database.Principals = append(database.Principals, migration.DatabasePrincipal{Name: principal.Name, GrantSets: append([]string(nil), principal.GrantSets...), SecretID: secretID,CredentialDisposition:disposition})
			}
			manifest.Databases = append(manifest.Databases, database)
		}
	}
	if plan.Selection.DNS {
		for _, value := range snapshot.DNSZones {
			zone := migration.DNSZone{SourceID: mappedID("dns", value.SourceID), Name: normalizeHostname(value.Name), Mode: value.Mode, DNSSEC: value.DNSSEC, Provenance: provenance("dns-zone", value.SourceID)}
			for _, recordSet := range value.RecordSets { zone.RecordSets = append(zone.RecordSets, migration.DNSRecordSet{Name: normalizeDNSName(recordSet.Name), Type: strings.ToUpper(recordSet.Type), TTL: recordSet.TTL, Values: append([]string(nil), recordSet.Values...)}) }
			manifest.DNSZones = append(manifest.DNSZones, zone)
		}
	}
	if plan.Selection.Mail {
		for _, value := range snapshot.MailDomains {
			domain := migration.MailDomain{SourceID: mappedID("mail", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), Name: normalizeHostname(value.Name), Aliases: append([]string(nil), value.Aliases...), Forwarders: append([]string(nil), value.Forwarders...), CatchAll: append([]string(nil), value.CatchAll...), DKIMSecretID: secretIDs[value.DKIMPrivateKey], Provenance: provenance("mail-domain", value.SourceID)}
			for _, mailboxValue := range value.Mailboxes {
				secretID:=secretIDs[mailboxValue.Password]
				disposition:=migration.CredentialResetRequired
				if secretID!=""{disposition=migration.CredentialPreserved}
				mailbox := migration.Mailbox{SourceID: mappedID("mbx", mailboxValue.SourceID), Address: strings.ToLower(mailboxValue.Address), QuotaBytes: mailboxValue.QuotaBytes, CredentialSecretID: secretID,CredentialDisposition:disposition}
				if descriptor, exists := descriptors[mailboxValue.DataArtifact]; exists { mailbox.Data = []migration.Chunk{descriptor} }
				domain.Mailboxes = append(domain.Mailboxes, mailbox)
			}
			manifest.MailDomains = append(manifest.MailDomains, domain)
		}
	}
	if plan.Selection.Certificates {
		for _, value := range snapshot.Certificates {
			certificate := migration.Certificate{SourceID: mappedID("cert", value.SourceID), Names: normalizedHostnames(value.Names), PrivateKeySecretID: secretIDs[value.PrivateKey], Issuer: value.Issuer, NotAfter: value.NotAfter, Provenance: provenance("certificate", value.SourceID)}
			if descriptor, exists := descriptors[value.CertificateArtifact]; exists { certificate.Certificate = []migration.Chunk{descriptor} }
			if descriptor, exists := descriptors[value.ChainArtifact]; exists { certificate.Chain = []migration.Chunk{descriptor} }
			manifest.Certificates = append(manifest.Certificates, certificate)
		}
	}
	if plan.Selection.Credentials {
		for _, value := range snapshot.Credentials {
			secretID:=secretIDs[value.Secret]
			disposition:=migration.CredentialResetRequired
			if secretID!=""{disposition=migration.CredentialPreserved}else if strings.TrimSpace(value.PublicKey)!=""{disposition=migration.CredentialPublicOnly}
			manifest.Credentials = append(manifest.Credentials, migration.AccessCredential{SourceID: mappedID("cred", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), Kind: value.Kind, Label: value.Label, RootRelative: value.RootRelative, PublicKey: value.PublicKey, SecretID: secretID,CredentialDisposition:disposition, Provenance: provenance("credential", value.SourceID)})
		}
	}
	if plan.Selection.Schedules {
		for _, value := range snapshot.Schedules { manifest.Schedules = append(manifest.Schedules, migration.Schedule{SourceID: mappedID("cron", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), Kind: value.Kind, Expression: value.Expression, Timezone: value.Timezone, InvocationID: value.InvocationID, Enabled: value.Enabled, Provenance: provenance("schedule", value.SourceID)}) }
	}
	if plan.Selection.Repositories {
		for _, value := range snapshot.Repositories { manifest.Repositories = append(manifest.Repositories, migration.RepositoryBinding{SourceID: mappedID("repo", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), Provider: value.Provider, Origin: value.Origin, Branch: value.Branch, CredentialSecretID: secretIDs[value.Credential], AutoDeploy: value.AutoDeploy, Provenance: provenance("repository", value.SourceID)}) }
	}
	if plan.Selection.Containers {
		for _, value := range snapshot.Containers {
			container := migration.ContainerApplication{SourceID: mappedID("app", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), RecipeID: value.RecipeID, RecipeVersion: value.RecipeVersion, Provenance: provenance("container", value.SourceID)}
			if descriptor, exists := descriptors[value.DescriptorArtifact]; exists { container.Descriptor = []migration.Chunk{descriptor} }
			for _, artifact := range value.VolumeArtifacts { if descriptor, exists := descriptors[artifact]; exists { container.VolumeData = append(container.VolumeData, descriptor) } }
			for _, secret := range value.Secrets { if id := secretIDs[secret]; id != "" { container.SecretIDs = append(container.SecretIDs, id) } }
			manifest.Containers = append(manifest.Containers, container)
		}
	}
	if plan.Selection.BackupPolicies {
		for _, value := range snapshot.BackupPolicies { manifest.BackupPolicies = append(manifest.BackupPolicies, migration.BackupPolicy{SourceID: mappedID("backup", value.SourceID), SiteID: mappedID("site", value.SiteSourceID), Schedule: value.Schedule, Retention: value.Retention, Provider: value.Provider, Repository: value.Repository, CredentialSecretID: secretIDs[value.Credential], Provenance: provenance("backup-policy", value.SourceID)}) }
	}
	return manifest, nil
}

func sourceGeneration(snapshot Snapshot, descriptors map[ArtifactID]migration.Chunk,secretDigests map[SecretRef]string) (uint64, error) {
	stable := snapshot
	stable.ObservedAt = time.Time{}
	normalizeSnapshot(&stable)
	artifacts := make([]struct{ ID ArtifactID; Chunk migration.Chunk }, 0, len(descriptors))
	for id, descriptor := range descriptors { artifacts = append(artifacts, struct{ ID ArtifactID; Chunk migration.Chunk }{ID: id, Chunk: descriptor}) }
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].ID < artifacts[j].ID })
	type stableSecret struct{Ref SecretRef;Digest string};secrets:=make([]stableSecret,0,len(secretDigests));for ref,digest:=range secretDigests{secrets=append(secrets,stableSecret{Ref:ref,Digest:digest})};sort.Slice(secrets,func(i,j int)bool{return secrets[i].Ref<secrets[j].Ref})
	raw, err := json.Marshal(struct{ Snapshot Snapshot; Artifacts any;Secrets any }{Snapshot: stable, Artifacts: artifacts,Secrets:secrets})
	if err != nil { return 0, err }
	sum := sha256.Sum256(raw)
	generation := binary.BigEndian.Uint64(sum[:8])
	if generation == 0 { generation = 1 }
	return generation, nil
}

func normalizeSnapshot(snapshot *Snapshot) {
	sort.Slice(snapshot.Sites, func(i, j int) bool { return snapshot.Sites[i].SourceID < snapshot.Sites[j].SourceID })
	sort.Slice(snapshot.Databases, func(i, j int) bool { return snapshot.Databases[i].SourceID < snapshot.Databases[j].SourceID })
	sort.Slice(snapshot.DNSZones, func(i, j int) bool { return snapshot.DNSZones[i].SourceID < snapshot.DNSZones[j].SourceID })
	sort.Slice(snapshot.MailDomains, func(i, j int) bool { return snapshot.MailDomains[i].SourceID < snapshot.MailDomains[j].SourceID })
	sort.Slice(snapshot.Certificates, func(i, j int) bool { return snapshot.Certificates[i].SourceID < snapshot.Certificates[j].SourceID })
	sort.Slice(snapshot.Credentials, func(i, j int) bool { return snapshot.Credentials[i].SourceID < snapshot.Credentials[j].SourceID })
	sort.Slice(snapshot.Schedules, func(i, j int) bool { return snapshot.Schedules[i].SourceID < snapshot.Schedules[j].SourceID })
	sort.Slice(snapshot.Repositories, func(i, j int) bool { return snapshot.Repositories[i].SourceID < snapshot.Repositories[j].SourceID })
	sort.Slice(snapshot.Containers, func(i, j int) bool { return snapshot.Containers[i].SourceID < snapshot.Containers[j].SourceID })
	sort.Slice(snapshot.BackupPolicies, func(i, j int) bool { return snapshot.BackupPolicies[i].SourceID < snapshot.BackupPolicies[j].SourceID })
}

func validChunk(value migration.Chunk) bool {
	return isDigest(value.Digest) && value.Size > 0 && value.MediaType != "" && value.ObjectCount > 0
}

func mappedID(kind, source string) migration.ID {
	sum := sha256.Sum256([]byte(kind+"\x00"+source))
	return migration.ID("src_"+kind+"_"+hex.EncodeToString(sum[:12]))
}

func audienceDigest(plan SourcePlan, material SecretMaterial) string {
	return digestText(plan.MigrationID.String()+"\x00"+plan.TargetInstallationID+"\x00"+material.Purpose+"\x00"+string(material.Ref))
}

func resettableCredentialPurpose(purpose string)bool{return purpose=="database-principal"||purpose=="mailbox-credential"||purpose=="access-credential"}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func digestBytes(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}

func normalizeHostname(value string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".") }
func normalizeDNSName(value string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".") }

func normalizedHostnames(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = normalizeHostname(value)
		if value == "" { continue }
		if _, exists := seen[value]; exists { continue }
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func idsBySite[T any](values []T, site func(T) string, id func(T) migration.ID) map[string][]migration.ID {
	out := map[string][]migration.ID{}
	for _, value := range values { key := site(value); out[key] = append(out[key], id(value)) }
	for key := range out { sort.Slice(out[key], func(i, j int) bool { return out[key][i] < out[key][j] }) }
	return out
}

func wipe(value []byte) { for index := range value { value[index] = 0 } }
func boolUint64(value bool)uint64{if value{return 1};return 0}

var _ migration.SourceReader = (*Extractor)(nil)
