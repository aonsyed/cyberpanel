//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	hostingsite "github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/serviceregistry"
)

const projectionSourceRowMaximumBytes = 4 << 20

type controlProjectionSource struct{}

type controlProjectionCollector struct {
	resources []federation.ProjectionResource
	bytes     int
}

func (controlProjectionSource) ScanProjection(ctx context.Context, tx *sql.Tx) (federation.ProjectionScan, error) {
	var scan federation.ProjectionScan
	if ctx == nil || tx == nil {
		return scan, federation.ErrInvalid
	}
	serviceStatus, err := projectionTableExists(ctx, tx, "service_observed")
	if err != nil {
		return scan, err
	}
	scan.Coverage = federation.NodeProjectionCoverage(serviceStatus)
	collector := &controlProjectionCollector{}
	steps := []struct {
		name string
		run  func(context.Context, *sql.Tx, *controlProjectionCollector) error
	}{
		{"tenants", scanProjectionTenants},
		{"sites", scanProjectionSites},
		{"dns zones", scanProjectionDNSZones},
		{"databases", scanProjectionDatabases},
		{"mail", scanProjectionMail},
		{"certificates", scanProjectionCertificates},
		{"applications", scanProjectionApplications},
		{"container workloads", scanProjectionWorkloads},
		{"backups", scanProjectionBackups},
		{"host operations", scanProjectionHostOperations},
	}
	if serviceStatus {
		steps = append(steps, struct {
			name string
			run  func(context.Context, *sql.Tx, *controlProjectionCollector) error
		}{"host services", scanProjectionHostServices})
	}
	for _, step := range steps {
		if err = step.run(ctx, tx, collector); err != nil {
			return scan, fmt.Errorf("scan federation projection %s: %w", step.name, err)
		}
	}
	scan.Resources = collector.resources
	return scan, nil
}

func (collector *controlProjectionCollector) add(tenant, kind, id string, generation uint64, status map[string]any) error {
	status["schema"] = "cyberpanel.resource-summary.v1"
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if len(raw) > projectionSourceRowMaximumBytes || len(collector.resources) >= federation.ProjectionMaximumRows || collector.bytes+len(raw) > federation.ProjectionMaximumSourceBytes {
		return federation.ErrProjectionBackpressure
	}
	collector.bytes += len(raw)
	collector.resources = append(collector.resources, federation.ProjectionResource{TenantID: tenant, ResourceKind: kind, ResourceID: id, Generation: generation, SanitizedJSON: raw})
	return nil
}

func projectionTableExists(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	var present int
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`, table).Scan(&present)
	return present == 1, err
}

func decodeProjectionRow(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > projectionSourceRowMaximumBytes || json.Unmarshal(raw, target) != nil {
		return federation.ErrInvalid
	}
	return nil
}

func scanProjectionTenants(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,parent_tenant_id,kind,name,state,plan_id,generation,authz_epoch FROM identity_tenants WHERE state<>'deleted' ORDER BY id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id, parent, kind, name, state, plan string
		var generation, authzEpoch uint64
		if err = rows.Scan(&id, &parent, &kind, &name, &state, &plan, &generation, &authzEpoch); err != nil { return err }
		if err = collector.add(id, "identity.tenant", id, generation, map[string]any{"id": id, "parentTenantId": parent, "kind": kind, "name": name, "state": state, "planId": plan, "generation": generation, "authzEpoch": authzEpoch}); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionSites(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id,site_id,generation,aggregate_json FROM hosting_sites ORDER BY tenant_id,site_id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var tenant, id string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&tenant, &id, &generation, &raw); err != nil { return err }
		if len(raw) == 0 || len(raw) > projectionSourceRowMaximumBytes { return federation.ErrInvalid }
		value, restoreErr := hostingsite.Restore(raw)
		if restoreErr != nil || value.ID().String() != id || value.TenantID().String() != tenant || value.Generation() != generation { return federation.ErrInvalid }
		if value.Lifecycle() == hostingsite.LifecycleDeleted { continue }
		bindings := value.Bindings()
		domainCount := 0
		for _, binding := range bindings { if binding.Kind != hostingsite.BindingPreview { domainCount++ } }
		if err = collector.add(tenant, "hosting.site", id, generation, map[string]any{"id": id, "tenantId": tenant, "projectId": value.ProjectID().String(), "phpProfile": string(value.PHPProfile()), "lifecycle": string(value.Lifecycle()), "desiredLifecycle": string(value.DesiredLifecycle()), "generation": generation, "domainCount": domainCount}); err != nil { return err }
		for _, binding := range bindings {
			if binding.Kind == hostingsite.BindingPreview { continue }
			hostname := binding.Hostname.String()
			if err = collector.add(tenant, "hosting.domain", hostname, generation, map[string]any{"hostname": hostname, "tenantId": tenant, "siteId": id, "kind": string(binding.Kind), "redirectTarget": binding.RedirectTarget.String(), "redirectStatus": string(binding.RedirectStatus), "siteLifecycle": string(value.Lifecycle()), "generation": generation}); err != nil { return err }
		}
	}
	return rows.Err()
}

func scanProjectionDNSZones(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT z.id,z.zone_json,COALESCE(d.tenant_id,''),COALESCE(d.generation,0),COALESCE(d.phase,'disabled') FROM dns_zones z LEFT JOIN dnssec_status_v2 d ON d.zone_id=z.id ORDER BY z.id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id, tenant, phase string
		var dnssecGeneration uint64
		var raw []byte
		if err = rows.Scan(&id, &raw, &tenant, &dnssecGeneration, &phase); err != nil { return err }
		var zone dns.Zone
		if decodeProjectionRow(raw, &zone) != nil || string(zone.ID) != id { return federation.ErrInvalid }
		generation := zone.Serial
		if dnssecGeneration > generation { generation = dnssecGeneration }
		if generation == 0 { generation = 1 }
		if err = collector.add(tenant, "dns.zone", id, generation, map[string]any{"id": id, "name": zone.Name, "role": string(zone.Role), "serial": zone.Serial, "providerBound": zone.Provider != "", "transferPeerCount": len(zone.Peers), "dnssecPhase": phase, "dnssecGeneration": dnssecGeneration}); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionDatabases(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT kind,resource_id,tenant_id,site_id,parent_id,physical_name,generation,status_json,updated_at FROM panel_database_resources WHERE kind IN ('database_instance','database','database_principal') ORDER BY kind,resource_id`)
	if err != nil { return err }
	defer rows.Close()
	kinds := map[string]string{"database_instance": "database.instance", "database": "database.database", "database_principal": "database.principal"}
	for rows.Next() {
		var sourceKind, id, tenant, siteID, parentID, physicalName, updatedAt string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&sourceKind, &id, &tenant, &siteID, &parentID, &physicalName, &generation, &raw, &updatedAt); err != nil { return err }
		var status database.ResourceStatus
		if decodeProjectionRow(raw, &status) != nil { return federation.ErrInvalid }
		if status.Lifecycle == database.LifecycleDeleted { continue }
		if err = collector.add(tenant, kinds[sourceKind], id, generation, map[string]any{"id": id, "tenantId": tenant, "siteId": siteID, "parentId": parentID, "physicalName": physicalName, "generation": generation, "lifecycle": string(status.Lifecycle), "health": string(status.Health), "reconciliation": string(status.Reconciliation), "observedGeneration": status.ObservedGeneration, "proofDigest": status.ProofDigest, "messageCode": status.MessageCode, "updatedAt": updatedAt}); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionMail(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id,kind,resource_id,generation,state,resource_json FROM mail_resources_v2 WHERE kind IN ('mail.domain','mail.mailbox','mail.alias') ORDER BY kind,tenant_id,resource_id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var tenant, kind, id, state string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&tenant, &kind, &id, &generation, &state, &raw); err != nil { return err }
		var envelope mail.ResourceEnvelope
		if decodeProjectionRow(raw, &envelope) != nil || envelope.TenantID != tenant || string(envelope.Kind) != kind || envelope.ID != id || envelope.Generation != generation || string(envelope.State) != state { return federation.ErrInvalid }
		if envelope.State == mail.StateDeleted { continue }
		status := map[string]any{"id": id, "tenantId": tenant, "generation": generation, "state": state}
		switch envelope.Kind {
		case mail.ResourceDomain:
			var value mail.Domain
			if decodeProjectionRow(envelope.Spec, &value) != nil || string(value.ID) != id || value.Tenant != tenant { return federation.ErrInvalid }
			status["name"], status["policyId"] = value.Name, string(value.Policy)
			status["dkimEnabled"], status["dkimSelector"] = value.DKIM.Enabled, value.DKIM.Selector
			status["relayConfigured"] = value.Relay.Host != "" || value.Relay.CredentialRef != ""
		case mail.ResourceMailbox:
			var value mail.Mailbox
			if decodeProjectionRow(envelope.Spec, &value) != nil || string(value.ID) != id { return federation.ErrInvalid }
			status["domainId"], status["local"], status["quotaBytes"], status["enabled"] = string(value.Domain), value.Local, value.QuotaBytes, value.Enabled
		case mail.ResourceAlias:
			var value mail.Alias
			if decodeProjectionRow(envelope.Spec, &value) != nil || string(value.ID) != id { return federation.ErrInvalid }
			targets := make([]string, 0, len(value.Targets))
			for _, target := range value.Targets { targets = append(targets, string(target)) }
			sort.Strings(targets)
			status["domainId"], status["source"], status["targets"] = string(value.Domain), string(value.Source), targets
			status["catchAll"], status["capability"] = value.CatchAll, string(value.Capability)
		default:
			return federation.ErrInvalid
		}
		if err = collector.add(tenant, kind, id, generation, status); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionCertificates(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,generation,policy_json FROM certificate_policies_v2 ORDER BY id`)
	if err != nil { return err }
	for rows.Next() {
		var id, tenant string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&id, &tenant, &generation, &raw); err != nil { rows.Close(); return err }
		var policy certificates.CertificatePolicy
		if decodeProjectionRow(raw, &policy) != nil || string(policy.ID) != id || policy.TenantID != tenant || policy.Generation != generation { rows.Close(); return federation.ErrInvalid }
		names := append([]string(nil), policy.Names...)
		sort.Strings(names)
		if err = collector.add(tenant, "certificate.policy", id, generation, map[string]any{"id": id, "tenantId": tenant, "names": names, "preferredChallenge": string(policy.PreferredChallenge), "keyAlgorithm": policy.KeyAlgorithm, "renewBeforeNanos": int64(policy.RenewBefore), "mustStaple": policy.MustStaple, "reuseKey": policy.ReuseKey, "generation": generation}); err != nil { rows.Close(); return err }
	}
	if err = rows.Err(); err != nil { rows.Close(); return err }
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT id,tenant_id,policy_id,phase,issuance_json FROM certificate_issuances_v2 ORDER BY id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id, tenant, policyID, phase string
		var raw []byte
		if err = rows.Scan(&id, &tenant, &policyID, &phase, &raw); err != nil { return err }
		var issuance certificates.Issuance
		if decodeProjectionRow(raw, &issuance) != nil || issuance.ID != id || issuance.TenantID != tenant || string(issuance.PolicyID) != policyID || string(issuance.Phase) != phase { return federation.ErrInvalid }
		generation := issuance.PolicyGeneration
		if generation == 0 { generation = 1 }
		status := map[string]any{"id": id, "tenantId": tenant, "policyId": policyID, "policyGeneration": issuance.PolicyGeneration, "phase": phase, "attempt": issuance.Attempt, "createdAt": issuance.CreatedAt, "updatedAt": issuance.UpdatedAt}
		if !issuance.NextAttemptAt.IsZero() { status["nextAttemptAt"] = issuance.NextAttemptAt }
		if issuance.Certificate.ID != "" {
			names := append([]string(nil), issuance.Certificate.Names...)
			sort.Strings(names)
			status["certificateId"], status["names"], status["serial"] = string(issuance.Certificate.ID), names, issuance.Certificate.Serial
			status["fingerprintSha256"], status["notBefore"], status["notAfter"], status["issuer"] = issuance.Certificate.FingerprintSHA256, issuance.Certificate.NotBefore, issuance.Certificate.NotAfter, issuance.Certificate.Issuer
		}
		if err = collector.add(tenant, "certificate.status", id, generation, status); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionApplications(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,site_id,definition_id,kind,state,generation,installation_json FROM app_installations ORDER BY id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id, tenant, siteID, definitionID, kind, state string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&id, &tenant, &siteID, &definitionID, &kind, &state, &generation, &raw); err != nil { return err }
		var value apps.ApplicationInstallation
		if decodeProjectionRow(raw, &value) != nil || string(value.ID) != id || string(value.TenantID) != tenant || string(value.SiteID) != siteID || string(value.DefinitionID) != definitionID || string(value.Kind) != kind || string(value.State) != state || value.Generation != generation { return federation.ErrInvalid }
		if value.State == apps.InstallationRemoved { continue }
		status := map[string]any{"id": id, "tenantId": tenant, "projectId": string(value.ProjectID), "siteId": siteID, "definitionId": definitionID, "kind": kind, "storageMode": string(value.StorageMode), "state": state, "generation": generation, "productVersion": value.Recipe.ProductVersion, "recipeDigest": value.Recipe.RecipeDigest, "health": string(value.Health.State), "createdAt": value.CreatedAt, "updatedAt": value.UpdatedAt}
		if !value.Health.CheckedAt.IsZero() { status["healthCheckedAt"] = value.Health.CheckedAt }
		status["healthDefinitionDigest"], status["healthReleaseDigest"] = value.Health.DefinitionDigest, value.Health.ReleaseDigest
		if err = collector.add(tenant, "application.installation", id, generation, status); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionWorkloads(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,generation,observed_generation,state,spec_digest,value_json FROM container_workloads ORDER BY id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id, tenant, state, specDigest string
		var generation, observedGeneration uint64
		var raw []byte
		if err = rows.Scan(&id, &tenant, &generation, &observedGeneration, &state, &specDigest, &raw); err != nil { return err }
		var value containers.Workload
		if decodeProjectionRow(raw, &value) != nil || value.ID.String() != id || value.TenantID.String() != tenant || value.Generation != generation || value.ObservedGeneration != observedGeneration || string(value.DesiredLifecycle) != state || value.SpecDigest != specDigest { return federation.ErrInvalid }
		if value.DesiredLifecycle == containers.LifecycleDeleted { continue }
		if err = collector.add(tenant, "container.workload", id, generation, map[string]any{"id": id, "tenantId": tenant, "projectId": value.ProjectID.String(), "siteId": value.SiteID.String(), "name": value.Name, "tier": string(value.Tier), "desiredLifecycle": string(value.DesiredLifecycle), "observedLifecycle": string(value.ObservedLifecycle), "health": string(value.ObservedHealth), "generation": generation, "observedGeneration": observedGeneration, "specDigest": specDigest, "observedDigest": value.ObservedDigest, "restartCount": value.RestartCount, "createdAt": value.CreatedAt, "updatedAt": value.UpdatedAt}); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionBackups(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,generation,policy_json FROM backup_policies_v2 ORDER BY id`)
	if err != nil { return err }
	for rows.Next() {
		var id, tenant string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&id, &tenant, &generation, &raw); err != nil { rows.Close(); return err }
		var policy backup.BackupPolicySpec
		if decodeProjectionRow(raw, &policy) != nil || string(policy.ID) != id || policy.TenantID != tenant || policy.Generation != generation { rows.Close(); return federation.ErrInvalid }
		components := make([]string, 0, len(policy.Components))
		for _, component := range policy.Components { components = append(components, string(component)) }
		sort.Strings(components)
		if err = collector.add(tenant, "backup.policy", id, generation, map[string]any{"id": id, "tenantId": tenant, "scope": policy.Scope, "schedule": policy.Schedule, "components": components, "repositoryCount": len(policy.Repositories), "requiredCopies": policy.RequiredCopies, "consistency": string(policy.Consistency), "retention": policy.Retention, "generation": generation, "enabled": policy.Enabled}); err != nil { rows.Close(); return err }
	}
	if err = rows.Err(); err != nil { rows.Close(); return err }
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT p.id,p.tenant_id,p.policy_id,p.state,p.manifest_digest,p.manifest_json,p.created_at,COUNT(c.id),COALESCE(SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN c.status='failed' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN c.status='pruned' THEN 1 ELSE 0 END),0) FROM recovery_points_v2 p LEFT JOIN recovery_copies_v2 c ON c.recovery_point_id=p.id GROUP BY p.id,p.tenant_id,p.policy_id,p.state,p.manifest_digest,p.manifest_json,p.created_at ORDER BY p.id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id, tenant, policyID, state, manifestDigest string
		var raw []byte
		var createdAt time.Time
		var copies, verified, failed, pruned uint64
		if err = rows.Scan(&id, &tenant, &policyID, &state, &manifestDigest, &raw, &createdAt, &copies, &verified, &failed, &pruned); err != nil { return err }
		var manifest backup.RecoveryPointManifest
		if decodeProjectionRow(raw, &manifest) != nil || string(manifest.RecoveryPointID) != id || manifest.TenantID != tenant || string(manifest.PolicyID) != policyID || manifest.ManifestDigest != manifestDigest { return federation.ErrInvalid }
		generation := manifest.SourceGeneration
		if generation == 0 { generation = manifest.WriteFrontier }
		if generation == 0 { generation = 1 }
		components := make([]string, 0, len(manifest.RequiredComponents))
		for _, component := range manifest.RequiredComponents { components = append(components, string(component)) }
		sort.Strings(components)
		if err = collector.add(tenant, "backup.recovery_status", id, generation, map[string]any{"id": id, "tenantId": tenant, "policyId": policyID, "state": state, "manifestDigest": manifestDigest, "scope": manifest.Scope, "writeFrontier": manifest.WriteFrontier, "sourceGeneration": manifest.SourceGeneration, "requiredComponents": components, "copyCount": copies, "verifiedCopies": verified, "failedCopies": failed, "prunedCopies": pruned, "createdAt": createdAt}); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionHostOperations(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT kind,resource_id,node_id,tenant_id,site_id,parent_id,generation,status_json,updated_at FROM panel_operation_resources WHERE node_id=(SELECT node_id FROM federation_state WHERE singleton_id=1) ORDER BY kind,resource_id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var kind, id, nodeID, tenant, siteID, parentID, updatedAt string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&kind, &id, &nodeID, &tenant, &siteID, &parentID, &generation, &raw, &updatedAt); err != nil { return err }
		var status operations.ResourceStatus
		if decodeProjectionRow(raw, &status) != nil { return federation.ErrInvalid }
		if status.Lifecycle == operations.LifecycleDeleted { continue }
		resourceID := kind + ":" + id
		if err = collector.add(tenant, "host.operation_status", resourceID, generation, map[string]any{"id": id, "resourceKind": kind, "nodeId": nodeID, "tenantId": tenant, "siteId": siteID, "parentId": parentID, "generation": generation, "lifecycle": string(status.Lifecycle), "health": string(status.Health), "reconciliation": string(status.Reconciliation), "observedGeneration": status.ObservedGeneration, "proofDigest": status.ProofDigest, "messageCode": status.MessageCode, "statusUpdatedAt": status.UpdatedAt, "updatedAt": updatedAt}); err != nil { return err }
	}
	return rows.Err()
}

func scanProjectionHostServices(ctx context.Context, tx *sql.Tx, collector *controlProjectionCollector) error {
	rows, err := tx.QueryContext(ctx, `SELECT node_id,service_id,generation,evidence_digest,payload FROM service_observed WHERE node_id=(SELECT node_id FROM federation_state WHERE singleton_id=1) ORDER BY service_id`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var nodeID, id, evidenceDigest string
		var generation uint64
		var raw []byte
		if err = rows.Scan(&nodeID, &id, &generation, &evidenceDigest, &raw); err != nil { return err }
		var value serviceregistry.ServiceObservation
		if decodeProjectionRow(raw, &value) != nil || value.NodeID != nodeID || string(value.ServiceID) != id || value.Generation != generation || value.EvidenceDigest != evidenceDigest { return federation.ErrInvalid }
		if err = collector.add("", "host.service_status", id, generation, map[string]any{"serviceId": id, "nodeId": value.NodeID, "generation": generation, "configGeneration": value.ConfigGeneration, "definitionDigest": value.DefinitionDigest, "install": string(value.Install), "enable": string(value.Enable), "active": string(value.Active), "config": string(value.Config), "dependenciesReady": value.DependenciesReady, "expectedListenersOwned": value.ExpectedListenersOwned, "internallyHealthy": value.InternallyHealthy, "externallyFunctional": value.ExternallyFunctional, "desiredGenerationObserved": value.DesiredGenerationObserved, "health": string(value.Health), "drift": string(value.Drift), "needDaemonReload": value.NeedDaemonReload, "evidenceDigest": evidenceDigest, "observedAt": value.ObservedAt}); err != nil { return err }
	}
	return rows.Err()
}
