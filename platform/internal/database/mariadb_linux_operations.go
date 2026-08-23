//go:build linux

package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func (executor *LinuxMariaDBExecutor) applyCreateDatabase(ctx context.Context, request EffectRequest, database Database) (effectApplication, error) {
	instance, err := executor.instance(database.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	observed, err := connection.query(ctx, sqlObserveDatabase, database)
	if err != nil {
		return effectApplication{failureCode: "connection_failed", ambiguous: true}, err
	}
	if len(strings.TrimSpace(string(observed))) != 0 {
		var stored Database
		if stateErr := executor.readResource("databases", database.ID, &stored); stateErr == nil && sameDatabaseIdentity(stored, database) {
			return effectApplication{proof: observed, mutated: true}, nil
		}
		return effectApplication{failureCode: "database_conflict"}, ErrConflict
	}
	compensation, err := executor.saveCompensation(request, mariaDBCompensation{Kind: EffectCreateDatabase, InstanceID: instance.ID, Database: &database, RemoveState: true})
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	proof, applyErr := connection.query(ctx, sqlCreateDatabase, database)
	if applyErr != nil {
		return executor.resolveDatabaseCreateFailure(ctx, connection, database, compensation, applyErr)
	}
	if len(strings.TrimSpace(string(proof))) == 0 {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "database_apply_failed"}, ErrInvalidEffect
	}
	if err := executor.writeResource("databases", database.ID, database); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) resolveDatabaseCreateFailure(ctx context.Context, connection *mariaDBConnection, database Database, compensation *mariaDBCompensation, applyErr error) (effectApplication, error) {
	observed, observeErr := connection.query(ctx, sqlObserveDatabase, database)
	if observeErr != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "database_apply_failed", ambiguous: true}, applyErr
	}
	if len(strings.TrimSpace(string(observed))) == 0 {
		_ = executor.removeResource("compensations", compensation.Token)
		return effectApplication{failureCode: "database_apply_failed"}, applyErr
	}
	if err := executor.writeResource("databases", database.ID, database); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, errors.Join(applyErr, err)
	}
	return effectApplication{proof: observed, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) applyDeleteDatabase(ctx context.Context, _ EffectRequest, effect DeleteDatabaseEffect) (effectApplication, error) {
	if !effect.WaiveRecovery && effect.RecoveryPointRef.IsZero() || effect.WaiveRecovery && effect.ApprovalRef.IsZero() {
		return effectApplication{failureCode: "precondition_failed"}, ErrUnauthorized
	}
	database := effect.Database
	var stored Database
	if err := executor.readResource("databases", database.ID, &stored); err != nil || !sameDatabaseIdentity(stored, database) {
		return effectApplication{failureCode: "database_conflict"}, errors.Join(ErrConflict, err)
	}
	instance, err := executor.instance(database.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	observed, err := connection.query(ctx, sqlObserveDatabase, database)
	if err != nil {
		return effectApplication{failureCode: "connection_failed", ambiguous: true}, err
	}
	if len(strings.TrimSpace(string(observed))) == 0 {
		if err := executor.removeResource("databases", database.ID); err != nil {
			return effectApplication{mutated: true, failureCode: "state_persistence_failed", ambiguous: true}, err
		}
		return effectApplication{proof: []byte("database-absent\x00" + database.ID.String()), mutated: true}, nil
	}
	proof, applyErr := connection.query(ctx, sqlDropDatabase, database)
	if applyErr != nil {
		observed, observeErr := connection.query(ctx, sqlObserveDatabase, database)
		if observeErr != nil {
			return effectApplication{mutated: true, failureCode: "database_delete_failed", ambiguous: true}, applyErr
		}
		if len(strings.TrimSpace(string(observed))) != 0 {
			return effectApplication{failureCode: "database_delete_failed"}, applyErr
		}
		proof = []byte("database-absent\x00" + database.ID.String())
	}
	if err := executor.removeResource("databases", database.ID); err != nil {
		return effectApplication{mutated: true, failureCode: "state_persistence_failed", ambiguous: true}, err
	}
	return effectApplication{proof: proof, mutated: true}, nil
}

func (executor *LinuxMariaDBExecutor) applyCreatePrincipal(ctx context.Context, request EffectRequest, principal DatabasePrincipal) (effectApplication, error) {
	instance, err := executor.instance(principal.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	mode, err := executor.principalTLS(instance, principal)
	if err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	password, err := executor.secrets.PrincipalPassword(ctx, principal.CredentialSecretRef, principal.ID, principal.TenantID.String(), principal.SiteID.String())
	if err != nil {
		return effectApplication{failureCode: "credential_unavailable"}, err
	}
	defer wipeBytes(password)
	if len(password) == 0 || len(password) > maximumSecretBytes {
		return effectApplication{failureCode: "credential_unavailable"}, ErrInvalidResource
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	observed, err := connection.query(ctx, sqlObservePrincipal, principal)
	if err != nil {
		return effectApplication{failureCode: "connection_failed", ambiguous: true}, err
	}
	if len(strings.TrimSpace(string(observed))) != 0 {
		var stored DatabasePrincipal
		if stateErr := executor.readResource("principals", principal.ID, &stored); stateErr == nil && samePrincipalIdentity(stored, principal) {
			return effectApplication{proof: observed, mutated: true}, nil
		}
		return effectApplication{failureCode: "principal_conflict"}, ErrConflict
	}
	compensation, err := executor.saveCompensation(request, mariaDBCompensation{Kind: EffectCreatePrincipal, InstanceID: instance.ID, Principal: &principal, RemoveState: true})
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	proof, applyErr := connection.query(ctx, sqlCreatePrincipal, principalMutation{Principal: principal, Password: password, TLS: mode})
	if applyErr != nil {
		observed, observeErr := connection.query(ctx, sqlObservePrincipal, principal)
		if observeErr != nil {
			return effectApplication{mutated: true, compensation: compensation, failureCode: "principal_apply_failed", ambiguous: true}, applyErr
		}
		if len(strings.TrimSpace(string(observed))) == 0 {
			_ = executor.removeResource("compensations", compensation.Token)
			return effectApplication{failureCode: "principal_apply_failed"}, applyErr
		}
		proof = observed
	}
	if err := executor.writeResource("principals", principal.ID, principal); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) applyDeletePrincipal(ctx context.Context, _ EffectRequest, principal DatabasePrincipal) (effectApplication, error) {
	var stored DatabasePrincipal
	if err := executor.readResource("principals", principal.ID, &stored); err != nil || !samePrincipalIdentity(stored, principal) {
		return effectApplication{failureCode: "principal_conflict"}, errors.Join(ErrConflict, err)
	}
	instance, err := executor.instance(principal.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	observed, err := connection.query(ctx, sqlObservePrincipal, principal)
	if err != nil {
		return effectApplication{failureCode: "connection_failed", ambiguous: true}, err
	}
	if len(strings.TrimSpace(string(observed))) == 0 {
		if err := executor.removeResource("principals", principal.ID); err != nil {
			return effectApplication{mutated: true, failureCode: "state_persistence_failed", ambiguous: true}, err
		}
		return effectApplication{proof: []byte("principal-absent\x00" + principal.ID.String()), mutated: true}, nil
	}
	proof, applyErr := connection.query(ctx, sqlDropPrincipal, principal)
	if applyErr != nil {
		observed, observeErr := connection.query(ctx, sqlObservePrincipal, principal)
		if observeErr != nil {
			return effectApplication{mutated: true, failureCode: "principal_delete_failed", ambiguous: true}, applyErr
		}
		if len(strings.TrimSpace(string(observed))) != 0 {
			return effectApplication{failureCode: "principal_delete_failed"}, applyErr
		}
		proof = []byte("principal-absent\x00" + principal.ID.String())
	}
	if err := executor.removeResource("principals", principal.ID); err != nil {
		return effectApplication{mutated: true, failureCode: "state_persistence_failed", ambiguous: true}, err
	}
	return effectApplication{proof: proof, mutated: true}, nil
}

func (executor *LinuxMariaDBExecutor) applyRotatePassword(ctx context.Context, request EffectRequest, effect RotatePasswordEffect) (effectApplication, error) {
	principal := effect.Principal
	var previous DatabasePrincipal
	if err := executor.readResource("principals", principal.ID, &previous); err != nil || !samePrincipalIdentity(previous, principal) {
		return effectApplication{failureCode: "principal_conflict"}, errors.Join(ErrConflict, err)
	}
	instance, err := executor.instance(principal.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	mode, err := executor.principalTLS(instance, principal)
	if err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	password, err := executor.secrets.PrincipalPassword(ctx, effect.NewSecretRef, principal.ID, principal.TenantID.String(), principal.SiteID.String())
	if err != nil {
		return effectApplication{failureCode: "credential_unavailable"}, err
	}
	defer wipeBytes(password)
	compensation, err := executor.saveCompensation(request, mariaDBCompensation{Kind: EffectRotatePassword, InstanceID: instance.ID, Principal: &previous})
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	proof, err := connection.query(ctx, sqlRotatePrincipal, principalMutation{Principal: principal, Password: password, TLS: mode})
	if err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "principal_apply_failed"}, err
	}
	if err := executor.writeResource("principals", principal.ID, principal); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) applyReplaceGrants(ctx context.Context, request EffectRequest, grantSet GrantSet) (effectApplication, error) {
	database, principal, instance, err := executor.grantOwners(grantSet)
	if err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	compensationValue := mariaDBCompensation{Kind: EffectReplaceGrants, InstanceID: instance.ID, TargetID: grantSet.ID, Database: &database, Principal: &principal, RemoveState: true}
	var previous GrantSet
	if err := executor.readResource("grants", grantSet.ID, &previous); err == nil {
		compensationValue.GrantSet, compensationValue.RemoveState = &previous, false
	} else if !errors.Is(err, ErrNotFound) {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	compensation, err := executor.saveCompensation(request, compensationValue)
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	proof, err := connection.query(ctx, sqlReplaceGrants, grantMutation{Database: database, Principal: principal, GrantSet: grantSet})
	if err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "grant_apply_failed"}, err
	}
	if err := executor.writeResource("grants", grantSet.ID, grantSet); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) grantOwners(grantSet GrantSet) (Database, DatabasePrincipal, DatabaseInstance, error) {
	var database Database
	if err := executor.readResource("databases", grantSet.DatabaseID, &database); err != nil {
		return Database{}, DatabasePrincipal{}, DatabaseInstance{}, err
	}
	var principal DatabasePrincipal
	if err := executor.readResource("principals", grantSet.PrincipalID, &principal); err != nil {
		return Database{}, DatabasePrincipal{}, DatabaseInstance{}, err
	}
	if database.InstanceID != grantSet.InstanceID || principal.InstanceID != grantSet.InstanceID || database.TenantID != grantSet.TenantID || principal.TenantID != grantSet.TenantID || database.SiteID != grantSet.SiteID || principal.SiteID != grantSet.SiteID {
		return Database{}, DatabasePrincipal{}, DatabaseInstance{}, ErrUnauthorized
	}
	instance, err := executor.instance(grantSet.InstanceID)
	return database, principal, instance, err
}

func (executor *LinuxMariaDBExecutor) applyBindExternal(ctx context.Context, request EffectRequest, instance DatabaseInstance) (effectApplication, error) {
	if instance.Placement != PlacementExternal || instance.External == nil || !sameServerName(instance.External.Endpoint.Host, instance.External.ServerName) {
		return effectApplication{failureCode: "precondition_failed"}, ErrInvalidResource
	}
	var prior DatabaseInstance
	if err := executor.readResource("instances", instance.ID, &prior); err == nil {
		if sameInstanceIdentity(prior, instance) {
			connection, cleanup, connectionErr := executor.connection(ctx, prior)
			if connectionErr != nil {
				return effectApplication{failureCode: "connection_failed"}, connectionErr
			}
			defer cleanup()
			proof, connectionErr := connection.query(ctx, sqlObserveStatus)
			return effectApplication{proof: proof, mutated: true}, connectionErr
		}
		return effectApplication{failureCode: "instance_conflict"}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	proof, err := connection.query(ctx, sqlObserveStatus)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	version, err := parseMariaDBVersion(firstField(proof))
	if err != nil || compareVersion(version, instance.Version) != 0 {
		return effectApplication{failureCode: "instance_conflict"}, ErrConflict
	}
	compensation, err := executor.saveCompensation(request, mariaDBCompensation{Kind: EffectBindExternalInstance, InstanceID: instance.ID, Instance: &instance, RemoveState: true})
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	manifest, _ := json.MarshalIndent(instance, "", "  ")
	if _, err := executor.writeGeneration(instance.ID, instance.Generation, map[string]generatedFile{"external-instance.json": {Payload: append(manifest, '\n'), Mode: 0600}}); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	if err := executor.writeResource("instances", instance.ID, instance); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) applyConsoleSession(ctx context.Context, request EffectRequest, session DatabaseWorkspaceSession) (effectApplication, error) {
	if !session.ExpiresAt.After(executor.now().UTC()) {
		return effectApplication{failureCode: "precondition_failed"}, ErrUnauthorized
	}
	var database Database
	if err := executor.readResource("databases", session.DatabaseID, &database); err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	var principal DatabasePrincipal
	if err := executor.readResource("principals", session.PrincipalID, &principal); err != nil {
		return effectApplication{failureCode: "precondition_failed"}, err
	}
	if database.TenantID != session.TenantID || principal.TenantID != session.TenantID || database.SiteID != session.SiteID || principal.SiteID != session.SiteID || database.InstanceID != principal.InstanceID {
		return effectApplication{failureCode: "precondition_failed"}, ErrUnauthorized
	}
	instance, err := executor.instance(database.InstanceID)
	if err != nil {
		return effectApplication{failureCode: "instance_not_found"}, err
	}
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil {
		return effectApplication{failureCode: "connection_failed"}, err
	}
	defer cleanup()
	databaseProof, err := connection.query(ctx, sqlObserveDatabase, database)
	if err != nil || len(strings.TrimSpace(string(databaseProof))) == 0 {
		return effectApplication{failureCode: "console_apply_failed"}, errors.Join(ErrNotFound, err)
	}
	principalProof, err := connection.query(ctx, sqlObservePrincipal, principal)
	if err != nil || len(strings.TrimSpace(string(principalProof))) == 0 {
		return effectApplication{failureCode: "console_apply_failed"}, errors.Join(ErrNotFound, err)
	}
	compensation, err := executor.saveCompensation(request, mariaDBCompensation{Kind: EffectOpenConsoleSession, InstanceID: instance.ID, Session: &session, RemoveState: true})
	if err != nil {
		return effectApplication{failureCode: "state_persistence_failed"}, err
	}
	ticket, _ := json.MarshalIndent(struct {
		Version      int                       `json:"version"`
		Session      DatabaseWorkspaceSession  `json:"session"`
		InstanceID   ResourceID                `json:"instance_id"`
		DatabaseName SQLIdentifier             `json:"database_name"`
		Principal    SQLIdentifier             `json:"principal"`
	}{1, session, instance.ID, database.Name, principal.Name}, "", "  ")
	if _, err := executor.writeGeneration(session.ID, session.Generation, map[string]generatedFile{"workspace-session.json": {Payload: append(ticket, '\n'), Mode: 0600}}); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "console_apply_failed"}, err
	}
	if err := executor.writeResource("sessions", session.ID, session); err != nil {
		return effectApplication{mutated: true, compensation: compensation, failureCode: "state_persistence_failed"}, err
	}
	proof := append(append(databaseProof, '\x00'), principalProof...)
	return effectApplication{proof: proof, mutated: true, compensation: compensation}, nil
}

func (executor *LinuxMariaDBExecutor) principalTLS(instance DatabaseInstance, principal DatabasePrincipal) (TLSMode, error) {
	if instance.Placement == PlacementExternal {
		return instance.External.RequiredTLS, nil
	}
	if principal.HostScope == HostScopeLoopback {
		return TLSRequired, nil
	}
	var policy NetworkAccessPolicy
	if err := executor.readResource("policies", principal.NetworkPolicyID, &policy); err != nil {
		return "", err
	}
	if policy.InstanceID != instance.ID {
		return "", ErrUnauthorized
	}
	return policy.TLS, nil
}

func (executor *LinuxMariaDBExecutor) applyCompensation(ctx context.Context, compensation mariaDBCompensation) ([]byte, error) {
	switch compensation.Kind {
	case EffectCreateDatabase:
		if compensation.Database == nil {
			return nil, ErrInvalidResource
		}
		instance, err := executor.instance(compensation.InstanceID)
		if err != nil { return nil, err }
		connection, cleanup, err := executor.connection(ctx, instance)
		if err != nil { return nil, err }
		defer cleanup()
		proof, err := connection.query(ctx, sqlDropDatabase, *compensation.Database)
		if err == nil { err = executor.removeResource("databases", compensation.Database.ID) }
		return proof, err
	case EffectCreatePrincipal:
		if compensation.Principal == nil { return nil, ErrInvalidResource }
		instance, err := executor.instance(compensation.InstanceID)
		if err != nil { return nil, err }
		connection, cleanup, err := executor.connection(ctx, instance)
		if err != nil { return nil, err }
		defer cleanup()
		proof, err := connection.query(ctx, sqlDropPrincipal, *compensation.Principal)
		if err == nil { err = executor.removeResource("principals", compensation.Principal.ID) }
		return proof, err
	case EffectRotatePassword:
		if compensation.Principal == nil { return nil, ErrInvalidResource }
		principal := *compensation.Principal
		instance, err := executor.instance(compensation.InstanceID)
		if err != nil { return nil, err }
		password, err := executor.secrets.PrincipalPassword(ctx, principal.CredentialSecretRef, principal.ID, principal.TenantID.String(), principal.SiteID.String())
		if err != nil { return nil, err }
		defer wipeBytes(password)
		mode, err := executor.principalTLS(instance, principal)
		if err != nil { return nil, err }
		connection, cleanup, err := executor.connection(ctx, instance)
		if err != nil { return nil, err }
		defer cleanup()
		proof, err := connection.query(ctx, sqlRotatePrincipal, principalMutation{Principal: principal, Password: password, TLS: mode})
		if err == nil { err = executor.writeResource("principals", principal.ID, principal) }
		return proof, err
	case EffectReplaceGrants:
		return executor.compensateGrants(ctx, compensation)
	case EffectApplyNetworkPolicy:
		return executor.compensateNetworkPolicy(ctx, compensation)
	case EffectBindExternalInstance:
		if compensation.Instance == nil { return nil, ErrInvalidResource }
		return []byte("external-instance-removed\x00" + compensation.Instance.ID.String()), executor.removeResource("instances", compensation.Instance.ID)
	case EffectOpenConsoleSession:
		if compensation.Session == nil { return nil, ErrInvalidResource }
		return []byte("console-session-removed\x00" + compensation.Session.ID.String()), executor.removeResource("sessions", compensation.Session.ID)
	case EffectApplyTuning:
		return executor.compensateTuning(ctx, compensation)
	default:
		return nil, ErrCompensationFailed
	}
}

func (executor *LinuxMariaDBExecutor) compensateGrants(ctx context.Context, compensation mariaDBCompensation) ([]byte, error) {
	instance, err := executor.instance(compensation.InstanceID)
	if err != nil { return nil, err }
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil { return nil, err }
	defer cleanup()
	if compensation.GrantSet == nil {
		if compensation.Principal == nil || compensation.TargetID.IsZero() { return nil, ErrCompensationFailed }
		proof, clearErr := connection.query(ctx, sqlClearGrants, *compensation.Principal)
		if clearErr == nil { clearErr = executor.removeResource("grants", compensation.TargetID) }
		return proof, clearErr
	}
	grantSet := *compensation.GrantSet
	database, principal, _, err := executor.grantOwners(grantSet)
	if err != nil { return nil, err }
	proof, err := connection.query(ctx, sqlReplaceGrants, grantMutation{Database: database, Principal: principal, GrantSet: grantSet})
	if err == nil { err = executor.writeResource("grants", grantSet.ID, grantSet) }
	return proof, err
}

func sameDatabaseIdentity(left, right Database) bool {
	return left.ID == right.ID && left.InstanceID == right.InstanceID && left.Name == right.Name && left.TenantID == right.TenantID && left.SiteID == right.SiteID
}

func samePrincipalIdentity(left, right DatabasePrincipal) bool {
	return left.ID == right.ID && left.InstanceID == right.InstanceID && left.Name == right.Name && left.HostScope == right.HostScope && left.NetworkPolicyID == right.NetworkPolicyID && left.TenantID == right.TenantID && left.SiteID == right.SiteID
}

func sameInstanceIdentity(left, right DatabaseInstance) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func (executor *LinuxMariaDBExecutor) describeResource(kind string, id ResourceID) string {
	return fmt.Sprintf("%s:%s", kind, id.String())
}
