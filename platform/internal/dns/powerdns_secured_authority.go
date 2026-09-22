package dns

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrPowerDNSTSIGSecret = errors.New("PowerDNS TSIG secret is unavailable")
	ErrPowerDNSTSIGState  = errors.New("PowerDNS TSIG state could not be updated")
)

// PowerDNSTSIGSecretResolver returns raw, caller-owned HMAC key bytes for a
// tenant-scoped secret reference. Implementations must return a fresh buffer;
// the authority Base64-encodes it for PowerDNS and wipes both representations.
type PowerDNSTSIGSecretResolver interface {
	ResolvePowerDNSTSIGSecret(context.Context, string, string) ([]byte, error)
}

// SecuredPowerDNSAuthority mutates a purpose-bound authoritative database. A
// zone update and all of its records, metadata, and TSIG keys share one
// serializable transaction.
type SecuredPowerDNSAuthority struct {
	database PowerDNSAuthoritativeDatabase
	secrets  PowerDNSTSIGSecretResolver
}

func NewSecuredPowerDNSAuthority(database PowerDNSAuthoritativeDatabase, secrets PowerDNSTSIGSecretResolver) (*SecuredPowerDNSAuthority, error) {
	if !database.valid() {
		return nil, ErrPowerDNSDatabaseIsolation
	}
	return &SecuredPowerDNSAuthority{database: database, secrets: secrets}, nil
}

// DatabaseIdentity exposes the non-secret identity for composition-time
// fingerprint checks without exposing the database handle or credential.
func (authority *SecuredPowerDNSAuthority) DatabaseIdentity() PowerDNSAuthoritativeDatabaseIdentity {
	if authority == nil {
		return PowerDNSAuthoritativeDatabaseIdentity{}
	}
	return authority.database.Identity()
}

func (authority *SecuredPowerDNSAuthority) Zone(ctx context.Context,tenant string,id ZoneID)(ZoneSpec,error){if authority==nil||!authority.database.valid(){return ZoneSpec{},ErrPowerDNSDatabaseIsolation};return (PowerDNSAuthority{DB:authority.database.database}).Zone(ctx,tenant,id)}
func (authority *SecuredPowerDNSAuthority) ListZones(ctx context.Context,tenant string,limit int,cursor string)([]ZoneSpec,string,error){if authority==nil||!authority.database.valid(){return nil,"",ErrPowerDNSDatabaseIsolation};return (PowerDNSAuthority{DB:authority.database.database}).ListZones(ctx,tenant,limit,cursor)}
func (authority *SecuredPowerDNSAuthority) ListRecordSets(ctx context.Context,zone ZoneSpec,limit int,cursor string)([]RecordSet,string,error){if authority==nil||!authority.database.valid(){return nil,"",ErrPowerDNSDatabaseIsolation};return (PowerDNSAuthority{DB:authority.database.database}).ListRecordSets(ctx,zone,limit,cursor)}
func (authority *SecuredPowerDNSAuthority) ObserveZone(ctx context.Context,tenant string,id ZoneID,effect string)(ZoneSpec,AuthorityReceipt,error){if authority==nil||!authority.database.valid(){return ZoneSpec{},AuthorityReceipt{},ErrPowerDNSDatabaseIsolation};return (PowerDNSAuthority{DB:authority.database.database}).ObserveZone(ctx,tenant,id,effect)}
func (authority *SecuredPowerDNSAuthority) ConfirmZoneAbsent(ctx context.Context,id ZoneID,name DNSName)error{if authority==nil||!authority.database.valid(){return ErrPowerDNSDatabaseIsolation};return (PowerDNSAuthority{DB:authority.database.database}).ConfirmZoneAbsent(ctx,id,name)}

// AdoptZone writes an exact ownership tuple only when the selected legacy
// domain has no ownership metadata. Exact metadata is accepted on retry; any
// partial, duplicate, conflicting, or already-owned tuple is quarantined.
func(authority *SecuredPowerDNSAuthority)AdoptZone(ctx context.Context,effectID string,backendDomainID int64,spec ZoneSpec)(AuthorityReceipt,error){
	if authority==nil||!authority.database.valid(){return AuthorityReceipt{},ErrPowerDNSDatabaseIsolation};if ctx==nil||!validPowerDNSEffectID(effectID)||backendDomainID<1||spec.Generation!=1||validateZoneSpec(spec,nil,nil)!=nil{return AuthorityReceipt{},ErrInvalidDNS}
	tx,err:=authority.database.database.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return AuthorityReceipt{},err};defer tx.Rollback();candidate,serial,err:=powerDNSAdoptionCandidate(ctx,tx,backendDomainID,spec);if err!=nil{return AuthorityReceipt{},err};if !sameZoneSpec(candidate,spec){return AuthorityReceipt{},ErrDNSConflict}
	metadata:=map[string][]string{};for _,kind:=range []string{cyberPanelZoneIDMetadata,cyberPanelTenantMetadata,cyberPanelGenerationMetadata}{rows,queryErr:=tx.QueryContext(ctx,`SELECT content FROM domainmetadata WHERE domain_id=? AND kind=? ORDER BY id LIMIT 2`,backendDomainID,kind);if queryErr!=nil{return AuthorityReceipt{},queryErr};for rows.Next(){var value string;if err=rows.Scan(&value);err!=nil{rows.Close();return AuthorityReceipt{},err};metadata[kind]=append(metadata[kind],value)};if err=rows.Err();err!=nil{rows.Close();return AuthorityReceipt{},err};if err=rows.Close();err!=nil{return AuthorityReceipt{},err}}
	expected:=map[string]string{cyberPanelZoneIDMetadata:string(spec.ID),cyberPanelTenantMetadata:spec.TenantID,cyberPanelGenerationMetadata:strconv.FormatUint(spec.Generation,10)};var duplicates uint64;if err=tx.QueryRowContext(ctx,`SELECT COUNT(DISTINCT domain_id) FROM domainmetadata WHERE kind=? AND content=? AND domain_id<>?`,cyberPanelZoneIDMetadata,spec.ID,backendDomainID).Scan(&duplicates);err!=nil{return AuthorityReceipt{},err};if duplicates!=0{return AuthorityReceipt{},ErrDNSConflict}
	hasMetadata:=len(metadata[cyberPanelZoneIDMetadata])+len(metadata[cyberPanelTenantMetadata])+len(metadata[cyberPanelGenerationMetadata])!=0;if hasMetadata{for kind,value:=range expected{if len(metadata[kind])!=1||metadata[kind][0]!=value{return AuthorityReceipt{},ErrDNSConflict}};observed,observedSerial,observeErr:=powerDNSZoneObservationByDomain(ctx,tx,backendDomainID);if observeErr!=nil||!sameZoneSpec(observed,spec)||observedSerial!=serial{return AuthorityReceipt{},errors.Join(ErrDNSConflict,observeErr)};return AuthorityReceipt{EffectID:effectID,ZoneID:spec.ID,Serial:serial,ObservedAt:time.Now().UTC()},tx.Commit()}
	if _,err=tx.ExecContext(ctx,`UPDATE domains SET account=? WHERE id=?`,spec.Account,backendDomainID);err!=nil{return AuthorityReceipt{},err};for kind,value:=range expected{if _,err=tx.ExecContext(ctx,`INSERT INTO domainmetadata(domain_id,kind,content) VALUES(?,?,?)`,backendDomainID,kind,value);err!=nil{return AuthorityReceipt{},err}};observed,observedSerial,err:=powerDNSZoneObservationByDomain(ctx,tx,backendDomainID);if err!=nil||!sameZoneSpec(observed,spec)||observedSerial!=serial{return AuthorityReceipt{},errors.Join(ErrDNSConflict,err)};if err=tx.Commit();err!=nil{return AuthorityReceipt{},err};return AuthorityReceipt{EffectID:effectID,ZoneID:spec.ID,Serial:serial,ObservedAt:time.Now().UTC()},nil
}

// ImportRecordSets replaces either the supplied RRsets or every non-SOA
// RRset in one transaction while retaining zone ownership, transfer peers,
// TSIG keys, DNSSEC keys, and provider metadata.
func(authority *SecuredPowerDNSAuthority)ImportRecordSets(ctx context.Context,effectID string,spec ZoneSpec,sets []RecordSet,replace bool)(AuthorityReceipt,error){
	if authority==nil||!authority.database.valid()||ctx==nil||!validPowerDNSEffectID(effectID)||len(sets)==0&&!replace||len(sets)>10000{return AuthorityReceipt{},ErrInvalidDNS};for _,set:=range sets{if set.ZoneID!=spec.ID||set.Validate(spec.Name)!=nil{return AuthorityReceipt{},ErrInvalidDNS}}
	tx,err:=authority.database.database.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return AuthorityReceipt{},err};defer tx.Rollback();domainID,err:=exactPowerDNSDomainID(ctx,tx,spec.TenantID,spec.ID);if err!=nil{return AuthorityReceipt{},err};stored,err:=powerDNSZoneByDomain(ctx,tx,domainID);if err!=nil||stored.ID!=spec.ID||stored.TenantID!=spec.TenantID||stored.Name.String()!=spec.Name.String()||stored.Generation+1!=spec.Generation{return AuthorityReceipt{},errors.Join(ErrDNSConflict,err)}
	removed:=uint32(0);if replace{result,deleteErr:=tx.ExecContext(ctx,`DELETE FROM records WHERE domain_id=? AND type<>'SOA'`,domainID);if deleteErr!=nil{return AuthorityReceipt{},deleteErr};count,countErr:=result.RowsAffected();if countErr!=nil{return AuthorityReceipt{},countErr};removed=uint32(count)}
	for _,set:=range sets{canonical,_:=set.Canonical(spec.Name);owner:=absoluteOwner(canonical.Owner,spec.Name);if !replace{result,deleteErr:=tx.ExecContext(ctx,`DELETE FROM records WHERE domain_id=? AND name=? AND type=?`,domainID,owner,canonical.Kind);if deleteErr!=nil{return AuthorityReceipt{},deleteErr};count,countErr:=result.RowsAffected();if countErr!=nil{return AuthorityReceipt{},countErr};removed+=uint32(count)};for _,record:=range canonical.Records{content,priority:=powerDNSContent(canonical.Kind,record);if _,err=tx.ExecContext(ctx,`INSERT INTO records(domain_id,name,type,content,ttl,prio,disabled,auth) VALUES(?,?,?,?,?,?,?,?)`,domainID,owner,canonical.Kind,content,canonical.TTL,priority,false,true);err!=nil{return AuthorityReceipt{},err}}}
	serial,err:=incrementPowerDNSSOASerial(ctx,tx,domainID);if err!=nil{return AuthorityReceipt{},err};result,err:=tx.ExecContext(ctx,`UPDATE domainmetadata SET content=? WHERE domain_id=? AND kind=? AND content=?`,strconv.FormatUint(spec.Generation,10),domainID,cyberPanelGenerationMetadata,strconv.FormatUint(stored.Generation,10));if err!=nil{return AuthorityReceipt{},err};affected,err:=result.RowsAffected();if err!=nil||affected!=1{return AuthorityReceipt{},ErrDNSConflict};if err=tx.Commit();err!=nil{return AuthorityReceipt{},err};return AuthorityReceipt{EffectID:effectID,ZoneID:spec.ID,Serial:serial,AppliedSets:uint32(len(sets)),RemovedSets:removed,ObservedAt:time.Now().UTC()},nil
}

// MutateACMETXT performs a targeted, serializable ACME TXT update without
// replacing the zone, its transfer-peer metadata, DNSSEC keys, or TSIG state.
func(authority *SecuredPowerDNSAuthority)MutateACMETXT(ctx context.Context,effectID,tenant,owner,value string,remove bool)(AuthorityReceipt,error){
	if authority==nil||!authority.database.valid(){return AuthorityReceipt{},ErrPowerDNSDatabaseIsolation};if ctx==nil||!validPowerDNSEffectID(effectID)||!validPowerDNSIdentityValue(tenant,512){return AuthorityReceipt{},ErrInvalidDNS};name,err:=ParseName(owner);if err!=nil||!strings.HasPrefix(name.String(),"_acme-challenge.")||len(value)<32||len(value)>128{return AuthorityReceipt{},ErrInvalidDNS};decoded,decodeErr:=base64.RawURLEncoding.DecodeString(value);if decodeErr!=nil||len(decoded)!=32{return AuthorityReceipt{},ErrInvalidDNS}
	tx,err:=authority.database.database.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return AuthorityReceipt{},err};defer tx.Rollback();rows,err:=tx.QueryContext(ctx,`SELECT d.id,d.name FROM domains d JOIN domainmetadata t ON t.domain_id=d.id AND t.kind=? WHERE t.content=?`,cyberPanelTenantMetadata,tenant);if err!=nil{return AuthorityReceipt{},err};var domainID int64;var zoneName string;for rows.Next(){var candidateID int64;var candidate string;if rows.Scan(&candidateID,&candidate)!=nil{rows.Close();return AuthorityReceipt{},ErrInvalidDNS};if name.String()==candidate||strings.HasSuffix(name.String(),"."+candidate){if len(candidate)>len(zoneName){domainID,zoneName=candidateID,candidate}}};if err=rows.Close();err!=nil{return AuthorityReceipt{},err};if domainID==0{return AuthorityReceipt{},sql.ErrNoRows};spec,err:=powerDNSZoneByDomain(ctx,tx,domainID);if err!=nil||spec.TenantID!=tenant||spec.Name.String()!=zoneName||spec.Mode==ZoneSecondary{return AuthorityReceipt{},ErrDNSConflict}
	canonical:=strconv.Quote(value);changed:=false;if remove{result,deleteErr:=tx.ExecContext(ctx,`DELETE FROM records WHERE domain_id=? AND name=? AND type='TXT' AND content=?`,domainID,name.String(),canonical);err=deleteErr;if err==nil{affected,affectedErr:=result.RowsAffected();if affectedErr!=nil{return AuthorityReceipt{},affectedErr};changed=affected>0}}else{var count uint32;if err=tx.QueryRowContext(ctx,`SELECT COUNT(1) FROM records WHERE domain_id=? AND name=? AND type='TXT' AND content=?`,domainID,name.String(),canonical).Scan(&count);err==nil&&count==0{_,err=tx.ExecContext(ctx,`INSERT INTO records(domain_id,name,type,content,ttl,prio,disabled,auth) VALUES(?,?,?,?,?,?,?,?)`,domainID,name.String(),"TXT",canonical,60,0,false,true);changed=err==nil}};if err!=nil{return AuthorityReceipt{},err}
	serial,err:=currentPowerDNSSOASerial(ctx,tx,domainID);if err!=nil{return AuthorityReceipt{},err};if changed{serial,err=incrementPowerDNSSOASerial(ctx,tx,domainID);if err!=nil{return AuthorityReceipt{},err}};if err=tx.Commit();err!=nil{return AuthorityReceipt{},err};return AuthorityReceipt{EffectID:effectID,ZoneID:spec.ID,Serial:serial,AppliedSets:1,ObservedAt:time.Now().UTC()},nil
}

func currentPowerDNSSOASerial(ctx context.Context,tx *sql.Tx,domainID int64)(uint64,error){var content string;if err:=tx.QueryRowContext(ctx,`SELECT content FROM records WHERE domain_id=? AND type='SOA' LIMIT 1`,domainID).Scan(&content);err!=nil{return 0,err};fields:=strings.Fields(content);if len(fields)!=7{return 0,ErrInvalidDNS};serial,err:=strconv.ParseUint(fields[2],10,64);if err!=nil||serial==0{return 0,ErrInvalidDNS};return serial,nil}
func incrementPowerDNSSOASerial(ctx context.Context,tx *sql.Tx,domainID int64)(uint64,error){var content string;if err:=tx.QueryRowContext(ctx,`SELECT content FROM records WHERE domain_id=? AND type='SOA' LIMIT 1`,domainID).Scan(&content);err!=nil{return 0,err};fields:=strings.Fields(content);if len(fields)!=7{return 0,ErrInvalidDNS};current,err:=strconv.ParseUint(fields[2],10,64);if err!=nil{return 0,ErrInvalidDNS};now:=time.Now().UTC();floor:=uint64(now.Year()*1000000+int(now.Month())*10000+now.Day()*100);serial:=current+1;if serial<floor{serial=floor};fields[2]=strconv.FormatUint(serial,10);result,err:=tx.ExecContext(ctx,`UPDATE records SET content=? WHERE domain_id=? AND type='SOA'`,strings.Join(fields," "),domainID);if err!=nil{return 0,err};affected,err:=result.RowsAffected();if err!=nil||affected!=1{return 0,ErrDNSConflict};return serial,nil}

// ApplyZone replaces the complete authoritative representation of a zone. No
// secret material is returned or included in an error, and every database
// mutation is rolled back when any part of the replacement fails.
func (authority *SecuredPowerDNSAuthority) ApplyZone(ctx context.Context, effectID string, spec ZoneSpec, sets []RecordSet, peers []TransferPeerSpec) (AuthorityReceipt, error) {
	if authority == nil || !authority.database.valid() {
		return AuthorityReceipt{}, ErrPowerDNSDatabaseIsolation
	}
	if ctx == nil || !validPowerDNSEffectID(effectID) {
		return AuthorityReceipt{}, ErrInvalidDNS
	}

	normalizedPeers, err := normalizePowerDNSTransferPeers(peers)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	if err = validateZoneSpec(spec, sets, normalizedPeers); err != nil {
		return AuthorityReceipt{}, err
	}

	keys, err := preparePowerDNSTSIGKeys(ctx, spec.TenantID, normalizedPeers, authority.secrets)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	defer wipePreparedPowerDNSTSIGKeys(keys)

	tx, err := authority.database.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AuthorityReceipt{}, err
	}
	defer tx.Rollback()

	if err = admitPowerDNSZoneApply(ctx, tx, spec); err != nil {
		return AuthorityReceipt{}, err
	}
	domainID, err := ensurePowerDNSDomain(ctx, tx, spec)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	previousKeys, err := powerDNSTSIGNamesForDomain(ctx, tx, domainID)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	if err = reconcilePowerDNSTSIGKeys(ctx, tx, domainID, keys); err != nil {
		return AuthorityReceipt{}, err
	}

	serial, err := replaceSecuredPowerDNSRecords(ctx, tx, domainID, spec, sets)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	if err = applySecuredPowerDNSMetadata(ctx, tx, domainID, spec, normalizedPeers); err != nil {
		return AuthorityReceipt{}, err
	}
	if err = cleanupUnreferencedPowerDNSTSIGKeys(ctx, tx, previousKeys); err != nil {
		return AuthorityReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return AuthorityReceipt{}, err
	}

	return AuthorityReceipt{
		EffectID:    effectID,
		ZoneID:      spec.ID,
		Serial:      serial,
		AppliedSets: uint32(len(sets) + 1),
		ObservedAt:  time.Now().UTC(),
	}, nil
}

// DeleteZone removes the zone and any TSIG keys that no remaining PowerDNS
// metadata references, in the same transaction.
func (authority *SecuredPowerDNSAuthority) DeleteZone(ctx context.Context, effectID string, spec ZoneSpec) (AuthorityReceipt, error) {
	if authority == nil || !authority.database.valid() {
		return AuthorityReceipt{}, ErrPowerDNSDatabaseIsolation
	}
	if ctx == nil || !validPowerDNSEffectID(effectID) || spec.ID == "" || spec.TenantID == "" || spec.Generation == 0 {
		return AuthorityReceipt{}, ErrInvalidDNS
	}

	tx, err := authority.database.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AuthorityReceipt{}, err
	}
	defer tx.Rollback()

	var domainID int64
	domainID, err = exactPowerDNSDomainID(ctx, tx, spec.TenantID, spec.ID)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	stored, err := powerDNSZoneByDomain(ctx, tx, domainID)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	if stored.ID != spec.ID || stored.TenantID != spec.TenantID || stored.Generation != spec.Generation ||
		(spec.Name.String() != "" && stored.Name.String() != spec.Name.String()) {
		return AuthorityReceipt{}, ErrDNSConflict
	}

	keys, err := powerDNSTSIGNamesForDomain(ctx, tx, domainID)
	if err != nil {
		return AuthorityReceipt{}, err
	}
	for _, statement := range []string{
		`DELETE FROM records WHERE domain_id=?`,
		`DELETE FROM domainmetadata WHERE domain_id=?`,
		`DELETE FROM cryptokeys WHERE domain_id=?`,
		`DELETE FROM comments WHERE domain_id=?`,
		`DELETE FROM domains WHERE id=?`,
	} {
		if _, err = tx.ExecContext(ctx, statement, domainID); err != nil {
			return AuthorityReceipt{}, err
		}
	}
	if err = cleanupUnreferencedPowerDNSTSIGKeys(ctx, tx, keys); err != nil {
		return AuthorityReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return AuthorityReceipt{}, err
	}

	return AuthorityReceipt{
		EffectID:   effectID,
		ZoneID:     spec.ID,
		ObservedAt: time.Now().UTC(),
	}, nil
}

type preparedPowerDNSTSIGKey struct {
	name      string
	algorithm TSIGAlgorithm
	secret    []byte
}

type powerDNSTSIGKeyRequest struct {
	name      string
	algorithm TSIGAlgorithm
	secretRef string
}

func normalizePowerDNSTransferPeers(peers []TransferPeerSpec) ([]TransferPeerSpec, error) {
	normalized := append([]TransferPeerSpec(nil), peers...)
	peerIDs := make(map[PeerID]struct{}, len(peers))
	keys := make(map[string]powerDNSTSIGKeyRequest, len(peers))
	for index := range normalized {
		peer := &normalized[index]
		if _, exists := peerIDs[peer.ID]; peer.ID == "" || exists {
			return nil, ErrInvalidDNS
		}
		peerIDs[peer.ID] = struct{}{}
		if !peer.Address.IsValid() || peer.Address.IsUnspecified() || peer.Address.IsMulticast() {
			return nil, ErrInvalidDNS
		}

		if strings.TrimSpace(peer.TSIGName) != peer.TSIGName ||
			!validPowerDNSIdentityValue(peer.TSIGSecretRef, 2048) {
			return nil, ErrInvalidDNS
		}
		name, err := ParseName(peer.TSIGName)
		if err != nil || name.String() == "@" || strings.Contains(name.String(), "*") {
			return nil, ErrInvalidDNS
		}
		peer.TSIGName = name.String()

		request := powerDNSTSIGKeyRequest{name: peer.TSIGName, algorithm: peer.TSIGAlgorithm, secretRef: peer.TSIGSecretRef}
		if existing, exists := keys[request.name]; exists {
			if existing.algorithm != request.algorithm || existing.secretRef != request.secretRef {
				return nil, ErrDNSConflict
			}
		} else {
			keys[request.name] = request
		}
	}
	return normalized, nil
}

func preparePowerDNSTSIGKeys(ctx context.Context, tenant string, peers []TransferPeerSpec, resolver PowerDNSTSIGSecretResolver) ([]preparedPowerDNSTSIGKey, error) {
	if len(peers) == 0 {
		return nil, nil
	}
	if resolver == nil {
		return nil, ErrPowerDNSTSIGSecret
	}

	requestsByName := make(map[string]powerDNSTSIGKeyRequest, len(peers))
	for _, peer := range peers {
		requestsByName[peer.TSIGName] = powerDNSTSIGKeyRequest{
			name:      peer.TSIGName,
			algorithm: peer.TSIGAlgorithm,
			secretRef: peer.TSIGSecretRef,
		}
	}
	names := make([]string, 0, len(requestsByName))
	for name := range requestsByName {
		names = append(names, name)
	}
	sort.Strings(names)

	prepared := make([]preparedPowerDNSTSIGKey, 0, len(names))
	for _, name := range names {
		request := requestsByName[name]
		material, err := resolver.ResolvePowerDNSTSIGSecret(ctx, tenant, request.secretRef)
		if err != nil || len(material) == 0 || base64.StdEncoding.EncodedLen(len(material)) > 255 {
			wipePowerDNSSecret(material)
			wipePreparedPowerDNSTSIGKeys(prepared)
			return nil, ErrPowerDNSTSIGSecret
		}
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(material)))
		base64.StdEncoding.Encode(encoded, material)
		wipePowerDNSSecret(material)
		prepared = append(prepared, preparedPowerDNSTSIGKey{
			name:      request.name,
			algorithm: request.algorithm,
			secret:    encoded,
		})
	}
	return prepared, nil
}

func wipePreparedPowerDNSTSIGKeys(keys []preparedPowerDNSTSIGKey) {
	for index := range keys {
		wipePowerDNSSecret(keys[index].secret)
	}
}

func admitPowerDNSZoneApply(ctx context.Context, tx *sql.Tx, spec ZoneSpec) error {
	var existingID int64
	lookupErr := tx.QueryRowContext(ctx, `SELECT id FROM domains WHERE name=?`, spec.Name.String()).Scan(&existingID)
	if lookupErr == nil {
		current, loadErr := powerDNSZoneByDomain(ctx, tx, existingID)
		if loadErr != nil || current.ID != spec.ID || current.TenantID != spec.TenantID ||
			current.Name.String() != spec.Name.String() || current.Generation+1 != spec.Generation {
			return ErrDNSConflict
		}
	} else if !errors.Is(lookupErr, sql.ErrNoRows) {
		return lookupErr
	} else if spec.Generation != 1 {
		return ErrDNSConflict
	}

	rows,duplicateErr:=tx.QueryContext(ctx,`SELECT DISTINCT d.id,d.name FROM domains d JOIN domainmetadata m ON m.domain_id=d.id AND m.kind=? AND m.content=? ORDER BY d.id LIMIT 2`,cyberPanelZoneIDMetadata,spec.ID);if duplicateErr!=nil{return duplicateErr};defer rows.Close();matches:=0;for rows.Next(){var domainID int64;var otherName string;if duplicateErr=rows.Scan(&domainID,&otherName);duplicateErr!=nil{return duplicateErr};matches++;if otherName!=spec.Name.String()||existingID!=0&&domainID!=existingID{return ErrDNSConflict}};if duplicateErr=rows.Err();duplicateErr!=nil{return duplicateErr};if matches>1{return ErrDNSConflict}
	return nil
}

func replaceSecuredPowerDNSRecords(ctx context.Context, tx *sql.Tx, domainID int64, spec ZoneSpec, sets []RecordSet) (uint64, error) {
	serial, err := nextSerial(ctx, tx, domainID, spec)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM records WHERE domain_id=?`, domainID); err != nil {
		return 0, err
	}

	soa := fmt.Sprintf("%s %s %d %d %d %d %d", spec.SOA.Primary.FQDN(), spec.SOA.Hostmaster.FQDN(), serial, spec.SOA.Refresh, spec.SOA.Retry, spec.SOA.Expire, spec.SOA.Minimum)
	if _, err = tx.ExecContext(ctx, `INSERT INTO records(domain_id,name,type,content,ttl,prio,disabled,auth) VALUES(?,?,?,?,?,?,?,?)`, domainID, spec.Name.String(), "SOA", soa, spec.SOA.DefaultTTL, 0, false, true); err != nil {
		return 0, err
	}

	for _, set := range sets {
		canonical, canonicalErr := set.Canonical(spec.Name)
		if canonicalErr != nil {
			return 0, canonicalErr
		}
		owner := absoluteOwner(canonical.Owner, spec.Name)
		for _, record := range canonical.Records {
			content, priority := powerDNSContent(canonical.Kind, record)
			if _, err = tx.ExecContext(ctx, `INSERT INTO records(domain_id,name,type,content,ttl,prio,disabled,auth) VALUES(?,?,?,?,?,?,?,?)`, domainID, owner, canonical.Kind, content, canonical.TTL, priority, false, true); err != nil {
				return 0, err
			}
		}
	}
	return serial, nil
}

func applySecuredPowerDNSMetadata(ctx context.Context, tx *sql.Tx, domainID int64, spec ZoneSpec, peers []TransferPeerSpec) error {
	if err := applyPowerDNSMetadata(ctx, tx, domainID, spec, peers); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM domainmetadata WHERE domain_id=? AND kind='ALLOW-NOTIFY-FROM'`, domainID); err != nil {
		return err
	}
	if spec.Mode != ZoneSecondary {
		return nil
	}
	for _, address := range spec.PrimaryAddresses {
		if _, err := tx.ExecContext(ctx, `INSERT INTO domainmetadata(domain_id,kind,content) VALUES(?,?,?)`, domainID, "ALLOW-NOTIFY-FROM", address.String()); err != nil {
			return err
		}
	}
	return nil
}

func powerDNSTSIGNamesForDomain(ctx context.Context, tx *sql.Tx, domainID int64) (map[string]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT content FROM domainmetadata WHERE domain_id=? AND kind IN ('TSIG-ALLOW-AXFR','AXFR-MASTER-TSIG')`, domainID)
	if err != nil {
		return nil, ErrPowerDNSTSIGState
	}
	defer rows.Close()

	names := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil || name == "" || len(name) > 255 || strings.ContainsAny(name, "\x00\r\n") {
			return nil, ErrPowerDNSTSIGState
		}
		names[name] = struct{}{}
	}
	if rows.Err() != nil {
		return nil, ErrPowerDNSTSIGState
	}
	return names, nil
}

func reconcilePowerDNSTSIGKeys(ctx context.Context, tx *sql.Tx, domainID int64, keys []preparedPowerDNSTSIGKey) error {
	for _, key := range keys {
		rows, err := tx.QueryContext(ctx, `SELECT algorithm,secret FROM tsigkeys WHERE name=? ORDER BY id`, key.name)
		if err != nil {
			return ErrPowerDNSTSIGState
		}

		total := 0
		matching := 0
		for rows.Next() {
			var algorithm string
			var storedSecret []byte
			if err = rows.Scan(&algorithm, &storedSecret); err != nil {
				wipePowerDNSSecret(storedSecret)
				_ = rows.Close()
				return ErrPowerDNSTSIGState
			}
			total++
			if algorithm == string(key.algorithm) && len(storedSecret) == len(key.secret) &&
				subtle.ConstantTimeCompare(storedSecret, key.secret) == 1 {
				matching++
			}
			wipePowerDNSSecret(storedSecret)
		}
		rowsErr := rows.Err()
		_ = rows.Close()
		if rowsErr != nil {
			return ErrPowerDNSTSIGState
		}
		if total == 1 && matching == 1 {
			continue
		}

		var otherReferences int64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM domainmetadata WHERE domain_id<>? AND kind IN ('TSIG-ALLOW-AXFR','AXFR-MASTER-TSIG','TSIG-ALLOW-DNSUPDATE') AND content=?`, domainID, key.name).Scan(&otherReferences); err != nil {
			return ErrPowerDNSTSIGState
		}
		if otherReferences != 0 {
			return ErrDNSConflict
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM tsigkeys WHERE name=?`, key.name); err != nil {
			return ErrPowerDNSTSIGState
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO tsigkeys(name,algorithm,secret) VALUES(?,?,?)`, key.name, key.algorithm, key.secret); err != nil {
			return ErrPowerDNSTSIGState
		}
	}
	return nil
}

func cleanupUnreferencedPowerDNSTSIGKeys(ctx context.Context, tx *sql.Tx, candidates map[string]struct{}) error {
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := tx.ExecContext(ctx, `DELETE FROM tsigkeys WHERE name=? AND NOT EXISTS (SELECT 1 FROM domainmetadata WHERE kind IN ('TSIG-ALLOW-AXFR','AXFR-MASTER-TSIG','TSIG-ALLOW-DNSUPDATE') AND content=?)`, name, name); err != nil {
			return ErrPowerDNSTSIGState
		}
	}
	return nil
}

func validPowerDNSEffectID(effectID string) bool {
	return validPowerDNSIdentityValue(effectID, 2048)
}
