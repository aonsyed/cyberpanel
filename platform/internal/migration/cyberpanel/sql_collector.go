package cyberpanel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SupplementalCollector owns host-only discovery that is not represented in
// CyberPanel's Django/MariaDB schema. Its methods are typed deliberately: the
// remote caller cannot supply a path, query, command, or executable.
type SupplementalCollector interface {
	CollectCertificates(context.Context, []SiteRecord) ([]CertificateRecord, error)
	CollectCredentials(context.Context, []SiteRecord, []CredentialRecord) ([]CredentialRecord, error)
	CollectSchedules(context.Context, []SiteRecord) ([]ScheduleRecord, error)
	CollectRepositories(context.Context, []SiteRecord) ([]RepositoryRecord, error)
	CollectMailExtensions(context.Context, []MailDomainRecord) ([]MailDomainRecord, error)
}

type SQLCollectorConfig struct {
	Database *sql.DB
	InstallationID string
	Supplemental SupplementalCollector
	Clock func() time.Time
}

type SQLCollector struct {
	database *sql.DB
	installationID string
	supplemental SupplementalCollector
	clock func() time.Time
}

func NewSQLCollector(config SQLCollectorConfig) (*SQLCollector, error) {
	if config.Database == nil || strings.TrimSpace(config.InstallationID) == "" {
		return nil, ErrInvalid
	}
	if config.Clock == nil { config.Clock = time.Now }
	return &SQLCollector{database: config.Database, installationID: config.InstallationID, supplemental: config.Supplemental, clock: config.Clock}, nil
}

func (c *SQLCollector) Collect(ctx context.Context, request CollectRequest) (Snapshot, error) {
	if c == nil || c.database == nil || ctx == nil || !request.MigrationID.Valid() || !request.Selection.any() {
		return Snapshot{}, ErrInvalid
	}
	tx, err := c.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil { return Snapshot{}, err }
	defer tx.Rollback()
	snapshot := Snapshot{InstallationID: c.installationID, ObservedAt: c.clock().UTC()}
	if request.Selection.Sites || request.Selection.Databases || request.Selection.Mail || request.Selection.Credentials || request.Selection.Schedules || request.Selection.Repositories || request.Selection.Containers || request.Selection.BackupPolicies || request.Selection.Certificates || request.Selection.DNS&&len(request.SiteSourceIDs)!=0 {
		if err:=validateCyberPanelSiteSelection(request.SiteSourceIDs);err!=nil{return Snapshot{},err}
		snapshot.Sites, err = collectSites(ctx, tx, request.SiteSourceIDs)
		if err != nil { return Snapshot{}, err }
	}
	if request.Selection.Databases {
		snapshot.Databases, err = collectDatabases(ctx, tx, snapshot.Sites)
		if err != nil { return Snapshot{}, err }
	}
	if request.Selection.DNS {
		snapshot.DNSZones, err = collectDNS(ctx, tx, snapshot.Sites, len(request.SiteSourceIDs) != 0)
		if err != nil { return Snapshot{}, err }
	}
	if request.Selection.Mail {
		snapshot.MailDomains, err = collectMail(ctx, tx, snapshot.Sites)
		if err != nil { return Snapshot{}, err }
		if c.supplemental != nil {
			snapshot.MailDomains, err = c.supplemental.CollectMailExtensions(ctx, snapshot.MailDomains)
			if err != nil { return Snapshot{}, err }
		}
	}
	if request.Selection.Credentials {
		snapshot.Credentials, err = collectFTP(ctx, tx, snapshot.Sites)
		if err != nil { return Snapshot{}, err }
		if c.supplemental != nil {
			snapshot.Credentials, err = c.supplemental.CollectCredentials(ctx, snapshot.Sites, snapshot.Credentials)
			if err != nil { return Snapshot{}, err }
		}
	}
	if request.Selection.Containers {
		snapshot.Containers, err = collectContainers(ctx, tx, snapshot.Sites)
		if err != nil { return Snapshot{}, err }
	}
	if request.Selection.BackupPolicies {
		snapshot.BackupPolicies, err = collectBackupPolicies(ctx, tx, snapshot.Sites)
		if err != nil { return Snapshot{}, err }
	}
	if c.supplemental != nil {
		if request.Selection.Certificates {
			snapshot.Certificates, err = c.supplemental.CollectCertificates(ctx, snapshot.Sites)
			if err != nil { return Snapshot{}, err }
		}
		if request.Selection.Schedules {
			snapshot.Schedules, err = c.supplemental.CollectSchedules(ctx, snapshot.Sites)
			if err != nil { return Snapshot{}, err }
		}
		if request.Selection.Repositories {
			snapshot.Repositories, err = c.supplemental.CollectRepositories(ctx, snapshot.Sites)
			if err != nil { return Snapshot{}, err }
		}
	}
	if err := tx.Commit(); err != nil { return Snapshot{}, err }
	stable := snapshot
	stable.ObservedAt = time.Time{}
	stable.Revision = ""
	normalizeSnapshot(&stable)
	raw, err := json.Marshal(stable)
	if err != nil { return Snapshot{}, err }
	sum := sha256.Sum256(raw)
	snapshot.Revision = hex.EncodeToString(sum[:])
	return snapshot, nil
}

func validateCyberPanelSiteSelection(values []string)error{for _,value:=range values{if !strings.HasPrefix(value,"website:"){return ErrDenied};number:=strings.TrimPrefix(value,"website:");parsed,err:=strconv.ParseUint(number,10,63);if err!=nil||parsed==0||strconv.FormatUint(parsed,10)!=number{return ErrDenied}};return nil}

func collectSites(ctx context.Context, tx *sql.Tx, selected []string) ([]SiteRecord, error) {
	allowed := make(map[string]struct{}, len(selected))
	for _, id := range selected { allowed[id] = struct{}{} }
	rows, err := tx.QueryContext(ctx, `SELECT w.id, w.admin_id, w.package_id, w.domain, w.phpSelection, w.state, w.externalApp,
		COALESCE(p.diskSpace,0), COALESCE(p.bandwidth,0), COALESCE(p.memoryLimitMB,0), COALESCE(p.cpuCores,0),
		COALESCE(p.ioLimitMBPS,0), COALESCE(p.maxConnections,0)
		FROM websiteFunctions_websites w JOIN packages_package p ON p.id=w.package_id ORDER BY w.id`)
	if err != nil { return nil, err }
	defer rows.Close()
	values := []SiteRecord{}
	mainDomains := map[int64]string{}
	mainIncluded := map[int64]bool{}
	for rows.Next() {
		var id, ownerID, packageID, diskMB, transferMB, memoryMB, cpuCores, ioMBPS, maxConnections int64
		var domain, phpVersion, externalApp string
		var state int
		if err := rows.Scan(&id, &ownerID, &packageID, &domain, &phpVersion, &state, &externalApp, &diskMB, &transferMB, &memoryMB, &cpuCores, &ioMBPS, &maxConnections); err != nil { return nil, err }
		sourceID := "website:"+strconv.FormatInt(id, 10)
		mainDomains[id] = normalizeHostname(domain)
		_, include := allowed[sourceID]
		if len(allowed) == 0 { include = true }
		mainIncluded[id] = include
		if !include { continue }
		values = append(values, SiteRecord{SourceID: sourceID, OwnerSourceID: "administrator:"+strconv.FormatInt(ownerID,10), PackageSourceID: "package:"+strconv.FormatInt(packageID,10), PrimaryHostname: normalizeHostname(domain), PHPVersion: normalizePHPVersion(phpVersion), DocumentRootRelative: "public_html", RuntimeKind: "php_lsapi", RuntimeUser: externalApp, Enabled: state == 1, DiskBytes: megabytes(diskMB), TransferBytes: megabytes(transferMB), MemoryBytes: megabytes(memoryMB), CPUMilli: positive(cpuCores)*1000, IOBytesPerSecond: megabytes(ioMBPS), MaxConnections: positive(maxConnections), ContentArtifact: ArtifactID("site-content:website:"+strconv.FormatInt(id,10))})
	}
	if err := rows.Err(); err != nil { return nil, err }
	childRows, err := tx.QueryContext(ctx, `SELECT id, master_id, domain, path, ssl, phpSelection, alais FROM websiteFunctions_childdomains ORDER BY id`)
	if err != nil { return nil, err }
	defer childRows.Close()
	childByParent := map[string][]string{}
	legacyChildAliases:=map[string][]string{}
	for childRows.Next() {
		var id, masterID int64
		var domain, path, phpVersion string
		var sslEnabled, alias int
		if err := childRows.Scan(&id, &masterID, &domain, &path, &sslEnabled, &phpVersion, &alias); err != nil { return nil, err }
		sourceID := "child:"+strconv.FormatInt(id,10)
		_, explicitlySelected := allowed[sourceID]
		if len(allowed) != 0 && !explicitlySelected && !mainIncluded[masterID] { continue }
		parentID := "website:"+strconv.FormatInt(masterID,10)
		hostname := normalizeHostname(domain)
		if alias != 0 {legacyChildAliases[parentID]=append(legacyChildAliases[parentID],hostname);continue }
		childByParent[parentID] = append(childByParent[parentID], hostname)
		values = append(values, SiteRecord{SourceID: sourceID, ParentSourceID: parentID, PrimaryHostname: hostname, PHPVersion: normalizePHPVersion(phpVersion), DocumentRootRelative: relativeDocumentRoot(mainDomains[masterID], path, hostname), RuntimeKind: "php_lsapi", Enabled: true, ContentArtifact: ArtifactID("site-content:child:"+strconv.FormatInt(id,10))})
		_ = sslEnabled
	}
	if err := childRows.Err(); err != nil { return nil, err }
	aliasRows, err := tx.QueryContext(ctx, `SELECT id, master_id, aliasDomain FROM websiteFunctions_aliasdomains ORDER BY id`)
	if err != nil { return nil, err }
	defer aliasRows.Close()
	aliases := map[string][]string{}
	for aliasRows.Next() {
		var id, masterID int64
		var hostname string
		if err := aliasRows.Scan(&id, &masterID, &hostname); err != nil { return nil, err }
		aliases["website:"+strconv.FormatInt(masterID,10)] = append(aliases["website:"+strconv.FormatInt(masterID,10)], normalizeHostname(hostname))
		_ = id
	}
	if err := aliasRows.Err(); err != nil { return nil, err }
	for parent,values:=range legacyChildAliases{aliases[parent]=append(aliases[parent],values...)}
	for index := range values {
		values[index].Aliases = aliases[values[index].SourceID]
		values[index].ChildHostnames = childByParent[values[index].SourceID]
	}
	return values, nil
}

func collectDatabases(ctx context.Context, tx *sql.Tx, sites []SiteRecord) ([]DatabaseRecord, error) {
	allowed := selectedMainDatabaseIDs(sites)
	rows, err := tx.QueryContext(ctx, `SELECT d.id, d.website_id, d.dbName, d.dbUser,
		COALESCE(MAX(CASE WHEN m.key='charset' THEN m.value END),'utf8mb4'),
		COALESCE(MAX(CASE WHEN m.key='collation' THEN m.value END),'utf8mb4_unicode_ci')
		FROM databases_databases d LEFT JOIN databases_dbmeta m ON m.database_id=d.id
		GROUP BY d.id,d.website_id,d.dbName,d.dbUser ORDER BY d.id`)
	if err != nil { return nil, err }
	defer rows.Close()
	values := []DatabaseRecord{}
	for rows.Next() {
		var id, websiteID int64
		var name, username, charset, collation string
		if err := rows.Scan(&id, &websiteID, &name, &username, &charset, &collation); err != nil { return nil, err }
		siteID, include := allowed[websiteID]
		if !include { continue }
		principals:=[]DatabasePrincipalRecord{{Name: username, GrantSets: []string{"ALL PRIVILEGES"}, Password: lookupSecretRef("database-password",username)}}
		principalRows,queryErr:=tx.QueryContext(ctx,`SELECT username FROM databases_databasesusers WHERE owner_id=? ORDER BY username`,id)
		if queryErr!=nil{return nil,queryErr}
		seenPrincipals:=map[string]struct{}{strings.ToLower(username):{}}
		for principalRows.Next(){var additional string;if scanErr:=principalRows.Scan(&additional);scanErr!=nil{principalRows.Close();return nil,scanErr};key:=strings.ToLower(additional);if _,duplicate:=seenPrincipals[key];duplicate{continue};seenPrincipals[key]=struct{}{};principals=append(principals,DatabasePrincipalRecord{Name:additional,GrantSets:[]string{"ALL PRIVILEGES"},Password:lookupSecretRef("database-password",additional)})}
		if principalErr:=principalRows.Err();principalErr!=nil{principalRows.Close();return nil,principalErr};principalRows.Close()
		values = append(values, DatabaseRecord{SourceID: "database:"+strconv.FormatInt(id,10), SiteSourceID: siteID, Name: name, Charset: charset, Collation: collation, DumpArtifact: ArtifactID("database-dump:database:"+strconv.FormatInt(id,10)), Principals: principals})
	}
	return values, rows.Err()
}

func collectDNS(ctx context.Context, tx *sql.Tx, sites []SiteRecord, restricted bool) ([]DNSZoneRecord, error) {
	hostnames := siteHostnames(sites)
	rows, err := tx.QueryContext(ctx, `SELECT d.id,d.name,d.type,
		CASE WHEN EXISTS(SELECT 1 FROM cryptokeys k WHERE k.domain_id=d.id AND k.active=1) THEN 1 ELSE 0 END
		FROM domains d ORDER BY d.id`)
	if err != nil { return nil, err }
	defer rows.Close()
	type zoneIdentity struct { id int64; value DNSZoneRecord }
	zones := []zoneIdentity{}
	for rows.Next() {
		var id int64
		var name, mode string
		var dnssec int
		if err := rows.Scan(&id,&name,&mode,&dnssec); err != nil { return nil, err }
		name = normalizeHostname(name)
		if restricted && !zoneMatchesSites(name, hostnames) { continue }
		zones = append(zones, zoneIdentity{id:id,value:DNSZoneRecord{SourceID:"dns-zone:"+strconv.FormatInt(id,10),Name:name,Mode:normalizeDNSMode(mode),DNSSEC:dnssec!=0}})
	}
	if err := rows.Err(); err != nil { return nil, err }
	for index := range zones {
		recordRows, queryErr := tx.QueryContext(ctx, `SELECT name,type,content,COALESCE(ttl,3600),COALESCE(prio,0) FROM records WHERE domain_id=? AND COALESCE(disabled,0)=0 ORDER BY name,type,ttl,prio,content`, zones[index].id)
		if queryErr != nil { return nil, queryErr }
		sets := map[string]*DNSRecordSet{}
		for recordRows.Next() {
			var name, recordType, content string
			var ttl uint32
			var priority int
			if scanErr := recordRows.Scan(&name,&recordType,&content,&ttl,&priority); scanErr != nil { recordRows.Close(); return nil, scanErr }
			if ttl==0{ttl=3600}
			key := normalizeDNSName(name)+"\x00"+strings.ToUpper(recordType)
			set := sets[key]
			if set == nil { set=&DNSRecordSet{Name:normalizeDNSName(name),Type:strings.ToUpper(recordType),TTL:ttl}; sets[key]=set }else if ttl>0&&ttl<set.TTL{set.TTL=ttl}
			if priority > 0 && (set.Type == "MX" || set.Type == "SRV") { content = strconv.Itoa(priority)+" "+content }
			set.Values = append(set.Values, strings.TrimSpace(content))
		}
		if recordErr := recordRows.Err(); recordErr != nil { recordRows.Close(); return nil, recordErr }
		recordRows.Close()
		for _, set := range sets { sort.Strings(set.Values); zones[index].value.RecordSets=append(zones[index].value.RecordSets,*set) }
		sort.Slice(zones[index].value.RecordSets,func(i,j int)bool{left,right:=zones[index].value.RecordSets[i],zones[index].value.RecordSets[j];return left.Name+left.Type+strconv.FormatUint(uint64(left.TTL),10)<right.Name+right.Type+strconv.FormatUint(uint64(right.TTL),10)})
	}
	values:=make([]DNSZoneRecord,0,len(zones));for _,zone:=range zones{values=append(values,zone.value)};return values,nil
}

func collectMail(ctx context.Context, tx *sql.Tx, sites []SiteRecord) ([]MailDomainRecord, error) {
	mainSites, childSites := selectedSiteDatabaseIDs(sites)
	rows, err := tx.QueryContext(ctx, `SELECT domain,domainOwner_id,childOwner_id FROM e_domains ORDER BY domain`)
	if err != nil { return nil, err }
	defer rows.Close()
	values := []MailDomainRecord{}
	for rows.Next() {
		var domain string
		var mainID, childID sql.NullInt64
		if err := rows.Scan(&domain,&mainID,&childID); err != nil { return nil, err }
		siteID := ""
		if mainID.Valid { siteID = mainSites[mainID.Int64] }
		if siteID == "" && childID.Valid { siteID = childSites[childID.Int64] }
		if siteID == "" { continue }
		domain = normalizeHostname(domain)
		mailDomain := MailDomainRecord{SourceID:"mail-domain:"+safeOpaque(domain),SiteSourceID:siteID,Name:domain}
		mailboxRows, queryErr := tx.QueryContext(ctx, `SELECT email,mail FROM e_users WHERE emailOwner_id=? ORDER BY email`, domain)
		if queryErr != nil { return nil, queryErr }
		for mailboxRows.Next() {
			var address,mailLocation string
			if scanErr := mailboxRows.Scan(&address,&mailLocation); scanErr != nil { mailboxRows.Close(); return nil, scanErr }
			mailboxID := "mailbox:"+safeOpaque(strings.ToLower(address))
			mailDomain.Mailboxes=append(mailDomain.Mailboxes,MailboxRecord{SourceID:mailboxID,Address:strings.ToLower(address),Format:mailboxFormat(mailLocation),Password:lookupSecretRef("mailbox-password",address),DataArtifact:ArtifactID("mailbox-data:"+safeOpaque(strings.ToLower(address)))})
		}
		if mailboxErr:=mailboxRows.Err();mailboxErr!=nil{mailboxRows.Close();return nil,mailboxErr};mailboxRows.Close()
		values=append(values,mailDomain)
	}
	if err:=rows.Err();err!=nil{return nil,err}
	forwardRows,err:=tx.QueryContext(ctx,`SELECT source,destination FROM e_forwardings ORDER BY source,destination`)
	if err!=nil{return nil,err};defer forwardRows.Close()
	byDomain:=map[string]*MailDomainRecord{};for index:=range values{byDomain[values[index].Name]=&values[index]}
	for forwardRows.Next(){var source,destination string;if err:=forwardRows.Scan(&source,&destination);err!=nil{return nil,err};parts:=strings.Split(strings.ToLower(source),"@");if len(parts)!=2{continue};if domain:=byDomain[parts[1]];domain!=nil{entry:=source+" -> "+destination;domain.Forwarders=append(domain.Forwarders,entry)}}
	if err:=forwardRows.Err();err!=nil{return nil,err}
	if present,err:=legacyTablePresent(ctx,tx,"e_catchall");err!=nil{return nil,err}else if present{catchRows,err:=tx.QueryContext(ctx,`SELECT domain_id,destination,enabled FROM e_catchall ORDER BY domain_id`);if err!=nil{return nil,err};for catchRows.Next(){var domainName,destination string;var enabled bool;if err:=catchRows.Scan(&domainName,&destination,&enabled);err!=nil{catchRows.Close();return nil,err};if domain:=byDomain[normalizeHostname(domainName)];domain!=nil&&enabled{domain.CatchAll=append(domain.CatchAll,destination)}};if err:=catchRows.Err();err!=nil{catchRows.Close();return nil,err};catchRows.Close()}
	if present,err:=legacyTablePresent(ctx,tx,"e_pattern_forwarding");err!=nil{return nil,err}else if present{patternRows,err:=tx.QueryContext(ctx,`SELECT domain_id,pattern,destination,pattern_type,priority,enabled FROM e_pattern_forwarding ORDER BY domain_id,priority,id`);if err!=nil{return nil,err};for patternRows.Next(){var domainName,pattern,destination,patternType string;var priority int;var enabled bool;if err:=patternRows.Scan(&domainName,&pattern,&destination,&patternType,&priority,&enabled);err!=nil{patternRows.Close();return nil,err};if domain:=byDomain[normalizeHostname(domainName)];domain!=nil&&enabled{domain.Forwarders=append(domain.Forwarders,patternType+":"+pattern+" -> "+destination)}};if err:=patternRows.Err();err!=nil{patternRows.Close();return nil,err};patternRows.Close()}
	if present,err:=legacyTablePresent(ctx,tx,"e_pipeprograms");err!=nil{return nil,err}else if present{pipeRows,err:=tx.QueryContext(ctx,`SELECT source,destination FROM e_pipeprograms ORDER BY source`);if err!=nil{return nil,err};for pipeRows.Next(){var source,destination string;if err:=pipeRows.Scan(&source,&destination);err!=nil{pipeRows.Close();return nil,err};parts:=strings.Split(strings.ToLower(source),"@");if len(parts)==2{if domain:=byDomain[parts[1]];domain!=nil{domain.Forwarders=append(domain.Forwarders,"pipe:"+source+" -> "+destination)}}};if err:=pipeRows.Err();err!=nil{pipeRows.Close();return nil,err};pipeRows.Close()}
	return values,nil
}

func legacyTablePresent(ctx context.Context,tx *sql.Tx,name string)(bool,error){return tablePresent(ctx,tx,name)}

func collectFTP(ctx context.Context, tx *sql.Tx, sites []SiteRecord) ([]CredentialRecord, error) {
	mainSites,_:=selectedSiteDatabaseIDs(sites)
	rows,err:=tx.QueryContext(ctx,`SELECT ID,domain_id,User,Dir,Status FROM users ORDER BY ID`);if err!=nil{return nil,err};defer rows.Close()
	values:=[]CredentialRecord{}
	for rows.Next(){var id,websiteID int64;var username,directory,status string;if err:=rows.Scan(&id,&websiteID,&username,&directory,&status);err!=nil{return nil,err};siteID:=mainSites[websiteID];if siteID==""{continue};relative,ok:=relativeHomePath(siteHostname(sites,siteID),directory);if !ok{return nil,ErrInvalid};values=append(values,CredentialRecord{SourceID:"ftp:"+strconv.FormatInt(id,10),SiteSourceID:siteID,Kind:"ftps",Label:username,RootRelative:relative,Secret:lookupSecretRef("ftp-password",username)});_ = status}
	return values,rows.Err()
}

func collectContainers(ctx context.Context, tx *sql.Tx, sites []SiteRecord) ([]ContainerRecord,error){
	mainSites,_:=selectedSiteDatabaseIDs(sites);rows,err:=tx.QueryContext(ctx,`SELECT id,admin_id,SiteType,SiteName FROM websiteFunctions_dockersites ORDER BY id`);if err!=nil{return nil,err};defer rows.Close();values:=[]ContainerRecord{}
	for rows.Next(){var id,websiteID int64;var siteType int;var name string;if err:=rows.Scan(&id,&websiteID,&siteType,&name);err!=nil{return nil,err};siteID:=mainSites[websiteID];if siteID==""{continue};recipe:="cyberpanel-wordpress";if siteType!=0{recipe="cyberpanel-legacy-application"};values=append(values,ContainerRecord{SourceID:"container:"+strconv.FormatInt(id,10),SiteSourceID:siteID,RecipeID:recipe,RecipeVersion:"legacy-v1",DescriptorArtifact:ArtifactID("container-descriptor:"+strconv.FormatInt(id,10)),VolumeArtifacts:[]ArtifactID{ArtifactID("container-volumes:"+strconv.FormatInt(id,10))}});_ = name}
	return values,rows.Err()
}

func collectBackupPolicies(ctx context.Context, tx *sql.Tx, sites []SiteRecord)([]BackupPolicyRecord,error){
	values:=[]BackupPolicyRecord{}
	collectors:=[]struct{table string;collect func(context.Context,*sql.Tx,[]SiteRecord)([]BackupPolicyRecord,error)}{
		{table:"websiteFunctions_backupschedules",collect:collectLegacyBackupPolicies},
		{table:"websiteFunctions_normalbackupjobs",collect:collectNormalBackupPolicies},
		{table:"IncBackups_backupjob",collect:collectIncrementalBackupPolicies},
		{table:"websiteFunctions_gdrive",collect:collectGoogleDriveBackupPolicies},
		{table:"websiteFunctions_remotebackupschedule",collect:collectRemoteBackupPolicies},
	}
	for _,collector:=range collectors{
		present,err:=tablePresent(ctx,tx,collector.table)
		if err!=nil{return nil,err}
		if !present{continue}
		collected,err:=collector.collect(ctx,tx,sites)
		if err!=nil{return nil,err}
		values=append(values,collected...)
	}
	sort.Slice(values,func(i,j int)bool{return values[i].SourceID<values[j].SourceID})
	return values,nil
}

func collectLegacyBackupPolicies(ctx context.Context,tx *sql.Tx,sites []SiteRecord)([]BackupPolicyRecord,error){
	rows,err:=tx.QueryContext(ctx,`SELECT s.id,d.destLoc,s.frequency FROM websiteFunctions_backupschedules s JOIN websiteFunctions_dest d ON d.id=s.dest_id ORDER BY s.id`)
	if err!=nil{return nil,err}
	defer rows.Close()
	type schedule struct{id int64;destination,frequency string}
	schedules:=[]schedule{}
	for rows.Next(){var value schedule;if err:=rows.Scan(&value.id,&value.destination,&value.frequency);err!=nil{return nil,err};schedules=append(schedules,value)}
	if err:=rows.Err();err!=nil{return nil,err}
	values:=[]BackupPolicyRecord{}
	for _,site:=range sites{if site.ParentSourceID!=""{continue};for _,schedule:=range schedules{values=append(values,BackupPolicyRecord{SourceID:"backup-policy:legacy:"+strconv.FormatInt(schedule.id,10)+":"+safeOpaque(site.SourceID),SiteSourceID:site.SourceID,Schedule:legacyBackupSchedule(schedule.frequency),Retention:"source-default",Provider:legacyBackupProvider(schedule.destination),Repository:safeBackupRepository(schedule.destination)})}}
	return values,nil
}

func collectNormalBackupPolicies(ctx context.Context,tx *sql.Tx,sites []SiteRecord)([]BackupPolicyRecord,error){
	rows,err:=tx.QueryContext(ctx,`SELECT j.id,j.name,j.config,d.id,d.name,d.config FROM websiteFunctions_normalbackupjobs j JOIN websiteFunctions_normalbackupdests d ON d.id=j.owner_id ORDER BY j.id`)
	if err!=nil{return nil,err}
	defer rows.Close()
	type job struct{id,destinationID int64;name,config,destination,destinationConfig string}
	jobs:=[]job{}
	for rows.Next(){var value job;if err:=rows.Scan(&value.id,&value.name,&value.config,&value.destinationID,&value.destination,&value.destinationConfig);err!=nil{return nil,err};jobs=append(jobs,value)}
	if err:=rows.Err();err!=nil{return nil,err}
	assigned:=map[int64]map[int64]struct{}{}
	if present,err:=tablePresent(ctx,tx,"websiteFunctions_normalbackupsites");err!=nil{return nil,err}else if present{
		siteRows,err:=tx.QueryContext(ctx,`SELECT owner_id,domain_id FROM websiteFunctions_normalbackupsites ORDER BY owner_id,domain_id`)
		if err!=nil{return nil,err}
		for siteRows.Next(){var jobID,websiteID int64;if err:=siteRows.Scan(&jobID,&websiteID);err!=nil{siteRows.Close();return nil,err};if assigned[jobID]==nil{assigned[jobID]=map[int64]struct{}{}};assigned[jobID][websiteID]=struct{}{}}
		if err:=siteRows.Err();err!=nil{siteRows.Close();return nil,err}
		siteRows.Close()
	}
	mainSites:=selectedMainDatabaseIDs(sites)
	values:=[]BackupPolicyRecord{}
	for _,job:=range jobs{
		config,err:=decodeBackupConfig(job.config)
		if err!=nil{return nil,err}
		destinationConfig,err:=decodeBackupConfig(job.destinationConfig)
		if err!=nil{return nil,err}
		schedule:=legacyBackupSchedule(backupConfigString(config,"frequency"))
		if schedule==""{schedule="manual"}
		retention:=backupConfigString(config,"retention")
		if retention==""{retention="source-default"}
		provider:=legacyBackupProvider(firstNonEmptyString(backupConfigString(destinationConfig,"type","provider"),job.destination))
		repository:=backupRepositoryDescriptor(job.destination,destinationConfig)
		credential:=SecretRef("")
		if backupConfigHasSecret(destinationConfig){credential=SecretRef("backup-normal-destination:"+strconv.FormatInt(job.destinationID,10))}
		allSites:=strings.EqualFold(backupConfigString(config,"allSites","all_sites"),"all")
		for websiteID,siteID:=range mainSites{if _,selected:=assigned[job.id][websiteID];!allSites&&!selected{continue};values=append(values,BackupPolicyRecord{SourceID:"backup-policy:normal:"+strconv.FormatInt(job.id,10)+":"+safeOpaque(siteID),SiteSourceID:siteID,Schedule:schedule,Retention:retention,Provider:provider,Repository:repository,Credential:credential})}
	}
	return values,nil
}

func collectIncrementalBackupPolicies(ctx context.Context,tx *sql.Tx,sites []SiteRecord)([]BackupPolicyRecord,error){
	rows,err:=tx.QueryContext(ctx,`SELECT j.id,j.destination,j.frequency,COALESCE(j.retention,0),s.website FROM IncBackups_backupjob j JOIN IncBackups_jobsites s ON s.job_id=j.id ORDER BY j.id,s.id`)
	if err!=nil{return nil,err}
	defer rows.Close()
	byHostname:=siteIDsByHostname(sites)
	values:=[]BackupPolicyRecord{}
	seen:=map[string]struct{}{}
	for rows.Next(){var id,retention int64;var destination,frequency,hostname string;if err:=rows.Scan(&id,&destination,&frequency,&retention,&hostname);err!=nil{return nil,err};siteID:=byHostname[normalizeHostname(hostname)];if siteID==""{continue};identity:=strconv.FormatInt(id,10)+"\x00"+siteID;if _,duplicate:=seen[identity];duplicate{continue};seen[identity]=struct{}{};retentionValue:="unlimited";if retention>0{retentionValue=strconv.FormatInt(retention,10)+" days"};values=append(values,BackupPolicyRecord{SourceID:"backup-policy:incremental:"+strconv.FormatInt(id,10)+":"+safeOpaque(siteID),SiteSourceID:siteID,Schedule:legacyBackupSchedule(frequency),Retention:retentionValue,Provider:legacyBackupProvider(destination),Repository:safeBackupRepository(destination)})}
	return values,rows.Err()
}

func collectGoogleDriveBackupPolicies(ctx context.Context,tx *sql.Tx,sites []SiteRecord)([]BackupPolicyRecord,error){
	rows,err:=tx.QueryContext(ctx,`SELECT g.id,g.name,g.auth,g.runTime,s.domain FROM websiteFunctions_gdrive g JOIN websiteFunctions_gdrivesites s ON s.owner_id=g.id ORDER BY g.id,s.id`)
	if err!=nil{return nil,err}
	defer rows.Close()
	byHostname:=siteIDsByHostname(sites)
	values:=[]BackupPolicyRecord{}
	seen:=map[string]struct{}{}
	for rows.Next(){var id int64;var name,auth,frequency,hostname string;if err:=rows.Scan(&id,&name,&auth,&frequency,&hostname);err!=nil{return nil,err};siteID:=byHostname[normalizeHostname(hostname)];if siteID==""{continue};identity:=strconv.FormatInt(id,10)+"\x00"+siteID;if _,duplicate:=seen[identity];duplicate{continue};seen[identity]=struct{}{};retention:="source-default";credential:=SecretRef("");if strings.TrimSpace(auth)!=""&&!strings.EqualFold(strings.TrimSpace(auth),"inactive"){credential=SecretRef("backup-google-drive-auth:"+strconv.FormatInt(id,10));if config,decodeErr:=decodeBackupConfig(auth);decodeErr==nil{if value:=backupConfigString(config,"FileRetentiontime","retention");value!=""{retention=value}}};values=append(values,BackupPolicyRecord{SourceID:"backup-policy:google-drive:"+strconv.FormatInt(id,10)+":"+safeOpaque(siteID),SiteSourceID:siteID,Schedule:legacyBackupSchedule(frequency),Retention:retention,Provider:"google_drive",Repository:safeBackupRepository(name),Credential:credential})}
	return values,rows.Err()
}

func collectRemoteBackupPolicies(ctx context.Context,tx *sql.Tx,sites []SiteRecord)([]BackupPolicyRecord,error){
	rows,err:=tx.QueryContext(ctx,`SELECT s.id,s.Name,s.timeintervel,s.fileretention,s.config,c.id,c.configtype,c.config,COALESCE(w.owner_id,d.website_id) FROM websiteFunctions_remotebackupschedule s JOIN websiteFunctions_remotebackupconfig c ON c.id=s.RemoteBackupConfig_id JOIN websiteFunctions_remotebackupsites r ON r.owner_id=s.id LEFT JOIN websiteFunctions_wpsites w ON w.id=r.WPsites LEFT JOIN databases_databases d ON d.id=r.database WHERE w.owner_id IS NOT NULL OR d.website_id IS NOT NULL ORDER BY s.id,r.id`)
	if err!=nil{return nil,err}
	defer rows.Close()
	mainSites:=selectedMainDatabaseIDs(sites)
	values:=[]BackupPolicyRecord{}
	seen:=map[string]struct{}{}
	for rows.Next(){var scheduleID,configID,websiteID int64;var name,frequency,retention,scheduleConfigRaw,configType,configRaw string;if err:=rows.Scan(&scheduleID,&name,&frequency,&retention,&scheduleConfigRaw,&configID,&configType,&configRaw,&websiteID);err!=nil{return nil,err};siteID:=mainSites[websiteID];if siteID==""{continue};identity:=strconv.FormatInt(scheduleID,10)+"\x00"+siteID;if _,duplicate:=seen[identity];duplicate{continue};seen[identity]=struct{}{};scheduleConfig,err:=decodeBackupConfig(scheduleConfigRaw);if err!=nil{return nil,err};destinationConfig,err:=decodeBackupConfig(configRaw);if err!=nil{return nil,err};credential:=SecretRef("");if backupConfigHasSecret(destinationConfig){credential=SecretRef("backup-remote-config:"+strconv.FormatInt(configID,10))};values=append(values,BackupPolicyRecord{SourceID:"backup-policy:remote:"+strconv.FormatInt(scheduleID,10)+":"+safeOpaque(siteID),SiteSourceID:siteID,Schedule:legacyBackupSchedule(frequency),Retention:firstNonEmptyString(retention,"source-default"),Provider:legacyBackupProvider(configType),Repository:backupRepositoryDescriptor(name,mergeBackupConfig(destinationConfig,scheduleConfig)),Credential:credential})}
	return values,rows.Err()
}

func selectedMainDatabaseIDs(sites []SiteRecord)map[int64]string{main,_:=selectedSiteDatabaseIDs(sites);return main}
func selectedSiteDatabaseIDs(sites []SiteRecord)(map[int64]string,map[int64]string){main:=map[int64]string{};child:=map[int64]string{};for _,site:=range sites{parts:=strings.Split(site.SourceID,":");if len(parts)!=2{continue};id,err:=strconv.ParseInt(parts[1],10,64);if err!=nil{continue};if parts[0]=="website"{main[id]=site.SourceID}else if parts[0]=="child"{child[id]=site.SourceID}};return main,child}
func siteHostnames(sites []SiteRecord)[]string{values:=[]string{};for _,site:=range sites{values=append(values,site.PrimaryHostname);values=append(values,site.Aliases...)};return normalizedHostnames(values)}
func zoneMatchesSites(zone string,sites []string)bool{for _,site:=range sites{if site==zone||strings.HasSuffix(site,"."+zone){return true}};return false}
func siteHostname(sites []SiteRecord,id string)string{for _,site:=range sites{if site.SourceID==id{return site.PrimaryHostname}};return ""}
func siteIDsByHostname(sites []SiteRecord)map[string]string{values:=map[string]string{};for _,site:=range sites{values[normalizeHostname(site.PrimaryHostname)]=site.SourceID;for _,alias:=range site.Aliases{values[normalizeHostname(alias)]=site.SourceID}};return values}
func normalizePHPVersion(value string)string{value=strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(value),"PHP"));value=strings.TrimSpace(value);if value==""||strings.EqualFold(value,"inherit"){return "8.3"};digits:=[]rune{};for _,character:=range value{if character>='0'&&character<='9'{digits=append(digits,character)}};if len(digits)>=2{return string(digits[0])+"."+string(digits[1:])};return value}
func relativeDocumentRoot(masterDomain,path,child string)string{relative,ok:=relativeHomePath(masterDomain,path);if ok{return relative};return "public_html/"+safeOpaque(child)}
func relativeHomePath(domain,path string)(string,bool){prefix:="/home/"+domain+"/";if !strings.HasPrefix(path,prefix){return "",false};value:=strings.TrimPrefix(path,prefix);value=strings.Trim(value,"/");if value==""||strings.Contains(value,"..")||strings.Contains(value,"\\"){return "",false};return value,true}
func safeOpaque(value string)string{canonical:=strings.TrimSpace(value);normalized:=strings.ToLower(canonical);var builder strings.Builder;for _,character:=range normalized{if(character>='a'&&character<='z')||(character>='0'&&character<='9')||character=='.'||character=='@'||character=='-'||character=='_'{builder.WriteRune(character)}else{builder.WriteByte('-')}};slug:=strings.Trim(builder.String(),"-.");if len(slug)>48{slug=slug[:48]};if len(slug)<3{slug="id"};sum:=sha256.Sum256([]byte(canonical));return slug+"-"+hex.EncodeToString(sum[:16])}
func megabytes(value int64)uint64{if value<=0{return 0};return uint64(value)*1024*1024}
func positive(value int64)uint64{if value<=0{return 0};return uint64(value)}
func legacyBackupSchedule(value string)string{value=strings.TrimSpace(value);switch strings.ToLower(value){case"30 minutes":return"*/30 * * * *";case"1 hour","hourly":return"0 * * * *";case"6 hours":return"0 */6 * * *";case"12 hours":return"0 */12 * * *";case"1 day","daily":return"0 3 * * *";case"3 days":return"0 3 */3 * *";case"1 week","weekly":return"0 3 * * 0";case"monthly":return"0 3 1 * *"};return value}
func legacyBackupProvider(value string)string{value=strings.ToLower(value);if strings.Contains(value,"sftp")||strings.Contains(value,"ssh"){return"sftp"};if strings.Contains(value,"drive"){return"google_drive"};if strings.Contains(value,"s3")||strings.Contains(value,"amazon")||strings.Contains(value,"wasabi")||strings.Contains(value,"backblaze"){return"s3"};return"local"}
func tablePresent(ctx context.Context,tx *sql.Tx,name string)(bool,error){var count int;err:=tx.QueryRowContext(ctx,`SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND BINARY TABLE_NAME=BINARY ?`,name).Scan(&count);return count>0,err}
func decodeBackupConfig(raw string)(map[string]any,error){raw=strings.TrimSpace(raw);if raw==""||strings.EqualFold(raw,"inactive"){return map[string]any{},nil};decoder:=json.NewDecoder(strings.NewReader(raw));decoder.UseNumber();values:=map[string]any{};if err:=decoder.Decode(&values);err!=nil{return nil,ErrInvalid};var trailing any;if err:=decoder.Decode(&trailing);!errors.Is(err,io.EOF){return nil,ErrInvalid};return values,nil}
func backupConfigString(config map[string]any,keys ...string)string{for _,key:=range keys{for candidate,value:=range config{if !strings.EqualFold(candidate,key){continue};switch typed:=value.(type){case string:if strings.TrimSpace(typed)!=""{return strings.TrimSpace(typed)};case json.Number:return typed.String();case float64:return strconv.FormatFloat(typed,'f',-1,64);case bool:return strconv.FormatBool(typed)}}};return ""}
func backupConfigHasSecret(config map[string]any)bool{for key,value:=range config{normalized:=strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key,"_",""),"-",""));switch normalized{case"password","passwd","secretkey","secertkey","accesskey","token","refreshtoken","clientsecret","privatekey":if strings.TrimSpace(backupAnyString(value))!=""{return true}}};return false}
func backupAnyString(value any)string{switch typed:=value.(type){case string:return typed;case json.Number:return typed.String();case float64:return strconv.FormatFloat(typed,'f',-1,64);case bool:return strconv.FormatBool(typed)};return ""}
func mergeBackupConfig(left,right map[string]any)map[string]any{values:=make(map[string]any,len(left)+len(right));for key,value:=range left{values[key]=value};for key,value:=range right{values[key]=value};return values}
func backupRepositoryDescriptor(name string,config map[string]any)string{parts:=[]string{safeBackupRepository(name)};for _,keys:=range [][]string{{"Provider","provider","type"},{"Hostname","host","ip"},{"Path","path"},{"S3keyname","bucket","BucketName"},{"EndUrl","endpoint"},{"username","Username","user"},{"port"}}{if value:=backupConfigString(config,keys...);value!=""{parts=append(parts,safeBackupRepository(value))}};return strings.Join(parts,"|")}
func safeBackupRepository(value string)string{value=strings.TrimSpace(value);if value==""{return"source-default"};if len(value)>512{value=value[:512]};if parsed,err:=url.Parse(value);err==nil&&parsed.User!=nil{parsed.User=nil;value=parsed.String()};value=strings.Map(func(character rune)rune{if character=='\r'||character=='\n'||character=='\x00'{return -1};return character},value);if strings.TrimSpace(value)==""{return"source-default"};return value}
func normalizeDNSMode(value string)string{switch strings.ToLower(strings.TrimSpace(value)){case"master","primary":return"primary";case"slave","secondary":return"secondary";default:return"native"}}
func mailboxFormat(value string)string{if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)),"mdbox:"){return"mdbox"};return"maildir"}

type SQLSecretSource struct{database *sql.DB}
func NewSQLSecretSource(database *sql.DB)(*SQLSecretSource,error){if database==nil{return nil,ErrInvalid};return &SQLSecretSource{database:database},nil}
func(s *SQLSecretSource)ReadSecret(ctx context.Context,ref SecretRef)([]byte,error){if s==nil||s.database==nil||ctx==nil||!ref.Valid(){return nil,ErrInvalid};value:=string(ref);var query,argument string;var err error;switch{case strings.HasPrefix(value,"mailbox-password:"):query=`SELECT password FROM e_users WHERE BINARY email=BINARY ?`;argument,err=decodeLookupSecretRef(value,"mailbox-password");case strings.HasPrefix(value,"ftp-password:"):query=`SELECT Password FROM users WHERE BINARY User=BINARY ?`;argument,err=decodeLookupSecretRef(value,"ftp-password");case strings.HasPrefix(value,"database-password:"):query=`SELECT COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.authentication_string')),'') FROM mysql.global_priv WHERE BINARY User=BINARY ? AND Host IN ('localhost','127.0.0.1','::1','%') ORDER BY CASE Host WHEN 'localhost' THEN 0 WHEN '127.0.0.1' THEN 1 WHEN '::1' THEN 2 ELSE 3 END LIMIT 1`;argument,err=decodeLookupSecretRef(value,"database-password");case strings.HasPrefix(value,"backup-normal-destination:"):query=`SELECT config FROM websiteFunctions_normalbackupdests WHERE id=?`;argument=strings.TrimPrefix(value,"backup-normal-destination:");case strings.HasPrefix(value,"backup-google-drive-auth:"):query=`SELECT auth FROM websiteFunctions_gdrive WHERE id=?`;argument=strings.TrimPrefix(value,"backup-google-drive-auth:");case strings.HasPrefix(value,"backup-remote-config:"):query=`SELECT config FROM websiteFunctions_remotebackupconfig WHERE id=?`;argument=strings.TrimPrefix(value,"backup-remote-config:");default:return nil,ErrDenied};if err!=nil{return nil,ErrDenied};var secret []byte;err=s.database.QueryRowContext(ctx,query,argument).Scan(&secret);if err!=nil{if errors.Is(err,sql.ErrNoRows){return nil,ErrDenied};return nil,err};if len(secret)==0{return nil,ErrDenied};valueCopy:=append([]byte(nil),secret...);wipe(secret);return valueCopy,nil}
func lookupSecretRef(kind,value string)SecretRef{return SecretRef(kind+":"+hex.EncodeToString([]byte(strings.TrimSpace(value))))}
func decodeLookupSecretRef(value,kind string)(string,error){encoded:=strings.TrimPrefix(value,kind+":");if encoded==value||encoded==""||len(encoded)%2!=0{return "",ErrInvalid};raw,err:=hex.DecodeString(encoded);if err!=nil||len(raw)==0||strings.ContainsRune(string(raw),'\x00'){return "",ErrInvalid};return string(raw),nil}

var _ Collector = (*SQLCollector)(nil)
var _ SecretSource = (*SQLSecretSource)(nil)
