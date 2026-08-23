//go:build linux

package apps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const linuxAdoptedApplicationManifestVersion = 1

type linuxAdoptionSignature struct {
	Kind ApplicationKind
	Markers []string
	Configurations []string
}

var linuxAdoptionSignatures = []linuxAdoptionSignature{
	{Kind: ApplicationJoomla, Markers: []string{"index.php", "cli/joomla.php", "administrator/manifests/files/joomla.xml"}, Configurations: []string{"configuration.php"}},
	{Kind: ApplicationPrestaShop, Markers: []string{"index.php", "bin/console", "config/defines.inc.php", "src/PrestaShopBundle"}, Configurations: []string{"app/config/parameters.php", "config/settings.inc.php"}},
	{Kind: ApplicationMautic, Markers: []string{"index.php", "bin/console", "app/bundles/CoreBundle"}, Configurations: []string{"config/local.php", "app/config/local.php"}},
	{Kind: ApplicationMagento, Markers: []string{"pub/index.php", "bin/magento", "app/etc/di.xml"}, Configurations: []string{"app/etc/env.php"}},
}

type linuxAdoptionConfigurationObservation struct {
	DatabaseLocal bool `json:"database_local"`
	DatabaseReachable bool `json:"database_reachable"`
	SearchStatus DiscoverySearchStatus `json:"search_status"`
	SearchEvidenceDigest string `json:"search_evidence_digest"`
}

type linuxAdoptedApplicationManifest struct {
	Version uint32 `json:"version"`
	InstallationID InstallationID `json:"installation_id"`
	ReleaseID ReleaseID `json:"release_id"`
	TenantID TenantID `json:"tenant_id"`
	SiteID SiteID `json:"site_id"`
	DefinitionID DefinitionID `json:"definition_id"`
	DefinitionDigest string `json:"definition_digest"`
	RecipeDigest string `json:"recipe_digest"`
	Candidate DiscoveryCandidate `json:"candidate"`
	CanonicalURL string `json:"canonical_url"`
	CreatedAt time.Time `json:"created_at"`
}

func (manifest linuxAdoptedApplicationManifest) Validate() error {
	if manifest.Version != linuxAdoptedApplicationManifestVersion || !validID(string(manifest.InstallationID)) || !validID(string(manifest.ReleaseID)) || !validID(string(manifest.TenantID)) || !validID(string(manifest.SiteID)) || !validID(string(manifest.DefinitionID)) || !validDigest(manifest.DefinitionDigest) || !validDigest(manifest.RecipeDigest) || manifest.Candidate.Validate() != nil || manifest.CreatedAt.IsZero() {
		return ErrIntegrity
	}
	parsed, err := url.Parse(manifest.CanonicalURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Port() != "" && parsed.Port() != "443" { return ErrIntegrity }
	if manifest.InstallationID != DerivedAdoptionInstallationID(manifest.TenantID, manifest.SiteID, manifest.Candidate) { return ErrIntegrity }
	if manifest.ReleaseID != DerivedAdoptionReleaseID(manifest.InstallationID, manifest.Candidate) { return ErrIntegrity }
	return nil
}

func linuxAdoptionManifestPath(installation InstallationID) (string, error) {
	directory, err := applicationManifestDirectory(installation)
	if err != nil { return "", err }
	return filepath.Join(directory, "adopted.json"), nil
}

func saveLinuxAdoptedApplicationManifest(manifest linuxAdoptedApplicationManifest) error {
	if err := manifest.Validate(); err != nil { return err }
	path, err := linuxAdoptionManifestPath(manifest.InstallationID)
	if err != nil { return err }
	payload, err := json.Marshal(manifest)
	if err != nil { return err }
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if bytes.Equal(existing, payload) { return nil }
		return ErrConflict
	} else if !errors.Is(readErr, os.ErrNotExist) { return readErr }
	return writeRootApplicationState(path, payload)
}

func loadLinuxAdoptedApplicationManifest(installation InstallationID) (linuxAdoptedApplicationManifest, error) {
	var manifest linuxAdoptedApplicationManifest
	path, err := linuxAdoptionManifestPath(installation)
	if err != nil { return manifest, err }
	payload, err := os.ReadFile(path)
	if err != nil { return manifest, err }
	if len(payload) == 0 || len(payload) > 4<<20 || json.Unmarshal(payload, &manifest) != nil || manifest.InstallationID != installation || manifest.Validate() != nil { return linuxAdoptedApplicationManifest{}, ErrIntegrity }
	return manifest, nil
}

func linuxAdoptionOwnedEntry(root, relative string, binding LinuxApplicationSiteBinding) (string, error) {
	parsed, err := ParseRelativePath(relative)
	if err != nil || parsed.IsRoot() { return "", ErrInvalid }
	entry, err := secureLinuxApplicationEntry(root, parsed)
	if err != nil { return "", err }
	info, err := os.Lstat(entry)
	if err != nil || info.Mode()&os.ModeSymlink != 0 { return "", errors.Join(err, ErrPolicyDenied) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != binding.UID || stat.Gid != binding.GID { return "", ErrPolicyDenied }
	return entry, nil
}

func linuxAdoptionOwnedRoot(root string, binding LinuxApplicationSiteBinding) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return errors.Join(err, ErrPolicyDenied) }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != binding.UID || stat.Gid != binding.GID { return ErrPolicyDenied }
	return nil
}

func linuxAdoptionCandidateRoot(base RelativePath, relative string) (RelativePath, error) {
	value := base.String()
	if relative != "." {
		if value != "" { value += "/" }
		value += filepath.ToSlash(relative)
	}
	return ParseRelativePath(value)
}

func requestedAdoptionKinds(kinds []ApplicationKind) (map[ApplicationKind]struct{}, error) {
	requested := make(map[ApplicationKind]struct{}, len(kinds))
	for _, kind := range kinds {
		switch kind {
		case ApplicationJoomla, ApplicationPrestaShop, ApplicationMautic, ApplicationMagento:
		default: return nil, ErrUnsupported
		}
		if _, duplicate := requested[kind]; duplicate { return nil, ErrInvalid }
		requested[kind] = struct{}{}
	}
	if len(requested) == 0 { return nil, ErrInvalid }
	return requested, nil
}

func matchingLinuxAdoptionSignatures(root string, binding LinuxApplicationSiteBinding, requested map[ApplicationKind]struct{}) ([]linuxAdoptionSignature, map[ApplicationKind]string, error) {
	matches := make([]linuxAdoptionSignature, 0, 1)
	configurations := make(map[ApplicationKind]string)
	for _, signature := range linuxAdoptionSignatures {
		complete := true
		for _, marker := range signature.Markers {
			if _, err := secureLinuxApplicationEntry(root, MustRelativePath(marker)); err != nil { complete = false; break }
		}
		if !complete { continue }
		configuration := ""
		for _, candidate := range signature.Configurations {
			if _, err := secureLinuxApplicationEntry(root, MustRelativePath(candidate)); err == nil { configuration = candidate; break }
		}
		if configuration == "" { continue }
		if err := linuxAdoptionOwnedRoot(root, binding); err != nil { return nil, nil, err }
		for _, marker := range append(append([]string(nil), signature.Markers...), configuration) {
			if _, err := linuxAdoptionOwnedEntry(root, marker, binding); err != nil { return nil, nil, err }
		}
		matches = append(matches, signature)
		configurations[signature.Kind] = configuration
	}
	if len(matches) > 1 { return nil, nil, ErrAmbiguousDiscovery }
	if len(matches) == 1 { if _, allowed := requested[matches[0].Kind]; !allowed { return nil, map[ApplicationKind]string{}, nil } }
	return matches, configurations, nil
}

func adoptionVersionArguments(kind ApplicationKind) ([]string, error) {
	switch kind {
	case ApplicationJoomla:
		return []string{"cli/joomla.php", "--version"}, nil
	case ApplicationPrestaShop:
		return []string{"-r", "require 'config/defines.inc.php'; echo _PS_VERSION_;"}, nil
	case ApplicationMautic:
		return []string{"bin/console", "--version", "--no-interaction"}, nil
	case ApplicationMagento:
		return []string{"bin/magento", "--version", "--no-interaction"}, nil
	default:
		return nil, ErrUnsupported
	}
}

func (runtime *LinuxApplicationRuntime) adoptionVersion(ctx context.Context, scope linuxApplicationScope, kind ApplicationKind, runtimeID string) (string, error) {
	arguments, err := adoptionVersionArguments(kind)
	if err != nil { return "", err }
	stdout, _, _, err := runtime.php(ctx, scope, runtimeID, nil, 1<<20, arguments...)
	if err != nil { return "", ErrIntegrity }
	version := certifiedVersionPattern.FindString(strings.TrimSpace(string(stdout)))
	if version == "" || !versionPattern.MatchString(version) { return "", ErrIntegrity }
	return version, nil
}

const linuxAdoptionDatabaseProbePHP = `
$databaseLocal = false;
$databaseReachable = false;
$host = trim((string)$host);
$port = (int)$port;
if ($port <= 0 || $port > 65535) { $port = 3306; }
if (substr_count($host, ':') === 1 && preg_match('/^([^:]+):([0-9]+)$/', $host, $match)) { $host = $match[1]; $port = (int)$match[2]; }
$normalizedHost = strtolower(trim($host, "[] \t\r\n"));
$databaseLocal = in_array($normalizedHost, ['localhost', '127.0.0.1', '::1'], true);
$pdo = null;
if ($databaseLocal) {
    try {
        $connectHost = $normalizedHost === '::1' ? '::1' : ($normalizedHost === 'localhost' ? 'localhost' : '127.0.0.1');
        $pdo = new PDO('mysql:host=' . $connectHost . ';port=' . $port . ';dbname=' . $database . ';charset=utf8mb4', (string)$user, (string)$password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 3]);
        $databaseReachable = ((string)$pdo->query('SELECT 1')->fetchColumn() === '1');
    } catch (Throwable $ignored) { $databaseReachable = false; $pdo = null; }
}
$searchStatus = 'not_applicable';
$observedSearchEngine = '';
$observedSearchHost = '';
$observedSearchPort = 0;
if (!empty($magento)) {
    $searchStatus = 'not_configured';
    if ($databaseReachable && $pdo instanceof PDO) {
        try {
            $paths = ['catalog/search/engine', 'catalog/search/opensearch_server_hostname', 'catalog/search/opensearch_server_port', 'catalog/search/elasticsearch7_server_hostname', 'catalog/search/elasticsearch7_server_port'];
            $quoted = implode(',', array_map(static fn($value) => $pdo->quote($value), $paths));
            foreach ($pdo->query("SELECT path,value FROM core_config_data WHERE scope='default' AND scope_id=0 AND path IN (" . $quoted . ')') as $row) { $search[$row['path']] = (string)$row['value']; }
        } catch (Throwable $ignored) {}
    }
    $engine = strtolower((string)($search['catalog/search/engine'] ?? $searchEngine ?? ''));
	$observedSearchEngine = $engine;
    if (str_contains($engine, 'opensearch')) {
        $searchHost = (string)($search['catalog/search/opensearch_server_hostname'] ?? $searchHost ?? 'localhost');
        $searchPort = (int)($search['catalog/search/opensearch_server_port'] ?? $searchPort ?? 9200);
        $normalizedSearchHost = strtolower(trim($searchHost, "[] \t\r\n"));
		$observedSearchHost = $normalizedSearchHost;
		$observedSearchPort = $searchPort;
        if (!in_array($normalizedSearchHost, ['localhost', '127.0.0.1', '::1'], true)) { $searchStatus = 'non_local'; }
        else {
            $socketHost = $normalizedSearchHost === '::1' ? '[::1]' : ($normalizedSearchHost === 'localhost' ? '127.0.0.1' : $normalizedSearchHost);
            $socket = @fsockopen($socketHost, $searchPort > 0 ? $searchPort : 9200, $errorCode, $errorMessage, 2.0);
            if (is_resource($socket)) { fclose($socket); $searchStatus = 'local_reachable'; } else { $searchStatus = 'local_unreachable'; }
        }
    }
}
$searchEvidenceDigest = hash('sha256', 'magento-local-opensearch-v1' . "\0" . $observedSearchEngine . "\0" . $observedSearchHost . "\0" . $observedSearchPort . "\0" . $searchStatus);
echo json_encode(['database_local' => $databaseLocal, 'database_reachable' => $databaseReachable, 'search_status' => $searchStatus, 'search_evidence_digest' => $searchEvidenceDigest], JSON_THROW_ON_ERROR);
`

func adoptionConfigurationPHP(kind ApplicationKind, configuration string) (string, error) {
	var prefix string
	switch kind {
	case ApplicationJoomla:
		if configuration != "configuration.php" { return "", ErrIntegrity }
		prefix = `ob_start(); require 'configuration.php'; ob_end_clean(); $config = new JConfig(); $host=$config->host; $port=3306; $database=$config->db; $user=$config->user; $password=$config->password; $magento=false;`
	case ApplicationPrestaShop:
		switch configuration {
		case "app/config/parameters.php":
			prefix = `ob_start(); $raw=require 'app/config/parameters.php'; ob_end_clean(); $config=$raw['parameters'] ?? []; $host=$config['database_host'] ?? ''; $port=$config['database_port'] ?? 3306; $database=$config['database_name'] ?? ''; $user=$config['database_user'] ?? ''; $password=$config['database_password'] ?? ''; $magento=false;`
		case "config/settings.inc.php":
			prefix = `ob_start(); require 'config/settings.inc.php'; ob_end_clean(); $host=defined('_DB_SERVER_')?_DB_SERVER_:''; $port=3306; $database=defined('_DB_NAME_')?_DB_NAME_:''; $user=defined('_DB_USER_')?_DB_USER_:''; $password=defined('_DB_PASSWD_')?_DB_PASSWD_:''; $magento=false;`
		default: return "", ErrIntegrity
		}
	case ApplicationMautic:
		if configuration != "config/local.php" && configuration != "app/config/local.php" { return "", ErrIntegrity }
		prefix = `ob_start(); $raw=require '` + configuration + `'; ob_end_clean(); $config=$raw['parameters'] ?? $raw; $host=$config['db_host'] ?? ''; $port=$config['db_port'] ?? 3306; $database=$config['db_name'] ?? ''; $user=$config['db_user'] ?? ''; $password=$config['db_password'] ?? ''; $magento=false;`
	case ApplicationMagento:
		if configuration != "app/etc/env.php" { return "", ErrIntegrity }
		prefix = `ob_start(); $environment=require 'app/etc/env.php'; ob_end_clean(); $config=$environment['db']['connection']['default'] ?? []; $host=$config['host'] ?? ''; $port=3306; $database=$config['dbname'] ?? ''; $user=$config['username'] ?? ''; $password=$config['password'] ?? ''; $magento=true; $search=$environment['system']['default'] ?? []; $searchEngine=$search['catalog']['search']['engine'] ?? ''; $searchHost=$search['catalog']['search']['opensearch_server_hostname'] ?? ''; $searchPort=$search['catalog']['search']['opensearch_server_port'] ?? 9200;`
	default:
		return "", ErrUnsupported
	}
	return prefix + linuxAdoptionDatabaseProbePHP, nil
}

func (runtime *LinuxApplicationRuntime) adoptionConfigurationObservation(ctx context.Context, scope linuxApplicationScope, kind ApplicationKind, runtimeID, configuration string) (linuxAdoptionConfigurationObservation, error) {
	script, err := adoptionConfigurationPHP(kind, configuration)
	if err != nil { return linuxAdoptionConfigurationObservation{}, err }
	stdout, _, _, err := runtime.php(ctx, scope, runtimeID, nil, 64<<10, "-d", "log_errors=0", "-r", script)
	if err != nil { return linuxAdoptionConfigurationObservation{}, ErrIntegrity }
	var observation linuxAdoptionConfigurationObservation
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(stdout)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&observation) != nil || decoder.Decode(&struct{}{}) != io.EOF { return linuxAdoptionConfigurationObservation{}, ErrIntegrity }
	if !observation.DatabaseLocal { return linuxAdoptionConfigurationObservation{}, ErrPolicyDenied }
	if !observation.DatabaseReachable { return linuxAdoptionConfigurationObservation{}, ErrIntegrity }
	if !validDigest(observation.SearchEvidenceDigest) { return linuxAdoptionConfigurationObservation{}, ErrIntegrity }
	return observation, nil
}

func linuxAdoptionStructureDigest(scope linuxApplicationScope, kind ApplicationKind) (string, error) {
	var signature *linuxAdoptionSignature
	for index := range linuxAdoptionSignatures { if linuxAdoptionSignatures[index].Kind == kind { signature = &linuxAdoptionSignatures[index]; break } }
	if signature == nil { return "", ErrUnsupported }
	var evidence strings.Builder
	for _, marker := range signature.Markers {
		entry, err := linuxAdoptionOwnedEntry(scope.root, marker, scope.binding)
		if err != nil { return "", err }
		info, err := os.Lstat(entry)
		if err != nil { return "", err }
		evidence.WriteString(marker)
		evidence.WriteByte(0)
		evidence.WriteString(info.Mode().String())
		evidence.WriteByte(0)
		evidence.WriteString(strconv.FormatInt(info.Size(), 10))
		evidence.WriteByte(0)
		if info.Mode().IsRegular() {
			if info.Size() <= 0 || info.Size() > 64<<20 { return "", ErrIntegrity }
			digest, digestErr := digestLinuxApplicationFile(entry, 64<<20)
			if digestErr != nil { return "", digestErr }
			evidence.WriteString(digest)
		}
		evidence.WriteByte(0)
	}
	return linuxApplicationDigest([]byte(evidence.String())), nil
}

func (runtime *LinuxApplicationRuntime) probeLinuxAdoptionDirectory(ctx context.Context, scope linuxApplicationScope, kind ApplicationKind, root RelativePath, runtimeID, configuration string) (DiscoveryCandidate, error) {
	if !validApplicationRuntimeID(runtimeID) { return DiscoveryCandidate{}, ErrUnsupported }
	version, err := runtime.adoptionVersion(ctx, scope, kind, runtimeID)
	if err != nil { return DiscoveryCandidate{}, err }
	configurationPath, err := linuxAdoptionOwnedEntry(scope.root, configuration, scope.binding)
	if err != nil { return DiscoveryCandidate{}, err }
	configurationInfo, err := os.Lstat(configurationPath)
	if err != nil || !configurationInfo.Mode().IsRegular() || configurationInfo.Size() <= 0 || configurationInfo.Size() > 4<<20 { return DiscoveryCandidate{}, ErrIntegrity }
	configurationDigest, err := digestLinuxApplicationFile(configurationPath, 4<<20)
	if err != nil { return DiscoveryCandidate{}, err }
	structureDigest, err := linuxAdoptionStructureDigest(scope, kind)
	if err != nil { return DiscoveryCandidate{}, err }
	observation, err := runtime.adoptionConfigurationObservation(ctx, scope, kind, runtimeID, configuration)
	if err != nil { return DiscoveryCandidate{}, err }
	status := observation.SearchStatus
	if kind != ApplicationMagento { status = DiscoverySearchNotApplicable }
	searchEvidence := observation.SearchEvidenceDigest
	candidate := DiscoveryCandidate{Kind: kind, Root: root, Version: version, RuntimeID: runtimeID, ConfigurationPath: MustRelativePath(configuration), ConfigurationDigest: configurationDigest, StructureDigest: structureDigest, DatabaseReachable: observation.DatabaseReachable, OwnershipValid: true, SearchStatus: status, SearchEvidenceDigest: searchEvidence}
	candidate.EvidenceDigest, err = candidate.evidenceDigest()
	if err != nil || candidate.Validate() != nil { return DiscoveryCandidate{}, ErrIntegrity }
	return candidate, nil
}

func (runtime *LinuxApplicationRuntime) discoverAdoptableApplications(ctx context.Context, execution DiscoveryExecution) ([]DiscoveryCandidate, ExecutionReceipt, error) {
	if execution.Scope.Validate() != nil || execution.MaximumDepth == 0 || execution.MaximumDepth > 16 || execution.MaximumCandidates == 0 || execution.MaximumCandidates > 1000 || !validApplicationRuntimeID(execution.RuntimeID) { return nil, ExecutionReceipt{}, ErrInvalid }
	requested, err := requestedAdoptionKinds(execution.Kinds)
	if err != nil { return nil, ExecutionReceipt{}, err }
	base, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return nil, ExecutionReceipt{}, err }
	candidates := make([]DiscoveryCandidate, 0)
	visited := uint32(0)
	err = filepath.WalkDir(base.root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if entry.Type()&os.ModeSymlink != 0 { if entry.IsDir() { return filepath.SkipDir }; return nil }
		if !entry.IsDir() { return nil }
		visited++
		if visited > 100000 { return ErrPolicyDenied }
		relative, relErr := filepath.Rel(base.root, current)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) { return ErrPolicyDenied }
		depth := uint8(0)
		if relative != "." { depth = uint8(len(strings.Split(relative, string(os.PathSeparator)))) }
		if depth > execution.MaximumDepth { return filepath.SkipDir }
		matches, configurations, matchErr := matchingLinuxAdoptionSignatures(current, base.binding, requested)
		if matchErr != nil { return matchErr }
		if len(matches) == 0 { return nil }
		candidateRoot, rootErr := linuxAdoptionCandidateRoot(execution.Scope.Root, relative)
		if rootErr != nil { return rootErr }
		candidateScope := linuxApplicationScope{binding: base.binding, root: current}
		candidate, probeErr := runtime.probeLinuxAdoptionDirectory(ctx, candidateScope, matches[0].Kind, candidateRoot, execution.RuntimeID, configurations[matches[0].Kind])
		if probeErr != nil { return probeErr }
		candidates = append(candidates, candidate)
		if len(candidates) > int(execution.MaximumCandidates) { return ErrPolicyDenied }
		return nil
	})
	if err != nil { return nil, ExecutionReceipt{}, err }
	sort.Slice(candidates, func(i, j int) bool { if candidates[i].Root.String() == candidates[j].Root.String() { return candidates[i].Kind < candidates[j].Kind }; return candidates[i].Root.String() < candidates[j].Root.String() })
	for index := range candidates {
		for other := index + 1; other < len(candidates); other++ {
			left, right := candidates[index].Root.String(), candidates[other].Root.String()
			if left == right || left != "" && strings.HasPrefix(right, left+"/") || left == "" { return nil, ExecutionReceipt{}, ErrAmbiguousDiscovery }
		}
	}
	receipt := receiptForApplication("discover", execution.Scope, "", execution, candidates, "", "", false)
	return candidates, receipt, nil
}

func (runtime *LinuxApplicationRuntime) adoptDiscoveredApplication(ctx context.Context, execution AdoptExecution) (ExecutionReceipt, error) {
	if execution.Scope.Validate() != nil || !validID(string(execution.Installation)) || !validID(string(execution.ReleaseID)) || execution.Candidate.Validate() != nil || execution.Candidate.Root != execution.Scope.Root || execution.Definition.Validate(time.Now().UTC()) != nil || execution.Definition.Kind != execution.Candidate.Kind || execution.Definition.Recipe.ProductVersion != execution.Candidate.Version || execution.Installation != DerivedAdoptionInstallationID(execution.Scope.TenantID, execution.Scope.SiteID, execution.Candidate) || execution.ReleaseID != DerivedAdoptionReleaseID(execution.Installation, execution.Candidate) { return ExecutionReceipt{}, ErrInvalid }
	parsed, err := url.Parse(execution.CanonicalURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" { return ExecutionReceipt{}, ErrInvalid }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ExecutionReceipt{}, err }
	matches, configurations, err := matchingLinuxAdoptionSignatures(scope.root, scope.binding, map[ApplicationKind]struct{}{execution.Candidate.Kind: struct{}{}})
	if err != nil || len(matches) != 1 { if err != nil { return ExecutionReceipt{}, err }; return ExecutionReceipt{}, ErrIntegrity }
	fresh, err := runtime.probeLinuxAdoptionDirectory(ctx, scope, execution.Candidate.Kind, execution.Candidate.Root, execution.Candidate.RuntimeID, configurations[execution.Candidate.Kind])
	if err != nil { return ExecutionReceipt{}, err }
	if fresh.EvidenceDigest != execution.Candidate.EvidenceDigest { return ExecutionReceipt{}, ErrConflict }
	manifest := linuxAdoptedApplicationManifest{Version: linuxAdoptedApplicationManifestVersion, InstallationID: execution.Installation, ReleaseID: execution.ReleaseID, TenantID: execution.Scope.TenantID, SiteID: execution.Scope.SiteID, DefinitionID: execution.Definition.ID, DefinitionDigest: execution.Definition.DefinitionDigest, RecipeDigest: execution.Definition.Recipe.RecipeDigest, Candidate: fresh, CanonicalURL: execution.CanonicalURL, CreatedAt: execution.Definition.Recipe.PublishedAt.UTC()}
	if err := saveLinuxAdoptedApplicationManifest(manifest); err != nil { return ExecutionReceipt{}, err }
	return receiptForApplication("adopt", execution.Scope, execution.Installation, execution, fresh.EvidenceDigest, execution.ReleaseID, "", false), nil
}

func (runtime *LinuxApplicationRuntime) inspectAdoptedApplication(ctx context.Context, execution InspectExecution) (ComponentInventory, HealthObservation, ExecutionReceipt, error) {
	manifest, err := loadLinuxAdoptedApplicationManifest(execution.Installation)
	if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }
	if manifest.TenantID != execution.Scope.TenantID || manifest.SiteID != execution.Scope.SiteID || manifest.Candidate.Root != execution.Scope.Root || manifest.Candidate.Kind != execution.Kind || manifest.RecipeDigest != execution.RecipeDigest { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, ErrConflict }
	scope, err := runtime.resolve(ctx, execution.Scope)
	if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }
	matches, configurations, err := matchingLinuxAdoptionSignatures(scope.root, scope.binding, map[ApplicationKind]struct{}{manifest.Candidate.Kind: struct{}{}})
	if err != nil || len(matches) != 1 { if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }; return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, ErrIntegrity }
	started := time.Now()
	fresh, err := runtime.probeLinuxAdoptionDirectory(ctx, scope, manifest.Candidate.Kind, manifest.Candidate.Root, manifest.Candidate.RuntimeID, configurations[manifest.Candidate.Kind])
	if err != nil { return ComponentInventory{}, HealthObservation{}, ExecutionReceipt{}, err }
	now := time.Now().UTC()
	healthState := HealthHealthy
	summary := "local application structure and database evidence verified"
	if fresh.EvidenceDigest != manifest.Candidate.EvidenceDigest { healthState = HealthDegraded; summary = "local application evidence changed since adoption" }
	receipts := []ProbeReceipt{
		{Name: "adopted_configuration", Passed: fresh.ConfigurationDigest == manifest.Candidate.ConfigurationDigest, Digest: fresh.ConfigurationDigest, Duration: time.Since(started), ObservedAt: now},
		{Name: "adopted_database", Passed: fresh.DatabaseReachable, Digest: linuxApplicationDigest([]byte("local-mariadb\x00reachable")), Duration: time.Since(started), ObservedAt: now},
	}
	if manifest.Candidate.Kind == ApplicationMagento {
		passed := fresh.SearchStatus == DiscoverySearchLocalReachable
		receipts = append(receipts, ProbeReceipt{Name: "magento_local_opensearch", Passed: passed, Digest: fresh.SearchEvidenceDigest, Duration: time.Since(started), ObservedAt: now})
		if !passed && healthState == HealthHealthy { healthState = HealthDegraded; summary = "Magento local OpenSearch status: " + string(fresh.SearchStatus) }
	}
	component := Component{Kind: ComponentCore, Name: string(manifest.Candidate.Kind), Version: manifest.Candidate.Version, Digest: manifest.Candidate.EvidenceDigest, State: ComponentActive, Origin: "adopted-local"}
	inventory := ComponentInventory{InstallationID: execution.Installation, Generation: uint64(now.UnixNano()), ObservedAt: now, SourceDigest: fresh.EvidenceDigest, Components: []Component{component}}
	health := HealthObservation{State: healthState, CheckedAt: now, DefinitionDigest: manifest.DefinitionDigest, ReleaseDigest: manifest.Candidate.EvidenceDigest, ProbeReceipts: receipts, Summary: summary}
	return inventory, health, receiptForApplication("inspect", execution.Scope, execution.Installation, execution, inventory, manifest.ReleaseID, "", false), nil
}
