package siteops

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const lifecyclePHPBinary = "/usr/local/lsws/lsphp83/bin/lsphp"

type UnixIdentity struct {
	RuntimeKey provisioning.RuntimeKey
	Username   string
	UID        uint32
	GID        uint32
	SiteKey    string
}

func identityFromBinding(binding RuntimeBinding) (UnixIdentity, error) {
	if err := binding.Validate(); err != nil { return UnixIdentity{}, err }
	return UnixIdentity{RuntimeKey: binding.RuntimeKey, Username: binding.Username, UID: binding.UID, GID: binding.GID, SiteKey: binding.SiteKey}, nil
}

type DirectoryOwner string

const (
	OwnerRoot DirectoryOwner = "root"
	OwnerSite DirectoryOwner = "site"
	OwnerRootSiteGroup DirectoryOwner = "root_site_group"
)

type DirectoryDefinition struct {
	Components []string
	Mode       uint32
	Owner      DirectoryOwner
}

// DirectoryLayout contains only product constants plus registry-derived keys.
// Components are consumed one at a time by descriptor-relative filesystem I/O.
type DirectoryLayout struct {
	SiteKey    string
	Generation uint64
	Definitions []DirectoryDefinition
}

func layoutFor(binding RuntimeBinding, generation uint64) DirectoryLayout {
	generationLeaf := "g" + strconv.FormatUint(generation, 10)
	root := []string{binding.SiteKey, "roots", generationLeaf}
	appendTo := func(suffix ...string) []string { value := append([]string(nil), root...); return append(value, suffix...) }
	return DirectoryLayout{
		SiteKey: binding.SiteKey, Generation: generation,
		Definitions: []DirectoryDefinition{
			{Components: []string{binding.SiteKey}, Mode: 0711, Owner: OwnerRoot},
			{Components: []string{binding.SiteKey, "roots"}, Mode: 0711, Owner: OwnerRoot},
			{Components: root, Mode: 0750, Owner: OwnerRootSiteGroup},
			{Components: appendTo("releases"), Mode: 0750, Owner: OwnerSite},
			{Components: appendTo("releases", "current"), Mode: 0750, Owner: OwnerSite},
			{Components: appendTo("releases", "current", "public"), Mode: 0750, Owner: OwnerSite},
			{Components: appendTo("shared"), Mode: 0750, Owner: OwnerSite},
			{Components: appendTo("shared", "uploads"), Mode: 0750, Owner: OwnerSite},
			{Components: appendTo("private"), Mode: 0700, Owner: OwnerSite},
			{Components: appendTo("private", "php"), Mode: 0700, Owner: OwnerSite},
			{Components: appendTo("private", "php", "sessions"), Mode: 0700, Owner: OwnerSite},
			{Components: appendTo("private", "php", "tmp"), Mode: 0700, Owner: OwnerSite},
			{Components: appendTo("logs"), Mode: 0750, Owner: OwnerSite},
			{Components: appendTo("tmp"), Mode: 0700, Owner: OwnerSite},
		},
	}
}

func (layout DirectoryLayout) Validate() error {
	if !validToken(layout.SiteKey, 3, 64) || layout.SiteKey[:2] != "s-" || layout.Generation == 0 || len(layout.Definitions) == 0 { return errors.New("invalid site directory layout") }
	for _, definition := range layout.Definitions {
		if len(definition.Components) == 0 || definition.Mode > 0777 || definition.Mode&0002 != 0 || definition.Owner != OwnerRoot && definition.Owner != OwnerSite && definition.Owner != OwnerRootSiteGroup { return errors.New("invalid site directory definition") }
		for _, component := range definition.Components { if !validPathComponent(component) { return errors.New("invalid site directory component") } }
	}
	return nil
}

func validPathComponent(component string) bool {
	if component == "" || component == "." || component == ".." || len(component) > 255 { return false }
	for index := range component { character := component[index]; if !alphaNumeric(character) && character != '-' && character != '_' && character != '.' { return false } }
	return true
}

type LSAPISpec struct {
	Edition       EngineEdition
	SiteKey       string
	Username      string
	UID           uint32
	GID           uint32
	Generation    uint64
	MaxConnections uint32
	PHPBinary     string
	ProcessProfile provisioning.SiteProcessResourceProfile
}

type observedProcessLimit struct {
	Supported bool
	Known     bool
	Unlimited bool
	Value     uint64
	Device    string
}

type ProcessResourceObservation struct {
	Generation  uint64
	CPUQuota    observedProcessLimit
	CPUWeight   observedProcessLimit
	MemoryHigh  observedProcessLimit
	MemoryMax   observedProcessLimit
	TasksMax    observedProcessLimit
	IOReadBPS   observedProcessLimit
	IOWriteBPS  observedProcessLimit
	IOReadIOPS  observedProcessLimit
	IOWriteIOPS observedProcessLimit
}

func (spec LSAPISpec) UnitName() string { return "cyberpanel-lsapi-" + spec.SiteKey + "-g" + strconv.FormatUint(spec.Generation, 10) + ".service" }
func (spec LSAPISpec) PoolKey() string { return "pool-" + spec.SiteKey }
func (spec LSAPISpec) SocketPath() string { return RuntimeRootPath + "/" + spec.SiteKey + "/php/" + spec.PoolKey() + "/g" + strconv.FormatUint(spec.Generation, 10) + ".sock" }
func (spec LSAPISpec) RuntimeDirectory() string { return "cyberpanel/site-runtime/" + spec.SiteKey + "/php/" + spec.PoolKey() }
func (spec LSAPISpec) WorkingDirectory() string { return SitesRootPath + "/" + spec.SiteKey + "/roots/g" + strconv.FormatUint(spec.Generation, 10) + "/releases/current" }
func (spec LSAPISpec) GenerationRoot() string { return SitesRootPath + "/" + spec.SiteKey + "/roots/g" + strconv.FormatUint(spec.Generation, 10) }
func (spec LSAPISpec) PHPConfigDirectory() string { return PHPConfigRootPath + "/" + spec.SiteKey + "/g" + strconv.FormatUint(spec.Generation, 10) }

// HealthDocumentRoot is root-owned attestation storage. Web-engine renderers
// map only the fixed activation token from this directory; the site identity
// cannot replace or rename the attestation.
func HealthDocumentRoot(siteKey string, generation uint64) (string, error) {
	if !validToken(siteKey, 3, 64) || !strings.HasPrefix(siteKey, "s-") || generation == 0 { return "", errors.New("invalid health document root") }
	return HealthRootPath + "/" + siteKey + "/g" + strconv.FormatUint(generation, 10), nil
}

func (spec LSAPISpec) Validate() error {
	if !spec.Edition.valid() || !validToken(spec.SiteKey, 3, 64) || spec.SiteKey[:2] != "s-" || spec.Username != deriveUsername(spec.SiteKey) || spec.UID < 1000 || spec.GID != spec.UID || spec.Generation == 0 || spec.MaxConnections == 0 || spec.MaxConnections > 10000 || !trustedPHPBinary(spec.PHPBinary) || spec.ProcessProfile.Generation != spec.Generation || spec.ProcessProfile.Validate() != nil { return errors.New("invalid LSAPI service specification") }
	return nil
}

func (spec LSAPISpec) RenderSystemdUnit() ([]byte, error) {
	if err := spec.Validate(); err != nil { return nil, err }
	engineName := "OpenLiteSpeed"; if spec.Edition == EditionLiteSpeedEnterprise { engineName = "LiteSpeed Enterprise" }
	children := strconv.FormatUint(uint64(spec.MaxConnections), 10)
	var unit strings.Builder
	unit.WriteString("# Managed by CyberPanel. Local changes are replaced.\n")
	unit.WriteString("[Unit]\nDescription=CyberPanel ")
	unit.WriteString(engineName)
	unit.WriteString(" LSAPI pool ")
	unit.WriteString(spec.SiteKey)
	unit.WriteString(" generation ")
	unit.WriteString(strconv.FormatUint(spec.Generation, 10))
	unit.WriteString("\nAfter=local-fs.target lsws.service\nPartOf=lsws.service\n\n[Service]\nType=simple\n")
	unit.WriteString("User="); unit.WriteString(spec.Username); unit.WriteByte('\n')
	unit.WriteString("Group="); unit.WriteString(spec.Username); unit.WriteByte('\n')
	unit.WriteString("WorkingDirectory="); unit.WriteString(spec.WorkingDirectory()); unit.WriteByte('\n')
	unit.WriteString("RuntimeDirectory="); unit.WriteString(spec.RuntimeDirectory()); unit.WriteByte('\n')
	unit.WriteString("RuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\nUMask=0027\n")
	unit.WriteString("Environment=LSAPI_AVOID_FORK=0\nEnvironment=LSAPI_CHILDREN="); unit.WriteString(children); unit.WriteByte('\n')
	unit.WriteString("Environment=LSAPI_EXTRA_CHILDREN=0\nEnvironment=LSAPI_MAX_REQS=10000\nEnvironment=LSAPI_MAX_IDLE=300\nEnvironment=LSPHP_ENABLE_USER_INI=on\n")
	unit.WriteString("Environment=PHP_INI_SCAN_DIR=:"); unit.WriteString(spec.PHPConfigDirectory()); unit.WriteByte('\n')
	unit.WriteString("Environment=PANEL_ENGINE_EDITION="); unit.WriteString(string(spec.Edition)); unit.WriteByte('\n')
	unit.WriteString("ExecStartPre=/usr/bin/rm -f "); unit.WriteString(spec.SocketPath()); unit.WriteByte('\n')
	unit.WriteString("ExecStart="); unit.WriteString(spec.PHPBinary); unit.WriteString(" -b "); unit.WriteString(spec.SocketPath()); unit.WriteByte('\n')
	unit.WriteString("Restart=on-failure\nRestartSec=2s\nTimeoutStartSec=60s\nTimeoutStopSec=30s\nKillMode=mixed\n")
	unit.WriteString("NoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectKernelLogs=true\nProtectControlGroups=true\nProtectClock=true\nLockPersonality=true\nRestrictSUIDSGID=true\nRestrictRealtime=true\nRestrictNamespaces=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n")
	unit.WriteString("ReadWritePaths="); unit.WriteString(SitesRootPath + "/" + spec.SiteKey); unit.WriteByte(' '); unit.WriteString(RuntimeRootPath + "/" + spec.SiteKey); unit.WriteByte('\n')
	unit.WriteString("ReadOnlyPaths="); unit.WriteString(spec.PHPConfigDirectory()); unit.WriteByte('\n')
	profile := spec.ProcessProfile
	unit.WriteString("CPUAccounting=true\nMemoryAccounting=true\nTasksAccounting=true\nIOAccounting=true\n")
	unit.WriteString("CPUQuota="); unit.WriteString(formatCPUQuota(profile.CPUQuotaPerSecondUSec)); unit.WriteString("%\nCPUQuotaPeriodSec=1s\n")
	unit.WriteString("CPUWeight="); unit.WriteString(decimal(profile.CPUWeight)); unit.WriteByte('\n')
	unit.WriteString("MemoryHigh="); unit.WriteString(decimal(profile.MemoryHighBytes)); unit.WriteByte('\n')
	unit.WriteString("MemoryMax="); unit.WriteString(decimal(profile.MemoryMaxBytes)); unit.WriteByte('\n')
	unit.WriteString("TasksMax="); unit.WriteString(decimal(profile.TasksMax)); unit.WriteByte('\n')
	if profile.IOReadBytesPerSecond != 0 { unit.WriteString("IOReadBandwidthMax="); unit.WriteString(spec.GenerationRoot()); unit.WriteByte(' '); unit.WriteString(decimal(profile.IOReadBytesPerSecond)); unit.WriteByte('\n') }
	if profile.IOWriteBytesPerSecond != 0 { unit.WriteString("IOWriteBandwidthMax="); unit.WriteString(spec.GenerationRoot()); unit.WriteByte(' '); unit.WriteString(decimal(profile.IOWriteBytesPerSecond)); unit.WriteByte('\n') }
	if profile.IOReadOperationsPerSec != 0 { unit.WriteString("IOReadIOPSMax="); unit.WriteString(spec.GenerationRoot()); unit.WriteByte(' '); unit.WriteString(decimal(profile.IOReadOperationsPerSec)); unit.WriteByte('\n') }
	if profile.IOWriteOperationsPerSec != 0 { unit.WriteString("IOWriteIOPSMax="); unit.WriteString(spec.GenerationRoot()); unit.WriteByte(' '); unit.WriteString(decimal(profile.IOWriteOperationsPerSec)); unit.WriteByte('\n') }
	unit.WriteString("OOMPolicy=stop\nLimitNOFILE=4096\n\n[Install]\nWantedBy=multi-user.target\n")
	return []byte(unit.String()), nil
}

func formatCPUQuota(value uint64) string {
	whole, fraction := value/10_000, value%10_000
	if fraction == 0 { return decimal(whole) }
	return decimal(whole) + "." + strings.TrimRight(fmt.Sprintf("%04d", fraction), "0")
}

func (spec LSAPISpec) RenderPHPINI() ([]byte, error) {
	if err := spec.Validate(); err != nil { return nil, err }
	privatePHP := spec.GenerationRoot()+"/private/php"
	var content strings.Builder
	content.WriteString("; Managed by CyberPanel. Local changes are replaced.\n")
	content.WriteString("expose_php=Off\ncgi.fix_pathinfo=0\nsession.use_strict_mode=1\nsession.use_only_cookies=1\nsession.cookie_httponly=1\n")
	content.WriteString("session.save_path=\""); content.WriteString(privatePHP+"/sessions"); content.WriteString("\"\n")
	content.WriteString("upload_tmp_dir=\""); content.WriteString(privatePHP+"/tmp"); content.WriteString("\"\n")
	content.WriteString("sys_temp_dir=\""); content.WriteString(privatePHP+"/tmp"); content.WriteString("\"\n")
	content.WriteString("open_basedir=\""); content.WriteString(spec.GenerationRoot()); content.WriteString(":/tmp:/usr/local/lsws:/usr/share\"\n")
	return []byte(content.String()), nil
}

type PHPBinaryResolver interface { Resolve(site.PHPProfile) (string, error) }

type InstalledPHPResolver struct{}

func (InstalledPHPResolver) Resolve(profile site.PHPProfile) (string, error) {
	var candidate string
	switch profile {
	case site.PHPProfile82: candidate = "/usr/local/lsws/lsphp82/bin/lsphp"
	case site.PHPProfile83: candidate = "/usr/local/lsws/lsphp83/bin/lsphp"
	case site.PHPProfile84: candidate = "/usr/local/lsws/lsphp84/bin/lsphp"
	default: return "", errors.New("unsupported PHP profile")
	}
	info, err := os.Stat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 { return "", errors.New("selected LiteSpeed PHP binary is not installed") }
	return candidate, nil
}

func trustedPHPBinary(value string) bool {
	switch value {
	case "/usr/local/lsws/lsphp84/bin/lsphp", "/usr/local/lsws/lsphp83/bin/lsphp", "/usr/local/lsws/lsphp82/bin/lsphp", "/usr/local/lsws/lsphp81/bin/lsphp": return true
	default: return false
	}
}

func poolSpec(binding RuntimeBinding, request Request, edition EngineEdition, binary string) LSAPISpec {
	profile := request.SiteProcessProfile
	if profile.Generation == 0 { profile = provisioning.DefaultSiteProcessResourceProfile(request.Generation, 8) }
	return LSAPISpec{Edition: edition, SiteKey: binding.SiteKey, Username: binding.Username, UID: binding.UID, GID: binding.GID, Generation: request.Generation, MaxConnections: 8, PHPBinary: binary, ProcessProfile: profile}
}

func evidence(parts ...string) string {
	encoded := make([][]byte, len(parts)); for index := range parts { encoded[index] = []byte(parts[index]) }
	return digest("cyberpanel:siteops:evidence:v1", encoded...)
}

func decimal(value uint64) string { return strconv.FormatUint(value, 10) }

func invalidSpec(kind string) error { return fmt.Errorf("invalid %s specification", kind) }
