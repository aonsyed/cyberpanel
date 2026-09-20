//go:build linux

package operations

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const baselineAssetsPath = "/usr/share/modsecurity-crs"
const baselineCRSEntry = "/usr/share/modsecurity-crs/owasp-crs.load"

// Shared by first installation and subsequent policy generations. These parser
// guards are not tenant exclusions. Audit output deliberately omits bodies,
// headers and matched-data messages; the service's stderr owns log delivery.
const wafParserConfiguration = `SecRequestBodyAccess On
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 512
SecArgumentsLimit 1000
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml(?:\s*;|$)" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|$)" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule &ARGS "@ge 1000" "id:200007,phase:2,t:none,deny,status:400,nolog"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,deny,status:400,nolog"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,deny,status:400,nolog"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:200004,phase:2,t:none,deny,status:400,nolog"
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000
SecRule TX:/^MSC_/ "!@streq 0" "id:200005,phase:2,t:none,deny,status:400,nolog"
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
SecTmpDir /var/lib/cyberpanel-waf/tmp
SecDataDir /var/lib/cyberpanel-waf/data
SecUploadKeepFiles Off
SecUploadFileMode 0600
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts AZ
SecAuditLogType Serial
SecAuditLog /proc/self/fd/2
SecArgumentSeparator &
SecCookieFormat 0
SecStatusEngine Off
`

func InitialWAFConfiguration() ([]byte, error) {
	if err := VerifyInitialWAFAssets(); err != nil {
		return nil, err
	}
	path, _, err := installedWAFUnicodeMapping("/")
	if err != nil {
		return nil, err
	}
	return initialWAFConfiguration(path), nil
}

func initialWAFConfiguration(mappingPath string) []byte {
	return []byte("# CyberPanel initial WAF baseline v1\nSecRuleEngine On\nSecRequestBodyLimit 13107200\nSecAuditEngine RelevantOnly\n" + wafParserConfigurationWithMapping(mappingPath) + "Include " + baselineCRSEntry + "\n")
}

func wafParserConfigurationWithMapping(path string) string {
	return strings.Replace(wafParserConfiguration, "SecStatusEngine Off\n", "SecUnicodeMapFile "+path+" 20127\nSecStatusEngine Off\n", 1)
}

func isInitialWAFConfiguration(content []byte) bool {
	// Recognize the exact initial template with an installed-layout mapping path.
	// This also preserves journal handoff for an initial policy written before a
	// package update changed that path; arbitrary directives are never accepted.
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "SecUnicodeMapFile" && fields[2] == "20127" && allowedWAFMappingPath(fields[1]) {
			return bytes.Equal(content, initialWAFConfiguration(fields[1]))
		}
	}
	return false
}

// VerifyExistingInitialWAFConfiguration permits native package layout changes
// without rewriting a live policy whose exact bootstrap template still works.
func VerifyExistingInitialWAFConfiguration(content []byte) error {
	return verifyExistingInitialWAFConfiguration("/", content)
}

func verifyExistingInitialWAFConfiguration(root string, content []byte) error {
	if !isInitialWAFConfiguration(content) {
		return ErrConflict
	}
	if _, err := installedWAFAssets(root); err != nil {
		return err
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "SecUnicodeMapFile" {
			mapping, err := readTrustedWAFAsset(filepath.Join(root, fields[1]), 2<<20)
			if err != nil || len(mapping) == 0 {
				return errors.Join(ErrConflict, err)
			}
			return nil
		}
	}
	return ErrConflict
}

func allowedWAFMappingPath(path string) bool {
	if filepath.Clean(path) != path || filepath.Base(path) != "unicode.mapping" || strings.ContainsAny(path, "\r\n\t \"'`\\") {
		return false
	}
	return strings.HasPrefix(path, baselineAssetsPath+"/") || path == "/etc/modsecurity/unicode.mapping" || path == "/etc/modsecurity.d/unicode.mapping" || path == "/usr/local/lsws/conf/modsec/unicode.mapping"
}

func installedWAFUnicodeMapping(root string) (string, []byte, error) {
	// Prefer conventional package/configuration locations. The final glob permits
	// an installed versioned layout without compiling its release into the panel.
	paths := []string{"/etc/modsecurity/unicode.mapping", "/etc/modsecurity.d/unicode.mapping", "/usr/local/lsws/conf/modsec/unicode.mapping", baselineAssetsPath + "/unicode.mapping"}
	versioned, err := filepath.Glob(filepath.Join(root, baselineAssetsPath, "*", "unicode.mapping"))
	if err != nil {
		return "", nil, err
	}
	for _, path := range versioned {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return "", nil, err
		}
		paths = append(paths, "/"+relative)
	}
	var selected string
	var selectedContent []byte
	for i, path := range paths {
		if !allowedWAFMappingPath(path) {
			return "", nil, ErrConflict
		}
		full := filepath.Join(root, path)
		if _, err := os.Lstat(full); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", nil, err
		}
		content, err := readTrustedWAFAsset(full, 2<<20)
		if err != nil || len(content) == 0 {
			return "", nil, errors.Join(errors.New("unsafe installed Unicode mapping"), err)
		}
		if i < 4 {
			return path, content, nil
		}
		if selected != "" {
			return "", nil, errors.New("multiple installed Unicode mappings; configure a conventional mapping path")
		}
		selected, selectedContent = path, content
	}
	if selected == "" {
		return "", nil, errors.New("installed ModSecurity Unicode mapping is missing")
	}
	return selected, selectedContent, nil
}

func validateWAFPreviousGeneration(index wafActiveIndex, previous *wafNativeGeneration, snapshot operationsFileSnapshot) error {
	if len(index.Policies) == 0 {
		if previous != nil || (snapshot.Existed && (!isInitialWAFConfiguration(snapshot.Content) || snapshot.UID != 0 || snapshot.GID != 0 || snapshot.Mode != 0600)) {
			return ErrConflict
		}
		return nil
	}
	if previous == nil || !snapshot.Existed || digestBytes(snapshot.Content) != previous.Digest || !wafPolicyPointersEqual(previous.Policies, index.Policies) {
		return ErrConflict
	}
	return nil
}

// Inventory installed rules without requiring a panel-built package or release
// manifest. The root-owned installer/package manager owns this trust boundary.
// Each activation records the inventory digest as evidence, not a version lock.
func VerifyInitialWAFAssets() error {
	_, err := installedWAFAssets("/")
	return err
}

func installedWAFAssets(root string) (wafSourceEvidence, error) {
	if content, err := readTrustedWAFAsset(filepath.Join(root, baselineCRSEntry), 2<<20); err != nil || len(content) == 0 {
		return wafSourceEvidence{}, errors.Join(errors.New("missing or unsafe installed CRS entrypoint"), err)
	}
	var inventory bytes.Buffer
	var total int64
	var count int
	// Native packages keep local CRS setup/exclusions outside /usr/share. Include
	// those bytes in activation evidence too; neither location pins a release.
	assetRoots := []string{baselineAssetsPath, "/etc/modsecurity/crs", "/etc/modsecurity.d/owasp-crs"}
	for index, assetRoot := range assetRoots {
		fullRoot := filepath.Join(root, assetRoot)
		if _, err := os.Lstat(fullRoot); index > 0 && errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return wafSourceEvidence{}, err
		}
		err := filepath.WalkDir(fullRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
					return ErrConflict
				}
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil || !entry.Type().IsRegular() {
				return errors.New("unsafe WAF runtime asset")
			}
			count++
			if count > 10000 {
				return errors.New("WAF runtime inventory exceeds file limit")
			}
			data, err := readTrustedWAFAsset(path, 2<<20)
			if err != nil {
				return err
			}
			total += int64(len(data))
			if total > 64<<20 {
				return errors.New("WAF runtime inventory exceeds size limit")
			}
			// WalkDir is lexical; quoted paths make inventory records unambiguous.
			fmt.Fprintf(&inventory, "%s  %q\n", digestBytes(data), relative)
			return nil
		})
		if err != nil {
			return wafSourceEvidence{}, err
		}
	}
	mappingPath, mapping, err := installedWAFUnicodeMapping(root)
	if err != nil {
		return wafSourceEvidence{}, err
	}
	fmt.Fprintf(&inventory, "%s  %q\n", digestBytes(mapping), mappingPath)
	return wafSourceEvidence{Provider: ResourceID{value: "cyberpanel"}, Name: ResourceID{value: "waf-runtime"}, Version: "installed", Digest: digestBytes(inventory.Bytes()), Path: baselineAssetsPath}, nil
}

func readTrustedWAFAsset(path string, limit int64) ([]byte, error) {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, ErrConflict
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return nil, ErrConflict
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, ErrConflict
	}
	return content, nil
}
