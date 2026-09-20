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
SecUnicodeMapFile /usr/share/modsecurity-crs/modsecurity-3.0.16/unicode.mapping 20127
SecStatusEngine Off
`

func InitialWAFConfiguration() []byte {
	return []byte("# CyberPanel initial WAF baseline v1\nSecRuleEngine On\nSecRequestBodyLimit 13107200\nSecAuditEngine RelevantOnly\n" + wafParserConfiguration + "Include " + baselineCRSEntry + "\n")
}

func isInitialWAFConfiguration(content []byte) bool {
	return bytes.Equal(content, InitialWAFConfiguration())
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
	err := filepath.WalkDir(filepath.Join(root, baselineAssetsPath), func(path string, entry fs.DirEntry, err error) error {
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
