//go:build linux

package operations

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const baselineManifestDigest = "be2f0cf033c538e9f594bc7996f7842d2f0984881dfba8d5d32871f8983acaef"
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

// Pin the recursive runtime manifest, not just a tiny Include file. Check for
// extra files too: native wildcard Includes must not admit unlisted rules.
func VerifyInitialWAFAssets() error {
	return verifyWAFAssets("/", "/usr/share/doc/cyberpanel-waf-crs/runtime.sha256", baselineManifestDigest)
}

func verifyWAFAssets(root, manifest, expected string) error {
	content, err := readTrustedWAFAsset(filepath.Join(root, manifest), 64<<10)
	if err != nil || digestBytes(content) != expected {
		return errors.Join(errors.New("WAF runtime manifest differs from pinned release"), err)
	}
	listed := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		fields := strings.Split(line, "  ")
		if len(fields) != 2 || !validSHA256(fields[0]) || !strings.HasPrefix(fields[1], "usr/share/modsecurity-crs/") || filepath.Clean(fields[1]) != fields[1] || listed[fields[1]] {
			return errors.New("invalid WAF runtime manifest entry")
		}
		data, err := readTrustedWAFAsset(filepath.Join(root, fields[1]), 2<<20)
		if err != nil || digestBytes(data) != fields[0] {
			return errors.New("WAF runtime asset differs from pinned release: " + fields[1])
		}
		listed[fields[1]] = true
	}
	return filepath.WalkDir(filepath.Join(root, "usr/share/modsecurity-crs"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !entry.Type().IsRegular() || !listed[relative] {
			return errors.New("unlisted or unsafe WAF runtime asset")
		}
		return nil
	})
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
