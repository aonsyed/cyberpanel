//go:build linux

package apps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
)

//go:embed wordpress_db_tls.php
var wordpressDatabaseTLSDropin []byte

//go:embed wordpress_mariadb_tls.sh
var wordpressMariaDBTLSClient []byte

type ApplicationDatabaseConnections interface {
	ApplicationConnection(context.Context, database.ResourceID, string, string) (database.ApplicationConnection, error)
}

type applicationDatabaseClientIdentity struct {
	CertificatePEM []byte `json:"certificate_pem"`
	KeyPEM         []byte `json:"key_pem"`
}

func (runtime *LinuxApplicationRuntime) configureWordPressDatabaseTLS(ctx context.Context, scope linuxApplicationScope, owner SiteExecutionScope, installation InstallationID, binding DatabaseBinding) error {
	if runtime.DatabaseConnections == nil {
		return ErrPolicyDenied
	}
	id, err := database.NewResourceID(string(binding.ID))
	if err != nil {
		return ErrInvalid
	}
	connection, err := runtime.DatabaseConnections.ApplicationConnection(ctx, id, string(owner.TenantID), string(owner.SiteID))
	if err != nil {
		return err
	}
	defer wipeLinuxApplicationBytes(connection.CertificateAuthorityPEM)
	if connection.InstanceID.String() != string(binding.InstanceID) || connection.DatabaseName != binding.DatabaseName || connection.PrincipalName != binding.PrincipalName {
		return ErrPolicyDenied
	}
	if connection.Endpoint.Host == "" {
		if binding.Placement != "local" || binding.EndpointRef != "local-mariadb" {
			return ErrPolicyDenied
		}
		return installWordPressTLSFiles(scope, installation, nil)
	}
	if binding.Placement != "external" || binding.EndpointRef != net.JoinHostPort(connection.Endpoint.Host, strconv.Itoa(int(connection.Endpoint.Port))) || !binding.TLSRequired || (connection.TLS != database.TLSRequired && connection.TLS != database.TLSMutual) {
		return ErrPolicyDenied
	}
	pool := x509.NewCertPool()
	if len(connection.CertificateAuthorityPEM) == 0 || len(connection.CertificateAuthorityPEM) > 64<<10 || !pool.AppendCertsFromPEM(connection.CertificateAuthorityPEM) {
		return ErrIntegrity
	}
	identity := applicationDatabaseClientIdentity{}
	defer func() { wipeLinuxApplicationBytes(identity.CertificatePEM); wipeLinuxApplicationBytes(identity.KeyPEM) }()
	if connection.TLS == database.TLSMutual {
		// This is a distinct application-audience lease. Never request the
		// external administrator's identity from the database adapter.
		material, err := runtime.Secrets.ApplicationSecret(ctx, SecretRef(ApplicationManagedSecretID("database_tls", installation).String()), owner.TenantID, owner.SiteID, installation, "database_tls")
		if err != nil {
			return err
		}
		defer wipeLinuxApplicationBytes(material)
		if decodeLinuxApplicationPayload(material, &identity) != nil || len(identity.CertificatePEM) > 64<<10 || len(identity.KeyPEM) > 64<<10 {
			return ErrIntegrity
		}
		if err := validateApplicationDatabaseClientIdentity(identity.CertificatePEM, identity.KeyPEM, time.Now().UTC()); err != nil {
			return ErrIntegrity
		}
	}
	configuration, err := json.Marshal(struct {
		Version int    `json:"version"`
		Host    string `json:"host"`
		Port    uint16 `json:"port"`
		Mutual  bool   `json:"mutual"`
	}{1, connection.Endpoint.Host, connection.Endpoint.Port, connection.TLS == database.TLSMutual})
	if err != nil {
		return err
	}
	return installWordPressTLSFiles(scope, installation, map[string][]byte{
		".cyberpanel-db-ca.pem":     connection.CertificateAuthorityPEM,
		".cyberpanel-db-client.pem": identity.CertificatePEM,
		".cyberpanel-db-client.key": identity.KeyPEM,
		".cyberpanel-db-tls.json":   configuration,
	})
}

var wordpressTLSFiles = []string{".cyberpanel-db-ca.pem", ".cyberpanel-db-client.pem", ".cyberpanel-db-client.key", ".cyberpanel-db-tls.json", "mariadb", "mysql"}

const wordpressTLSPathToken = "__CYBERPANEL_PRIVATE_DIRECTORY_BASE64__"

func wordpressTLSGeneration(scope linuxApplicationScope) string {
	return filepath.Join(linuxApplicationSitesRoot, scope.binding.SiteKey, "roots", "g"+strconv.FormatUint(scope.binding.Generation, 10))
}

func wordpressTLSPrivatePath(scope linuxApplicationScope, installation InstallationID) (string, error) {
	if !validID(string(installation)) || !validID(scope.binding.SiteKey) || scope.binding.Generation == 0 {
		return "", ErrInvalid
	}
	return filepath.Join(wordpressTLSGeneration(scope), "application-db-"+linuxApplicationDigest([]byte(installation))), nil
}

func renderWordPressTLSDropin(path string) []byte {
	return bytes.Replace(wordpressDatabaseTLSDropin, []byte(wordpressTLSPathToken), []byte(base64.StdEncoding.EncodeToString([]byte(path))), 1)
}

// Purge also removes material outside the document root, even when the tenant
// has deleted db.php. Only the installation's fixed private filenames are used.
func removeWordPressTLSMaterial(scope linuxApplicationScope, installation InstallationID) error {
	path, err := wordpressTLSPrivatePath(scope, installation)
	if err != nil {
		return err
	}
	directory, err := openWordPressTLSPath(scope, path, false)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	for _, name := range wordpressTLSFiles {
		if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil && !errors.Is(err, syscall.ENOENT) {
			return err
		}
	}
	return directory.Sync()
}

func wordPressTLSManagedPath(dropin []byte) (string, bool) {
	parts := bytes.Split(wordpressDatabaseTLSDropin, []byte(wordpressTLSPathToken))
	if len(parts) != 2 || !bytes.HasPrefix(dropin, parts[0]) || !bytes.HasSuffix(dropin, parts[1]) || len(dropin) < len(parts[0])+len(parts[1]) {
		return "", false
	}
	encoded := dropin[len(parts[0]) : len(dropin)-len(parts[1])]
	path, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil || !filepath.IsAbs(string(path)) || filepath.Clean(string(path)) != string(path) || bytes.IndexByte(path, 0) >= 0 {
		return "", false
	}
	return string(path), true
}

// Walk each directory with O_NOFOLLOW and retain the final descriptor. A tenant
// swapping a directory or leaf for a symlink cannot redirect a root write.
func openWordPressTLSDirectory(scope linuxApplicationScope) (*os.File, error) {
	return openWordPressTLSPath(scope, filepath.Join(scope.root, "wp-content"), false)
}

func openWordPressTLSPath(scope linuxApplicationScope, path string, createLeaf bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return nil, ErrInvalid
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		if errors.Is(openErr, syscall.ENOENT) && createLeaf && index == len(parts)-1 {
			mkdirErr := syscall.Mkdirat(fd, part, 0700)
			if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				syscall.Close(fd)
				return nil, mkdirErr
			}
			next, openErr = syscall.Openat(fd, part, flags, 0)
			if openErr == nil && mkdirErr == nil {
				openErr = syscall.Fchown(next, int(scope.binding.UID), int(scope.binding.GID))
				if openErr != nil {
					syscall.Close(next)
				}
			}
			if openErr == nil {
				openErr = syscall.Fsync(fd)
				if openErr != nil {
					syscall.Close(next)
				}
			}
		}
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	directory := os.NewFile(uintptr(fd), path)
	info, err := directory.Stat()
	if err != nil {
		directory.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != scope.binding.UID || stat.Gid != scope.binding.GID || info.Mode().Perm()&0002 != 0 {
		directory.Close()
		return nil, ErrPolicyDenied
	}
	if filepath.Base(path) != "wp-content" && info.Mode().Perm() != 0700 {
		directory.Close()
		return nil, ErrPolicyDenied
	}
	return directory, nil
}

func readWordPressTLSFile(directory *os.File, name string, scope linuxApplicationScope) ([]byte, bool, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != scope.binding.UID || stat.Gid != scope.binding.GID || info.Size() > 128<<10 || info.Mode().Perm()&0022 != 0 {
		return nil, false, ErrPolicyDenied
	}
	expectedMode := os.FileMode(0600)
	if name == "mariadb" || name == "mysql" {
		expectedMode = 0700
	}
	if name != "db.php" && info.Mode().Perm() != expectedMode {
		return nil, false, ErrPolicyDenied
	}
	value, err := io.ReadAll(io.LimitReader(file, 128<<10+1))
	if len(value) > 128<<10 {
		return nil, false, ErrIntegrity
	}
	return value, true, err
}

func installWordPressTLSFiles(scope linuxApplicationScope, installation InstallationID, payloads map[string][]byte) error {
	privatePath, err := wordpressTLSPrivatePath(scope, installation)
	if err != nil {
		return err
	}
	directory, err := openWordPressTLSDirectory(scope)
	if err != nil {
		return err
	}
	defer directory.Close()
	existing, found, err := readWordPressTLSFile(directory, "db.php", scope)
	if err != nil {
		return err
	}
	existingPath, owned := wordPressTLSManagedPath(existing)
	if found && !owned {
		if payloads == nil {
			return nil
		} // Local connection: preserve unrelated drop-ins.
		return ErrConflict
	}
	if payloads == nil {
		if !owned {
			return nil
		}
		// A cloned drop-in may still name the source installation. Never
		// remove the source's credentials when converting the clone to local.
		if existingPath == privatePath {
			private, err := openWordPressTLSPath(scope, privatePath, false)
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				return err
			}
			if err == nil {
				defer private.Close()
				for _, name := range wordpressTLSFiles {
					if err := syscall.Unlinkat(int(private.Fd()), name); err != nil && !errors.Is(err, syscall.ENOENT) {
						return err
					}
				}
				if err := private.Sync(); err != nil {
					return err
				}
			}
		}
		if err := syscall.Unlinkat(int(directory.Fd()), "db.php"); err != nil {
			return err
		}
		return directory.Sync()
	}
	private, err := openWordPressTLSPath(scope, privatePath, true)
	if err != nil {
		return err
	}
	defer private.Close()
	for _, name := range wordpressTLSFiles {
		value, present, err := readWordPressTLSFile(private, name, scope)
		wipeLinuxApplicationBytes(value)
		if err != nil {
			return err
		}
		if present && (!owned || existingPath != privatePath) {
			return ErrConflict
		}
	}
	// Publish ownership before material so an interrupted initial install can
	// replay. The driver fails closed until all private files are present.
	if err := writeWordPressTLSFile(directory, "db.php", renderWordPressTLSDropin(privatePath), scope); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	for _, name := range wordpressTLSFiles {
		value := payloads[name]
		if name == "mariadb" || name == "mysql" {
			value = wordpressMariaDBTLSClient
		}
		if err := writeWordPressTLSFile(private, name, value, scope); err != nil {
			return err
		}
	}
	return private.Sync()
}

func writeWordPressTLSFile(directory *os.File, name string, value []byte, scope linuxApplicationScope) error {
	temporary := ".cyberpanel-tls-" + rand.Text()
	fd, err := syscall.Openat(int(directory.Fd()), temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(int(directory.Fd()), temporary)
	file := os.NewFile(uintptr(fd), temporary)
	_, writeErr := file.Write(value)
	var modeErr error
	if name == "mariadb" || name == "mysql" {
		modeErr = file.Chmod(0700)
	}
	ownerErr := file.Chown(int(scope.binding.UID), int(scope.binding.GID))
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, modeErr, ownerErr, syncErr, closeErr); err != nil {
		return err
	}
	return syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), name)
}

// WP-CLI import/export invokes the MariaDB CLI without loading WordPress's
// database drop-in. Supply equivalent TLS policy explicitly for that path.
func wordpressDatabaseCLIArguments(scope linuxApplicationScope, arguments []string) ([]string, error) {
	if len(arguments) < 2 || arguments[0] != "db" || (arguments[1] != "import" && arguments[1] != "export") {
		return arguments, nil
	}
	directory, err := openWordPressTLSDirectory(scope)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	dropin, found, err := readWordPressTLSFile(directory, "db.php", scope)
	if err != nil {
		return nil, err
	}
	privatePath, owned := wordPressTLSManagedPath(dropin)
	if !found || !owned {
		return arguments, nil
	}
	if filepath.Dir(privatePath) != wordpressTLSGeneration(scope) || !strings.HasPrefix(filepath.Base(privatePath), "application-db-") || !validDigest(strings.TrimPrefix(filepath.Base(privatePath), "application-db-")) {
		return nil, ErrPolicyDenied
	}
	private, err := openWordPressTLSPath(scope, privatePath, false)
	if err != nil {
		return nil, err
	}
	defer private.Close()
	for _, argument := range arguments[2:] {
		for _, prefix := range []string{"--ssl", "--skip-ssl", "--host", "--port", "--protocol", "--defaults"} {
			if strings.HasPrefix(argument, prefix) {
				return nil, ErrPolicyDenied
			}
		}
	}
	content, found, err := readWordPressTLSFile(private, ".cyberpanel-db-tls.json", scope)
	if err != nil || !found {
		return nil, errors.Join(ErrIntegrity, err)
	}
	var configuration struct {
		Version int    `json:"version"`
		Host    string `json:"host"`
		Port    uint16 `json:"port"`
		Mutual  bool   `json:"mutual"`
	}
	if decodeLinuxApplicationPayload(content, &configuration) != nil || configuration.Version != 1 || configuration.Host == "" || configuration.Port == 0 {
		return nil, ErrIntegrity
	}
	for _, name := range wordpressTLSFiles[:3] {
		if !configuration.Mutual && name != ".cyberpanel-db-ca.pem" {
			continue
		}
		value, found, err := readWordPressTLSFile(private, name, scope)
		length := len(value)
		wipeLinuxApplicationBytes(value)
		if err != nil || !found || length == 0 {
			return nil, errors.Join(ErrIntegrity, err)
		}
	}
	result := append([]string(nil), arguments...)
	result = append(result, "--protocol=tcp", "--host="+configuration.Host, "--port="+strconv.Itoa(int(configuration.Port)), "--ssl=1", "--ssl-verify-server-cert=1", "--ssl-ca="+filepath.Join(privatePath, ".cyberpanel-db-ca.pem"))
	if configuration.Mutual {
		result = append(result, "--ssl-cert="+filepath.Join(privatePath, ".cyberpanel-db-client.pem"), "--ssl-key="+filepath.Join(privatePath, ".cyberpanel-db-client.key"))
	}
	return result, nil
}

func wordpressDatabaseCLIEnvironment(scope linuxApplicationScope, arguments []string) ([]string, error) {
	if len(arguments) < 2 || arguments[0] != "db" || arguments[1] != "import" {
		return nil, nil
	}
	// Transport arguments were generated from the validated private profile.
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "--ssl-ca=") {
			continue
		}
		path := filepath.Dir(strings.TrimPrefix(argument, "--ssl-ca="))
		if filepath.Dir(path) != wordpressTLSGeneration(scope) {
			return nil, ErrPolicyDenied
		}
		directory, err := openWordPressTLSPath(scope, path, false)
		if err != nil {
			return nil, err
		}
		defer directory.Close()
		for _, name := range []string{"mariadb", "mysql"} {
			value, found, err := readWordPressTLSFile(directory, name, scope)
			if err != nil || !found || !bytes.Equal(value, wordpressMariaDBTLSClient) {
				return nil, errors.Join(ErrIntegrity, err)
			}
		}
		return []string{"PATH=" + path + ":/usr/local/bin:/usr/bin:/bin"}, nil
	}
	return nil, nil
}
