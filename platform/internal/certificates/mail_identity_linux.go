//go:build linux

package certificates

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// PublishLocalMailIdentity mirrors only the selected mail/default public leaf.
// Bootstrap, activation and rollback call this before reloading native mail.
// Private files and their directory permissions are never changed.
func PublishLocalMailIdentity(root string) error {
	if root == "" {
		root = defaultCertificateRoot
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || os.Geteuid() != 0 {
		return ErrInvalidCertificate
	}
	public := filepath.Join(root, "public")
	if err := secureRootDirectory(public, 0755); err != nil {
		return err
	}
	path := filepath.Join(public, "mail-default.pem")
	current := filepath.Join(root, "consumers", "mail", "default", "current")
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		info, err = os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || !safeRootFile(info, 0444) {
			return ErrInvalidCertificate
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		return syncDirectory(public)
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ErrInvalidCertificate
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return ErrInvalidCertificate
	}
	target, err := os.Readlink(current)
	if err != nil || !filepath.IsAbs(target) || filepath.Clean(target) != target || !pathWithin(filepath.Join(root, "generations", "mail", "default"), target) {
		return ErrInvalidCertificate
	}
	leaf, err := readMailPublicIdentity(filepath.Join(target, "certificate.pem"), 0440)
	if err != nil {
		return err
	}
	return atomicRootFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0444, false)
}

// LocalMailTLSConfig reloads the selected public identity for every connection,
// so certificate activation and rollback do not require restarting panel-core.
func LocalMailTLSConfig(serverName string) (*tls.Config, error) {
	return localMailTLSConfig(filepath.Join(defaultCertificateRoot, "public", "mail-default.pem"), serverName)
}

func localMailTLSConfig(path, serverName string) (*tls.Config, error) {
	leaf, err := readMailPublicIdentity(path, 0444)
	if err != nil {
		return nil, err
	}
	// This exception identifies only the installer's locally generated fallback.
	// Every other managed identity must cover the configured mail hostname.
	if leaf.Subject.CommonName == "CyberPanel bootstrap fallback" && len(leaf.DNSNames) == 1 && leaf.DNSNames[0] == "cyberpanel.invalid" && bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		serverName = "cyberpanel.invalid"
	}
	if serverName == "" || leaf.VerifyHostname(serverName) != nil {
		return nil, ErrInvalidCertificate
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, leaf.Raw) {
			return ErrInvalidCertificate
		}
		return nil
	}}, nil
}

func readMailPublicIdentity(path string, mode os.FileMode) (*x509.Certificate, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidCertificate
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !safeRootOwnedDirectory(info) {
			return nil, ErrInvalidCertificate
		}
		if directory == "/" {
			break
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !safeRootFile(info, mode) || info.Size() == 0 || info.Size() > 1<<20 {
		return nil, ErrInvalidCertificate
	}
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidCertificate
	}
	return x509.ParseCertificate(block.Bytes)
}
