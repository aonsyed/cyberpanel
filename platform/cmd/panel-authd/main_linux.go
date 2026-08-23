//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/authn"
	_ "modernc.org/sqlite"
)

const (
	defaultConfigPath = "/etc/cyberpanel/authn.json"
	credentialRoot    = "/run/credentials/panel-authd.service"
	wrappingKeyPath   = credentialRoot + "/wrapping.key"
	lookupPepperPath  = credentialRoot + "/lookup.pepper"
	maximumConfigSize = int64(1 << 20)
)

type configuration struct {
	DatabasePath       string              `json:"database_path"`
	WebAuthnDisplayName string             `json:"webauthn_display_name"`
	WebAuthnOrigins    map[string][]string `json:"webauthn_origins"`
	MaximumConcurrent uint32              `json:"maximum_concurrent"`
}

func main() {
	flags := flag.NewFlagSet("panel-authd", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "protected authentication configuration")
	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 0 {
		log.Fatal("panel-authd accepts no positional arguments")
	}
	if err := run(*configPath); err != nil {
		log.Fatal(err)
	}
}

func run(configPath string) error {
	if os.Geteuid() == 0 {
		return errors.New("panel-authd refuses to run as root")
	}
	config, err := loadConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("load authn configuration: %w", err)
	}
	wrappingKey, err := readCredential(wrappingKeyPath)
	if err != nil {
		return fmt.Errorf("load wrapping key: %w", err)
	}
	defer clear(wrappingKey)
	lookupPepper, err := readCredential(lookupPepperPath)
	if err != nil {
		return fmt.Errorf("load lookup pepper: %w", err)
	}
	defer clear(lookupPepper)
	if err = requirePrivateStateDirectory(filepath.Dir(config.DatabasePath)); err != nil {
		return err
	}
	database, err := openDatabase(config.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	verifier, err := authn.New(database, wrappingKey, lookupPepper, authn.Config{
		WebAuthnDisplayName: config.WebAuthnDisplayName,
		WebAuthnOrigins:     config.WebAuthnOrigins,
	}, nil)
	if err != nil {
		return fmt.Errorf("initialize verifier: %w", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err = verifier.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap protected verifier store: %w", err)
	}
	controlUID, controlGID, err := authn.LookupControlIdentity()
	if err != nil {
		return fmt.Errorf("resolve control identity: %w", err)
	}
	peerPolicy, err := authn.NewPeerPolicy(controlUID)
	if err != nil {
		return err
	}
	listener, err := authn.ListenDefault(controlGID)
	if err != nil {
		return fmt.Errorf("listen on protected verifier socket: %w", err)
	}
	defer listener.Close()
	server := &authn.Server{
		Authorizer:        peerPolicy,
		Handler:           authn.Handler{Verifier: verifier},
		MaximumConcurrent: config.MaximumConcurrent,
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		_ = listener.Close()
		err = <-serveErrors
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("authn server stopped: %w", err)
		}
	case err = <-serveErrors:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("authn server failed: %w", err)
		}
	}
	return nil
}

func loadConfiguration(path string) (configuration, error) {
	var config configuration
	if path != defaultConfigPath {
		return config, errors.New("configuration path is not the registered path")
	}
	content, err := readProtectedFile(path, maximumConfigSize, 0644)
	if err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytesReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return config, err
	}
	if err = decoder.Decode(&struct{}{}); err != io.EOF {
		return config, errors.New("trailing authentication configuration data")
	}
	if config.DatabasePath != "/var/lib/cyberpanel-auth/authn.db" || config.MaximumConcurrent > 2048 || len(config.WebAuthnOrigins) == 0 {
		return config, errors.New("invalid authentication configuration")
	}
	if config.MaximumConcurrent == 0 {
		config.MaximumConcurrent = 128
	}
	return config, nil
}

func openDatabase(path string) (*sql.DB, error) {
	if path != "/var/lib/cyberpanel-auth/authn.db" {
		return nil, errors.New("unregistered authentication database path")
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=trusted_schema(0)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func readCredential(path string) ([]byte, error) {
	if path != wrappingKeyPath && path != lookupPepperPath {
		return nil, errors.New("unregistered credential path")
	}
	content, err := readProtectedFile(path, 32, 0400)
	if err != nil {
		return nil, err
	}
	if len(content) != 32 {
		clear(content)
		return nil, errors.New("authentication key must contain exactly 32 raw bytes")
	}
	return content, nil
}

func readProtectedFile(path string, maximum int64, maximumMode os.FileMode) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, errors.New("unsafe protected file path")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maximum || before.Mode().Perm()&^maximumMode != 0 {
		return nil, errors.New("unsafe protected file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("protected file changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		clear(content)
		return nil, errors.New("protected file exceeds limit")
	}
	return content, nil
}

func requirePrivateStateDirectory(path string) error {
	if path != "/var/lib/cyberpanel-auth" {
		return errors.New("unregistered authentication state directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe authentication state directory")
	}
	return nil
}

type byteReader struct {
	value []byte
	offset int
}

func bytesReader(value []byte) *byteReader { return &byteReader{value: value} }
func (reader *byteReader) Read(target []byte) (int, error) {
	if reader.offset == len(reader.value) {
		return 0, io.EOF
	}
	count := copy(target, reader.value[reader.offset:])
	reader.offset += count
	return count, nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
