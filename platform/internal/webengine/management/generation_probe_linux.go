//go:build linux

package management

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type lifecycleChallenge struct {
	Application webengine.ResourceRef `json:"application"`
	Filename    string                `json:"filename"`
	Secret      string                `json:"secret"`
}

type lifecycleExchange struct {
	Hostname          string
	Port              uint16
	TLS               bool
	Status            int
	BodyDigest        string
	CertificateDigest string
	ObservedAt        time.Time
}

// Challenges live on the actual site filesystem because managed external
// LSAPI pools do not share the candidate's mount namespace. The parent owns
// cleanup even if the private worker is forcibly killed or times out.
func prepareLifecycleChallenges(render native.RenderRequest) ([]lifecycleChallenge, func() error, error) {
	if err := recoverLifecycleChallenges(); err != nil {
		return nil, func() error { return nil }, err
	}
	var challenges []lifecycleChallenge
	type ownedFile struct {
		root *os.Root
		name string
		info os.FileInfo
	}
	var owned []ownedFile
	cleanup := func() error {
		var failures []error
		for _, item := range owned {
			current, err := item.root.Lstat(item.name)
			if err == nil && !os.SameFile(current, item.info) {
				err = ErrConflict
			}
			if err == nil {
				err = item.root.Remove(item.name)
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, err)
			}
			failures = append(failures, item.root.Close())
		}
		owned = nil
		err := errors.Join(failures...)
		if err == nil {
			err = atomicPHPFile(filepath.Join(lifecycleStateRoot, "candidate-challenges.json"), []byte("null"))
		}
		return err
	}
	fail := func(err error) ([]lifecycleChallenge, func() error, error) {
		return nil, func() error { return nil }, errors.Join(err, cleanup())
	}
	sites := map[webengine.ResourceRef]native.SiteRuntime{}
	for _, site := range render.Snapshot.Sites {
		sites[site.SiteRef] = site
	}
	active := map[webengine.ResourceRef]bool{}
	for _, binding := range render.Desired.Bindings {
		if binding.RoutingState == webengine.RoutingServe && binding.Relationship == webengine.BindingPrimary {
			active[binding.ApplicationRef] = true
		}
	}
	for _, app := range render.Desired.Applications {
		if !active[app.Ref] {
			continue
		}
		if len(challenges) >= 32 || app.PHPProfileRef == "" || app.ReverseProxy != nil {
			return fail(ErrUnsupported)
		}
		site, exists := sites[app.SiteRef]
		if !exists {
			return fail(ErrInvalid)
		}
		rootPath := filepath.Join("/var/lib/cyberpanel/sites", string(site.SiteKey), "roots", "g"+strconv.FormatUint(site.RootGeneration, 10))
		before, err := os.Lstat(rootPath)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return fail(ErrInvalid)
		}
		owner, ok := before.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || owner.Gid < siteops.DefaultUIDMinimum || owner.Gid > siteops.DefaultUIDMaximum {
			return fail(ErrInvalid)
		}
		resolved, err := filepath.EvalSymlinks(rootPath)
		if err != nil || resolved != rootPath {
			return fail(ErrInvalid)
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			return fail(err)
		}
		after, err := root.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			root.Close()
			return fail(ErrConflict)
		}
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			root.Close()
			return fail(err)
		}
		token := hex.EncodeToString(secret[:])
		filename := ".panel-runtime-" + token[:24] + ".php"
		name := filepath.Join(app.DocumentRoot, filename)
		challenges = append(challenges, lifecycleChallenge{Application: app.Ref, Filename: filename, Secret: token})
		manifest, err := json.Marshal(lifecycleChallengeManifest{Render: render, Challenges: challenges})
		if err != nil {
			root.Close()
			return fail(err)
		}
		if err = atomicPHPFile(filepath.Join(lifecycleStateRoot, "candidate-challenges.json"), manifest); err != nil {
			root.Close()
			return fail(err)
		}
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			root.Close()
			return fail(err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			root.Remove(name)
			root.Close()
			return fail(statErr)
		}
		owned = append(owned, ownedFile{root: root, name: name, info: info})
		if err = file.Chown(0, int(owner.Gid)); err == nil {
			err = file.Chmod(0o440)
		}
		if err != nil {
			file.Close()
			return fail(err)
		}
		// The expected response never occurs in the source. Two independent
		// request nonces distinguish actual PHP execution from static delivery.
		script := "<?php header('Content-Type: text/plain'); header('Cache-Control: no-store'); echo hash_hmac('sha256', $_SERVER['HTTP_X_PANEL_PROBE_NONCE'] ?? '', '" + token + "'), \"\\n\";"
		_, writeErr := io.WriteString(file, script)
		err = errors.Join(writeErr, file.Sync(), file.Close())
		if err != nil {
			return fail(err)
		}
	}
	if len(challenges) == 0 {
		return fail(ErrUnsupported)
	}
	return challenges, cleanup, nil
}

type lifecycleChallengeManifest struct {
	Render     native.RenderRequest `json:"render"`
	Challenges []lifecycleChallenge `json:"challenges"`
}

type lifecycleChallengeRecoveryMarker struct {
	Version        uint32          `json:"version"`
	ManifestDigest string          `json:"manifest_digest"`
	Manifest       json.RawMessage `json:"manifest"`
}

// A root-owned manifest precedes file creation, so broker restart can clean a
// killed parent's challenge without trusting a tenant-controlled pathname.
func recoverLifecycleChallenges() error {
	return recoverLifecycleChallengesExpected("")
}

func readLifecycleChallengeManifest() ([]byte, *lifecycleChallengeManifest, error) {
	manifestPath := filepath.Join(lifecycleStateRoot, "candidate-challenges.json")
	info, err := os.Lstat(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !rootOwnedFile(info) || info.Size() > linuxManagementMaximumFrame {
		return nil, nil, ErrInvalid
	}
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	var manifest *lifecycleChallengeManifest
	if decodeLifecyclePayload(content, &manifest) != nil {
		return nil, nil, ErrInvalid
	}
	return content, manifest, nil
}

func recoverLifecycleChallengesExpected(expectedDigest string) error {
	if err := recoverLifecycleChallengeFilesExpected(expectedDigest); err != nil {
		return err
	}
	return clearLifecycleChallengeManifest()
}

func recoverLifecycleChallengeFilesExpected(expectedDigest string) error {
	content, manifest, err := readLifecycleChallengeManifest()
	if err != nil {
		return err
	}
	return recoverLifecycleChallengeFiles(content, manifest, expectedDigest, true)
}

func recoverLifecycleChallengeFiles(content []byte, manifest *lifecycleChallengeManifest, expectedDigest string, remove bool) error {
	if expectedDigest != "" && (manifest == nil || linuxManagementDigest(content) != expectedDigest) {
		return ErrConflict
	}
	if manifest == nil {
		return nil
	}
	if native.ValidateRequest(manifest.Render, manifest.Render.Desired.Engine.Edition) != nil || len(manifest.Challenges) > 32 {
		return ErrInvalid
	}
	for _, challenge := range manifest.Challenges {
		if !validSHA256(challenge.Secret) || challenge.Filename != ".panel-runtime-"+challenge.Secret[:24]+".php" {
			return ErrInvalid
		}
		found := false
		for _, app := range manifest.Render.Desired.Applications {
			if app.Ref != challenge.Application {
				continue
			}
			for _, site := range manifest.Render.Snapshot.Sites {
				if site.SiteRef != app.SiteRef {
					continue
				}
				found = true
				base := filepath.Join("/var/lib/cyberpanel/sites", string(site.SiteKey), "roots", "g"+strconv.FormatUint(site.RootGeneration, 10))
				resolved, resolveErr := filepath.EvalSymlinks(base)
				if resolveErr != nil || resolved != base {
					return ErrInvalid
				}
				root, openErr := os.OpenRoot(base)
				if openErr != nil {
					return openErr
				}
				name := filepath.Join(app.DocumentRoot, challenge.Filename)
				file, statErr := root.Lstat(name)
				if errors.Is(statErr, os.ErrNotExist) {
					root.Close()
					continue
				}
				if statErr != nil || !file.Mode().IsRegular() || !rootOwnedFile(file) {
					root.Close()
					return ErrConflict
				}
				if !remove {
					root.Close()
					return ErrConflict
				}
				removeErr := root.Remove(name)
				closeErr := root.Close()
				if removeErr != nil || closeErr != nil {
					return errors.Join(removeErr, closeErr)
				}
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}

func clearLifecycleChallengeManifest() error {
	return atomicPHPFile(filepath.Join(lifecycleStateRoot, "candidate-challenges.json"), []byte("null"))
}

func writeLifecycleChallengeRecoveryMarker(content []byte, manifestDigest string) (string, error) {
	if !json.Valid(content) || linuxManagementDigest(content) != manifestDigest {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(lifecycleChallengeRecoveryMarker{Version: 1, ManifestDigest: manifestDigest, Manifest: append(json.RawMessage(nil), content...)})
	if err != nil {
		return "", err
	}
	if err = atomicPHPFile(filepath.Join(lifecycleStateRoot, "candidate-challenges-recovery.json"), encoded); err != nil {
		return "", err
	}
	return linuxManagementDigest(encoded), nil
}

func readLifecycleChallengeRecoveryMarker() ([]byte, *lifecycleChallengeRecoveryMarker, error) {
	markerPath := filepath.Join(lifecycleStateRoot, "candidate-challenges-recovery.json")
	info, err := os.Lstat(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !rootOwnedFile(info) || info.Size() > linuxManagementMaximumFrame+4096 {
		return nil, nil, ErrInvalid
	}
	content, err := os.ReadFile(markerPath)
	if err != nil {
		return nil, nil, err
	}
	var marker lifecycleChallengeRecoveryMarker
	if decodeLifecyclePayload(content, &marker) != nil || marker.Version != 1 || !json.Valid(marker.Manifest) || marker.ManifestDigest != linuxManagementDigest(marker.Manifest) {
		return nil, nil, ErrInvalid
	}
	var manifest *lifecycleChallengeManifest
	if decodeLifecyclePayload(marker.Manifest, &manifest) != nil || manifest == nil {
		return nil, nil, ErrInvalid
	}
	return content, &marker, nil
}

func readRecoverableLifecycleChallengeManifest() ([]byte, *lifecycleChallengeManifest, string, error) {
	content, manifest, err := readLifecycleChallengeManifest()
	if err != nil || manifest != nil {
		return content, manifest, "", err
	}
	markerContent, marker, err := readLifecycleChallengeRecoveryMarker()
	if err != nil || marker == nil {
		return nil, nil, "", err
	}
	if decodeLifecyclePayload(marker.Manifest, &manifest) != nil || manifest == nil {
		return nil, nil, "", ErrInvalid
	}
	return append([]byte(nil), marker.Manifest...), manifest, linuxManagementDigest(markerContent), nil
}

func verifyLifecycleChallengeRecoveryState(content []byte, manifestDigest, markerDigest string) error {
	_, remaining, err := readLifecycleChallengeManifest()
	if err != nil || remaining != nil {
		return errors.Join(ErrAmbiguous, err)
	}
	markerContent, marker, err := readLifecycleChallengeRecoveryMarker()
	if err != nil || marker == nil || marker.ManifestDigest != manifestDigest || string(marker.Manifest) != string(content) || linuxManagementDigest(markerContent) != markerDigest {
		return errors.Join(ErrAmbiguous, err)
	}
	var manifest *lifecycleChallengeManifest
	if decodeLifecyclePayload(content, &manifest) != nil || manifest == nil {
		return ErrInvalid
	}
	return recoverLifecycleChallengeFiles(content, manifest, manifestDigest, false)
}

func probeLifecycleHTTP(ctx context.Context, input lifecycleGenerationInput) (receipt ProbeReceipt, err error) {
	if _, err = renderLifecycleGeneration(ctx, input); err != nil {
		return receipt, err
	}
	challenges, cleanup, err := prepareLifecycleChallenges(input.Render)
	if err != nil {
		return receipt, err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	return executeLifecycleProbes(ctx, input, challenges)
}

func executeLifecycleProbes(ctx context.Context, input lifecycleGenerationInput, challenges []lifecycleChallenge) (ProbeReceipt, error) {
	receipt := ProbeReceipt{EffectID: input.Request.EffectID, ConfigDigest: input.ConfigDigest}
	challengeByApp := map[webengine.ResourceRef]lifecycleChallenge{}
	for _, challenge := range challenges {
		if !validSHA256(challenge.Secret) || challenge.Filename != ".panel-runtime-"+challenge.Secret[:24]+".php" || challengeByApp[challenge.Application].Application != "" {
			return receipt, ErrInvalid
		}
		challengeByApp[challenge.Application] = challenge
	}
	listeners := map[webengine.ResourceRef]webengine.Listener{}
	for _, listener := range input.Render.Desired.Engine.Listeners {
		listeners[listener.Ref] = listener
	}
	var evidence []lifecycleExchange
	seenHTTP, seenTLS, seenPHP := false, false, false
	count := 0
	for _, binding := range input.Render.Desired.Bindings {
		// Preview and redirect aliases have different redirect/auth semantics;
		// this receipt attests active primary application bindings only.
		if binding.RoutingState != webengine.RoutingServe || binding.Relationship != webengine.BindingPrimary {
			continue
		}
		challenge, exists := challengeByApp[binding.ApplicationRef]
		if !exists || len(binding.Hostnames) == 0 {
			return receipt, ErrInvalid
		}
		for _, ref := range binding.ListenerRefs {
			listener, exists := listeners[ref]
			if !exists || !lifecycleLoopbackListener(listener) {
				return receipt, ErrUnsupported
			}
			for _, hostname := range binding.Hostnames {
				count++
				if count > 64 {
					return receipt, ErrInvalid
				}
				for nonceIndex := 0; nonceIndex < 2; nonceIndex++ {
					var nonceBytes [32]byte
					if _, err := rand.Read(nonceBytes[:]); err != nil {
						return receipt, err
					}
					nonce := hex.EncodeToString(nonceBytes[:])
					exchange, err := lifecycleHTTPExchange(ctx, hostname.String(), listener, challenge, nonce)
					if err != nil {
						return receipt, err
					}
					evidence = append(evidence, exchange)
				}
				seenPHP = true
				if listener.TLSMode == webengine.TLSModeTLS {
					seenTLS = true
				} else {
					seenHTTP = true
				}
			}
		}
	}
	if count == 0 || !seenPHP {
		return receipt, ErrUnsupported
	}
	receipt.HTTP, receipt.HTTPS, receipt.TLS, receipt.PHP = seenHTTP, seenTLS, seenTLS, seenPHP
	receipt.EvidenceDigest = digestJSON(struct {
		Config    string
		Exchanges []lifecycleExchange
	}{input.ConfigDigest, evidence})
	receipt.ObservedAt = time.Now().UTC()
	return receipt, nil
}

func lifecycleLoopbackListener(listener webengine.Listener) bool {
	for _, address := range listener.Addresses {
		if address == "0.0.0.0" || address == "127.0.0.1" {
			return true
		}
	}
	return false
}

func lifecycleHTTPExchange(ctx context.Context, hostname string, listener webengine.Listener, challenge lifecycleChallenge, nonce string) (lifecycleExchange, error) {
	result := lifecycleExchange{Hostname: hostname, Port: listener.Port, TLS: listener.TLSMode == webengine.TLSModeTLS}
	parsed, err := webengine.ParseHostname(hostname)
	if err != nil || parsed.String() != hostname || listener.Port == 0 {
		return result, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	scheme := "http"
	if result.TLS {
		scheme = "https"
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(hostname, strconv.Itoa(int(listener.Port))) {
			return nil, ErrInvalid
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listener.Port))))
	}}
	defer transport.CloseIdleConnections()
	url := scheme + "://" + net.JoinHostPort(hostname, strconv.Itoa(int(listener.Port))) + "/" + challenge.Filename
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}
	request.Host = hostname
	request.Header.Set("X-Panel-Probe-Nonce", nonce)
	request.Header.Set("Cache-Control", "no-store")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return result, err
	}
	if response == nil || response.Body == nil {
		return result, ErrAmbiguous
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		return result, ErrAmbiguous
	}
	mac := hmac.New(sha256.New, []byte(challenge.Secret))
	_, _ = mac.Write([]byte(nonce))
	expected := hex.EncodeToString(mac.Sum(nil)) + "\n"
	if response.StatusCode != http.StatusOK || !hmac.Equal(body, []byte(expected)) || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain") {
		return result, fmt.Errorf("%w: candidate did not execute the bound PHP challenge", ErrAmbiguous)
	}
	if result.TLS {
		if response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
			return result, ErrAmbiguous
		}
		result.CertificateDigest = linuxManagementDigest(response.TLS.PeerCertificates[0].Raw)
	}
	result.Status, result.BodyDigest, result.ObservedAt = response.StatusCode, linuxManagementDigest(body), time.Now().UTC()
	return result, nil
}
