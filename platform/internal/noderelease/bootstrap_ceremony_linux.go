//go:build linux

package noderelease

import (
 "context"
 "encoding/json"
 "fmt"
 "os"
 "os/exec"
 "os/user"
 "path/filepath"
 "strings"
)

// Fresh-install bootstrap ceremony. An offline bundle applied to a clean
// host must provision the fixed panel service identities and run the panel
// binary's closed installer hooks (authority, secrets, authn, database,
// DNS, mail) before any service probe: the packaged units read credential
// files and directories those hooks create. Upgrades never run this; the
// running ceremony is already present, and each hook is independently
// idempotent through its own receipt journal when a resume replays.

// bootstrapPanelIdentities mirrors the fixed identity records of the system
// installer (internal/install identityRecord). Subordinate ID spans for the
// rootless container identity remain part of container provisioning.
var bootstrapPanelIdentities = [][3]string{
 {"cyberpanel", "/var/lib/cyberpanel/control", "/usr/sbin/nologin"},
 {"cyberpanel-auth", "/var/lib/cyberpanel-auth", "/usr/sbin/nologin"},
 {"cyberpanel-secrets", "/var/lib/cyberpanel-secrets", "/usr/sbin/nologin"},
 {"cyberpanel-gateway", "/var/lib/cyberpanel-gateway", "/usr/sbin/nologin"},
 {"cyberpanel-containers", "/var/lib/cyberpanel-containers", "/usr/sbin/nologin"},
 {"cyberpanel-web", "/var/lib/cyberpanel-web", "/usr/sbin/nologin"},
}

func ensureBootstrapIdentities(ctx context.Context) error {
	for _, identity := range bootstrapPanelIdentities {
		name, home, shell := identity[0], identity[1], identity[2]
		if _, err := user.Lookup(name); err == nil {
			continue
		} else if _, unknown := err.(user.UnknownUserError); !unknown {
			return err
		}
		output, err := runFixed(ctx, "/usr/sbin/useradd", "--system", "--user-group", "--home-dir", home, "--create-home", "--shell", shell, name)
		if err != nil {
			return fmt.Errorf("bootstrap identity %s: %w: %s", name, err, output)
		}
		if _, err = user.Lookup(name); err != nil {
			return err
		}
	}
	return nil
}

// bootstrapHookBinary resolves the panel binary inside the materialized
// release tree with the same ownership/mode discipline as other trusted
// executables. The tree itself is digest-verified at staging.
func bootstrapHookBinary(releasePath string) (string, error) {
	// Materialized releases keep every managed destination under root/.
	binary := filepath.Join(releasePath, "root", "usr", "lib", "cyberpanel", "bin", "cyberpanel")
	info, err := os.Lstat(binary)
	metadata, ok := entryMetadata(info)
	if err != nil || !ok || metadata.Uid != 0 || metadata.Gid != 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("%w: bootstrap panel binary unavailable at %s", ErrIntegrity, binary)
	}
	return binary, nil
}

// packagedCatalogReleaseID returns the release identity the packaged
// application catalog was signed under; the initialize-authority hook
// validates its receipts against exactly that identity, which may differ
// from the node release when the catalog component was assembled first.
func packagedCatalogReleaseID(binary, fallback string) string {
	manifestPath := filepath.Join(filepath.Dir(binary), "application-catalog", "manifest.json")
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		return fallback
	}
	var document struct {
		ReleaseID string `json:"release_id"`
	}
	if json.Unmarshal(payload, &document) != nil || document.ReleaseID == "" {
		return fallback
	}
	return document.ReleaseID
}

func runBootstrapHook(ctx context.Context, binary, verb, release, component string) (string, error) {
	command := exec.CommandContext(ctx, binary, "installer-hook", verb, "--release", release, "--component", component)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "CYBERPANEL_INSTALLER=1"}
	output, err := command.CombinedOutput()
	if len(output) > 1<<20 {
		output = output[:1<<20]
	}
	if err != nil {
		return string(output), fmt.Errorf("bootstrap hook %s: %w: %s", verb, err, commandDiagnostic(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

// reconcileServicesAfterBroker reruns the service reconciliation once the
// secret broker is freshly active, provisioning the broker-dependent trust
// (malware approval key) the pre-probe pass deferred. No-op for upgrades:
// the running installation already holds that trust.
func (installer *Installer) reconcileServicesAfterBroker(ctx context.Context, journal *Journal) error {
	if installer == nil || journal == nil || journal.Previous != nil {
		return nil
	}
	binary, err := bootstrapHookBinary(journal.Candidate.ReleasePath)
	if err != nil {
		return err
	}
	execute, err := beginEffect(journal, "bootstrap_hook", "reconcile-services-after-secrets", installer.now())
	if err != nil {
		return err
	}
	if !execute {
		return nil
	}
	output, hookErr := runBootstrapHook(ctx, binary, "reconcile-services", journal.Candidate.ReleaseID, "panel")
	if hookErr != nil {
		return hookErr
	}
	return completeEffect(journal, "bootstrap_hook", "reconcile-services-after-secrets", digestJSON(output), installer.now())
}

// bootstrapFreshInstall provisions identities and runs the closed hook set
// once per fresh release. Journal effects make resumes replay-safe: a
// completed hook is never re-executed, and a failed one retries on the next
// apply from its own durable receipt position.
func (installer *Installer) bootstrapFreshInstall(ctx context.Context, journal *Journal) error {
	if installer == nil || journal == nil || journal.Previous != nil {
		return nil
	}
	if journal.Candidate.ReleaseID == "" {
		return ErrInvalid
	}
	binary, err := bootstrapHookBinary(journal.Candidate.ReleasePath)
	if err != nil {
		return err
	}
	catalogRelease := packagedCatalogReleaseID(binary, journal.Candidate.ReleaseID)
	execute, err := beginEffect(journal, "bootstrap_identity", "panel-identities", installer.now())
	if err != nil {
		return err
	}
	if execute {
		if err = ensureBootstrapIdentities(ctx); err != nil {
			return err
		}
		if err = completeEffect(journal, "bootstrap_identity", "panel-identities", digestJSON("panel-identities"), installer.now()); err != nil {
			return err
		}
	}
	for _, hook := range []struct{ verb, release, component string }{
		{"initialize-authority", catalogRelease, "panel"},
		{"bootstrap-secrets", journal.Candidate.ReleaseID, "panel"},
		{"bootstrap-authn", journal.Candidate.ReleaseID, "panel_authn"},
		{"bootstrap-database", journal.Candidate.ReleaseID, "mariadb"},
		{"bootstrap-dns", journal.Candidate.ReleaseID, "powerdns"},
		{"bootstrap-mail", journal.Candidate.ReleaseID, "dovecot"},
		// Service authority reconciliation provisions the runtime directories
		// (web worker identity layout, site-health activation store, native
		// authority boundaries) that packaged units open at startup.
		{"reconcile-services", journal.Candidate.ReleaseID, "panel"},
	} {
		execute, err := beginEffect(journal, "bootstrap_hook", hook.verb, installer.now())
		if err != nil {
			return err
		}
		if !execute {
			continue
		}
		output, hookErr := runBootstrapHook(ctx, binary, hook.verb, hook.release, hook.component)
		if hookErr != nil {
			return hookErr
		}
		if err = completeEffect(journal, "bootstrap_hook", hook.verb, digestJSON(output), installer.now()); err != nil {
			return err
		}
	}
	return nil
}
