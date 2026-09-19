package sitepreview

import (
	"context"
	"errors"
	"fmt"
	"image/png"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

const DefaultChromiumProfileRoot = "/var/lib/cyberpanel/sitepreview/chromium-profiles"

var allowedChromeBinaries = map[string]struct{}{
	"/usr/bin/chromium":             {},
	"/usr/bin/chromium-browser":     {},
	"/usr/bin/google-chrome":        {},
	"/usr/bin/google-chrome-stable": {},
}

type DNSResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type ChromeLaunch struct {
	JobID                ScreenshotJobID
	Binary               string
	ProfileDirectory     string
	OutputPath           string
	URL                  string
	Host                 string
	SNI                  string
	AllowedEndpoint      netip.AddrPort
	Width                uint32
	Height               uint32
	MaximumResponseBytes uint64
	MaximumRedirects     uint8
	Deadline             time.Time
	Arguments            []string
}

func (launch ChromeLaunch) Validate() error {
	if !validID(string(launch.JobID)) || !allowedChromeBinary(launch.Binary) || !filepath.IsAbs(launch.ProfileDirectory) || !filepath.IsAbs(launch.OutputPath) ||
		filepath.Dir(launch.OutputPath) != launch.ProfileDirectory || filepath.Base(launch.OutputPath) != "screenshot.png" || !validHostname(launch.Host) || launch.SNI != launch.Host ||
		!launch.AllowedEndpoint.IsValid() || launch.AllowedEndpoint.Addr().IsUnspecified() || launch.AllowedEndpoint.Port() == 0 || launch.Width < 320 || launch.Height < 200 ||
		launch.MaximumResponseBytes == 0 || launch.MaximumResponseBytes > MaximumScreenshotBytes || launch.MaximumRedirects > MaximumRedirects || launch.Deadline.IsZero() {
		return ErrInvalid
	}
	parsed, err := url.Parse(launch.URL)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() != launch.Host || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrPolicyDenied
	}
	expected := fixedChromeArguments(launch.ProfileDirectory, launch.OutputPath, launch.URL, launch.Host, launch.AllowedEndpoint.Addr(), launch.Width, launch.Height)
	if len(launch.Arguments) != len(expected) {
		return ErrPolicyDenied
	}
	for index := range expected {
		if launch.Arguments[index] != expected[index] {
			return ErrPolicyDenied
		}
	}
	return nil
}

type NavigationHop struct {
	URL             string
	ResolvedAddress netip.Addr
	Status          uint16
}

type NavigationReceipt struct {
	JobID           ScreenshotJobID
	NamespaceID     string
	ProfileIsolated bool
	ExtensionsOff   bool
	DownloadsOff    bool
	CredentialsOff  bool
	FileURLsOff     bool
	DataURLsOff     bool
	Hops            []NavigationHop
	ResponseBytes   uint64
	StartedAt       time.Time
	FinishedAt      time.Time
	EvidenceDigest  string
}

// ChromeNamespace is a closed local helper boundary. Implementations create a
// fresh OS/user/network namespace, allow egress only to AllowedEndpoint, drive
// Chrome navigation while recording every redirect, and reject any argv that
// fails ChromeLaunch.Validate. It is not a generic process runner.
type ChromeNamespace interface {
	RunIsolatedChrome(context.Context, ChromeLaunch) (NavigationReceipt, error)
}

type ChromiumRenderer struct {
	binary      string
	profileRoot string
	resolver    DNSResolver
	namespace   ChromeNamespace
	now         func() time.Time
}

func NewChromiumRenderer(binary string, resolver DNSResolver, namespace ChromeNamespace) (*ChromiumRenderer, error) {
	if !allowedChromeBinary(binary) || resolver == nil || namespace == nil {
		return nil, ErrInvalid
	}
	return &ChromiumRenderer{binary: binary, profileRoot: DefaultChromiumProfileRoot, resolver: resolver, namespace: namespace, now: time.Now}, nil
}

func (renderer *ChromiumRenderer) RenderIsolated(ctx context.Context, job ScreenshotJob, site SiteSnapshot) (RenderedArtifact, error) {
	if renderer == nil || renderer.resolver == nil || renderer.namespace == nil || job.Validate() != nil || job.Mode != ScreenshotLocal || site.Validate() != nil || !exactJobSite(job, site) || job.Destination.Validate(site) != nil {
		return RenderedArtifact{}, ErrInvalid
	}
	if err := validateChromeBinary(renderer.binary); err != nil {
		return RenderedArtifact{}, err
	}
	parsed, err := url.Parse(job.Destination.URL)
	if err != nil || parsed.Scheme != string(site.Backend.Protocol) || parsed.Hostname() != site.Backend.ServerName || parsed.User != nil || parsed.Fragment != "" {
		return RenderedArtifact{}, ErrPolicyDenied
	}
	if err = renderer.revalidateDNS(ctx, parsed.Hostname(), site.Backend.Address); err != nil {
		return RenderedArtifact{}, err
	}
	if err = ensurePrivateRoot(renderer.profileRoot); err != nil {
		return RenderedArtifact{}, err
	}
	profile, err := os.MkdirTemp(renderer.profileRoot, "job-")
	if err != nil {
		return RenderedArtifact{}, err
	}
	cleanup := func() error { return os.RemoveAll(profile) }
	if err = os.Chmod(profile, 0o700); err != nil {
		_ = cleanup()
		return RenderedArtifact{}, err
	}
	output := filepath.Join(profile, "screenshot.png")
	endpoint := netip.AddrPortFrom(site.Backend.Address, site.Backend.Port)
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		_ = cleanup()
		return RenderedArtifact{}, ErrInvalid
	}
	launch := ChromeLaunch{JobID: job.ID, Binary: renderer.binary, ProfileDirectory: profile, OutputPath: output, URL: job.Destination.URL, Host: parsed.Hostname(), SNI: site.Backend.ServerName,
		AllowedEndpoint: endpoint, Width: job.Limits.Width, Height: job.Limits.Height, MaximumResponseBytes: job.Limits.MaximumBytes, MaximumRedirects: job.Limits.Redirects, Deadline: deadline.UTC()}
	launch.Arguments = fixedChromeArguments(profile, output, launch.URL, launch.Host, endpoint.Addr(), launch.Width, launch.Height)
	if launch.Validate() != nil {
		_ = cleanup()
		return RenderedArtifact{}, ErrIntegrity
	}
	receipt, err := renderer.namespace.RunIsolatedChrome(ctx, launch)
	if err != nil {
		_ = cleanup()
		return RenderedArtifact{}, err
	}
	if validateNavigationReceipt(receipt, launch, job.Limits, renderer.clock()) != nil {
		_ = cleanup()
		return RenderedArtifact{}, ErrPolicyDenied
	}
	if err = renderer.revalidateDNS(ctx, parsed.Hostname(), site.Backend.Address); err != nil {
		_ = cleanup()
		return RenderedArtifact{}, err
	}
	pathInfo, err := os.Lstat(output)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() <= 0 || uint64(pathInfo.Size()) > job.Limits.MaximumBytes {
		_ = cleanup()
		return RenderedArtifact{}, ErrPolicyDenied
	}
	file, err := os.Open(output)
	if err != nil {
		_ = cleanup()
		return RenderedArtifact{}, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		_ = cleanup()
		return RenderedArtifact{}, ErrPolicyDenied
	}
	configuration, err := png.DecodeConfig(file)
	if err != nil || configuration.Width != int(job.Limits.Width) || configuration.Height != int(job.Limits.Height) {
		_ = file.Close()
		_ = cleanup()
		return RenderedArtifact{}, ErrIntegrity
	}
	if _, err = file.Seek(0, 0); err != nil {
		_ = file.Close()
		_ = cleanup()
		return RenderedArtifact{}, err
	}
	return RenderedArtifact{Reader: file, MediaType: "image/png", Width: job.Limits.Width, Height: job.Limits.Height, Cleanup: cleanup}, nil
}

func (renderer *ChromiumRenderer) clock() time.Time {
	if renderer.now == nil {
		return time.Now().UTC()
	}
	return renderer.now().UTC()
}

func (renderer *ChromiumRenderer) revalidateDNS(ctx context.Context, hostname string, backend netip.Addr) error {
	addresses, err := renderer.resolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		// Pre-DNS previews are allowed to use only the exact canonical backend;
		// failure to resolve cannot widen that single-endpoint namespace.
		return nil
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return ErrPolicyDenied
	}
	canonical := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !safePublicAddress(address) && address != backend.Unmap() {
			return ErrPolicyDenied
		}
		canonical = append(canonical, address.String())
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return ErrPolicyDenied
		}
	}
	return nil
}

func validateNavigationReceipt(receipt NavigationReceipt, launch ChromeLaunch, limits ScreenshotLimits, now time.Time) error {
	if receipt.JobID != launch.JobID || !validID(receipt.NamespaceID) || !receipt.ProfileIsolated || !receipt.ExtensionsOff || !receipt.DownloadsOff || !receipt.CredentialsOff || !receipt.FileURLsOff || !receipt.DataURLsOff ||
		receipt.StartedAt.IsZero() || receipt.FinishedAt.Before(receipt.StartedAt) || receipt.FinishedAt.Sub(receipt.StartedAt) > limits.Timeout || receipt.FinishedAt.After(now.Add(time.Minute)) ||
		receipt.FinishedAt.After(launch.Deadline) || receipt.ResponseBytes == 0 || receipt.ResponseBytes > launch.MaximumResponseBytes || !validDigest(receipt.EvidenceDigest) ||
		len(receipt.Hops) == 0 || len(receipt.Hops) > int(launch.MaximumRedirects)+1 {
		return ErrInvalid
	}
	for index, hop := range receipt.Hops {
		parsed, err := url.Parse(hop.URL)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() != launch.Host ||
			effectiveURLPort(parsed) != launch.AllowedEndpoint.Port() || hop.ResolvedAddress.Unmap() != launch.AllowedEndpoint.Addr().Unmap() || hop.Status < 200 || hop.Status > 399 {
			return ErrPolicyDenied
		}
		if index == 0 && hop.URL != launch.URL {
			return ErrPolicyDenied
		}
		if index+1 < len(receipt.Hops) && (hop.Status < 300 || hop.Status > 399) {
			return ErrPolicyDenied
		}
	}
	if receipt.Hops[len(receipt.Hops)-1].Status >= 300 {
		return ErrPolicyDenied
	}
	return nil
}

func fixedChromeArguments(profile, output, target, hostname string, address netip.Addr, width, height uint32) []string {
	resolverRule := "MAP " + hostname + " " + address.String() + ", MAP * ~NOTFOUND, EXCLUDE localhost"
	window := strconv.FormatUint(uint64(width), 10) + "," + strconv.FormatUint(uint64(height), 10)
	return []string{
		"--headless=new",
		// The helper already places Chromium in a fresh, unprivileged user and
		// network namespace. Chromium sees namespace-root, so its setuid sandbox
		// cannot be used there; the outer namespace remains the security boundary.
		"--no-sandbox",
		"--disable-background-networking",
		"--disable-breakpad",
		"--disable-client-side-phishing-detection",
		"--disable-component-extensions-with-background-pages",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-features=DnsOverHttps,DownloadBubble,DownloadBubbleV2,FileSystemAccessAPI,OptimizationHints,PasswordManagerOnboarding",
		"--disable-notifications",
		"--disable-popup-blocking",
		"--disable-prompt-on-repost",
		"--disable-sync",
		"--disable-translate",
		"--deny-permission-prompts",
		"--disk-cache-size=1",
		"--hide-scrollbars",
		"--incognito",
		"--metrics-recording-only",
		"--no-default-browser-check",
		"--no-first-run",
		"--no-proxy-server",
		"--password-store=basic",
		"--site-per-process",
		"--user-data-dir=" + profile,
		"--host-resolver-rules=" + resolverRule,
		"--window-size=" + window,
		"--screenshot=" + output,
		target,
	}
}

func allowedChromeBinary(binary string) bool {
	_, allowed := allowedChromeBinaries[binary]
	return allowed && filepath.Clean(binary) == binary && filepath.IsAbs(binary)
}

func validateChromeBinary(binary string) error {
	if !allowedChromeBinary(binary) {
		return ErrPolicyDenied
	}
	info, err := os.Lstat(binary)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return ErrPolicyDenied
	}
	return nil
}

func ensurePrivateRoot(root string) error {
	if root != DefaultChromiumProfileRoot || filepath.Clean(root) != root || !filepath.IsAbs(root) {
		return ErrPolicyDenied
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrPolicyDenied
	}
	return nil
}

func safePublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var deniedPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func NewSystemDNSResolver() DNSResolver { return net.DefaultResolver }

func ValidateChromeNamespaceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("isolated chrome failed: %w", err)
}
