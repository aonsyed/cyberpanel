//go:build linux

package apps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// finishWordPressBootstrap only configures local inputs. Plugin installation
// belongs to the explicit plugin/cache operations, not the core install path.
func (runtime *LinuxApplicationRuntime) finishWordPressBootstrap(ctx context.Context, scope linuxApplicationScope, locale, timezone string) error {
	if locale == "" || strings.ContainsAny(locale, "/\\\x00") || locale == "." || locale == ".." {
		return ErrInvalid
	}
	if locale != "en_US" {
		language := filepath.Join(scope.root, "wp-content", "languages", locale+".mo")
		info, err := os.Lstat(language)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("WordPress language %q is unavailable locally; supply the language in the approved application input before installing: %w", locale, ErrRecipeUnavailable)
		}
		if _, stderr, _, err := runtime.wp(ctx, scope, nil, 1<<20, "language", "core", "activate", locale); err != nil {
			return fmt.Errorf("activate local WordPress language: %w: %s", err, stderr)
		}
	}
	if _, stderr, _, err := runtime.wp(ctx, scope, nil, 1<<20, "option", "update", "timezone_string", timezone); err != nil {
		return fmt.Errorf("configure WordPress timezone: %w: %s", err, stderr)
	}
	return nil
}
