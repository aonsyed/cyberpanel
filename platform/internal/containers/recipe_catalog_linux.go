//go:build linux

package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func ReadPackagedN8NRecipe(ctx context.Context, verifier RecipeVerifier) (ApplicationRecipe, error) {
	return readPackagedApplicationRecipe(ctx, verifier, "n8n")
}

func ReadPackagedHermesRecipe(ctx context.Context, verifier RecipeVerifier) (ApplicationRecipe, error) {
	return readPackagedApplicationRecipe(ctx, verifier, "hermes")
}

// Packaged application recipes are read only beside the installed executable.
// Neither a tenant path nor Compose text is accepted; rollback selects the old
// slot's independently signed recipes again.
func readPackagedApplicationRecipe(ctx context.Context, verifier RecipeVerifier, name string) (ApplicationRecipe, error) {
	var recipe ApplicationRecipe
	if ctx == nil || verifier == nil || name != "n8n" && name != "hermes" { return recipe, ErrInvalid }
	executable, err := os.Executable()
	if err != nil { return recipe, err }
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil { return recipe, err }
	parent := filepath.Dir(executable)
	if filepath.Base(executable) != "cyberpanel" || !strings.HasPrefix(parent, "/opt/cyberpanel/slots/") || filepath.Base(parent) != "panel" || filepath.Base(filepath.Dir(parent)) != "components" {
		return recipe, ErrForbidden
	}
	path := filepath.Join(parent, "container-recipes", name+".json")
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr != nil { return recipe, statErr }
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 { return recipe, ErrForbidden }
		if current == "/" { break }
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil { return recipe, err }
	defer file.Close()
	info, err := file.Stat()
	if err != nil { return recipe, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > 4<<20 { return recipe, ErrForbidden }
	payload, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || int64(len(payload)) != info.Size() { return recipe, ErrInvalid }
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&recipe) != nil || decoder.Decode(&struct{}{}) != io.EOF || recipe.Name != name { return recipe, ErrInvalid }
	if err = verifier.Verify(ctx, recipe); err != nil { return recipe, fmt.Errorf("packaged %s signature: %w", name, err) }
	return recipe, nil
}
