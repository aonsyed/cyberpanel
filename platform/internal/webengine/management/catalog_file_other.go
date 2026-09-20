//go:build !linux

package management

// Native signed catalogs are node-local Linux resources.
func readCatalogFile(string, int64, bool) ([]byte, error) { return nil, ErrUnsupported }
