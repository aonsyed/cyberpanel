package apiserver

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
)

func TestDatabaseExportUnsupportedObjectsDiagnostic(t *testing.T) {
	problem := classifyError(databaseExportError(database.ErrTransferUnsupportedObjects), "objects-fixture")
	if problem.Status != http.StatusBadRequest || !strings.Contains(problem.Detail, "routines, triggers, or events") || !strings.Contains(problem.Detail, "visibility") {
		t.Fatalf("unsupported schema objects lost their actionable diagnostic: %+v", problem)
	}
}
