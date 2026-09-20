//go:build linux

package main

import (
	"context"
	"database/sql"
	"testing"
)

func TestCoreRepositoriesBootstrapExecutionAdmission(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for i := 0; i < 2; i++ {
		if _, err = bootstrapControlRepositories(context.Background(), db); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = db.QueryRow(`SELECT count(*) FROM reboot_admission_gate WHERE singleton=1`).Scan(&count); err != nil || count != 1 {
			t.Fatal(count, err)
		}
	}
}
