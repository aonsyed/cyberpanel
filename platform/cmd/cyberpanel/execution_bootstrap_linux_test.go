//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
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

func TestExecutionBootstrapWaitsForConcurrentWriter(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(0)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err = bootstrapExecutionAdmission(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	writer, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE reboot_admission_gate SET epoch=epoch`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- bootstrapExecutionAdmission(ctx, db) }()
	select {
	case err = <-done:
		t.Fatalf("returned before writer released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM reboot_admission_gate`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	blocked, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback()
	if _, err = blocked.Exec(`UPDATE reboot_admission_gate SET epoch=epoch`); err != nil {
		t.Fatal(err)
	}
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if err = bootstrapExecutionAdmission(short, db); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}
