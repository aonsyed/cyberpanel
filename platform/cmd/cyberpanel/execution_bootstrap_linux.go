//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// Core owns this schema. Establish it before domain startup can request any
// privileged mutation; the executor must still complete its own recovery.
func bootstrapExecutionAdmission(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err := bootstrapExecutionAdmissionAttempt(ctx, db)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var coded interface{ Code() int }
		// Retry the entire rolled-back initialization, never a statement in a
		// stale WAL snapshot. Only SQLITE_BUSY (including extended codes) is
		// transient here; integrity, schema and permission errors remain fatal.
		if !errors.As(err, &coded) || coded.Code()&0xff != 5 {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func bootstrapExecutionAdmissionAttempt(ctx context.Context, db *sql.DB) error {
	repository, err := rebootcontrol.NewRepository(db)
	if err != nil {
		return err
	}
	if err = repository.Bootstrap(ctx); err != nil {
		return err
	}
	runtime := &rebootControlLocalRuntime{now: time.Now}
	boot, err := runtime.CurrentBootIdentity(ctx, "local")
	if err != nil {
		return err
	}
	_, err = rebootcontrol.NewAdmissionGate(ctx, db, boot.BootID, time.Now)
	return err
}
