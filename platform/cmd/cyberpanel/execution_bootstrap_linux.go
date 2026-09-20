//go:build linux

package main

import (
	"context"
	"database/sql"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// Core owns this schema. Establish it before domain startup can request any
// privileged mutation; the executor must still complete its own recovery.
func bootstrapExecutionAdmission(ctx context.Context, db *sql.DB) error {
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
