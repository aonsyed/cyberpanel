//go:build linux

package main

import "time"

type runtimeClock struct{}
func (runtimeClock) Now() time.Time { return time.Now().UTC() }
