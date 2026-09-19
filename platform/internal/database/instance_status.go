package database

import "time"

// MariaDBInstanceStatus is the bounded live observation returned by the root
// executor. It contains no SQL, credentials, secret references, or host paths.
type MariaDBInstanceStatus struct {
	InstanceID  ResourceID     `json:"instance_id"`
	Placement   Placement      `json:"placement"`
	Version     MariaDBVersion `json:"version"`
	Reachable   bool           `json:"reachable"`
	TLSVerified bool           `json:"tls_verified"`
	ProofDigest string         `json:"proof_digest"`
	ObservedAt  time.Time      `json:"observed_at"`
}

func (status MariaDBInstanceStatus) validate(expected ResourceID) error {
	if expected.IsZero() || status.InstanceID != expected || status.Version.Major == 0 || !status.Reachable ||
		(status.Placement != PlacementLocal && status.Placement != PlacementExternal) ||
		status.Placement == PlacementExternal && !status.TLSVerified ||
		status.Placement == PlacementLocal && status.TLSVerified ||
		!validSHA256(status.ProofDigest) || status.ObservedAt.IsZero() {
		return ErrInvalidReceipt
	}
	return nil
}
