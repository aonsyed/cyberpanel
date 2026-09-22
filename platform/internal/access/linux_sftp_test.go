//go:build linux

package access

import (
	"errors"
	"reflect"
	"testing"
)

func TestSFTPReloadSupportedUnitSelection(t *testing.T) {
	for _, test := range []struct {
		name              string
		primary, fallback error
		want              []string
		failed            bool
	}{
		{name: "sshd", want: []string{"sshd.service"}},
		{name: "ssh fallback", primary: errors.New("sshd unavailable"), want: []string{"sshd.service", "ssh.service"}},
		{name: "both fail", primary: errors.New("sshd unavailable"), fallback: errors.New("ssh unavailable"), want: []string{"sshd.service", "ssh.service"}, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var called []string
			err := reloadSFTPUnit(func(unit string) error {
				called = append(called, unit)
				if unit == "sshd.service" {
					return test.primary
				}
				return test.fallback
			})
			if !reflect.DeepEqual(called, test.want) || (err != nil) != test.failed {
				t.Fatalf("calls=%v error=%v", called, err)
			}
		})
	}
}
