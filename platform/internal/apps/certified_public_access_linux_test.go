//go:build linux

package apps

import (
	"encoding/binary"
	"testing"
)

func TestCertifiedPublicACLRejectsBroaderOrUnrelatedPolicy(t *testing.T) {
	value := make([]byte, 44)
	binary.LittleEndian.PutUint32(value, 2)
	for i, entry := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, 988}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		part := value[4+i*8:]
		binary.LittleEndian.PutUint16(part, uint16(entry[0]))
		binary.LittleEndian.PutUint16(part[2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(part[4:], entry[2])
	}
	if !validCertifiedPublicACL(value, 988) {
		t.Fatal("provisioned public-reader policy rejected")
	}
	for _, test := range []struct {
		name        string
		offset      int
		replacement byte
	}{
		{"version", 0, 3}, {"web-write", 14, 7}, {"other-read", 38, 4}, {"named-principal", 16, 1}, {"group-write", 22, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := append([]byte(nil), value...)
			bad[test.offset] = test.replacement
			if validCertifiedPublicACL(bad, 988) {
				t.Fatal("untrusted policy accepted")
			}
		})
	}
	if validCertifiedPublicACL(value[:36], 988) || validCertifiedPublicACL(append(value, 0), 988) || validCertifiedPublicACL(value, 989) {
		t.Fatal("malformed or unrelated policy accepted")
	}
}
