package cyberpanel

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
)

type AuthorizedPublicKey struct {
	Fingerprint string
	PublicKey   string
	Algorithm   string
	Label       string
}

func ParseAuthorizedKeys(raw []byte) ([]AuthorizedPublicKey, error) {
	if len(raw) > 8<<20 || bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	values := []AuthorizedPublicKey{}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		keyIndex := -1
		for index, field := range fields {
			if authorizedKeyType(field) {
				keyIndex = index
				break
			}
		}
		// Options, certificates and legacy algorithms are deliberately not
		// reinterpreted during migration. A future typed policy may add them.
		if keyIndex != 0 || keyIndex+1 >= len(fields) {
			return nil, ErrInvalid
		}
		blob, err := base64.StdEncoding.DecodeString(fields[keyIndex+1])
		if err != nil || len(blob) < 8 || len(blob) > 64<<10 {
			return nil, ErrInvalid
		}
		algorithmLength := binary.BigEndian.Uint32(blob[:4])
		if algorithmLength == 0 || uint64(algorithmLength) > uint64(len(blob)-4) || string(blob[4:4+algorithmLength]) != fields[keyIndex] {
			return nil, ErrInvalid
		}
		parsed, err := access.ParsePublicKey(fields[keyIndex] + " " + fields[keyIndex+1])
		if err != nil {
			return nil, ErrInvalid
		}
		fingerprint := parsed.Fingerprint
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, ErrInvalid
		}
		seen[fingerprint] = struct{}{}
		label := fields[keyIndex]
		if keyIndex+2 < len(fields) {
			label = strings.Join(fields[keyIndex+2:], " ")
			if len(label) > 191 {
				return nil, ErrInvalid
			}
		}
		publicKey := fields[keyIndex] + " " + fields[keyIndex+1]
		values = append(values, AuthorizedPublicKey{Fingerprint: fingerprint, PublicKey: publicKey, Algorithm: string(parsed.Algorithm), Label: label})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func authorizedKeyType(value string) bool {
	return value == "ssh-ed25519" || value == "ecdsa-sha2-nistp256" || value == "sk-ssh-ed25519@openssh.com"
}
