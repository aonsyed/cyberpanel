package mail

import (
	"bytes"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/argon2"
)

const mailboxArgonPrefix = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$"

// The caller supplies a unique enrollment salt, retained by the write-only
// command identity so an exact retry produces the same encrypted hash material.
func HashMailboxPassword(password, salt []byte) ([]byte, error) {
	if len(password) < 12 || len(password) > 1024 || len(salt) != 16 || bytes.IndexByte(password, 0) >= 0 {
		return nil, ErrInvalidCommand
	}
	key := argon2.IDKey(password, salt, 3, 65536, 1, 32)
	defer func() {
		for index := range key {
			key[index] = 0
		}
	}()
	return []byte(mailboxArgonPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)), nil
}

func ValidateMailboxPasswordHash(value []byte) error {
	if !bytes.HasPrefix(value, []byte(mailboxArgonPrefix)) {
		return ErrInvalidCommand
	}
	fields := strings.Split(string(value[len(mailboxArgonPrefix):]), "$")
	if len(fields) != 2 {
		return ErrInvalidCommand
	}
	for index, length := range []int{16, 32} {
		decoded, err := base64.RawStdEncoding.Strict().DecodeString(fields[index])
		if err != nil || len(decoded) != length {
			return ErrInvalidCommand
		}
	}
	return nil
}
