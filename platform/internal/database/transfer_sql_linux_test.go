//go:build linux

package database

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestTransferSQLRejectsExecutableCommentAndClientEscapes(t *testing.T) {
	for _, input := range []string{
		"/*M!100100 SELECT LOAD_FILE('/etc/passwd') */;",
		"SET @safe=1 /*M!100100 , @secret=LOAD_FILE('/etc/passwd') */;",
		"SET @safe=1\n\\! echo forbidden\n;",
		"SET @safe=1\n\\. /etc/passwd\n;",
		"/*M!999999\\- enable the sandbox mode */ /*M!100100 SELECT LOAD_FILE('/etc/passwd') */;",
	} {
		t.Run(input, func(t *testing.T) {
			reader := newConstrainedTransferSQLReader(bufio.NewReader(strings.NewReader(input)), nil)
			_, err := io.ReadAll(reader)
			if !errors.Is(err, ErrTransferUnsafeSQL) {
				t.Fatalf("unsafe input accepted: %v", err)
			}
		})
	}
}

func TestTransferSQLPreservesQuotedAndOrdinaryComments(t *testing.T) {
	for _, input := range []string{
		"INSERT INTO `sample` VALUES ('literal \\! and /*M! SELECT */');",
		"-- ordinary SELECT LOAD_FILE comment\nSET @safe=1;",
		"/* ordinary SELECT LOAD_FILE comment */ SET @safe=1;",
		"/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
		"/*M!100100 SET @safe=1 */;",
		"/*M!999999\\- enable the sandbox mode */ \n/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
	} {
		reader := newConstrainedTransferSQLReader(bufio.NewReader(strings.NewReader(input)), nil)
		output, err := io.ReadAll(reader)
		if err != nil || string(output) != input {
			t.Fatalf("safe dump changed: %v", err)
		}
	}
}
