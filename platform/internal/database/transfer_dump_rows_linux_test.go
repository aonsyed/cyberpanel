//go:build linux

package database

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestDumpRowsCountsStatementsAcrossChunkBoundaries(t *testing.T) {
	input := []byte("/*M!999999\\- enable the sandbox mode */\n-- INSERT INTO fake VALUES(0);\nCREATE TABLE `x\nINSERT INTO fake;`(v TEXT);\nINSERT INTO t VALUES (" + `'a;\'b` + "\nINSERT INTO fake;');\n/* INSERT INTO fake; */ INSERT INTO t VALUES (NULL);\n# INSERT INTO fake;\n")
	for width := 1; width <= len(input); width++ {
		var output bytes.Buffer
		counter := &transferDumpRows{destination: &output, maximum: 2}
		for start := 0; start < len(input); start += width {
			end := start + width
			if end > len(input) {
				end = len(input)
			}
			if _, err := counter.Write(input[start:end]); err != nil {
				t.Fatalf("width %d: %v", width, err)
			}
		}
		if err := counter.finish(); err != nil || counter.rows != 2 || !bytes.Equal(input, output.Bytes()) {
			t.Fatalf("width %d rows %d: %v", width, counter.rows, err)
		}
	}
}

func TestDumpRowsLimitAndIncompleteStatement(t *testing.T) {
	counter := &transferDumpRows{destination: io.Discard, maximum: 1}
	if _, err := counter.Write([]byte("INSERT INTO t VALUES (1);")); err != nil {
		t.Fatal(err)
	}
	if _, err := counter.Write([]byte("INSERT INTO t VALUES (2);")); !errors.Is(err, ErrTransferLimit) {
		t.Fatal("row limit not enforced", err)
	}
	for _, input := range []string{"INSERT INTO t VALUES (1)", "INSERT INTO t VALUES ('unfinished", "/* unfinished"} {
		counter := &transferDumpRows{destination: io.Discard, maximum: 2}
		if _, err := counter.Write([]byte(input)); err != nil {
			t.Fatal(err)
		}
		if counter.finish() == nil {
			t.Fatal("truncated native dump accepted")
		}
	}
}
