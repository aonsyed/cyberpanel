//go:build linux

package database

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestTransferViewDumpEnvelope(t *testing.T) {
	for _, statement := range []string{
		"CREATE VIEW `v` AS SELECT id FROM sample;",
		"CREATE DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v` AS SELECT id FROM sample;",
		"/*!50001 CREATE ALGORITHM=UNDEFINED */\n/*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */\n/*!50001 VIEW `v` AS select `sample`.`id` AS `id` from `sample` */;",
		"CREATE VIEW `v` (`id`) AS SELECT 1;",
		"CREATE VIEW `v` AS SELECT 'DEFINER=root; /* not a comment */' AS literal;",
	} {
		reader := newConstrainedTransferSQLReader(bufio.NewReader(strings.NewReader(statement)), nil)
		output, err := io.ReadAll(reader)
		if err != nil || !strings.Contains(string(output), "SQL SECURITY INVOKER VIEW") || strings.Contains(string(output), "DEFINER=`root`") {
			t.Fatalf("view envelope not safely rewritten: %v", err)
		}
	}
	for _, statement := range []string{
		"CREATE VIEW other.v AS SELECT 1;",
		"CREATE VIEW v AS SELECT LOAD_FILE('/etc/passwd');",
		"CREATE VIEW v AS SELECT SLEEP(10);",
		"CREATE VIEW v AS SELECT 1 INTO OUTFILE '/tmp/leak';",
		"CREATE VIEW v AS SELECT 1; GRANT ALL ON *.* TO somebody;",
		"CREATE VIEW v AS SELECT 1 /*!50001 INTO OUTFILE '/tmp/leak' */;",
		"CREATE VIEW v AS SELECT 1 \\! forbidden;",
	} {
		reader := newConstrainedTransferSQLReader(bufio.NewReader(strings.NewReader(statement)), nil)
		if _, err := io.ReadAll(reader); err == nil {
			t.Fatal("unsafe view accepted", statement)
		}
	}
}
