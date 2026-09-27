//go:build linux

package database

import (
 "encoding/hex"
 "strings"
 "testing"
)

func routineFixture() transferNativeRoutine {
 return transferNativeRoutine{Name: "sample_procedure", Kind: "PROCEDURE", Body: "BEGIN SELECT 7; END", DataAccess: "CONTAINS_SQL", Deterministic: false, SQLMode: "STRICT_TRANS_TABLES", CharacterSet: "utf8mb4", Collation: "utf8mb4_general_ci", DatabaseCollation: "utf8mb4_general_ci", Comment: "fixture"}
}

func TestTransferRoutineMarkerRoundTrip(t *testing.T) {
 routine := routineFixture()
 statement, err := routine.artifactStatement()
 if err != nil {
  t.Fatal(err)
 }
 if !strings.HasPrefix(string(statement), transferRoutineMarker) || !strings.HasSuffix(string(statement), " */;\n") {
  t.Fatalf("unexpected marker envelope: %q", statement)
 }
 prepared, matched, err := prepareTransferRoutineStatement(statement)
 if !matched || err != nil {
  t.Fatal(err)
 }
 script := string(prepared)
 for _, token := range []string{"PREPARE cp_routine FROM @cp_routine_sql", "EXECUTE cp_routine", "DEALLOCATE PREPARE cp_routine", "SET sql_mode='STRICT_TRANS_TABLES'", "SET character_set_client=utf8mb4"} {
  if !strings.Contains(script, token) {
   t.Fatal("script missing", token, script)
  }
 }
 if strings.Contains(script, "BEGIN SELECT 7") {
  t.Fatal("body leaked into script outside hex literal")
 }
 // Ordinary statements and truncated markers never match the routine path.
 if _, matched, err = prepareTransferRoutineStatement([]byte("INSERT INTO sample VALUES(1);")); matched || err != nil {
  t.Fatal("ordinary statement matched routine marker", matched, err)
 }
 if _, matched, err = prepareTransferRoutineStatement([]byte(transferRoutineMarker + "zz */;")); matched == false || err != ErrTransferUnsafeSQL {
  t.Fatal("corrupt marker payload accepted", matched, err)
 }
}

func TestTransferRoutineDefinitionValidation(t *testing.T) {
 valid := routineFixture()
 if _, err := valid.definition(); err != nil {
  t.Fatal(err)
 }
 rejects := map[string]func(*transferNativeRoutine){
  "kind":          func(r *transferNativeRoutine) { r.Kind = "TRIGGER" },
  "empty body":    func(r *transferNativeRoutine) { r.Body = "" },
  "nul body":      func(r *transferNativeRoutine) { r.Body = "BEGIN SELECT 1\x00; END" },
  "definer":       func(r *transferNativeRoutine) { r.Body = "BEGIN SELECT 1; END DEFINER=`root`@`localhost`" },
  "sql security":  func(r *transferNativeRoutine) { r.Body = "BEGIN SELECT 1; END SQL SECURITY DEFINER" },
  "data access":   func(r *transferNativeRoutine) { r.DataAccess = "MODIFIES" },
  "charset":       func(r *transferNativeRoutine) { r.CharacterSet = "utf8mb4'; DROP" },
  "ansi quotes":   func(r *transferNativeRoutine) { r.SQLMode = "ANSI_QUOTES,STRICT_TRANS_TABLES" },
  "escape mode":   func(r *transferNativeRoutine) { r.SQLMode = "NO_BACKSLASH_ESCAPES" },
  "mode quote":    func(r *transferNativeRoutine) { r.SQLMode = "STRICT'" },
  "returns":       func(r *transferNativeRoutine) { r.Kind = "FUNCTION"; r.Returns = "" },
  "proc returns":  func(r *transferNativeRoutine) { r.Returns = "INT" },
  "body too long": func(r *transferNativeRoutine) { r.Body = "BEGIN SELECT '" + strings.Repeat("x", MaximumTransferStatementBytes/2) + "'; END" },
 }
 for name, mutate := range rejects {
  routine := routineFixture()
  mutate(&routine)
  if _, err := routine.definition(); err == nil {
   t.Fatal("invalid routine accepted:", name)
  }
 }
 function := routineFixture()
 function.Kind, function.Returns = "FUNCTION", "INT"
 function.Deterministic = true
 definition, err := function.definition()
 if err != nil || !strings.Contains(definition, "RETURNS INT") || !strings.Contains(definition, "DETERMINISTIC") || !strings.Contains(definition, "SQL SECURITY INVOKER") {
  t.Fatal("function definition wrong", err, definition)
 }
 if strings.Contains(definition, "DEFINER=") {
  t.Fatal("definer leaked into definition")
 }
}

func TestTransferRoutineMarkerUnknownFields(t *testing.T) {
 routine := routineFixture()
 statement, err := routine.artifactStatement()
 if err != nil {
  t.Fatal(err)
 }
 payload := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(statement)), transferRoutineMarker)), " */;")
 decoded, err := hex.DecodeString(payload)
 if err != nil {
  t.Fatal(err)
 }
 injected := strings.TrimSuffix(string(decoded), "}") + `,"evil":1}`
 forged := transferRoutineMarker + hex.EncodeToString([]byte(injected)) + " */;"
 if _, matched, err := prepareTransferRoutineStatement([]byte(forged)); matched == false || err != ErrTransferUnsafeSQL {
  t.Fatal("unknown-field marker accepted", matched, err)
 }
}
