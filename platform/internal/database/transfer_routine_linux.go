//go:build linux

package database

import (
 "context"
 "encoding/hex"
 "encoding/json"
 "strings"
 "unicode/utf8"
)

// Routine records travel inside the existing SQL artifact, as one bounded
// comment statement. The ordinary top-level SQL reader never interprets body
// semicolons as commands. MariaDB PREPARE compiles precisely one CREATE under
// the isolated loader's grants; neither client DELIMITER nor multi-statements
// from the artifact are forwarded.
const transferRoutineMarker = "/* cyberpanel-invoker-routine-v1 "

type transferNativeRoutine struct {
 Name string `json:"name"`
 Kind string `json:"kind"`
 Parameters string `json:"parameters"`
 Returns string `json:"returns"`
 Body string `json:"body"`
 DataAccess string `json:"data_access"`
 Deterministic bool `json:"deterministic"`
 SQLMode string `json:"sql_mode"`
 CharacterSet string `json:"character_set"`
 Collation string `json:"collation"`
 DatabaseCollation string `json:"database_collation"`
 Comment string `json:"comment"`
}

func (r transferNativeRoutine) definition() (string,error) {
 name,err:=ParseSQLIdentifier(r.Name)
 if err!=nil || (r.Kind!="FUNCTION" && r.Kind!="PROCEDURE") || r.Body=="" || strings.IndexByte(r.Body,0)>=0 || !utf8.ValidString(r.Body) {return "",ErrTransferUnsupportedObjects}
 // A forged artifact marker must never elevate the reconstructed CREATE.
 // Native bodies are the BEGIN…END payload only; clause keywords outside
 // literals belong to the fixed prefix, so reject them in the body itself.
 upperBody:=strings.ToUpper(r.Body)
 if strings.Contains(upperBody,"DEFINER") || strings.Contains(upperBody,"SQL SECURITY") {return "",ErrTransferUnsupportedObjects}
 if _,err=ParseSQLIdentifier(r.CharacterSet);err!=nil{return "",ErrTransferUnsupportedObjects}
 if _,err=ParseSQLIdentifier(r.Collation);err!=nil{return "",ErrTransferUnsupportedObjects}
 if _,err=ParseSQLIdentifier(r.DatabaseCollation);err!=nil{return "",ErrTransferUnsupportedObjects}
 access:=""
 switch r.DataAccess {case "CONTAINS_SQL":access="CONTAINS SQL";case "NO_SQL":access="NO SQL";case "READS_SQL_DATA":access="READS SQL DATA";case "MODIFIES_SQL_DATA":access="MODIFIES SQL DATA";default:return "",ErrTransferUnsupportedObjects}
 // Stored creation modes affect both parsing and execution. ANSI_QUOTES and
 // NO_BACKSLASH_ESCAPES would invalidate the artifact lexical contract.
 for _,mode:=range strings.Split(r.SQLMode,","){if mode=="ANSI_QUOTES"||mode=="NO_BACKSLASH_ESCAPES"||mode=="ORACLE"{return "",ErrTransferUnsupportedObjects}}
 if strings.ContainsAny(r.SQLMode,"'\\\x00") {return "",ErrTransferUnsupportedObjects}
 deterministic:="NOT DETERMINISTIC"
 if r.Deterministic {deterministic="DETERMINISTIC"}
 returns:=""
 if r.Kind=="FUNCTION" {if r.Returns==""{return "",ErrTransferUnsupportedObjects};returns=" RETURNS "+r.Returns} else if r.Returns!="" {return "",ErrTransferUnsupportedObjects}
 // The native catalog is re-observed after staging. An uploaded record is not
 // authority for a privileged CREATE; promotion uses only that observation.
 definition:="CREATE "+r.Kind+" "+quotedIdentifier(name)+"("+r.Parameters+")"+returns+" "+deterministic+" "+access+" SQL SECURITY INVOKER COMMENT '"+strings.ReplaceAll(strings.ReplaceAll(r.Comment,"\\","\\\\"),"'","''")+"' "+r.Body
 if len(definition)>MaximumTransferStatementBytes/4{return "",ErrTransferLimit}
 return definition,nil
}

func (r transferNativeRoutine) script() (string,error) {
 definition,err:=r.definition();if err!=nil{return "",err}
 return "SET @cp_routine_mode=@@sql_mode; SET sql_mode='"+r.SQLMode+"'; SET character_set_client="+r.CharacterSet+"; SET collation_connection="+r.Collation+"; SET @cp_routine_sql=CONVERT(0x"+hex.EncodeToString([]byte(definition))+" USING "+r.CharacterSet+"); PREPARE cp_routine FROM @cp_routine_sql; EXECUTE cp_routine; DEALLOCATE PREPARE cp_routine; SET sql_mode=@cp_routine_mode;\n",nil
}

func (r transferNativeRoutine) artifactStatement() ([]byte,error) {
 if _,err:=r.definition();err!=nil{return nil,err}
 data,err:=json.Marshal(r);if err!=nil{return nil,err}
 return []byte(transferRoutineMarker+hex.EncodeToString(data)+" */;\n"),nil
}

func prepareTransferRoutineStatement(statement []byte) ([]byte,bool,error) {
 text:=strings.TrimSpace(string(statement))
 if !strings.HasPrefix(text,transferRoutineMarker){return nil,false,nil}
 if !strings.HasSuffix(text," */;"){return nil,true,ErrTransferUnsafeSQL}
 data,err:=hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(text,transferRoutineMarker)," */;"));if err!=nil{return nil,true,ErrTransferUnsafeSQL}
 var r transferNativeRoutine
 decoder:=json.NewDecoder(strings.NewReader(string(data)));decoder.DisallowUnknownFields()
 if err=decoder.Decode(&r);err!=nil{return nil,true,ErrTransferUnsafeSQL}
 output,err:=r.script();return []byte(output),true,err
}

func transferRoutinesSQL(database Database)(string,error){
 if database.Validate()!=nil{return "",ErrInvalidResource}
 return "SELECT HEX(name),type,HEX(param_list),HEX(returns),HEX(body),sql_data_access,is_deterministic,security_type,HEX(sql_mode),character_set_client,collation_connection,db_collation,HEX(comment) FROM mysql.proc WHERE db='"+database.Name.String()+"' ORDER BY type,BINARY name;\n",nil
}

func observeTransferRoutines(ctx context.Context,c *mariaDBConnection,database Database)([]transferNativeRoutine,error){
 raw,err:=c.query(ctx,sqlObserveTransferRoutines,database);if err!=nil{return nil,err}
 if len(raw)==0{return nil,nil}
 lines:=strings.Split(strings.TrimSuffix(string(raw),"\n"),"\n")
 if len(lines)>MaximumTransferTables{return nil,ErrTransferLimit}
 result:=make([]transferNativeRoutine,0,len(lines))
 for _,line:=range lines{
  f:=strings.Split(line,"\t");if len(f)!=13||f[7]!="INVOKER"{return nil,ErrTransferUnsupportedObjects}
  for _,index:=range []int{0,2,3,4,8,12}{value,e:=hex.DecodeString(f[index]);if e!=nil{return nil,ErrTransferInvalid};f[index]=string(value)}
  r:=transferNativeRoutine{f[0],f[1],f[2],f[3],f[4],f[5],f[6]=="YES",f[8],f[9],f[10],f[11],f[12]}
  if _,err=r.definition();err!=nil{return nil,err};result=append(result,r)
 }
 return result,nil
}

type transferRoutineMutation struct{Database Database; Routine transferNativeRoutine}
func transferRoutineMutationSQL(m transferRoutineMutation,drop bool)(string,error){
 if m.Database.Validate()!=nil{return "",ErrInvalidResource}
 if _,err:=m.Routine.definition();err!=nil{return "",err}
 name,_:=ParseSQLIdentifier(m.Routine.Name)
 if drop{return "DROP "+m.Routine.Kind+" "+quotedIdentifier(m.Database.Name)+"."+quotedIdentifier(name)+";\n",nil}
 script,err:=m.Routine.script();if err!=nil{return "",err}
 return "USE "+quotedIdentifier(m.Database.Name)+"; SET character_set_client="+m.Routine.CharacterSet+"; SET collation_connection="+m.Routine.Collation+";\n"+script,nil
}
