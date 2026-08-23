package cyberpanel

import "strings"

var supportedCronMacros=map[string]struct{}{
	"@annually":{},
	"@daily":{},
	"@hourly":{},
	"@midnight":{},
	"@monthly":{},
	"@reboot":{},
	"@weekly":{},
	"@yearly":{},
}

// ParseLegacyCronEntry separates only the fixed schedule prefix. The command
// remains byte-for-byte stable apart from surrounding horizontal whitespace;
// it is inventory data and is never dispatched by the extractor.
func ParseLegacyCronEntry(value string)(expression,command string,ok bool,err error){
	if value==""||len(value)>1<<20||strings.ContainsAny(value,"\r\n\x00"){return "","",false,ErrInvalid}
	value=strings.Trim(value," \t")
	if value==""||strings.HasPrefix(value,"#"){return "","",false,nil}
	first,rest,present:=takeCronFields(value,1)
	if !present{return "","",false,nil}
	if _,macro:=supportedCronMacros[strings.ToLower(first[0])];macro{
		command=strings.Trim(rest," \t")
		if command==""{return "","",false,ErrInvalid}
		return strings.ToLower(first[0]),command,true,nil
	}
	fields,rest,present:=takeCronFields(value,5)
	if !present{return "","",false,nil}
	command=strings.Trim(rest," \t")
	if command==""{return "","",false,ErrInvalid}
	return strings.Join(fields," "),command,true,nil
}

func takeCronFields(value string,count int)([]string,string,bool){
	fields:=make([]string,0,count)
	cursor:=0
	for len(fields)<count{
		for cursor<len(value)&&(value[cursor]==' '||value[cursor]=='\t'){cursor++}
		if cursor>=len(value){return nil,"",false}
		start:=cursor
		for cursor<len(value)&&value[cursor]!=' '&&value[cursor]!='\t'{cursor++}
		fields=append(fields,value[start:cursor])
	}
	return fields,value[cursor:],true
}

func cronEnvironmentValue(value,key string)(string,bool){
	value=strings.TrimSpace(value)
	equals:=strings.IndexByte(value,'=')
	if equals<=0||!strings.EqualFold(strings.TrimSpace(value[:equals]),key){return "",false}
	result:=strings.TrimSpace(value[equals+1:])
	if len(result)>=2&&((result[0]=='"'&&result[len(result)-1]=='"')||(result[0]=='\''&&result[len(result)-1]=='\'')){result=result[1:len(result)-1]}
	if result==""||len(result)>255||strings.ContainsAny(result,"\r\n\x00"){return "",false}
	return result,true
}
