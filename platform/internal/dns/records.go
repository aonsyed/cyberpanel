package dns

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalidDNS = errors.New("invalid DNS resource")
var ErrDNSConflict = errors.New("DNS resource generation conflict")
type DNSName struct{ value string }
func ParseName(value string)(DNSName,error){value=strings.ToLower(strings.TrimSpace(value));if value=="@"{return DNSName{value:"@"},nil};value=strings.TrimSuffix(value,".");if len(value)<1||len(value)>253{return DNSName{},ErrInvalidDNS};for _,label:=range strings.Split(value,"."){if len(label)<1||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return DNSName{},ErrInvalidDNS};for _,r:=range label{if !(r=='-'||r=='_'||r>='0'&&r<='9'||r>='a'&&r<='z'||r=='*'&&label=="*"){return DNSName{},ErrInvalidDNS}}};return DNSName{value:value},nil}
func (n DNSName)String()string{return n.value}
func (n DNSName)FQDN()string{if n.value=="@"{return"@"};return n.value+"."}
func (n DNSName)MarshalText()([]byte,error){if n.value==""{return nil,ErrInvalidDNS};return []byte(n.value),nil}
func (n *DNSName)UnmarshalText(value []byte)error{parsed,err:=ParseName(string(value));if err!=nil{return err};*n=parsed;return nil}

type RRKind string
const (
	RR_A RRKind="A"; RR_AAAA RRKind="AAAA"; RR_CNAME RRKind="CNAME"; RR_TXT RRKind="TXT"; RR_MX RRKind="MX"; RR_NS RRKind="NS"; RR_SOA RRKind="SOA"; RR_SRV RRKind="SRV"; RR_PTR RRKind="PTR"; RR_CAA RRKind="CAA"; RR_NAPTR RRKind="NAPTR"; RR_TLSA RRKind="TLSA"; RR_SSHFP RRKind="SSHFP"; RR_DS RRKind="DS"; RR_DNSKEY RRKind="DNSKEY"; RR_HTTPS RRKind="HTTPS"; RR_SVCB RRKind="SVCB"
)
type RecordSet struct { ZoneID ZoneID `json:"zone_id"`; Owner DNSName `json:"owner"`; Kind RRKind `json:"kind"`; TTL uint32 `json:"ttl"`; Records []string `json:"records"`; Proxied *bool `json:"proxied,omitempty"`; Comment string `json:"comment,omitempty"` }
func (s RecordSet)Validate(zone DNSName)error{if s.ZoneID==""||s.Owner.String()==""||!validRRKind(s.Kind)||s.TTL<30||s.TTL>604800||len(s.Records)<1||len(s.Records)>1000||len(s.Comment)>512{return ErrInvalidDNS};if s.Proxied!=nil&&s.Kind!=RR_A&&s.Kind!=RR_AAAA&&s.Kind!=RR_CNAME{return ErrInvalidDNS};if s.Kind==RR_CNAME&&len(s.Records)!=1{return ErrInvalidDNS};owner:=s.Owner.String();if owner!="@"&&owner!=zone.String()&&!strings.HasSuffix(owner,"."+zone.String()){return ErrInvalidDNS};seen:=map[string]struct{}{};for _,record:=range s.Records{canonical,err:=canonicalRData(s.Kind,record);if err!=nil{return err};if _,ok:=seen[canonical];ok{return ErrInvalidDNS};seen[canonical]=struct{}{}};return nil}
func (s RecordSet)Canonical(zone DNSName)(RecordSet,error){if err:=s.Validate(zone);err!=nil{return RecordSet{},err};out:=s;out.Comment=strings.TrimSpace(out.Comment);out.Records=make([]string,0,len(s.Records));for _,record:=range s.Records{canonical,_:=canonicalRData(s.Kind,record);out.Records=append(out.Records,canonical)};sort.Strings(out.Records);return out,nil}
func canonicalRData(kind RRKind,value string)(string,error){value=strings.TrimSpace(value);if value==""||strings.ContainsAny(value,"\x00\r\n"){return"",ErrInvalidDNS};switch kind{case RR_A:address,err:=netip.ParseAddr(value);if err!=nil||!address.Is4(){return"",ErrInvalidDNS};return address.String(),nil;case RR_AAAA:address,err:=netip.ParseAddr(value);if err!=nil||!address.Is6()||address.Zone()!=""{return"",ErrInvalidDNS};return address.String(),nil;case RR_CNAME,RR_NS,RR_PTR:name,err:=ParseName(value);if err!=nil||name.String()=="@"{return"",ErrInvalidDNS};return name.FQDN(),nil;case RR_MX:return canonicalPriorityName(value);case RR_SRV:return canonicalSRV(value);case RR_CAA:return canonicalCAA(value);case RR_TXT:if len(value)>4096{return"",ErrInvalidDNS};return strconv.Quote(strings.Trim(value,"\"")),nil;case RR_SSHFP:return numericFields(value,3,3,128);case RR_DS:return canonicalDS(value);case RR_TLSA:return numericHex(value,3);case RR_DNSKEY:return canonicalDNSKEY(value);case RR_NAPTR,RR_HTTPS,RR_SVCB,RR_SOA:if len(value)>8192{return"",ErrInvalidDNS};return strings.Join(strings.Fields(value)," "),nil};return"",ErrInvalidDNS}
func canonicalPriorityName(value string)(string,error){parts:=strings.Fields(value);if len(parts)!=2{return"",ErrInvalidDNS};priority,err:=strconv.ParseUint(parts[0],10,16);if err!=nil{return"",ErrInvalidDNS};name,err:=ParseName(parts[1]);if err!=nil||name.String()=="@"{return"",ErrInvalidDNS};return fmt.Sprintf("%d %s",priority,name.FQDN()),nil}
func canonicalSRV(value string)(string,error){parts:=strings.Fields(value);if len(parts)!=4{return"",ErrInvalidDNS};numbers:=make([]uint64,3);for i:=0;i<3;i++{parsed,err:=strconv.ParseUint(parts[i],10,16);if err!=nil{return"",ErrInvalidDNS};numbers[i]=parsed};name,err:=ParseName(parts[3]);if err!=nil||name.String()=="@"{return"",ErrInvalidDNS};return fmt.Sprintf("%d %d %d %s",numbers[0],numbers[1],numbers[2],name.FQDN()),nil}
func canonicalCAA(value string)(string,error){parts:=strings.Fields(value);if len(parts)<3{return"",ErrInvalidDNS};flag,err:=strconv.ParseUint(parts[0],10,8);if err!=nil{return"",ErrInvalidDNS};tag:=strings.ToLower(strings.Trim(parts[1],"\""));if tag!="issue"&&tag!="issuewild"&&tag!="iodef"{return"",ErrInvalidDNS};content:=strings.Trim(strings.Join(parts[2:]," "),"\"");if content==""||len(content)>1024{return"",ErrInvalidDNS};return fmt.Sprintf("%d %s %s",flag,tag,strconv.Quote(content)),nil}
func numericFields(value string,min,max int,bits int)(string,error){parts:=strings.Fields(value);if len(parts)<min||len(parts)>max{return"",ErrInvalidDNS};for _,part:=range parts{if _,err:=strconv.ParseUint(part,10,bits);err!=nil{return"",ErrInvalidDNS}};return strings.Join(parts," "),nil}
func numericHex(value string,numeric int)(string,error){parts:=strings.Fields(value);if len(parts)!=numeric+1{return"",ErrInvalidDNS};for _,part:=range parts[:numeric]{if _,err:=strconv.ParseUint(part,10,8);err!=nil{return"",ErrInvalidDNS}};digest:=strings.ToUpper(parts[numeric]);if len(digest)%2!=0{ return"",ErrInvalidDNS };if _,err:=hex.DecodeString(digest);err!=nil{return"",ErrInvalidDNS};return strings.Join(append(parts[:numeric],digest)," "),nil}
func canonicalDS(value string)(string,error){parts:=strings.Fields(value);if len(parts)!=4{return"",ErrInvalidDNS};if _,err:=strconv.ParseUint(parts[0],10,16);err!=nil{return"",ErrInvalidDNS};if _,err:=strconv.ParseUint(parts[1],10,8);err!=nil{return"",ErrInvalidDNS};if _,err:=strconv.ParseUint(parts[2],10,8);err!=nil{return"",ErrInvalidDNS};digest:=strings.ToUpper(parts[3]);if len(digest)<40||len(digest)%2!=0{return"",ErrInvalidDNS};if _,err:=hex.DecodeString(digest);err!=nil{return"",ErrInvalidDNS};return strings.Join([]string{parts[0],parts[1],parts[2],digest}," "),nil}
func canonicalDNSKEY(value string)(string,error){parts:=strings.Fields(value);if len(parts)!=4{return"",ErrInvalidDNS};if _,err:=strconv.ParseUint(parts[0],10,16);err!=nil{return"",ErrInvalidDNS};if _,err:=strconv.ParseUint(parts[1],10,8);err!=nil{return"",ErrInvalidDNS};if _,err:=strconv.ParseUint(parts[2],10,8);err!=nil{return"",ErrInvalidDNS};if len(parts[3])<16||len(parts[3])>8192{return"",ErrInvalidDNS};return strings.Join(parts," "),nil}
func validRRKind(kind RRKind)bool{switch kind{case RR_A,RR_AAAA,RR_CNAME,RR_TXT,RR_MX,RR_NS,RR_SOA,RR_SRV,RR_PTR,RR_CAA,RR_NAPTR,RR_TLSA,RR_SSHFP,RR_DS,RR_DNSKEY,RR_HTTPS,RR_SVCB:return true};return false}
