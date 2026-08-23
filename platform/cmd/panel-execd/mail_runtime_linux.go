//go:build linux

package main

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/mail"
)

func detectMailPlatform() (mail.LinuxMailPlatform,error) {
	content,err:=os.ReadFile("/etc/os-release");if err!=nil{return "",err}
	values:=map[string]string{};for _,line:=range strings.Split(string(content),"\n"){key,value,found:=strings.Cut(line,"=");if found{values[key]=strings.Trim(strings.TrimSpace(value),"\"")}}
	switch values["ID"]{case"ubuntu":if values["VERSION_ID"]!="24.04"{return "",errors.New("unsupported Ubuntu mail platform")};return mail.MailUbuntuNoble,nil;case"almalinux":if !strings.HasPrefix(values["VERSION_ID"],"9"){return "",errors.New("unsupported AlmaLinux mail platform")};return mail.MailAlma9,nil;default:return "",errors.New("unsupported mail platform")}
}

func resolveMailOwnership()(mail.MailOwnership,error){
	postfix,err:=lookupFirstGroup("postfix");if err!=nil{return mail.MailOwnership{},err}
	dovecot,err:=lookupFirstGroup("dovecot");if err!=nil{return mail.MailOwnership{},err}
	rspamd,err:=lookupFirstGroup("_rspamd","rspamd");if err!=nil{return mail.MailOwnership{},err}
	opendkim,err:=lookupFirstGroup("opendkim");if err!=nil{return mail.MailOwnership{},err}
	redis,err:=lookupFirstGroup("redis");if err!=nil{return mail.MailOwnership{},err}
	clamav,err:=lookupFirstGroup("clamav","clamscan");if err!=nil{return mail.MailOwnership{},err}
	return mail.MailOwnership{PostfixGID:postfix,DovecotGID:dovecot,RspamdGID:rspamd,OpenDKIMGID:opendkim,RedisGID:redis,ClamAVGID:clamav},nil
}

func lookupFirstGroup(names ...string)(uint32,error){for _,name:=range names{group,err:=user.LookupGroup(name);if err!=nil{continue};value,err:=strconv.ParseUint(group.Gid,10,32);if err==nil&&value>0{return uint32(value),nil}};return 0,errors.New("required service group is unavailable")}
