//go:build linux

package main

import(
	"fmt"
	"os"
	"strings"
	"syscall"
)

func main(){mode:=os.Getenv("CYBERPANEL_GIT_MODE");secret:=os.Getenv("CYBERPANEL_GIT_SECRET_PATH");if !strings.HasPrefix(secret,"/run/cyberpanel/git-credential-")||strings.Contains(strings.TrimPrefix(secret,"/run/cyberpanel/"),"../"){fatal("invalid secret path")};info,err:=os.Lstat(secret);if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Mode()&os.ModeSymlink!=0{fatal("unsafe secret material")};switch mode{case "askpass":content,readErr:=os.ReadFile(secret);if readErr!=nil||len(content)==0||len(content)>1<<20{fatal("credential unavailable")};_,_ = os.Stdout.Write(content);for index:=range content{content[index]=0};case "ssh":arguments:=os.Args[1:];if !validSSHInvocation(arguments){fatal("invalid Git SSH invocation")};fixed:=[]string{"ssh","-i",secret,"-o","IdentitiesOnly=yes","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile=/etc/ssh/ssh_known_hosts"};fixed=append(fixed,arguments...);if err=syscall.Exec("/usr/bin/ssh",fixed,[]string{"PATH=/usr/bin:/bin","LANG=C"});err!=nil{fatal(err.Error())};default:fatal("invalid transport mode")}}
func validSSHInvocation(arguments []string)bool{if len(arguments)<2||len(arguments)>8{return false};hostSeen:=false;for index:=0;index<len(arguments);index++{argument:=arguments[index];if argument==""||len(argument)>4096||strings.ContainsAny(argument,"\x00\r\n"){return false};if !hostSeen&&strings.HasPrefix(argument,"-"){switch argument{case "-4","-6":continue;case "-p":index++;if index>=len(arguments)||arguments[index]==""{return false};for _,character:=range arguments[index]{if character<'0'||character>'9'{return false}};case "-o":index++;if index>=len(arguments)||arguments[index]!="SendEnv=GIT_PROTOCOL"{return false};default:return false};continue};if !hostSeen{if !strings.HasPrefix(argument,"git@")||strings.ContainsAny(argument," /\\"){return false};hostSeen=true;continue};if index!=len(arguments)-1||!(strings.HasPrefix(argument,"git-upload-pack '")||strings.HasPrefix(argument,"git-receive-pack '"))||!strings.HasSuffix(argument,"'"){return false}};return hostSeen}
func fatal(message string){_,_ = fmt.Fprintln(os.Stderr,message);os.Exit(126)}
