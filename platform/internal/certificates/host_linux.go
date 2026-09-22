//go:build linux

package certificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultHTTP01Root="/var/lib/cyberpanel/acme/http-01"
const defaultCertificateRoot="/var/lib/cyberpanel/certificates"

type CertificateCommandRunner interface{Run(context.Context,string,...string)error}
type FixedCertificateCommandRunner struct{}
func(FixedCertificateCommandRunner)Run(ctx context.Context,program string,arguments ...string)error{allowed:=false;switch program{case "/usr/local/lsws/bin/lswsctrl":allowed=len(arguments)==1&&(arguments[0]=="reload"||arguments[0]=="status");case "/usr/bin/systemctl":if len(arguments)==2{verb,unit:=arguments[0],arguments[1];allowed=(verb=="reload"||verb=="restart"||verb=="is-active")&&(unit=="panel-gateway.service"||unit=="postfix.service"||unit=="dovecot.service")}};if !allowed{return ErrInvalidCertificate};return exec.CommandContext(ctx,program,arguments...).Run()}

type LinuxCertificateHost struct{HTTPRoot string;CertificateRoot string;Runner CertificateCommandRunner;PanelGID int}
func NewLinuxCertificateHost()(*LinuxCertificateHost,error){if os.Geteuid()!=0{return nil,ErrInvalidCertificate};group,err:=user.LookupGroup("cyberpanel");if err!=nil{return nil,err};gid,err:=strconv.Atoi(group.Gid);if err!=nil||gid<=0{return nil,ErrInvalidCertificate};return &LinuxCertificateHost{HTTPRoot:defaultHTTP01Root,CertificateRoot:defaultCertificateRoot,Runner:FixedCertificateCommandRunner{},PanelGID:gid},nil}
func(host *LinuxCertificateHost)roots()(string,string,error){if host==nil||host.Runner==nil{return "","",ErrInvalidCertificate};httpRoot:=host.HTTPRoot;if httpRoot==""{httpRoot=defaultHTTP01Root};certificateRoot:=host.CertificateRoot;if certificateRoot==""{certificateRoot=defaultCertificateRoot};if !filepath.IsAbs(httpRoot)||!filepath.IsAbs(certificateRoot)||filepath.Clean(httpRoot)!=httpRoot||filepath.Clean(certificateRoot)!=certificateRoot{return "","",ErrInvalidCertificate};return httpRoot,certificateRoot,nil}

func(host *LinuxCertificateHost)PresentHTTP01(ctx context.Context,challenge Challenge)error{root,_,err:=host.roots();if err!=nil{return err};token,authorization,err:=validatedHTTP01Challenge(challenge);if err!=nil{return err};if err=secureRootDirectory(root,0755);err!=nil{return err};select{case<-ctx.Done():return ctx.Err();default:};return atomicRootFile(filepath.Join(root,token),[]byte(authorization),0644,true)}
func(host *LinuxCertificateHost)RemoveHTTP01(ctx context.Context,challenge Challenge)error{root,_,err:=host.roots();if err!=nil{return err};token,authorization,err:=validatedHTTP01Challenge(challenge);if err!=nil{return err};path:=filepath.Join(root,token);info,err:=os.Lstat(path);if errors.Is(err,os.ErrNotExist){return nil};if err!=nil||!safeRootFile(info,0644){return ErrInvalidCertificate};content,err:=os.ReadFile(path);if err!=nil{return err};if !bytes.Equal(content,[]byte(authorization)){return ErrCertificateConflict};select{case<-ctx.Done():return ctx.Err();default:};return os.Remove(path)}

func (host *LinuxCertificateHost) StageCertificate(ctx context.Context, consumer string, material CertificateMaterial, privateKeyPEM []byte, effectID string) (string, string, error) {
	_, root, err := host.roots()
	if err != nil {
		return "", "", err
	}
	kind, identifier, err := validCertificateConsumer(consumer)
	if err != nil || !validCertificateEffect(effectID) || len(privateKeyPEM) == 0 || len(privateKeyPEM) > 1<<20 {
		return "", "", ErrInvalidCertificate
	}
	pair, err := tls.X509KeyPair(material.FullChainPEM, privateKeyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return "", "", ErrInvalidCertificate
	}
	parsed, err := certificateMaterialFromPEM(material.FullChainPEM)
	if err != nil || parsed.ID != material.ID || parsed.FingerprintSHA256 != material.FingerprintSHA256 || !bytes.Equal(parsed.LeafPEM, material.LeafPEM) || !bytes.Equal(parsed.ChainPEM, material.ChainPEM) || !parsed.NotBefore.Equal(material.NotBefore) || !parsed.NotAfter.Equal(material.NotAfter) || !parsed.NotAfter.After(time.Now().UTC()) {
		return "", "", ErrInvalidCertificate
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", ErrInvalidCertificate
	}
	for _, name := range material.Names {
		if leaf.VerifyHostname(name) != nil {
			return "", "", ErrInvalidCertificate
		}
	}
	generations := filepath.Join(root, "generations")
	consumerRoot := filepath.Join(root, "consumers", kind, identifier)
	if err = secureRootDirectory(generations, 0711); err != nil {
		return "", "", err
	}
	if err = secureRootDirectory(consumerRoot, 0750); err != nil {
		return "", "", err
	}
	candidateParent := filepath.Join(generations, kind, identifier)
	if err = secureRootDirectory(candidateParent, 0711); err != nil {
		return "", "", err
	}
	candidate := stagedCertificatePath(candidateParent, material, effectID)
	if _, tombstoneErr := os.Lstat(stagedCertificateTombstonePath(candidate)); tombstoneErr == nil {
		return "", "", ErrCertificateConflict
	} else if !errors.Is(tombstoneErr, os.ErrNotExist) {
		return "", "", tombstoneErr
	}
	created := false
	if err = os.Mkdir(candidate, 0750); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return "", "", err
	}
	gid := 0
	if kind == "panel" {
		gid = host.PanelGID
		if gid <= 0 {
			return "", "", ErrInvalidCertificate
		}
	}
	if !created {
		info, statErr := os.Lstat(candidate)
		ownerErr := validateStagedCertificateOwner(candidate, consumer, effectID)
		if ownerErr != nil {
			entries, readErr := os.ReadDir(candidate)
			_, markerErr := os.Lstat(filepath.Join(candidate, ".stage-owner"))
			if statErr != nil || !safeRootOwnedDirectory(info) || readErr != nil || len(entries) != 0 || !errors.Is(markerErr, os.ErrNotExist) {
				return "", "", ErrInvalidCertificate
			}
			created = true
		}
	}
	if created {
		if err = os.Chmod(candidate, 0750); err == nil {
			err = os.Chown(candidate, 0, gid)
		}
		if err != nil {
			return "", "", err
		}
	}
	info, err := os.Lstat(candidate)
	if err != nil || !safeRootDirectory(info, 0750) {
		return "", "", ErrInvalidCertificate
	}
	metadata, ownerOK := info.Sys().(*syscall.Stat_t)
	if !ownerOK || int(metadata.Gid) != gid {
		return "", "", ErrInvalidCertificate
	}
	if created {
		owner := []byte(stagedCertificateOwner(consumer, candidate, effectID) + "\n")
		if err = atomicRootFile(filepath.Join(candidate, ".stage-owner"), owner, 0400, true); err != nil {
			return "", "", err
		}
		if err = os.Chown(filepath.Join(candidate, ".stage-owner"), 0, gid); err != nil {
			return "", "", err
		}
	} else if err = validateStagedCertificateOwner(candidate, consumer, effectID); err != nil {
		return "", "", err
	}
	for _, file := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{{"certificate.pem", material.LeafPEM, 0440}, {"chain.pem", material.ChainPEM, 0440}, {"fullchain.pem", material.FullChainPEM, 0440}, {"private.key", privateKeyPEM, 0400}} {
		path := filepath.Join(candidate, file.name)
		if err = atomicRootFile(path, file.content, file.mode, true); err != nil {
			return "", "", err
		}
		if err = os.Chown(path, 0, gid); err != nil {
			return "", "", err
		}
	}
	if err = syncDirectory(candidate); err != nil {
		return "", "", err
	}
	previous := ""
	current := filepath.Join(consumerRoot, "current")
	if target, readErr := os.Readlink(current); readErr == nil {
		absolute := target
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(consumerRoot, target)
		}
		absolute = filepath.Clean(absolute)
		if !pathWithin(generations, absolute) {
			return "", "", ErrInvalidCertificate
		}
		previous = absolute
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", "", readErr
	}
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	default:
	}
	return previous, candidate, nil
}
func(host *LinuxCertificateHost)ActivateCertificate(ctx context.Context,consumer,candidate,effectID string)(string,error){_,root,err:=host.roots();if err!=nil{return "",err};kind,identifier,err:=validCertificateConsumer(consumer);if err!=nil||!validCertificateEffect(effectID){return "",ErrInvalidCertificate};generations:=filepath.Join(root,"generations");candidate=filepath.Clean(candidate);if !pathWithin(filepath.Join(generations,kind,identifier),candidate){return "",ErrInvalidCertificate};info,err:=os.Lstat(candidate);if err!=nil||!safeRootDirectory(info,0750)||validateStagedCertificateOwner(candidate,consumer,effectID)!=nil{return "",ErrInvalidCertificate};consumerRoot:=filepath.Join(root,"consumers",kind,identifier);if err=secureRootDirectory(consumerRoot,0750);err!=nil{return "",err};if err=atomicRootSymlink(filepath.Join(consumerRoot,"current"),candidate,effectID);err!=nil{return "",err};if kind=="mail"&&identifier=="default"{if err=PublishLocalMailIdentity(root);err!=nil{return "",err}};if err=host.reload(ctx,kind);err!=nil{return "",err};return filepath.Join(consumerRoot,"current"),nil}
func(host *LinuxCertificateHost)ProbeCertificate(ctx context.Context,consumer string,material CertificateMaterial)(string,error){_,root,err:=host.roots();if err!=nil{return "",err};kind,identifier,err:=validCertificateConsumer(consumer);if err!=nil{return "",err};current:=filepath.Join(root,"consumers",kind,identifier,"current");target,err:=os.Readlink(current);if err!=nil{return "",err};if !filepath.IsAbs(target){target=filepath.Join(filepath.Dir(current),target)};target=filepath.Clean(target);if !pathWithin(filepath.Join(root,"generations",kind,identifier),target){return "",ErrInvalidCertificate};content,err:=os.ReadFile(filepath.Join(target,"certificate.pem"));if err!=nil{return "",err};parsed,err:=certificateMaterialFromPEM(content);if err!=nil||parsed.FingerprintSHA256!=material.FingerprintSHA256{return "",ErrInvalidCertificate};if err=host.probe(ctx,kind);err!=nil{return "",err};return parsed.FingerprintSHA256,nil}
func(host *LinuxCertificateHost)RestoreCertificate(ctx context.Context,consumer,previous,effectID string)error{_,root,err:=host.roots();if err!=nil{return err};kind,identifier,err:=validCertificateConsumer(consumer);if err!=nil||!validCertificateEffect(effectID){return ErrInvalidCertificate};consumerRoot:=filepath.Join(root,"consumers",kind,identifier);current:=filepath.Join(consumerRoot,"current");if previous==""{info,lstatErr:=os.Lstat(current);if errors.Is(lstatErr,os.ErrNotExist){if kind=="mail"&&identifier=="default"{return PublishLocalMailIdentity(root)};return nil};if lstatErr!=nil||info.Mode()&os.ModeSymlink==0{return ErrInvalidCertificate};if err=os.Remove(current);err!=nil{return err};if err=syncDirectory(consumerRoot);err!=nil{return err};if kind=="mail"&&identifier=="default"{if err=PublishLocalMailIdentity(root);err!=nil{return err}};return host.reload(ctx,kind)};previous=filepath.Clean(previous);if !pathWithin(filepath.Join(root,"generations",kind,identifier),previous){return ErrInvalidCertificate};if info,statErr:=os.Lstat(previous);statErr!=nil||!safeRootDirectory(info,0750){return ErrInvalidCertificate};if err=atomicRootSymlink(current,previous,effectID+"-restore");err!=nil{return err};if kind=="mail"&&identifier=="default"{if err=PublishLocalMailIdentity(root);err!=nil{return err}};return host.reload(ctx,kind)}

func (host *LinuxCertificateHost) DiscardStagedCertificate(ctx context.Context, consumer, candidate string, material CertificateMaterial, effectID string) error {
	_, root, err := host.roots()
	if err != nil {
		return err
	}
	kind, identifier, err := validCertificateConsumer(consumer)
	if err != nil || !validCertificateEffect(effectID) {
		return ErrInvalidCertificate
	}
	candidateParent := filepath.Join(root, "generations", kind, identifier)
	expected := stagedCertificatePath(candidateParent, material, effectID)
	candidate = filepath.Clean(candidate)
	if candidate != expected || !pathWithin(candidateParent, candidate) {
		return ErrInvalidCertificate
	}
	tombstone := stagedCertificateTombstonePath(candidate)
	ownedPath := candidate
	if _, statErr := os.Lstat(candidate); errors.Is(statErr, os.ErrNotExist) {
		if _, tombstoneErr := os.Lstat(tombstone); errors.Is(tombstoneErr, os.ErrNotExist) {
			return nil
		} else if tombstoneErr != nil {
			return tombstoneErr
		}
		ownedPath = tombstone
	} else if statErr != nil {
		return statErr
	}
	if validateStagedCertificateOwnerAt(ownedPath, candidate, consumer, effectID) != nil {
		return ErrInvalidCertificate
	}
	consumerRoot := filepath.Join(root, "consumers", kind, identifier)
	current := filepath.Join(consumerRoot, "current")
	if linked, readErr := os.Readlink(current); readErr == nil {
		if !filepath.IsAbs(linked) {
			linked = filepath.Join(consumerRoot, linked)
		}
		linked = filepath.Clean(linked)
		if linked == candidate || linked == tombstone {
			return ErrCertificateConflict
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if ownedPath == candidate {
		if _, tombstoneErr := os.Lstat(tombstone); tombstoneErr == nil {
			return ErrCertificateConflict
		} else if !errors.Is(tombstoneErr, os.ErrNotExist) {
			return tombstoneErr
		}
		if err = os.Rename(candidate, tombstone); err != nil {
			return err
		}
		if err = syncDirectory(candidateParent); err != nil {
			return err
		}
		ownedPath = tombstone
	}
	entries, err := os.ReadDir(ownedPath)
	if err != nil {
		return err
	}
	modes := map[string]os.FileMode{".stage-owner": 0400, "certificate.pem": 0440, "chain.pem": 0440, "fullchain.pem": 0440, "private.key": 0400}
	marker := false
	for _, entry := range entries {
		mode, ok := modes[entry.Name()]
		if !ok {
			return ErrCertificateConflict
		}
		info, statErr := os.Lstat(filepath.Join(ownedPath, entry.Name()))
		if statErr != nil || !safeRootFile(info, mode) {
			return ErrCertificateConflict
		}
		marker = marker || entry.Name() == ".stage-owner"
	}
	if !marker {
		return ErrCertificateConflict
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	for _, name := range []string{"private.key", "fullchain.pem", "chain.pem", "certificate.pem"} {
		if err = os.Remove(filepath.Join(ownedPath, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Retain only the non-secret owner marker as a restart-safe tombstone. A
	// retry can prove ownership and finish removing any file left by a crash.
	return syncDirectory(ownedPath)
}
func stagedCertificatePath(parent string, material CertificateMaterial, effectID string) string {
	sum := sha256.Sum256([]byte("certificate-stage-path-v1\x00" + effectID))
	return filepath.Join(parent, string(material.ID)+"-"+material.FingerprintSHA256+"-"+hex.EncodeToString(sum[:])[:20])
}
func stagedCertificateTombstonePath(candidate string) string { return candidate + ".discarded" }
func stagedCertificateOwner(consumer, candidate, effectID string) string {
	sum := sha256.Sum256([]byte("certificate-stage-owner-v1\x00" + consumer + "\x00" + filepath.Base(candidate) + "\x00" + effectID))
	return hex.EncodeToString(sum[:])
}
func validateStagedCertificateOwner(candidate, consumer, effectID string) error {
	return validateStagedCertificateOwnerAt(candidate, candidate, consumer, effectID)
}
func validateStagedCertificateOwnerAt(path, candidate, consumer, effectID string) error {
	path = filepath.Join(path, ".stage-owner")
	info, err := os.Lstat(path)
	if err != nil || !safeRootFile(info, 0400) {
		return ErrInvalidCertificate
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, []byte(stagedCertificateOwner(consumer, candidate, effectID)+"\n")) {
		return ErrCertificateConflict
	}
	return nil
}
func(host *LinuxCertificateHost)reload(ctx context.Context,kind string)error{switch kind{case "webengine":return host.Runner.Run(ctx,"/usr/local/lsws/bin/lswsctrl","reload");case "panel":return host.Runner.Run(ctx,"/usr/bin/systemctl","restart","panel-gateway.service");case "mail":if err:=host.Runner.Run(ctx,"/usr/bin/systemctl","reload","postfix.service");err!=nil{return err};return host.Runner.Run(ctx,"/usr/bin/systemctl","reload","dovecot.service")};return ErrInvalidCertificate}
func(host *LinuxCertificateHost)probe(ctx context.Context,kind string)error{switch kind{case "webengine":return host.Runner.Run(ctx,"/usr/local/lsws/bin/lswsctrl","status");case "panel":return host.Runner.Run(ctx,"/usr/bin/systemctl","is-active","panel-gateway.service");case "mail":if err:=host.Runner.Run(ctx,"/usr/bin/systemctl","is-active","postfix.service");err!=nil{return err};return host.Runner.Run(ctx,"/usr/bin/systemctl","is-active","dovecot.service")};return ErrInvalidCertificate}

func validatedHTTP01Challenge(challenge Challenge)(string,string,error){if challenge.Kind!=HTTP01||challenge.ID==""||challenge.Token==""||len(challenge.Token)>128||challenge.KeyAuthorization==""||len(challenge.KeyAuthorization)>512||!strings.HasPrefix(challenge.KeyAuthorization,challenge.Token+"."){return "","",ErrInvalidCertificate};for _,value:=range []string{challenge.Token,challenge.KeyAuthorization}{if strings.ContainsAny(value,"/\\\x00\r\n") {return "","",ErrInvalidCertificate};for index:=range value{character:=value[index];if !(character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||character=='-'||character=='_'||character=='.'){return "","",ErrInvalidCertificate}}};return challenge.Token,challenge.KeyAuthorization,nil}
func validCertificateConsumer(value string)(string,string,error){parts:=strings.Split(value,"/");if len(parts)!=2||(parts[0]!="webengine"&&parts[0]!="panel"&&parts[0]!="mail")||!validCertificatePathComponent(parts[1]){return "","",ErrInvalidCertificate};return parts[0],parts[1],nil}
func validCertificatePathComponent(value string)bool{if len(value)<1||len(value)>96||value=="."||value==".."{return false};for index:=range value{character:=value[index];if !(character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||character=='-'||character=='_'){return false}};return true}
func validCertificateEffect(value string)bool{return validCertificatePathComponent(value)&&len(value)>=8}
func pathWithin(root,target string)bool{relative,err:=filepath.Rel(filepath.Clean(root),filepath.Clean(target));return err==nil&&relative!="."&&!strings.HasPrefix(relative,".."+string(os.PathSeparator))&&relative!=".."&&!filepath.IsAbs(relative)}

func secureRootDirectory(path string,mode os.FileMode)error{path=filepath.Clean(path);if !filepath.IsAbs(path)||path=="/"{return ErrInvalidCertificate};current:=string(os.PathSeparator);for _,component:=range strings.Split(strings.TrimPrefix(path,string(os.PathSeparator)),string(os.PathSeparator)){current=filepath.Join(current,component);info,err:=os.Lstat(current);if errors.Is(err,os.ErrNotExist){if err=os.Mkdir(current,mode);err!=nil{return err};info,err=os.Lstat(current)};if err!=nil||!safeRootOwnedDirectory(info){return ErrInvalidCertificate}};if err:=os.Chmod(path,mode);err!=nil{return err};return nil}
func safeRootOwnedDirectory(info os.FileInfo)bool{if info==nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0022!=0{return false};stat,ok:=info.Sys().(*syscall.Stat_t);return ok&&stat.Uid==0}
func safeRootDirectory(info os.FileInfo,mode os.FileMode)bool{return safeRootOwnedDirectory(info)&&info.Mode().Perm()==mode.Perm()}
func safeRootFile(info os.FileInfo,mode os.FileMode)bool{if info==nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=mode.Perm(){return false};stat,ok:=info.Sys().(*syscall.Stat_t);return ok&&stat.Uid==0&&stat.Nlink==1}
func atomicRootFile(path string,content []byte,mode os.FileMode,immutable bool)error{directory:=filepath.Dir(path);if info,err:=os.Lstat(path);err==nil{if !safeRootFile(info,mode){return ErrInvalidCertificate};existing,readErr:=os.ReadFile(path);if readErr!=nil{return readErr};if bytes.Equal(existing,content){return nil};if immutable{return ErrCertificateConflict}}else if !errors.Is(err,os.ErrNotExist){return err};random:=make([]byte,12);if _,err:=rand.Read(random);err!=nil{return err};temporary:=filepath.Join(directory,".certificate-"+hex.EncodeToString(random));file,err:=os.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,mode);if err!=nil{return err};cleanup:=true;defer func(){file.Close();if cleanup{os.Remove(temporary)}}();if _,err=file.Write(content);err!=nil{return err};if err=file.Chmod(mode);err!=nil{return err};if err=file.Sync();err!=nil{return err};if err=file.Close();err!=nil{return err};if err=os.Rename(temporary,path);err!=nil{return err};cleanup=false;return syncDirectory(directory)}
func atomicRootSymlink(path,target,effectID string)error{directory:=filepath.Dir(path);sum:=sha256.Sum256([]byte(effectID+"\x00"+target));temporary:=filepath.Join(directory,".current-"+hex.EncodeToString(sum[:])[:24]);_ = os.Remove(temporary);if err:=os.Symlink(target,temporary);err!=nil{return err};if err:=os.Rename(temporary,path);err!=nil{os.Remove(temporary);return err};return syncDirectory(directory)}
func syncDirectory(path string)error{directory,err:=os.Open(path);if err!=nil{return err};defer directory.Close();return directory.Sync()}

var _ CertificateBrokerHost=(*LinuxCertificateHost)(nil)
