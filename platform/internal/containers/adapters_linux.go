//go:build linux

package containers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
)

const DefaultContainerRecipeTrustPath = "/etc/cyberpanel/containers/recipe-trust.json"

type containerRecipeTrustDocument struct{Keys []struct{ID string `json:"id"`;PublicKey string `json:"public_key"`} `json:"keys"`}
func LoadLinuxRecipeVerifier(path string)(*SignedRecipeVerifier,error){if path!=DefaultContainerRecipeTrustPath{return nil,ErrForbidden};info,err:=os.Lstat(path);if err!=nil{return nil,err};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||stat.Uid!=0||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o022!=0||info.Size()<=0||info.Size()>1<<20{return nil,ErrForbidden};content,err:=os.ReadFile(filepath.Clean(path));if err!=nil{return nil,err};var document containerRecipeTrustDocument;if json.Unmarshal(content,&document)!=nil||len(document.Keys)==0||len(document.Keys)>64{return nil,ErrInvalid};keys:=map[string]ed25519.PublicKey{};for _,entry:=range document.Keys{raw,decodeErr:=base64.RawURLEncoding.DecodeString(entry.PublicKey);if decodeErr!=nil{raw,decodeErr=base64.StdEncoding.DecodeString(entry.PublicKey)};if decodeErr!=nil||entry.ID==""||len(raw)!=ed25519.PublicKeySize{return nil,ErrInvalid};if _,exists:=keys[entry.ID];exists{return nil,ErrConflict};keys[entry.ID]=ed25519.PublicKey(raw)};return NewSignedRecipeVerifier(keys)}

func LoadDefaultLinuxRecipeVerifier()(*SignedRecipeVerifier,error){if verifier,err:=LoadLinuxRecipeVerifier(DefaultContainerRecipeTrustPath);err==nil{return verifier,nil};const directory="/etc/cyberpanel/installer/trust.d";info,err:=os.Lstat(directory);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o022!=0{return nil,ErrForbidden};entries,err:=os.ReadDir(directory);if err!=nil{return nil,err};keys:=map[string]ed25519.PublicKey{};for _,entry:=range entries{if entry.IsDir()||entry.Type()&os.ModeSymlink!=0||filepath.Ext(entry.Name())!=".json"{continue};path:=filepath.Join(directory,entry.Name());fileInfo,infoErr:=entry.Info();if infoErr!=nil{return nil,infoErr};stat,ok:=fileInfo.Sys().(*syscall.Stat_t);if !ok||stat.Uid!=0||fileInfo.Mode().Perm()&0o022!=0{return nil,ErrForbidden};content,readErr:=os.ReadFile(path);if readErr!=nil{return nil,readErr};var document struct{ID string `json:"id"`;PublicKey string `json:"public_key"`};if json.Unmarshal(content,&document)!=nil{continue};raw,decodeErr:=hex.DecodeString(document.PublicKey);if decodeErr!=nil||document.ID==""||len(raw)!=ed25519.PublicKeySize{return nil,ErrInvalid};keys[document.ID]=ed25519.PublicKey(raw)};return NewSignedRecipeVerifier(keys)}
