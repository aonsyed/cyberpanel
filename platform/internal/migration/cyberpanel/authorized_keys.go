package cyberpanel

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

type AuthorizedPublicKey struct {
	Fingerprint string
	PublicKey string
	Label string
}

func ParseAuthorizedKeys(raw []byte)([]AuthorizedPublicKey,error){
	if len(raw)>8<<20||bytes.IndexByte(raw,0)>=0{return nil,ErrInvalid}
	values:=[]AuthorizedPublicKey{}
	seen:=map[string]struct{}{}
	scanner:=bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte,4096),256<<10)
	for scanner.Scan(){
		line:=strings.TrimSpace(scanner.Text())
		if line==""||strings.HasPrefix(line,"#"){continue}
		fields:=strings.Fields(line)
		keyIndex:=-1
		for index,field:=range fields{if authorizedKeyType(field){keyIndex=index;break}}
		if keyIndex<0||keyIndex+1>=len(fields){return nil,ErrInvalid}
		blob,err:=base64.StdEncoding.DecodeString(fields[keyIndex+1])
		if err!=nil||len(blob)<8||len(blob)>64<<10{return nil,ErrInvalid}
		algorithmLength:=binary.BigEndian.Uint32(blob[:4])
		if algorithmLength==0||uint64(algorithmLength)>uint64(len(blob)-4)||string(blob[4:4+algorithmLength])!=fields[keyIndex]{return nil,ErrInvalid}
		sum:=sha256.Sum256(blob)
		fingerprint:=hex.EncodeToString(sum[:])
		if _,duplicate:=seen[fingerprint];duplicate{continue}
		seen[fingerprint]=struct{}{}
		label:=fields[keyIndex]
		if keyIndex+2<len(fields){label=strings.Join(fields[keyIndex+2:]," ");if len(label)>191{label=label[:191]}}
		publicKey:=fields[keyIndex]+" "+fields[keyIndex+1]
		values=append(values,AuthorizedPublicKey{Fingerprint:fingerprint,PublicKey:publicKey,Label:label})
	}
	if err:=scanner.Err();err!=nil{return nil,err}
	return values,nil
}

func authorizedKeyType(value string)bool{
	if value=="ssh-rsa"||value=="ssh-dss"||value=="ssh-ed25519"||value=="sk-ssh-ed25519@openssh.com"{return true}
	if strings.HasPrefix(value,"ecdsa-sha2-")||strings.HasPrefix(value,"sk-ecdsa-sha2-"){return true}
	return (strings.HasPrefix(value,"ssh-rsa-cert-")||strings.HasPrefix(value,"ssh-dss-cert-")||strings.HasPrefix(value,"ssh-ed25519-cert-")||strings.HasPrefix(value,"ecdsa-sha2-")||strings.HasPrefix(value,"sk-ssh-ed25519-cert-")||strings.HasPrefix(value,"sk-ecdsa-sha2-"))&&strings.HasSuffix(value,"@openssh.com")
}
