package database

import "bytes"

type PrincipalCredentialFormat string

const CredentialFormatNativeHash PrincipalCredentialFormat = "mysql_native_password_hash"
const nativeHashCredentialPrefix = "\x00cyberpanel-mysql-native-password-v1\x00"

// These bytes remain inside a sealed migration envelope or the secret broker.
// The marker distinguishes an attested source hash from a plaintext password;
// neither a hash-looking password nor an arbitrary plugin is inferred here.
func EncodeNativePasswordHashCredential(hash []byte) ([]byte,error) {
	if !validNativePasswordHash(hash) { return nil,ErrInvalidResource }
	return append([]byte(nativeHashCredentialPrefix),hash...),nil
}

func DecodeNativePasswordHashCredential(material []byte) ([]byte,error) {
	if !bytes.HasPrefix(material,[]byte(nativeHashCredentialPrefix)) { return nil,ErrInvalidResource }
	hash:=material[len(nativeHashCredentialPrefix):]
	if !validNativePasswordHash(hash) { return nil,ErrInvalidResource }
	return append([]byte(nil),hash...),nil
}

func validNativePasswordHash(hash []byte) bool {
	if len(hash)!=41 || hash[0]!='*' { return false }
	for _,value:=range hash[1:] { if !(value>='0'&&value<='9'||value>='A'&&value<='F') { return false } }
	return true
}
