//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	MariaDBSecretAdapterID      = "database.mariadb"
	MariaDBSecretAdapterVersion = "linux-mariadb-v1"
)

type LinuxSecretBrokerSource struct {
	client            *secrets.MaterialClient
	installationOwner secrets.ID
}

func NewLinuxSecretBrokerSource(client *secrets.MaterialClient, installationOwner secrets.ID)(*LinuxSecretBrokerSource,error){if client==nil||!installationOwner.Valid(){return nil,ErrInvalidResource};return &LinuxSecretBrokerSource{client:client,installationOwner:installationOwner},nil}

type externalAdministratorMaterial struct{Username string `json:"username"`;Password []byte `json:"password"`;ClientCertificatePEM []byte `json:"client_certificate_pem,omitempty"`;ClientKeyPEM []byte `json:"client_key_pem,omitempty"`}
type serverTLSMaterial struct{CertificateAuthorityPEM []byte `json:"certificate_authority_pem"`;CertificatePEM []byte `json:"certificate_pem"`;KeyPEM []byte `json:"key_pem"`}

func(source *LinuxSecretBrokerSource)PrincipalPassword(ctx context.Context,ref SecretRef,principalID ResourceID,tenantID,siteID string)([]byte,error){
	if source==nil||ref.IsZero()||principalID.IsZero()||tenantID==""||siteID==""{return nil,ErrInvalidResource};owner:=DatabaseTenantOwnerID(tenantID);response,err:=source.read(ctx,DatabaseSecretRecordID(ref.String()),owner,DatabaseAudienceID(principalID.String()),secrets.OperationAuthenticate);if err!=nil{return nil,err};if len(response.Material)>maximumSecretBytes||bytes.HasPrefix(response.Material,[]byte(nativeHashCredentialPrefix)){wipeBytes(response.Material);return nil,ErrInvalidResource};return response.Material,nil
}

func(source *LinuxSecretBrokerSource)PrincipalNativePasswordHash(ctx context.Context,ref SecretRef,principalID ResourceID,tenantID,siteID string)([]byte,error){
	if source==nil||ref.IsZero()||principalID.IsZero()||tenantID==""||siteID==""{return nil,ErrInvalidResource}
	response,err:=source.read(ctx,DatabaseSecretRecordID(ref.String()),DatabaseTenantOwnerID(tenantID),DatabaseAudienceID(principalID.String()),secrets.OperationAuthenticate)
	if err!=nil{return nil,err};defer wipeBytes(response.Material)
	return DecodeNativePasswordHashCredential(response.Material)
}

func(source *LinuxSecretBrokerSource)ExternalAdministrator(ctx context.Context,ref SecretRef,audience ResourceID,instanceID ResourceID)(MariaDBAdministrator,error){
	if source==nil||ref.IsZero()||audience.IsZero()||instanceID.IsZero(){return MariaDBAdministrator{},ErrInvalidResource};response,err:=source.read(ctx,DatabaseSecretRecordID(ref.String()),source.installationOwner,DatabaseAudienceID(audience.String()),secrets.OperationAuthenticate);if err!=nil{return MariaDBAdministrator{},err};defer wipeBytes(response.Material);var material externalAdministratorMaterial;if err=decodeDatabaseSecret(response.Material,&material);err!=nil{return MariaDBAdministrator{},err};username,err:=ParseSQLIdentifier(material.Username);if err!=nil{return MariaDBAdministrator{},err};result:=MariaDBAdministrator{Username:username,Password:append([]byte(nil),material.Password...),ClientCertificatePEM:append([]byte(nil),material.ClientCertificatePEM...),ClientKeyPEM:append([]byte(nil),material.ClientKeyPEM...)};wipeBytes(material.Password,material.ClientCertificatePEM,material.ClientKeyPEM);if validateAdministrator(result,len(result.ClientCertificatePEM)>0||len(result.ClientKeyPEM)>0)!=nil{wipeBytes(result.Password,result.ClientCertificatePEM,result.ClientKeyPEM);return MariaDBAdministrator{},ErrInvalidResource};return result,nil
}

func(source *LinuxSecretBrokerSource)PinnedCertificateAuthority(ctx context.Context,ref SecretRef,audience ResourceID)([]byte,error){if source==nil||ref.IsZero()||audience.IsZero(){return nil,ErrInvalidResource};response,err:=source.read(ctx,DatabaseSecretRecordID(ref.String()),source.installationOwner,DatabaseAudienceID(audience.String()),secrets.OperationRead);if err!=nil{return nil,err};if len(response.Material)>maximumSecretBytes{wipeBytes(response.Material);return nil,ErrInvalidResource};return response.Material,nil}

func(source *LinuxSecretBrokerSource)LocalServerTLS(ctx context.Context,instanceID,policyID ResourceID,mode TLSMode)(MariaDBServerTLS,error){if source==nil||instanceID.IsZero()||policyID.IsZero()||(mode!=TLSRequired&&mode!=TLSMutual){return MariaDBServerTLS{},ErrInvalidResource};response,err:=source.read(ctx,DatabaseTLSSecretID(policyID.String()),source.installationOwner,DatabaseAudienceID(policyID.String()),secrets.OperationRead);if err!=nil{return MariaDBServerTLS{},err};defer wipeBytes(response.Material);var material serverTLSMaterial;if err=decodeDatabaseSecret(response.Material,&material);err!=nil{return MariaDBServerTLS{},err};result:=MariaDBServerTLS{CertificateAuthorityPEM:append([]byte(nil),material.CertificateAuthorityPEM...),CertificatePEM:append([]byte(nil),material.CertificatePEM...),KeyPEM:append([]byte(nil),material.KeyPEM...)};wipeBytes(material.CertificateAuthorityPEM,material.CertificatePEM,material.KeyPEM);if validateServerTLS(result)!=nil{wipeBytes(result.CertificateAuthorityPEM,result.CertificatePEM,result.KeyPEM);return MariaDBServerTLS{},ErrInvalidResource};return result,nil}

func(source *LinuxSecretBrokerSource)read(ctx context.Context,secretID,owner,audience secrets.ID,operation secrets.Operation)(secrets.MaterialResponse,error){if source.client==nil||!secretID.Valid()||!owner.Valid()||!audience.Valid(){return secrets.MaterialResponse{},ErrInvalidResource};response,err:=source.client.Read(ctx,secrets.MaterialRequest{SecretID:secretID,OwnerTenantID:owner,Purpose:secrets.PurposeDatabase,Operation:operation,AdapterID:MariaDBSecretAdapterID,AdapterVersion:MariaDBSecretAdapterVersion,ResourceID:audience});if err!=nil{return secrets.MaterialResponse{},err};return response,nil}

func DatabaseSecretRecordID(value string)secrets.ID{if identifier,err:=secrets.NewID(value);err==nil{return identifier};return databaseSecretIdentifier("dbsecret",value)}
func DatabaseTLSSecretID(policyID string)secrets.ID{return databaseSecretIdentifier("dbtls",policyID)}
func DatabaseAudienceID(resourceID string)secrets.ID{return databaseSecretIdentifier("resource",resourceID)}
func DatabaseTenantOwnerID(tenantID string)secrets.ID{return databaseSecretIdentifier("tenant",tenantID)}
func databaseSecretIdentifier(prefix,value string)secrets.ID{sum:=sha256.Sum256([]byte(prefix+"\x00"+value));identifier,_:=secrets.NewID(prefix+"_"+hex.EncodeToString(sum[:])[:48]);return identifier}

func decodeDatabaseSecret(payload []byte,target any)error{if len(payload)==0||len(payload)>maximumSecretBytes{return ErrInvalidResource};decoder:=json.NewDecoder(bytes.NewReader(payload));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return ErrInvalidResource};if decoder.Decode(&struct{}{})!=io.EOF{return ErrInvalidResource};return nil}

var _ LinuxMariaDBSecretSource = (*LinuxSecretBrokerSource)(nil)
