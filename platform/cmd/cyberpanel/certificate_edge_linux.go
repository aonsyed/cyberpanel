//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
)

type certificateEdge struct{issuance *certificates.IssuanceCoordinator;deployment *certificates.DeploymentCoordinator;secrets *certificates.SecretMaterialRuntime}

func newCertificateEdge(runtime *certificates.LinuxClientRuntime,issuance *certificates.IssuanceCoordinator,deployment *certificates.DeploymentCoordinator)(apiserver.CertificateEdgeService,error){if runtime==nil||runtime.Secrets==nil||issuance==nil||deployment==nil{return nil,errors.New("certificate edge dependencies required")};return &certificateEdge{issuance:issuance,deployment:deployment,secrets:runtime.Secrets},nil}

func(edge *certificateEdge)IssueCertificate(ctx context.Context,call apiserver.EdgeCall,payload apiserver.CertificateIssueEdgePayload)(apiserver.EdgeMutation[apiserver.CertificateEdgeProjection],error){return edge.issue(ctx,call,payload,false)}
func(edge *certificateEdge)IssueSiteCertificate(ctx context.Context,call apiserver.EdgeCall,payload apiserver.CertificateIssueEdgePayload)(apiserver.EdgeMutation[apiserver.CertificateEdgeProjection],error){return edge.issue(ctx,call,payload,true)}

func(edge *certificateEdge)issue(ctx context.Context,call apiserver.EdgeCall,payload apiserver.CertificateIssueEdgePayload,deploy bool)(apiserver.EdgeMutation[apiserver.CertificateEdgeProjection],error){
	if edge==nil||edge.issuance==nil||edge.secrets==nil||ctx==nil||call.TenantID==""||payload.Consumer==""||len(payload.Names)==0{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},certificates.ErrInvalidCertificate}
	names:=append([]string(nil),payload.Names...);for index:=range names{names[index]=strings.ToLower(strings.TrimSuffix(strings.TrimSpace(names[index]),"."))};sort.Strings(names)
	accountID:=certificates.AccountID(certificateEdgeID("account",call.TenantID,"letsencrypt"));account,err:=edge.issuance.Store.Account(ctx,call.TenantID,accountID);if errors.Is(err,sql.ErrNoRows){keyRef,keyErr:=edge.secrets.EnsureAccountKey(ctx,call.TenantID,accountID);if keyErr!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},keyErr};contactName:=strings.TrimPrefix(names[0],"*.");account=certificates.AccountSpec{ID:accountID,TenantID:call.TenantID,Directory:certificates.IssuerDirectory{Kind:certificates.IssuerLetsEncrypt,ProductionURL:certificates.LetsEncryptProductionDirectory,StagingURL:certificates.LetsEncryptStagingDirectory,PinnedOrigin:"https://acme-v02.api.letsencrypt.org"},Contact:[]string{"mailto:hostmaster@"+contactName},AccountKeyRef:keyRef,AcceptedTermsAt:time.Now().UTC(),Status:"active"};err=edge.issuance.Store.PutAccount(ctx,account)};if err!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},err}
	challenge:=certificates.HTTP01;if payload.Challenge=="dns-01"{challenge=certificates.DNS01};policyID:=certificates.PolicyID(certificateEdgeID("policy",call.TenantID,payload.Consumer,strings.Join(names,","),string(challenge)));policy,err:=edge.issuance.Store.Policy(ctx,call.TenantID,policyID);if errors.Is(err,sql.ErrNoRows){policy=certificates.CertificatePolicy{ID:policyID,TenantID:call.TenantID,AccountID:accountID,Names:names,PreferredChallenge:challenge,KeyAlgorithm:"ecdsa-p256",RenewBefore:30*24*time.Hour,Generation:1};err=edge.issuance.Store.PutPolicy(ctx,policy,0)};if err!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},err};if strings.Join(policy.Names,"\x00")!=strings.Join(names,"\x00")||policy.PreferredChallenge!=challenge{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},certificates.ErrCertificateConflict}
	issuanceID:=certificateEdgeID("issuance",call.TenantID,payload.Consumer,call.CommandID,call.IdempotencyKey);issued,err:=edge.issuance.Issue(ctx,call.TenantID,policyID,issuanceID,certificateEdgeID("idempotency",call.TenantID,payload.Consumer,call.CommandID,call.IdempotencyKey));if err!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},err}
	state:=string(issued.Phase);operationID:=issued.ID;if deploy{deployment,deployErr:=edge.deployment.Deploy(ctx,"webengine/"+payload.Consumer,issued.Certificate,certificateEdgeID("deploy",call.TenantID,payload.Consumer,issued.ID));if deployErr!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},deployErr};operationID=string(deployment.ID);state="active"}
	projection:=apiserver.CertificateEdgeProjection{ID:string(issued.Certificate.ID),Consumer:payload.Consumer,Names:append([]string(nil),issued.Certificate.Names...),State:state,NotAfter:issued.Certificate.NotAfter,Generation:issued.PolicyGeneration}
	return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{OperationID:operationID,State:state,Generation:issued.PolicyGeneration,Resource:projection},nil
}

func(edge *certificateEdge)DeployCertificate(ctx context.Context,call apiserver.EdgeCall,payload apiserver.CertificateDeployEdgePayload)(apiserver.EdgeMutation[apiserver.CertificateEdgeProjection],error){if edge==nil||edge.deployment==nil||ctx==nil||call.TenantID==""||call.ResourceID==""||payload.Consumer==""{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},certificates.ErrInvalidCertificate};material,err:=edge.issuance.Store.Material(ctx,call.TenantID,certificates.CertificateID(call.ResourceID));if err!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},err};issued,err:=edge.issuance.Store.Issuance(ctx,call.TenantID,material.IssuanceID);if err!=nil||issued.Certificate.ID!=material.ID{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},certificates.ErrInvalidCertificate};deployment,err:=edge.deployment.Deploy(ctx,"webengine/"+payload.Consumer,material,certificateEdgeID("deploy",call.TenantID,payload.Consumer,call.CommandID,call.IdempotencyKey));if err!=nil{return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{},err};projection:=apiserver.CertificateEdgeProjection{ID:string(material.ID),Consumer:payload.Consumer,Names:append([]string(nil),material.Names...),State:"active",NotAfter:material.NotAfter,Generation:issued.PolicyGeneration};return apiserver.EdgeMutation[apiserver.CertificateEdgeProjection]{OperationID:string(deployment.ID),State:"active",Generation:issued.PolicyGeneration,Resource:projection},nil}

func certificateEdgeID(kind string,values ...string)string{hash:=sha256.New();hash.Write([]byte("certificate-edge-v1\x00"+kind));for _,value:=range values{hash.Write([]byte{0});hash.Write([]byte(value))};return kind+"_"+hex.EncodeToString(hash.Sum(nil))[:48]}
var _ apiserver.CertificateEdgeService=(*certificateEdge)(nil)
