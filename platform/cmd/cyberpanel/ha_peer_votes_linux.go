//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

const haPeerCAPath = "/etc/cyberpanel/ha/peer-control-ca.pem"
const haPeerCertPath = "/etc/cyberpanel/ha/peer-control-cert.pem"
const haPeerTLSKeyPath = "/etc/cyberpanel/ha/peer-control.key"
const haPeerVoteKeyPath = "/etc/cyberpanel/ha/peer-vote.key"

// Initialized once during domain assembly, before recovery starts serving.
var localPeerVoteRuntime *ha.PeerVoteService
var localPeerCommitRuntime *ha.PeerCommitService

type haPeerTransport struct {
	db *sql.DB
	certificate tls.Certificate
	roots *x509.CertPool
	caDigest string
	node ha.NodeID
	membership string
}

func (transport *haPeerTransport) topology(ctx context.Context)(ha.PeerVoteTopology,error){
	bundle,err:=ha.LoadAdmittedPeerDeployment(ctx,transport.db)
	if err!=nil{return ha.PeerVoteTopology{},err}
	if ha.NodeID(bundle.Trust.NodeID)!=transport.node || bundle.PeerControl.CASHA256!=transport.caDigest || ha.PeerMembershipDigest(bundle.Group.ID,*bundle.PeerControl)!=transport.membership{return ha.PeerVoteTopology{},ha.ErrNoQuorum}
	digest,err:=ha.StaticDeploymentDigest(bundle);if err!=nil{return ha.PeerVoteTopology{},err}
	return ha.PeerVoteTopology{NodeID:ha.NodeID(bundle.Trust.NodeID),GroupID:bundle.Group.ID,AuthorityEpoch:bundle.AuthorityEpoch,DeploymentEpoch:bundle.DeploymentEpoch,DeploymentDigest:digest,Control:*bundle.PeerControl},nil
}

func (transport *haPeerTransport) caller(ctx context.Context,state tls.ConnectionState)(ha.NodeID,error){
	if state.Version!=tls.VersionTLS13||len(state.VerifiedChains)==0||len(state.PeerCertificates)==0{return "",ha.ErrForbidden}
	topology,err:=transport.topology(ctx);if err!=nil{return "",err}
	pin:=haSenderDigest(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	for _,voter:=range topology.Control.Voters{if voter.SPKISHA256==pin{return voter.NodeID,nil}}
	return "",ha.ErrForbidden
}

func (transport *haPeerTransport) RequestVote(ctx context.Context,voter ha.PeerVoter,proposal ha.PeerVoteProposal)(ha.PeerPromotionVote,error){
	topology,err:=transport.topology(ctx);if err!=nil{return ha.PeerPromotionVote{},err}
	matched:=false
	for _,configured:=range topology.Control.Voters{if configured.NodeID==voter.NodeID&&configured.Endpoint==voter.Endpoint&&configured.SPKISHA256==voter.SPKISHA256{matched=true}}
	if !matched||proposal.Coordinator!=transport.node{return ha.PeerPromotionVote{},ha.ErrForbidden}
	u,err:=url.Parse(voter.Endpoint);if err!=nil{return ha.PeerPromotionVote{},err}
	tlsConfig:=&tls.Config{MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,RootCAs:transport.roots,ServerName:u.Hostname(),Certificates:[]tls.Certificate{transport.certificate},VerifyConnection:func(state tls.ConnectionState)error{
		if len(state.VerifiedChains)==0||len(state.PeerCertificates)==0||haSenderDigest(state.PeerCertificates[0].RawSubjectPublicKeyInfo)!=voter.SPKISHA256{return ha.ErrForbidden};return nil
	}}
	dialer:=&net.Dialer{Timeout:2*time.Second}
	httpTransport:=&http.Transport{Proxy:nil,DialContext:dialer.DialContext,TLSClientConfig:tlsConfig,TLSHandshakeTimeout:2*time.Second,ResponseHeaderTimeout:3*time.Second,MaxResponseHeaderBytes:8<<10,DisableCompression:true,DisableKeepAlives:true,MaxConnsPerHost:1}
	defer httpTransport.CloseIdleConnections()
	client:=&http.Client{Transport:httpTransport,Timeout:4*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return ha.ErrForbidden}}
	raw,err:=json.Marshal(proposal);if err!=nil{return ha.PeerPromotionVote{},err}
	request,err:=http.NewRequestWithContext(ctx,http.MethodPost,voter.Endpoint+"/v1/ha/prepare-vote",bytes.NewReader(raw));if err!=nil{return ha.PeerPromotionVote{},err}
	request.Header.Set("Content-Type","application/json")
	// Retrying this POST is safe only because Cast commits an immutable exact
	// proposal promise before responding. No database/writer mutation occurs.
	response,err:=client.Do(request);if err!=nil{return ha.PeerPromotionVote{},err};defer response.Body.Close()
	if response.StatusCode!=http.StatusOK{return ha.PeerPromotionVote{},ha.ErrNoQuorum}
	encoded,err:=io.ReadAll(io.LimitReader(response.Body,(32<<10)+1));if err!=nil||len(encoded)>32<<10{return ha.PeerPromotionVote{},ha.ErrNoQuorum}
	var vote ha.PeerPromotionVote
	if err=decodeHAFederationJSON(encoded,&vote);err!=nil{return ha.PeerPromotionVote{},err};return vote,nil
}

func startHAPeerVoting(ctx context.Context,db *sql.DB,providers *localMariaDBHAProviders,now func()time.Time)error{
	if _,err:=os.Lstat(ha.StaticDeploymentIngressPath);errors.Is(err,os.ErrNotExist){return nil}else if err!=nil{return err}
	raw,err:=ha.ReadStaticDeploymentFile(ha.StaticDeploymentIngressPath,1<<20);if err!=nil{return err}
	var configured ha.StaticDeploymentFile
	if err=decodeHAFederationJSON(raw,&configured);err!=nil{
		// Legacy central-only ingress has no peer-control listener.
		return nil
	}
	if configured.Deployment.PeerControl==nil{return nil}
	bundle,err:=ha.LoadAdmittedPeerDeployment(ctx,db);if err!=nil{return err}
	if providers==nil{return ha.ErrInvalid}
	owner,ok:=providers.gate.(*ha.OwningNodeWriterGate);if !ok{return ha.ErrInvalid}
	gate,ok:=owner.Local.(*ha.LocalMariaDBWriterGate);if !ok||gate.Executor==nil{return ha.ErrInvalid}
	if now==nil{now=time.Now}
	ca,err:=ha.ReadStaticDeploymentFile(haPeerCAPath,64<<10);if err!=nil{return err}
	if haSenderDigest(ca)!=bundle.PeerControl.CASHA256{return ha.ErrForbidden}
	roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(ca){return ha.ErrForbidden}
	certPEM,err:=ha.ReadStaticDeploymentFile(haPeerCertPath,64<<10);if err!=nil{return err}
	keyPEM,err:=readHAPeerPrivate(haPeerTLSKeyPath,32<<10);if err!=nil{return err};defer clear(keyPEM)
	certificate,err:=tls.X509KeyPair(certPEM,keyPEM);if err!=nil||len(certificate.Certificate)==0{return ha.ErrForbidden}
	leaf,err:=x509.ParseCertificate(certificate.Certificate[0]);if err!=nil{return err}
	var local ha.PeerVoter
	for _,voter:=range bundle.PeerControl.Voters{if voter.NodeID==ha.NodeID(bundle.Trust.NodeID){local=voter}}
	if local.NodeID==""||haSenderDigest(leaf.RawSubjectPublicKeyInfo)!=local.SPKISHA256{return ha.ErrForbidden}
	localURL,err:=url.Parse(local.Endpoint);if err!=nil{return err}
	intermediates:=x509.NewCertPool()
	for _,rawCert:=range certificate.Certificate[1:]{intermediate,parseErr:=x509.ParseCertificate(rawCert);if parseErr!=nil{return parseErr};intermediates.AddCert(intermediate)}
	for _,usage:=range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,x509.ExtKeyUsageClientAuth}{
		if _,err=leaf.Verify(x509.VerifyOptions{Roots:roots,Intermediates:intermediates,DNSName:localURL.Hostname(),CurrentTime:now(),KeyUsages:[]x509.ExtKeyUsage{usage}});err!=nil{return err}
	}
	voteKey,err:=readHAPeerPrivate(haPeerVoteKeyPath,ed25519.PrivateKeySize);if err!=nil{return err}
	if len(voteKey)!=ed25519.PrivateKeySize{clear(voteKey);return ha.ErrForbidden}
	privateKey:=ed25519.NewKeyFromSeed(voteKey[:ed25519.SeedSize]);clear(voteKey)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey),local.VotePublicKey){clear(privateKey);return ha.ErrForbidden}
	transport:=&haPeerTransport{db:db,certificate:certificate,roots:roots,caDigest:bundle.PeerControl.CASHA256,node:ha.NodeID(bundle.Trust.NodeID),membership:ha.PeerMembershipDigest(bundle.Group.ID,*bundle.PeerControl)}
	service:=&ha.PeerVoteService{DB:db,Topology:transport.topology,Transport:transport,Now:now,Sign:func(signCtx context.Context,payload []byte)([]byte,error){if err:=signCtx.Err();err!=nil{return nil,err};return ed25519.Sign(privateKey,payload),nil}}
	service.Observe=func(observeCtx context.Context,proposal ha.PeerVoteProposal)(string,error){
		topology,err:=transport.topology(observeCtx);if err!=nil{return "",err}
		store:=ha.SQLRepository{DB:db}
		lease,err:=store.LoadLease(observeCtx,proposal.PreviousLeaseID)
		if err!=nil||lease.GroupID!=topology.GroupID||lease.ResourceID!=proposal.ResourceID||lease.HolderNodeID!=proposal.PreviousWriter||lease.FencingToken!=proposal.PreviousFencingEpoch||lease.AuthorityEpoch!=topology.AuthorityEpoch||proposal.AuthorityEpoch!=topology.AuthorityEpoch{return "",ha.ErrLeaseLost}
		var high uint64
		if err=db.QueryRowContext(observeCtx,`SELECT COALESCE(MAX(fencing_token),0) FROM ha_writer_leases WHERE resource_id=?`,proposal.ResourceID).Scan(&high);err!=nil||high!=proposal.PreviousFencingEpoch{return "",ha.ErrLeaseLost}
		cluster,err:=store.LoadDatabaseCluster(observeCtx,ha.ID(proposal.ResourceID));if err!=nil||cluster.GroupID!=topology.GroupID{return "",ha.ErrNoQuorum}
		// Observe exactly the owning node through the local broker alias; never
		// reinterpret another member's stored projection as a local observation.
		// Static admission already binds the sole local alias to this node. Keep
		// other members intact for cluster validation, but never count them.
		localMembers:=0
		for _,member:=range cluster.Members{if member.NodeID==ha.NodeID(localFederationNodeID){localMembers++}}
		if localMembers!=1{return "",ha.ErrNoQuorum}
		observed,err:=gate.Executor.ObserveCluster(observeCtx,cluster);if err!=nil{return "",err}
		if observed.ID!=cluster.ID||observed.GroupID!=cluster.GroupID{return "",ha.ErrNoQuorum}
		var member ha.DatabaseMember
		for _,actual:=range observed.Members{if actual.NodeID==ha.NodeID(localFederationNodeID){member=actual}}
		if member.NodeID!=ha.NodeID(localFederationNodeID)||!member.ReadOnly||member.ObservedAt.IsZero()||member.ObservedAt.Before(now().Add(-5*time.Second))||member.ObservedAt.After(now().Add(5*time.Second)){return "",ha.ErrNoQuorum}
		proof,err:=json.Marshal(struct{Node ha.NodeID;Proposal string;Lease ha.WriterLease;Member ha.DatabaseMember}{topology.NodeID,proposal.Digest(),lease,member});if err!=nil{return "",err};return haSenderDigest(proof),nil
	}
	if err=service.Bootstrap(ctx);err!=nil{return err}
	commits,err:=newHAPeerCommitRuntime(ctx,service,transport,gate.Executor);if err!=nil{return err}
	u,err:=url.Parse(local.Endpoint);if err!=nil{return err}
	listener,err:=net.Listen("tcp",u.Host);if err!=nil{return err}
	serverTLS:=&tls.Config{MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{certificate},ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:roots,VerifyConnection:func(state tls.ConnectionState)error{
		verifyCtx,cancel:=context.WithTimeout(ctx,2*time.Second);defer cancel();_,err:=transport.caller(verifyCtx,state);return err
	}}
	server:=&http.Server{ReadHeaderTimeout:2*time.Second,ReadTimeout:15*time.Second,WriteTimeout:15*time.Second,IdleTimeout:5*time.Second,MaxHeaderBytes:8<<10,TLSConfig:serverTLS,BaseContext:func(net.Listener)context.Context{return ctx}}
	server.Handler=http.HandlerFunc(func(writer http.ResponseWriter,request *http.Request){
		writer.Header().Set("Cache-Control","no-store");writer.Header().Set("X-Content-Type-Options","nosniff")
		if serveHAPeerCommit(commits,transport,writer,request){return}
		if request.Method!=http.MethodPost||request.URL.Path!="/v1/ha/prepare-vote"||request.URL.RawQuery!=""||request.Header.Get("Content-Type")!="application/json"||request.TLS==nil{http.Error(writer,"not permitted",http.StatusForbidden);return}
		requestCtx,cancel:=context.WithTimeout(request.Context(),4*time.Second);defer cancel()
		caller,err:=transport.caller(requestCtx,*request.TLS);if err!=nil{http.Error(writer,"not permitted",http.StatusForbidden);return}
		body,err:=io.ReadAll(http.MaxBytesReader(writer,request.Body,32<<10));if err!=nil{http.Error(writer,"invalid proposal",http.StatusBadRequest);return}
		var proposal ha.PeerVoteProposal
		if decodeHAFederationJSON(body,&proposal)!=nil{http.Error(writer,"invalid proposal",http.StatusBadRequest);return}
		vote,err:=service.Cast(requestCtx,caller,proposal);if err!=nil{http.Error(writer,"vote unavailable",http.StatusConflict);return}
		writer.Header().Set("Content-Type","application/json");_ = json.NewEncoder(writer).Encode(vote)
	})
	go func(){_ = server.Serve(tls.NewListener(listener,serverTLS))}()
	go func(){<-ctx.Done();shutdownCtx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel();_ = server.Shutdown(shutdownCtx)}()
	providers.quorum=service
	localPeerVoteRuntime=service
	localPeerCommitRuntime=commits
	return nil
}

func readHAPeerPrivate(path string,maximum int64)([]byte,error){
	info,err:=os.Lstat(path);if err!=nil{return nil,err}
	if info.Mode().Perm()&0007!=0{return nil,ha.ErrForbidden}
	return ha.ReadStaticDeploymentFile(path,maximum)
}
