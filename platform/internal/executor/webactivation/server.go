package webactivation

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

type PeerAuthorizer interface { Authorize(net.Conn) error }
type RequestHandler interface { Execute(context.Context, Request) (Response, error) }

type Server struct {
	Authorizer PeerAuthorizer
	Handler RequestHandler
	Admission rebootcontrol.ExecutionAdmission
	MaximumConcurrent uint32
	Now func() time.Time
	once sync.Once
	semaphore chan struct{}
}

func (server *Server) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Handler == nil { return errors.New("web-engine activation server dependencies are required") }
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 { maximum = 32 }
		if maximum > 128 { maximum = 128 }
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil { return err }
		select {
		case server.semaphore <- struct{}{}:
			go func() { defer func() { <-server.semaphore; _ = connection.Close() }(); server.serveConnection(connection) }()
		default:
			_ = connection.SetDeadline(time.Now())
			_ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(connection net.Conn) {
	if err := server.Authorizer.Authorize(connection); err != nil { return }
	now := time.Now().UTC()
	if server.Now != nil { now = server.Now().UTC() }
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request Request
	if err := readFrame(connection, &request); err != nil { return }
	if err := request.Validate(now); err != nil { return }
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	if server.Admission==nil{return}
	binding:=rebootcontrol.ExecutionBinding{Boundary:"webactivation",Method:"activate",EffectID:request.EffectID,RequestDigest:request.Digest(),Caller:"authenticated-panel-core",Resource:"local:webengine"}
	lease,err:=server.admitActivation(ctx,request,binding);if err!=nil{return}
	if len(lease.Cached)!=0 {
		var cached Response
		if json.Unmarshal(lease.Cached,&cached)==nil && cached.Validate(request,time.Now().UTC())==nil{_=writeFrame(connection,cached)};return
	}
	defer func(){_=rebootcontrol.SettleExecution(server.Admission,lease,false,nil)}()
	response, err := server.Handler.Execute(ctx, request)
	if err != nil {
		response = Response{
			Version: ProtocolVersion, EffectID: request.EffectID, ExpectedDigest: request.ExpectedDigest,
			Receipt: activation.Receipt{Status: activation.Ambiguous, CandidateDigest: request.ExpectedDigest},
			ErrorCode: "internal_error", CompletedAt: time.Now().UTC(),
		}
	}
	completed := time.Now().UTC()
	if server.Now != nil { completed = server.Now().UTC() }
	if err = response.Validate(request, completed); err != nil { return }
	terminal:=response.Receipt.Status==activation.Applied || response.Receipt.Status==activation.RolledBack
	if rebootcontrol.SettleExecution(server.Admission,lease,terminal,response)!=nil{return}
	_ = writeFrame(connection, response)
}
