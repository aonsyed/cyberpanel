package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// TLSServer is the bounded production accept loop for the federation endpoint.
// TLS policy is assembled by the executable so the endpoint only ever sees a
// connection whose client chain has already been checked against the pinned CA.
type TLSServer struct {
	Endpoint         *Endpoint
	TLSConfig        *tls.Config
	MaximumSessions  uint32
	ShutdownTimeout  time.Duration
}

func NewTLSServer(endpoint *Endpoint, tlsConfig *tls.Config, maximumSessions uint32, shutdownTimeout time.Duration) (*TLSServer, error) {
	if endpoint == nil || tlsConfig == nil || len(tlsConfig.Certificates) != 1 || tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil || maximumSessions == 0 || maximumSessions > 4096 || shutdownTimeout < time.Second || shutdownTimeout > 2*time.Minute {
		return nil, ErrInvalid
	}
	return &TLSServer{Endpoint: endpoint, TLSConfig: tlsConfig.Clone(), MaximumSessions: maximumSessions, ShutdownTimeout: shutdownTimeout}, nil
}

func (server *TLSServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || server.Endpoint == nil || server.TLSConfig == nil || ctx == nil || listener == nil {
		return ErrInvalid
	}
	sessionContext, cancelSessions := context.WithCancel(context.Background())
	defer cancelSessions()
	semaphore := make(chan struct{}, server.MaximumSessions)
	var sessions sync.WaitGroup
	stopAccepting := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopAccepting:
		}
	}()

	var serveErr error
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				serveErr = err
			}
			break
		}
		select {
		case semaphore <- struct{}{}:
			sessions.Add(1)
			go func(raw net.Conn) {
				defer sessions.Done()
				defer func() { <-semaphore }()
				_ = server.Endpoint.ServeTLS(sessionContext, tls.Server(raw, server.TLSConfig.Clone()))
			}(connection)
		default:
			_ = connection.Close()
		}
	}
	close(stopAccepting)
	cancelSessions()
	completed := make(chan struct{})
	go func() {
		sessions.Wait()
		close(completed)
	}()
	timer := time.NewTimer(server.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-completed:
		return serveErr
	case <-timer.C:
		if serveErr != nil {
			return errors.Join(serveErr, context.DeadlineExceeded)
		}
		return context.DeadlineExceeded
	}
}
