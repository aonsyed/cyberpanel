package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

type CoreProcessConfig struct{CoreSocket SocketOptions;RecoverySocket SocketOptions;GatewayUIDs []uint32;EnableRecovery bool;ShutdownTimeout time.Duration}
type CoreProcess struct{Core *Core;Recovery *RecoveryServer;Config CoreProcessConfig}

// Run owns the local state-writer process boundary. Public listeners never
// enter this process: panel-gateway reaches the signed core socket, while only
// root reaches the separate recovery socket.
func(process *CoreProcess)Run(ctx context.Context)error{if process==nil||process.Core==nil{return invalid("core process")};corePeer,err:=NewStaticPeerPolicy(process.Config.GatewayUIDs...);if err!=nil{return err};coreListener,err:=ListenUnix(process.Config.CoreSocket);if err!=nil{return err};defer coreListener.Close();coreServer:=&http.Server{Handler:process.Core.Handler(),ReadHeaderTimeout:3*time.Second,ReadTimeout:35*time.Second,WriteTimeout:5*time.Minute,IdleTimeout:30*time.Second,MaxHeaderBytes:32<<10};type runningServer struct{server *http.Server;listener net.Listener;peer PeerAuthorizer};servers:=[]runningServer{{coreServer,coreListener,corePeer}};if process.Config.EnableRecovery{if process.Recovery==nil{return invalid("recovery process")};recoveryPeer,_:=NewStaticPeerPolicy(0);recoveryListener,listenErr:=ListenUnix(process.Config.RecoverySocket);if listenErr!=nil{return listenErr};defer recoveryListener.Close();recoveryServer:=&http.Server{Handler:process.Recovery.Handler(),ReadHeaderTimeout:3*time.Second,ReadTimeout:35*time.Second,WriteTimeout:2*time.Minute,IdleTimeout:10*time.Second,MaxHeaderBytes:16<<10};servers=append(servers,runningServer{recoveryServer,recoveryListener,recoveryPeer})};errorsChannel:=make(chan error,len(servers));var wait sync.WaitGroup;for _,running:=range servers{running:=running;wait.Add(1);go func(){defer wait.Done();errorsChannel<-ServeCore(running.server,running.listener,running.peer)}()};var serveErr error;select{case <-ctx.Done():case serveErr=<-errorsChannel:};timeout:=process.Config.ShutdownTimeout;if timeout<=0{timeout=30*time.Second};shutdownCtx,cancel:=context.WithTimeout(context.Background(),timeout);defer cancel();for _,running:=range servers{_ = running.server.Shutdown(shutdownCtx);_ = running.listener.Close()};wait.Wait();if serveErr!=nil&&!errors.Is(serveErr,http.ErrServerClosed)&&!errors.Is(serveErr,net.ErrClosed){return serveErr};return nil}
