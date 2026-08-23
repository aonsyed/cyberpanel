package federation

import(
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const(MaxFrameBytes=4<<20)
type FrameType string
const(FrameHello FrameType="hello";FrameHelloAck FrameType="hello_ack";FrameIntent FrameType="intent";FrameReceipt FrameType="receipt";FrameEventBatch FrameType="event_batch";FrameEventAck FrameType="event_ack";FrameRevocation FrameType="revocation";FrameRevocationAck FrameType="revocation_ack";FrameSnapshotRequest FrameType="snapshot_request";FrameSnapshotChunk FrameType="snapshot_chunk";FrameHeartbeat FrameType="heartbeat";FrameError FrameType="error")
type Frame struct{Version uint16 `json:"version"`;Type FrameType `json:"type"`;Sequence uint64 `json:"sequence"`;Payload json.RawMessage `json:"payload"`}
type Session interface{Send(context.Context,Frame)error;Receive(context.Context)(Frame,error);Close()error}
type Connector interface{Connect(context.Context)(Session,error)}
type TLSConnector struct{Address,ServerName string;TLSConfig *tls.Config;Dialer net.Dialer;MaxFrame uint32}
func(c *TLSConnector)Connect(ctx context.Context)(Session,error){if c==nil||c.Address==""||c.ServerName==""||c.TLSConfig==nil||len(c.TLSConfig.Certificates)==0{return nil,ErrInvalid};config:=c.TLSConfig.Clone();config.ServerName=c.ServerName;config.MinVersion=tls.VersionTLS13;raw,err:=c.Dialer.DialContext(ctx,"tcp",c.Address);if err!=nil{return nil,err};connection:=tls.Client(raw,config);if err=connection.HandshakeContext(ctx);err!=nil{raw.Close();return nil,err};max:=c.MaxFrame;if max==0||max>MaxFrameBytes{max=MaxFrameBytes};return &framedSession{connection:connection,reader:bufio.NewReaderSize(connection,64<<10),max:max},nil}
type framedSession struct{connection net.Conn;reader *bufio.Reader;max uint32;write sync.Mutex}
func(s *framedSession)Send(ctx context.Context,frame Frame)error{raw,err:=json.Marshal(frame);if err!=nil{return err};if len(raw)>int(s.max){return ErrInvalid};deadline,ok:=ctx.Deadline();if ok{_ = s.connection.SetWriteDeadline(deadline)};s.write.Lock();defer s.write.Unlock();header:=make([]byte,4);binary.BigEndian.PutUint32(header,uint32(len(raw)));if _,err=s.connection.Write(header);err!=nil{return err};_,err=s.connection.Write(raw);return err}
func(s *framedSession)Receive(ctx context.Context)(Frame,error){var frame Frame;deadline,ok:=ctx.Deadline();if ok{_ = s.connection.SetReadDeadline(deadline)};header:=make([]byte,4);if _,err:=io.ReadFull(s.reader,header);err!=nil{return frame,err};size:=binary.BigEndian.Uint32(header);if size==0||size>s.max{return frame,ErrInvalid};raw:=make([]byte,size);if _,err:=io.ReadFull(s.reader,raw);err!=nil{return frame,err};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();if err:=decoder.Decode(&frame);err!=nil{return frame,err};if frame.Version!=1||frame.Type==""{return frame,ErrInvalid};return frame,nil}
func(s *framedSession)Close()error{return s.connection.Close()}

type Runner struct{Agent *Agent;Store *Store;Connector Connector;Capabilities func(context.Context)(CapabilitySet,error);ReconnectMin,ReconnectMax time.Duration}
func(r *Runner)Run(ctx context.Context)error{if r==nil||r.Agent==nil||r.Store==nil||r.Connector==nil||r.Capabilities==nil{return ErrInvalid};minimum:=r.ReconnectMin;if minimum<=0{minimum=time.Second};maximum:=r.ReconnectMax;if maximum<minimum{maximum=time.Minute};delay:=minimum;for{if err:=ctx.Err();err!=nil{return err};session,err:=r.Connector.Connect(ctx);if err!=nil{if waitErr:=waitContext(ctx,delay);waitErr!=nil{return waitErr};delay=nextDelay(delay,maximum);continue};delay=minimum;err=r.runSession(ctx,session);session.Close();if err!=nil&&!errors.Is(err,context.Canceled){if waitErr:=waitContext(ctx,delay);waitErr!=nil{return waitErr};delay=nextDelay(delay,maximum);continue};return err}}
func(r *Runner)runSession(ctx context.Context,session Session)error{capabilities,err:=r.Capabilities(ctx);if err!=nil{return err};capabilities.Digest=capabilities.CanonicalDigest();if err=sendPayload(ctx,session,FrameHello,capabilities);err!=nil{return err};incoming:=make(chan Frame,1);failures:=make(chan error,1);go func(){for{frame,receiveErr:=session.Receive(ctx);if receiveErr!=nil{failures<-receiveErr;return};select{case incoming<-frame:case<-ctx.Done():return}}}();flush:=time.NewTicker(time.Second);defer flush.Stop();heartbeat:=time.NewTicker(20*time.Second);defer heartbeat.Stop();for{select{case<-ctx.Done():return ctx.Err();case err:=<-failures:return err;case frame:=<-incoming:if err=r.handleFrame(ctx,session,frame);err!=nil{return err};case<-flush.C:if err=r.flushEvents(ctx,session);err!=nil{return err};case<-heartbeat.C:if err=sendPayload(ctx,session,FrameHeartbeat,map[string]any{"at":time.Now().UTC(),"authorityEpoch":capabilities.AuthorityEpoch});err!=nil{return err}}}}
func(r *Runner)handleFrame(ctx context.Context,session Session,frame Frame)error{switch frame.Type{case FrameIntent:var intent Intent;if err:=json.Unmarshal(frame.Payload,&intent);err!=nil{return err};receipt,acceptErr:=r.Agent.Accept(ctx,intent);if sendErr:=sendPayload(ctx,session,FrameReceipt,receipt);sendErr!=nil{return sendErr};return nilIfExpected(acceptErr);case FrameRevocation:var value Revocation;if err:=json.Unmarshal(frame.Payload,&value);err!=nil{return err};if err:=r.Agent.ApplyRevocation(ctx,value);err!=nil{return err};return sendPayload(ctx,session,FrameRevocationAck,map[string]any{"nodeId":value.NodeID,"authorityEpoch":value.NewAuthorityEpoch,"appliedAt":time.Now().UTC()});case FrameEventAck:var ack struct{Through uint64 `json:"through"`};if err:=json.Unmarshal(frame.Payload,&ack);err!=nil{return err};return r.Store.AckEvents(ctx,ack.Through);case FrameHelloAck,FrameHeartbeat:return nil;default:return fmt.Errorf("%w: unexpected frame %s",ErrInvalid,frame.Type)}}
func(r *Runner)flushEvents(ctx context.Context,session Session)error{events,err:=r.Store.Events(ctx,0,200,1<<20);if err!=nil||len(events)==0{return err};return sendPayload(ctx,session,FrameEventBatch,events)}
func sendPayload(ctx context.Context,session Session,kind FrameType,value any)error{raw,err:=json.Marshal(value);if err!=nil{return err};return session.Send(ctx,Frame{Version:1,Type:kind,Payload:raw})}
func waitContext(ctx context.Context,duration time.Duration)error{timer:=time.NewTimer(duration);defer timer.Stop();select{case<-ctx.Done():return ctx.Err();case<-timer.C:return nil}}
func nextDelay(current,maximum time.Duration)time.Duration{next:=current*2;if next>maximum{return maximum};return next}
func nilIfExpected(err error)error{if errors.Is(err,ErrForbidden)||errors.Is(err,ErrInvalid)||errors.Is(err,ErrStale)||errors.Is(err,ErrExpired)||errors.Is(err,ErrReplay){return nil};return err}
var _=binary.MaxVarintLen64
