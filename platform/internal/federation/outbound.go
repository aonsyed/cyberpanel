package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

type EventSigner interface {
	EventKeyID(context.Context) (string, error)
	SignEvent(context.Context, string, []byte) ([]byte, error)
}

type OutboundRunner struct {
	Runner           *Runner
	PeerID           ID
	EventSigner      EventSigner
	HelloTimeout     time.Duration
	ReceiveTimeout   time.Duration
	eventMutex       sync.Mutex
	sentEventThrough uint64
}

type outboundHelloAcknowledgement struct {
	Accepted          bool   `json:"accepted"`
	NodeID            ID     `json:"nodeId"`
	PeerID            ID     `json:"peerId"`
	ProtocolVersion   uint32 `json:"protocolVersion"`
	CapabilityDigest string `json:"capabilityDigest"`
	AuthorityEpoch    uint64 `json:"authorityEpoch"`
	RevocationPending bool   `json:"revocationPending"`
}

func NewOutboundRunner(runner *Runner, peerID ID, signer EventSigner) (*OutboundRunner, error) {
	if runner == nil || runner.Agent == nil || runner.Store == nil || runner.Agent.store != runner.Store || runner.Connector == nil || runner.Capabilities == nil || !peerID.Valid() || signer == nil {
		return nil, ErrInvalid
	}
	return &OutboundRunner{Runner: runner, PeerID: peerID, EventSigner: signer}, nil
}

func (runner *OutboundRunner) Run(ctx context.Context) error {
	if runner == nil || ctx == nil || runner.Runner == nil || runner.Runner.Agent == nil || runner.Runner.Store == nil || runner.Runner.Connector == nil || runner.Runner.Capabilities == nil || !runner.PeerID.Valid() || runner.EventSigner == nil {
		return ErrInvalid
	}
	minimum := runner.Runner.ReconnectMin
	if minimum <= 0 {
		minimum = time.Second
	}
	maximum := runner.Runner.ReconnectMax
	if maximum < minimum {
		maximum = time.Minute
	}
	delay := minimum
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		session, err := runner.Runner.Connector.Connect(ctx)
		if err != nil {
			if waitErr := waitContext(ctx, delay); waitErr != nil {
				return waitErr
			}
			delay = nextDelay(delay, maximum)
			continue
		}
		delay = minimum
		err = runner.runSession(ctx, session)
		_ = session.Close()
		if err != nil && !errors.Is(err, context.Canceled) {
			if waitErr := waitContext(ctx, delay); waitErr != nil {
				return waitErr
			}
			delay = nextDelay(delay, maximum)
			continue
		}
		return err
	}
}

func (runner *OutboundRunner) runSession(ctx context.Context, session Session) error {
	capabilities, err := runner.Runner.Capabilities(ctx)
	if err != nil {
		return err
	}
	nodeID, authorityEpoch, activePeer, err := runner.Runner.Store.State(ctx)
	if err != nil {
		return err
	}
	peer, peerErr := runner.Runner.Store.Peer(ctx, runner.PeerID)
	if peerErr != nil || peer.State != "active" || activePeer != runner.PeerID || capabilities.NodeID != nodeID || capabilities.AuthorityEpoch != authorityEpoch || !validOutboundCapabilities(capabilities) {
		return ErrForbidden
	}
	capabilities.Digest = capabilities.CanonicalDigest()
	reconnect, err := runner.negotiate(ctx, session, capabilities)
	if err != nil {
		return err
	}
	if reconnect {
		return ErrStale
	}
	runner.eventMutex.Lock()
	runner.sentEventThrough = 0
	runner.eventMutex.Unlock()
	receipts, err := runner.Runner.Agent.ReconcilePending(ctx, 1000)
	if err != nil {
		return err
	}
	for _, receipt := range receipts {
		if err = runner.deliverReceipt(ctx, session, receipt); err != nil {
			return err
		}
	}
	if err = runner.flushEvents(ctx, session); err != nil {
		return err
	}
	incoming := make(chan Frame, 1)
	failures := make(chan error, 1)
	go func() {
		for {
			timeout := runner.ReceiveTimeout
			if timeout <= 0 || timeout > 5*time.Minute {
				timeout = 45 * time.Second
			}
			receiveContext, cancel := context.WithTimeout(ctx, timeout)
			frame, receiveErr := session.Receive(receiveContext)
			cancel()
			if receiveErr != nil {
				select {
				case failures <- receiveErr:
				case <-ctx.Done():
				}
				return
			}
			select {
			case incoming <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-failures:
			return err
		case frame := <-incoming:
			if err = runner.handleFrame(ctx, session, frame); err != nil {
				return err
			}
		case <-flush.C:
			if err = runner.flushEvents(ctx, session); err != nil {
				return err
			}
		case <-heartbeat.C:
			value := map[string]any{"at": time.Now().UTC(), "nodeId": capabilities.NodeID, "peerId": runner.PeerID, "authorityEpoch": capabilities.AuthorityEpoch, "capabilityDigest": capabilities.Digest}
			if err = sendPayload(ctx, session, FrameHeartbeat, value); err != nil {
				return err
			}
		}
	}
}

func (runner *OutboundRunner) negotiate(ctx context.Context, session Session, capabilities CapabilitySet) (bool, error) {
	if err := sendPayload(ctx, session, FrameHello, capabilities); err != nil {
		return false, err
	}
	timeout := runner.HelloTimeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = 15 * time.Second
	}
	helloContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	frame, err := session.Receive(helloContext)
	if err != nil {
		return false, err
	}
	if frame.Type != FrameHelloAck {
		return false, ErrForbidden
	}
	var acknowledgement outboundHelloAcknowledgement
	if err = decodeOutboundPayload(frame.Payload, &acknowledgement); err != nil {
		return false, err
	}
	if !acknowledgement.Accepted || acknowledgement.NodeID != capabilities.NodeID || acknowledgement.PeerID != runner.PeerID || acknowledgement.ProtocolVersion != capabilities.ProtocolVersion || acknowledgement.CapabilityDigest != capabilities.Digest || acknowledgement.AuthorityEpoch == 0 {
		return false, ErrForbidden
	}
	if !acknowledgement.RevocationPending {
		if acknowledgement.AuthorityEpoch != capabilities.AuthorityEpoch {
			return false, ErrStale
		}
		return false, nil
	}
	if acknowledgement.AuthorityEpoch <= capabilities.AuthorityEpoch {
		return false, ErrStale
	}
	frame, err = session.Receive(helloContext)
	if err != nil {
		return false, err
	}
	if frame.Type != FrameRevocation {
		return false, ErrForbidden
	}
	var revocation Revocation
	if err = decodeOutboundPayload(frame.Payload, &revocation); err != nil || revocation.NewAuthorityEpoch != acknowledgement.AuthorityEpoch {
		return false, ErrForbidden
	}
	if err = runner.Runner.Agent.ApplyRevocation(ctx, revocation); err != nil {
		return false, err
	}
	if err = sendPayload(ctx, session, FrameRevocationAck, map[string]any{"nodeId": revocation.NodeID, "authorityEpoch": revocation.NewAuthorityEpoch, "appliedAt": time.Now().UTC()}); err != nil {
		return false, err
	}
	return true, nil
}

func (runner *OutboundRunner) handleFrame(ctx context.Context, session Session, frame Frame) error {
	switch frame.Type {
	case FrameIntent:
		var intent Intent
		if err := decodeOutboundPayload(frame.Payload, &intent); err != nil {
			return err
		}
		receipt, acceptErr := runner.Runner.Agent.Accept(ctx, intent)
		if sendErr := runner.deliverReceipt(ctx, session, receipt); sendErr != nil {
			return sendErr
		}
		return nilIfExpected(acceptErr)
	case FrameRevocation:
		var revocation Revocation
		if err := decodeOutboundPayload(frame.Payload, &revocation); err != nil {
			return err
		}
		if err := runner.Runner.Agent.ApplyRevocation(ctx, revocation); err != nil {
			return err
		}
		if err := sendPayload(ctx, session, FrameRevocationAck, map[string]any{"nodeId": revocation.NodeID, "authorityEpoch": revocation.NewAuthorityEpoch, "appliedAt": time.Now().UTC()}); err != nil {
			return err
		}
		return ErrStale
	case FrameEventAck:
		var acknowledgement struct {
			Through uint64 `json:"through"`
		}
		if err := decodeOutboundPayload(frame.Payload, &acknowledgement); err != nil {
			return err
		}
		runner.eventMutex.Lock()
		maximum := runner.sentEventThrough
		runner.eventMutex.Unlock()
		if acknowledgement.Through == 0 || acknowledgement.Through > maximum {
			return ErrForbidden
		}
		return runner.Runner.Store.AckEvents(ctx, acknowledgement.Through)
	case FrameHeartbeat:
		return nil
	default:
		return fmt.Errorf("%w: unexpected frame %s", ErrInvalid, frame.Type)
	}
}

func (runner *OutboundRunner) deliverReceipt(ctx context.Context, session Session, receipt Receipt) error {
	if !receipt.IntentID.Valid() || !receipt.NodeID.Valid() || receipt.EffectID == "" || receipt.IdempotencyKey == "" || receipt.Status == "" || receipt.UpdatedAt.IsZero() || receipt.SignatureKeyID == "" || len(receipt.Signature) == 0 {
		return ErrInvalid
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte("cyberpanel-federation-receipt-event-v1\x00"), raw...))
	eventID, err := NewID("receipt_" + hex.EncodeToString(sum[:24]))
	if err != nil {
		return err
	}
	event := NodeEvent{ID: eventID, NodeID: receipt.NodeID, Priority: PriorityReceipt, Kind: "federation.receipt.v1", ResourceID: receipt.IntentID.String(), ResourceKind: "federated_intent", Generation: receipt.LocalGeneration, Payload: raw, PayloadDigest: digest(raw), OccurredAt: receipt.UpdatedAt.UTC()}
	if err = runner.Runner.Store.EnqueueEvent(ctx, event); err != nil {
		return err
	}
	return sendPayload(ctx, session, FrameReceipt, receipt)
}

func (runner *OutboundRunner) flushEvents(ctx context.Context, session Session) error {
	events, err := runner.Runner.Store.ContiguousEvents(ctx, 200, 3<<20)
	if err != nil || len(events) == 0 {
		return err
	}
	for index := range events {
		if !events[index].ID.Valid() || !events[index].NodeID.Valid() || events[index].Sequence == 0 || events[index].PayloadDigest != digest(events[index].Payload) || events[index].OccurredAt.IsZero() {
			return ErrInvalid
		}
		keyID, keyErr := runner.EventSigner.EventKeyID(ctx)
		if keyErr != nil || keyID == "" {
			return outboundError(keyErr, ErrForbidden)
		}
		events[index].SignatureKeyID = keyID
		signature, signErr := runner.EventSigner.SignEvent(ctx, keyID, events[index].SigStructure())
		if signErr != nil || len(signature) == 0 {
			return outboundError(signErr, ErrForbidden)
		}
		events[index].Signature = signature
	}
	if err = sendPayload(ctx, session, FrameEventBatch, events); err != nil {
		return err
	}
	runner.eventMutex.Lock()
	runner.sentEventThrough = events[len(events)-1].Sequence
	runner.eventMutex.Unlock()
	return nil
}

func decodeOutboundPayload(raw []byte, target any) error {
	if len(raw) == 0 || target == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func validOutboundCapabilities(capabilities CapabilitySet) bool {
	if !capabilities.NodeID.Valid() || capabilities.ProtocolVersion == 0 || capabilities.AuthorityEpoch == 0 || capabilities.GeneratedAt.IsZero() || len(capabilities.Capabilities) > 4096 {
		return false
	}
	seen := map[string]struct{}{}
	for _, capability := range capabilities.Capabilities {
		if capability.CommandType == "" || capability.Version == 0 || !validSHA256Value(capability.SchemaHash) {
			return false
		}
		if _, found := seen[capability.CommandType]; found {
			return false
		}
		seen[capability.CommandType] = struct{}{}
	}
	return true
}

func outboundError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}
