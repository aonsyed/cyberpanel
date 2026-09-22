//go:build linux

package dns

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestPowerDNSNonZoneWireReplies(t *testing.T) {
	for _, reply := range []powerDNSWireReply{
		{ProtocolError: "invalid_request"},
		{Response: PowerDNSBrokerResponse{Version: 1, RequestID: "wire_request_20260922_fixture", Operation: PowerDNSBrokerConfirmZoneAbsent, Outcome: PowerDNSBrokerConfirmed, ObservedAt: time.Now().UTC()}},
		{Response: PowerDNSBrokerResponse{Version: 1, RequestID: "wire_request_20260922_fixture", Operation: PowerDNSBrokerObserveZone, Outcome: PowerDNSBrokerRejected, FailureCode: "not_found", ObservedAt: time.Now().UTC()}},
	} {
		var frame bytes.Buffer
		if err := writePowerDNSBrokerFrame(&frame, reply); err != nil {
			t.Fatalf("non-zone reply must serialize: %v", err)
		}
		var decoded powerDNSWireReply
		if err := readPowerDNSBrokerFrame(&frame, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ProtocolError != reply.ProtocolError || decoded.Response.FailureCode != reply.Response.FailureCode {
			t.Fatal("wire outcome changed")
		}
	}
	var frame bytes.Buffer
	if err := writePowerDNSBrokerFrame(&frame, powerDNSWireReply{Response: PowerDNSBrokerResponse{ZoneSpec: ZoneSpec{ID: "invalid_zone"}}}); err == nil {
		t.Fatal("nonzero invalid DNS name accepted")
	}
}

func TestQEMUPowerDNSAbsentZoneWire(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_DNS_WIRE") != "1" {
		t.Skip("read-only installed PowerDNS broker probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	name, _ := ParseName("qemu-dns-20260922.invalid")
	client := &PowerDNSDaemonClient{Transport: PowerDNSFramedTransport{Dialer: PowerDNSUnixDialer{}}}
	if err := client.ConfirmZoneAbsent(ctx, "qemu_absent_20260922", name); err != nil {
		t.Fatal("installed create preflight", err)
	}
}
