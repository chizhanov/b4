package nfq

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestRecordServerTTL(t *testing.T) {
	tracker := &connStateTracker{conns: make(map[string]*connInfo)}
	set := &config.SetConfig{}
	tracker.RegisterOutgoing("10.0.0.1:12345->1.2.3.4:443", set)

	tracker.RecordServerTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52)

	info := tracker.conns["10.0.0.1:12345->1.2.3.4:443"]
	if !info.ttlRecorded || info.serverTTL != 52 {
		t.Fatalf("expected TTL=52 recorded, got TTL=%d recorded=%v", info.serverTTL, info.ttlRecorded)
	}

	tracker.RecordServerTTL("10.0.0.1", 12345, "1.2.3.4", 443, 99)
	if info.serverTTL != 52 {
		t.Fatalf("TTL should not change after first recording, got %d", info.serverTTL)
	}
}

func TestRecordServerTTL_NoConnection(t *testing.T) {
	tracker := &connStateTracker{conns: make(map[string]*connInfo)}
	tracker.RecordServerTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52)
}

func TestCheckRSTTTL_NoConnection(t *testing.T) {
	tracker := &connStateTracker{conns: make(map[string]*connInfo)}
	if tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52, 3) {
		t.Fatal("should not drop RST for unknown connection")
	}
}

func TestCheckRSTTTL_NoTTLRecorded(t *testing.T) {
	tracker := &connStateTracker{conns: make(map[string]*connInfo)}
	set := &config.SetConfig{}
	tracker.RegisterOutgoing("10.0.0.1:12345->1.2.3.4:443", set)

	if !tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52, 3) {
		t.Fatal("should drop RST when no SYN-ACK TTL recorded yet")
	}
}

func TestCheckRSTTTL_MatchingTTL(t *testing.T) {
	tracker := &connStateTracker{conns: make(map[string]*connInfo)}
	set := &config.SetConfig{}
	tracker.RegisterOutgoing("10.0.0.1:12345->1.2.3.4:443", set)
	tracker.RecordServerTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52)

	if tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52, 3) {
		t.Fatal("should NOT drop RST with matching TTL")
	}
	if tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 50, 3) {
		t.Fatal("should NOT drop RST within tolerance (delta=2, tolerance=3)")
	}
	if tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 55, 3) {
		t.Fatal("should NOT drop RST within tolerance (delta=3, tolerance=3)")
	}
}

func TestCheckRSTTTL_InjectedRST(t *testing.T) {
	tracker := &connStateTracker{conns: make(map[string]*connInfo)}
	set := &config.SetConfig{}
	tracker.RegisterOutgoing("10.0.0.1:12345->1.2.3.4:443", set)
	tracker.RecordServerTTL("10.0.0.1", 12345, "1.2.3.4", 443, 52)

	if !tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 60, 3) {
		t.Fatal("should drop RST with TTL delta=8 (tolerance=3)")
	}
	if !tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 44, 3) {
		t.Fatal("should drop RST with TTL delta=8 (tolerance=3)")
	}
	if !tracker.CheckRSTTTL("10.0.0.1", 12345, "1.2.3.4", 443, 56, 3) {
		t.Fatal("should drop RST with TTL delta=4 (tolerance=3)")
	}
}
