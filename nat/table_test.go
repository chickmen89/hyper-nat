package nat

import (
	"net"
	"testing"
	"time"
)

func TestConnTrackTableCreate(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	entry, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if entry.Protocol != ProtocolTCP {
		t.Errorf("Protocol = %d, want %d", entry.Protocol, ProtocolTCP)
	}
	if !entry.InternalIP.Equal(intIP) {
		t.Errorf("InternalIP = %v, want %v", entry.InternalIP, intIP)
	}
	if entry.InternalPort != 54321 {
		t.Errorf("InternalPort = %d, want %d", entry.InternalPort, 54321)
	}
	if !entry.ExternalIP.Equal(extIP) {
		t.Errorf("ExternalIP = %v, want %v", entry.ExternalIP, extIP)
	}
	if entry.ExternalPort != 443 {
		t.Errorf("ExternalPort = %d, want %d", entry.ExternalPort, 443)
	}
	if entry.NATPort < 40000 || entry.NATPort > 60000 {
		t.Errorf("NATPort = %d, want between 40000 and 60000", entry.NATPort)
	}
	if entry.State != StateNew {
		t.Errorf("State = %v, want %v", entry.State, StateNew)
	}
}

func TestConnTrackTableLookup(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	created, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Forward lookup
	found := table.Lookup(ProtocolTCP, intIP, 54321, extIP, 443)
	if found == nil {
		t.Fatal("Lookup returned nil, expected entry")
	}
	if found.NATPort != created.NATPort {
		t.Errorf("Lookup returned wrong entry: NAT port = %d, want %d", found.NATPort, created.NATPort)
	}

	// Lookup non-existent entry
	notFound := table.Lookup(ProtocolTCP, intIP, 65535, extIP, 443)
	if notFound != nil {
		t.Error("Lookup should return nil for non-existent entry")
	}
}

func TestConnTrackTableLookupReverse(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	created, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Reverse lookup
	found := table.LookupReverse(ProtocolTCP, created.NATPort, extIP, 443)
	if found == nil {
		t.Fatal("LookupReverse returned nil, expected entry")
	}
	if found.InternalPort != 54321 {
		t.Errorf("LookupReverse returned wrong entry: internal port = %d, want %d", found.InternalPort, 54321)
	}

	// Lookup with wrong NAT port
	notFound := table.LookupReverse(ProtocolTCP, 65535, extIP, 443)
	if notFound != nil {
		t.Error("LookupReverse should return nil for non-existent entry")
	}
}

func TestConnTrackTableDelete(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	entry, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if table.Count() != 1 {
		t.Errorf("Count = %d, want 1", table.Count())
	}

	table.Delete(entry)

	if table.Count() != 0 {
		t.Errorf("Count after delete = %d, want 0", table.Count())
	}

	// Verify lookups return nil
	if table.Lookup(ProtocolTCP, intIP, 54321, extIP, 443) != nil {
		t.Error("Forward lookup should return nil after delete")
	}
	if table.LookupReverse(ProtocolTCP, entry.NATPort, extIP, 443) != nil {
		t.Error("Reverse lookup should return nil after delete")
	}
}

func TestConnTrackTableUpdateState(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	entry, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	oldLastSeen := entry.LastSeen

	// Small delay to ensure timestamp changes
	time.Sleep(10 * time.Millisecond)

	table.UpdateState(entry, StateEstablished)

	if entry.State != StateEstablished {
		t.Errorf("State = %v, want %v", entry.State, StateEstablished)
	}
	if !entry.LastSeen.After(oldLastSeen) {
		t.Error("LastSeen should be updated after UpdateState")
	}
}

func TestConnTrackTableDuplicateCreate(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	entry1, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("First Create failed: %v", err)
	}

	entry2, err := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	if err != nil {
		t.Fatalf("Second Create failed: %v", err)
	}

	// Should return the same entry
	if entry1.NATPort != entry2.NATPort {
		t.Errorf("Duplicate create returned different entry: %d vs %d", entry1.NATPort, entry2.NATPort)
	}

	// Count should be 1
	if table.Count() != 1 {
		t.Errorf("Count = %d, want 1", table.Count())
	}
}

func TestConnTrackTableMultipleEntries(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP1 := net.ParseIP("8.8.8.8").To4()
	extIP2 := net.ParseIP("1.1.1.1").To4()

	entry1, _ := table.Create(ProtocolTCP, intIP, 54321, extIP1, 443)
	entry2, _ := table.Create(ProtocolTCP, intIP, 54322, extIP1, 80)
	entry3, _ := table.Create(ProtocolUDP, intIP, 54323, extIP2, 53)

	if table.Count() != 3 {
		t.Errorf("Count = %d, want 3", table.Count())
	}

	// Each should have unique NAT port
	if entry1.NATPort == entry2.NATPort || entry2.NATPort == entry3.NATPort || entry1.NATPort == entry3.NATPort {
		t.Error("Entries should have unique NAT ports")
	}
}

func TestConnTrackTableCleanupExpired(t *testing.T) {
	table := NewConnTrackTable()

	intIP := net.ParseIP("172.23.240.10").To4()
	extIP := net.ParseIP("8.8.8.8").To4()

	// Create TCP entry in CLOSED state
	tcpEntry, _ := table.Create(ProtocolTCP, intIP, 54321, extIP, 443)
	table.UpdateState(tcpEntry, StateClosed)

	// Create UDP entry
	udpEntry, _ := table.Create(ProtocolUDP, intIP, 54322, extIP, 53)

	// Create TCP entry in ESTABLISHED state (should not be cleaned)
	establishedEntry, _ := table.Create(ProtocolTCP, intIP, 54323, extIP, 80)
	table.UpdateState(establishedEntry, StateEstablished)

	if table.Count() != 3 {
		t.Fatalf("Count = %d, want 3", table.Count())
	}

	// Simulate time passing by manually setting LastSeen
	table.mu.Lock()
	tcpEntry.LastSeen = time.Now().Add(-2 * time.Minute)
	udpEntry.LastSeen = time.Now().Add(-2 * time.Minute)
	table.mu.Unlock()

	// Cleanup with 1 minute timeout
	cleaned := table.CleanupExpired(1*time.Minute, 1*time.Minute, 1*time.Minute)

	// TCP CLOSED and UDP should be cleaned (2 entries)
	if cleaned != 2 {
		t.Errorf("Cleaned = %d, want 2", cleaned)
	}

	// Only ESTABLISHED entry should remain
	if table.Count() != 1 {
		t.Errorf("Count after cleanup = %d, want 1", table.Count())
	}

	// Verify ESTABLISHED entry still exists
	if table.Lookup(ProtocolTCP, intIP, 54323, extIP, 80) == nil {
		t.Error("ESTABLISHED entry should not be cleaned")
	}
}

func TestConnStateString(t *testing.T) {
	tests := []struct {
		state    ConnState
		expected string
	}{
		{StateNew, "NEW"},
		{StateSynSent, "SYN_SENT"},
		{StateEstablished, "ESTABLISHED"},
		{StateClosed, "CLOSED"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("ConnState(%d).String() = %q, want %q", tt.state, got, tt.expected)
		}
	}
}

func TestConnTrackEntryString(t *testing.T) {
	entry := &ConnTrackEntry{
		Protocol:     ProtocolTCP,
		InternalIP:   net.ParseIP("172.23.240.10").To4(),
		InternalPort: 54321,
		NATPort:      40001,
		ExternalIP:   net.ParseIP("8.8.8.8").To4(),
		ExternalPort: 443,
		State:        StateEstablished,
	}

	s := entry.String()
	if s == "" {
		t.Error("String() should not return empty string")
	}
	// Just verify it doesn't panic and contains key info
	if !contains(s, "TCP") || !contains(s, "172.23.240.10") || !contains(s, "ESTABLISHED") {
		t.Errorf("String() = %q, missing expected content", s)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
