// Package nat provides NAT engine functionality including connection tracking.
package nat

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Protocol constants
const (
	ProtocolICMP uint8 = 1
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
)

// ConnState represents TCP connection state
type ConnState int

const (
	StateNew ConnState = iota
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateCloseWait
	StateLastAck
	StateTimeWait
	StateClosed
)

func (s ConnState) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECEIVED"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait1:
		return "FIN_WAIT_1"
	case StateFinWait2:
		return "FIN_WAIT_2"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateLastAck:
		return "LAST_ACK"
	case StateTimeWait:
		return "TIME_WAIT"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// ConnTrackEntry represents a single NAT connection tracking entry.
type ConnTrackEntry struct {
	Protocol     uint8
	InternalIP   net.IP
	InternalPort uint16
	NATPort      uint16    // Port exposed to external network
	ExternalIP   net.IP    // Destination IP
	ExternalPort uint16    // Destination port
	LastSeen     time.Time // For timeout management
	State        ConnState // TCP state tracking
}

// String returns a human-readable representation of the entry.
func (e *ConnTrackEntry) String() string {
	var proto string
	switch e.Protocol {
	case ProtocolTCP:
		proto = "TCP"
	case ProtocolUDP:
		proto = "UDP"
	case ProtocolICMP:
		proto = "ICMP"
	default:
		proto = fmt.Sprintf("Proto%d", e.Protocol)
	}

	if e.Protocol == ProtocolICMP {
		return fmt.Sprintf("%s %s (ID:%d) -> %s (NAT ID: %d, state: %s)",
			proto,
			e.InternalIP, e.InternalPort, // InternalPort = original ICMP ID
			e.ExternalIP,
			e.NATPort, e.State)
	}
	return fmt.Sprintf("%s %s:%d -> %s:%d (NAT port: %d, state: %s)",
		proto,
		e.InternalIP, e.InternalPort,
		e.ExternalIP, e.ExternalPort,
		e.NATPort, e.State)
}

// ConnTrackTable manages connection tracking for NAT.
type ConnTrackTable struct {
	// forward maps (proto, intIP, intPort, extIP, extPort) -> entry
	// Used for outbound packet lookup
	forward map[string]*ConnTrackEntry

	// reverse maps (proto, natPort, extIP, extPort) -> entry
	// Used for inbound packet lookup
	reverse map[string]*ConnTrackEntry

	mu sync.RWMutex

	// NAT port allocation
	nextPort uint16
	minPort  uint16
	maxPort  uint16

	// Statistics
	totalEntries   uint64
	totalAllocated uint64
}

// NewConnTrackTable creates a new connection tracking table.
func NewConnTrackTable() *ConnTrackTable {
	return &ConnTrackTable{
		forward:  make(map[string]*ConnTrackEntry),
		reverse:  make(map[string]*ConnTrackEntry),
		nextPort: 40000, // Start NAT ports from 40000
		minPort:  40000,
		maxPort:  60000,
	}
}

// forwardKey generates the key for forward lookup.
// For ICMP, intPort is the ICMP Identifier, extPort is 0.
func forwardKey(proto uint8, intIP net.IP, intPort uint16, extIP net.IP, extPort uint16) string {
	if proto == ProtocolICMP {
		// ICMP uses internal IP, ICMP ID, and external IP (no port)
		return fmt.Sprintf("%d:%s:%d:%s", proto, intIP.String(), intPort, extIP.String())
	}
	return fmt.Sprintf("%d:%s:%d:%s:%d", proto, intIP.String(), intPort, extIP.String(), extPort)
}

// reverseKey generates the key for reverse lookup.
// For ICMP, extPort is not used (set to 0).
func reverseKey(proto uint8, natPort uint16, extIP net.IP, extPort uint16) string {
	if proto == ProtocolICMP {
		// ICMP uses only NAT ID and external IP (no port)
		return fmt.Sprintf("%d:%d:%s", proto, natPort, extIP.String())
	}
	return fmt.Sprintf("%d:%d:%s:%d", proto, natPort, extIP.String(), extPort)
}

// Lookup finds an existing entry for outbound traffic.
func (t *ConnTrackTable) Lookup(proto uint8, intIP net.IP, intPort uint16, extIP net.IP, extPort uint16) *ConnTrackEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := forwardKey(proto, intIP, intPort, extIP, extPort)
	return t.forward[key]
}

// LookupReverse finds an entry for inbound traffic (reverse NAT).
func (t *ConnTrackTable) LookupReverse(proto uint8, natPort uint16, extIP net.IP, extPort uint16) *ConnTrackEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := reverseKey(proto, natPort, extIP, extPort)
	return t.reverse[key]
}

// Create allocates a new NAT port and creates a tracking entry.
func (t *ConnTrackTable) Create(proto uint8, intIP net.IP, intPort uint16, extIP net.IP, extPort uint16) (*ConnTrackEntry, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if entry already exists
	fwdKey := forwardKey(proto, intIP, intPort, extIP, extPort)
	if entry, exists := t.forward[fwdKey]; exists {
		entry.LastSeen = time.Now()
		return entry, nil
	}

	// Allocate a new NAT port
	natPort, err := t.allocatePort()
	if err != nil {
		return nil, err
	}

	// Make copies of IP addresses since net.IP is a slice and the original
	// packet data may be modified after this entry is created
	internalIPCopy := make(net.IP, len(intIP))
	copy(internalIPCopy, intIP)
	externalIPCopy := make(net.IP, len(extIP))
	copy(externalIPCopy, extIP)

	entry := &ConnTrackEntry{
		Protocol:     proto,
		InternalIP:   internalIPCopy,
		InternalPort: intPort,
		NATPort:      natPort,
		ExternalIP:   externalIPCopy,
		ExternalPort: extPort,
		LastSeen:     time.Now(),
		State:        StateNew,
	}

	// Add to both maps
	t.forward[fwdKey] = entry
	revKey := reverseKey(proto, natPort, extIP, extPort)
	t.reverse[revKey] = entry

	t.totalEntries++
	t.totalAllocated++

	return entry, nil
}

// allocatePort finds an available NAT port.
// Must be called with lock held.
func (t *ConnTrackTable) allocatePort() (uint16, error) {
	startPort := t.nextPort
	for {
		port := t.nextPort
		t.nextPort++
		if t.nextPort > t.maxPort {
			t.nextPort = t.minPort
		}

		// Check if port is in use by scanning reverse map
		// This is O(n) but for MVP it's acceptable
		inUse := false
		for _, entry := range t.reverse {
			if entry.NATPort == port {
				inUse = true
				break
			}
		}

		if !inUse {
			return port, nil
		}

		// If we've gone full circle, all ports are in use
		if t.nextPort == startPort {
			return 0, fmt.Errorf("no available NAT ports")
		}
	}
}

// Delete removes an entry from the tracking table.
func (t *ConnTrackTable) Delete(entry *ConnTrackEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	fwdKey := forwardKey(entry.Protocol, entry.InternalIP, entry.InternalPort, entry.ExternalIP, entry.ExternalPort)
	revKey := reverseKey(entry.Protocol, entry.NATPort, entry.ExternalIP, entry.ExternalPort)

	delete(t.forward, fwdKey)
	delete(t.reverse, revKey)

	if t.totalEntries > 0 {
		t.totalEntries--
	}
}

// UpdateState updates the TCP state of an entry.
func (t *ConnTrackTable) UpdateState(entry *ConnTrackEntry, newState ConnState) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry.State = newState
	entry.LastSeen = time.Now()
}

// Touch updates the LastSeen timestamp.
func (t *ConnTrackTable) Touch(entry *ConnTrackEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry.LastSeen = time.Now()
}

// Count returns the number of active entries.
func (t *ConnTrackTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.forward)
}

// Stats returns table statistics.
func (t *ConnTrackTable) Stats() (active, total uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.totalEntries, t.totalAllocated
}

// CleanupExpired removes entries older than the given duration.
// For TCP: only remove CLOSED or TIME_WAIT entries older than timeout
// For UDP/ICMP: remove any entry older than timeout
func (t *ConnTrackTable) CleanupExpired(tcpTimeout, udpTimeout, icmpTimeout time.Duration) int {
	return t.CleanupExpiredWithEstablished(tcpTimeout, udpTimeout, icmpTimeout, 0)
}

// CleanupExpiredWithEstablished removes entries older than the given duration.
// For TCP CLOSED/TIME_WAIT: remove if older than tcpTimeout
// For TCP ESTABLISHED: remove if older than tcpEstablishedTimeout (to prevent memory leaks)
// For TCP half-open states (SYN_SENT, SYN_RECEIVED, FIN_WAIT, etc.): remove after 60 seconds
// For UDP/ICMP: remove if older than respective timeout
func (t *ConnTrackTable) CleanupExpiredWithEstablished(tcpTimeout, udpTimeout, icmpTimeout, tcpEstablishedTimeout time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Short timeout for TCP half-open connections to prevent SYN flood resource exhaustion
	const tcpHalfOpenTimeout = 60 * time.Second

	now := time.Now()
	toDelete := make([]*ConnTrackEntry, 0)

	for _, entry := range t.forward {
		var timeout time.Duration
		switch entry.Protocol {
		case ProtocolTCP:
			switch entry.State {
			case StateClosed, StateTimeWait:
				// Use short timeout for closed/time_wait connections
				timeout = tcpTimeout
			case StateEstablished:
				// Use long timeout for established connections
				if tcpEstablishedTimeout > 0 {
					timeout = tcpEstablishedTimeout
				} else {
					// If no established timeout set, skip established connections
					continue
				}
			default:
				// Half-open states: NEW, SYN_SENT, SYN_RECEIVED, FIN_WAIT1, FIN_WAIT2,
				// CLOSE_WAIT, LAST_ACK - use short timeout to prevent resource exhaustion
				timeout = tcpHalfOpenTimeout
			}
		case ProtocolICMP:
			timeout = icmpTimeout
		default: // UDP and others
			timeout = udpTimeout
		}

		if now.Sub(entry.LastSeen) > timeout {
			toDelete = append(toDelete, entry)
		}
	}

	// Delete expired entries
	for _, entry := range toDelete {
		fwdKey := forwardKey(entry.Protocol, entry.InternalIP, entry.InternalPort, entry.ExternalIP, entry.ExternalPort)
		revKey := reverseKey(entry.Protocol, entry.NATPort, entry.ExternalIP, entry.ExternalPort)
		delete(t.forward, fwdKey)
		delete(t.reverse, revKey)
		if t.totalEntries > 0 {
			t.totalEntries--
		}
	}

	return len(toDelete)
}

// ForEach iterates over all entries with a read lock.
func (t *ConnTrackTable) ForEach(fn func(*ConnTrackEntry)) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, entry := range t.forward {
		fn(entry)
	}
}
