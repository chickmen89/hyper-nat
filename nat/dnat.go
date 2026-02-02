// Package nat provides DNAT (port forwarding) functionality.
package nat

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/igjeong/hyper-nat/config"
)

// DNATEntry represents a port forwarding rule.
type DNATEntry struct {
	Name         string
	Protocol     string // "tcp" or "udp"
	ExternalPort uint16 // Port on NAT IP
	InternalIP   net.IP // Internal VM IP
	InternalPort uint16 // Internal VM port
}

// DNATSession tracks an active DNAT connection for reverse NAT.
type DNATSession struct {
	Protocol     uint8
	ExternalIP   net.IP // External client IP
	ExternalPort uint16 // External client port
	InternalIP   net.IP // Internal VM IP
	InternalPort uint16 // Internal VM port
	NATPort      uint16 // Port on NAT IP (external_port from rule)
	LastSeen     time.Time
}

// DNATTable manages port forwarding rules and sessions.
type DNATTable struct {
	// rules maps (protocol, external_port) -> DNATEntry
	rules map[string]*DNATEntry

	// sessions maps (protocol, internal_ip, internal_port, external_ip, external_port) -> DNATSession
	// Used for reverse NAT (response from VM to external client)
	sessions map[string]*DNATSession

	mu sync.RWMutex
}

// NewDNATTable creates a new DNAT table.
func NewDNATTable() *DNATTable {
	return &DNATTable{
		rules:    make(map[string]*DNATEntry),
		sessions: make(map[string]*DNATSession),
	}
}

// ruleKey generates the key for rule lookup.
func ruleKey(protocol string, port uint16) string {
	return fmt.Sprintf("%s:%d", protocol, port)
}

// sessionKey generates the key for session lookup.
func sessionKey(proto uint8, intIP net.IP, intPort uint16, extIP net.IP, extPort uint16) string {
	return fmt.Sprintf("%d:%s:%d:%s:%d", proto, intIP.String(), intPort, extIP.String(), extPort)
}

// reverseSessionKey generates the key for reverse session lookup (from external client perspective).
func reverseSessionKey(proto uint8, natPort uint16, extIP net.IP, extPort uint16) string {
	return fmt.Sprintf("rev:%d:%d:%s:%d", proto, natPort, extIP.String(), extPort)
}

// LoadRules loads port forwarding rules from configuration.
func (t *DNATTable) LoadRules(forwards []config.PortForward) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Clear existing rules
	t.rules = make(map[string]*DNATEntry)

	for _, pf := range forwards {
		// Make a copy of the internal IP
		internalIPCopy := make(net.IP, len(pf.InternalIP))
		copy(internalIPCopy, pf.InternalIP)

		entry := &DNATEntry{
			Name:         pf.Name,
			Protocol:     pf.Protocol,
			ExternalPort: pf.ExternalPort,
			InternalIP:   internalIPCopy,
			InternalPort: pf.InternalPort,
		}

		key := ruleKey(pf.Protocol, pf.ExternalPort)
		t.rules[key] = entry
	}
}

// LookupRule finds a DNAT rule by protocol and external port.
func (t *DNATTable) LookupRule(protocol string, externalPort uint16) *DNATEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := ruleKey(protocol, externalPort)
	return t.rules[key]
}

// LookupRuleByProto finds a DNAT rule using protocol number.
func (t *DNATTable) LookupRuleByProto(proto uint8, externalPort uint16) *DNATEntry {
	var protocol string
	switch proto {
	case ProtocolTCP:
		protocol = "tcp"
	case ProtocolUDP:
		protocol = "udp"
	default:
		return nil
	}
	return t.LookupRule(protocol, externalPort)
}

// CreateSession creates or updates a DNAT session.
func (t *DNATTable) CreateSession(proto uint8, extIP net.IP, extPort uint16, intIP net.IP, intPort uint16, natPort uint16) *DNATSession {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Make copies of IP addresses
	extIPCopy := make(net.IP, len(extIP))
	copy(extIPCopy, extIP)
	intIPCopy := make(net.IP, len(intIP))
	copy(intIPCopy, intIP)

	session := &DNATSession{
		Protocol:     proto,
		ExternalIP:   extIPCopy,
		ExternalPort: extPort,
		InternalIP:   intIPCopy,
		InternalPort: intPort,
		NATPort:      natPort,
		LastSeen:     time.Now(),
	}

	// Store by forward key (for reverse lookup from VM response)
	fwdKey := sessionKey(proto, intIPCopy, intPort, extIPCopy, extPort)
	t.sessions[fwdKey] = session

	// Also store by reverse key (for inbound packet matching)
	revKey := reverseSessionKey(proto, natPort, extIPCopy, extPort)
	t.sessions[revKey] = session

	return session
}

// LookupSession finds a DNAT session for reverse NAT (VM -> external client).
func (t *DNATTable) LookupSession(proto uint8, intIP net.IP, intPort uint16, extIP net.IP, extPort uint16) *DNATSession {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := sessionKey(proto, intIP, intPort, extIP, extPort)
	return t.sessions[key]
}

// LookupSessionInbound finds a DNAT session for inbound traffic (external client -> NAT IP).
func (t *DNATTable) LookupSessionInbound(proto uint8, natPort uint16, extIP net.IP, extPort uint16) *DNATSession {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := reverseSessionKey(proto, natPort, extIP, extPort)
	return t.sessions[key]
}

// TouchSession updates the LastSeen timestamp.
func (t *DNATTable) TouchSession(session *DNATSession) {
	t.mu.Lock()
	defer t.mu.Unlock()

	session.LastSeen = time.Now()
}

// CleanupExpiredSessions removes sessions older than the given duration.
func (t *DNATTable) CleanupExpiredSessions(tcpTimeout, udpTimeout time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	toDelete := make([]string, 0)

	for key, session := range t.sessions {
		var timeout time.Duration
		switch session.Protocol {
		case ProtocolTCP:
			timeout = tcpTimeout
		default:
			timeout = udpTimeout
		}

		if now.Sub(session.LastSeen) > timeout {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		delete(t.sessions, key)
	}

	return len(toDelete) / 2 // Each session has 2 keys
}

// RuleCount returns the number of port forwarding rules.
func (t *DNATTable) RuleCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.rules)
}

// SessionCount returns the number of active DNAT sessions.
func (t *DNATTable) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Divide by 2 because each session has 2 keys
	return len(t.sessions) / 2
}

// GetRules returns all port forwarding rules.
func (t *DNATTable) GetRules() []*DNATEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rules := make([]*DNATEntry, 0, len(t.rules))
	for _, rule := range t.rules {
		rules = append(rules, rule)
	}
	return rules
}
