package nat

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/igjeong/hyper-nat/config"
	"github.com/igjeong/hyper-nat/packet"
	"github.com/igjeong/hyper-nat/windivert"
)

// Engine is the main NAT processing engine.
type Engine struct {
	cfg            *config.Config
	table          *ConnTrackTable
	dnatTable      *DNATTable // DNAT (port forwarding) table
	matcher        *RuleMatcher
	outboundHandle *windivert.Handle // LayerNetworkForward for outbound TCP/UDP (VM -> Internet)
	inboundHandle  *windivert.Handle // LayerNetwork for inbound (Internet -> NAT IP)
	icmpHandle     *windivert.Handle // LayerNetworkForward for outbound ICMP (VM -> Internet)
	logger         *log.Logger
	verbose        bool
	allNATIPs      []net.IP // All NAT IPs (default + per-rule) for inbound filtering

	// Statistics
	packetsProcessed uint64
	packetsNATted    uint64
	packetsBypassed  uint64
	packetsDropped   uint64
	errorsRecovered  uint64

	// Cleanup configuration
	tcpTimeout            time.Duration
	udpTimeout            time.Duration
	icmpTimeout           time.Duration
	tcpEstablishedTimeout time.Duration // Timeout for established TCP connections

	// Error recovery configuration
	maxRetries     int
	retryBaseDelay time.Duration
	maxRetryDelay  time.Duration
}

// EngineOption is a functional option for Engine configuration.
type EngineOption func(*Engine)

// WithLogger sets a custom logger.
func WithLogger(logger *log.Logger) EngineOption {
	return func(e *Engine) {
		e.logger = logger
	}
}

// WithTCPTimeout sets the TCP connection timeout.
func WithTCPTimeout(d time.Duration) EngineOption {
	return func(e *Engine) {
		e.tcpTimeout = d
	}
}

// WithUDPTimeout sets the UDP connection timeout.
func WithUDPTimeout(d time.Duration) EngineOption {
	return func(e *Engine) {
		e.udpTimeout = d
	}
}

// WithICMPTimeout sets the ICMP connection timeout.
func WithICMPTimeout(d time.Duration) EngineOption {
	return func(e *Engine) {
		e.icmpTimeout = d
	}
}

// WithTCPEstablishedTimeout sets the timeout for established TCP connections.
// This prevents memory leaks from long-lived connections that never close properly.
func WithTCPEstablishedTimeout(d time.Duration) EngineOption {
	return func(e *Engine) {
		e.tcpEstablishedTimeout = d
	}
}

// WithVerbose enables verbose logging.
func WithVerbose(verbose bool) EngineOption {
	return func(e *Engine) {
		e.verbose = verbose
	}
}

// WithMaxRetries sets the maximum number of retries for error recovery.
func WithMaxRetries(n int) EngineOption {
	return func(e *Engine) {
		e.maxRetries = n
	}
}

// WithRetryDelay sets the base delay for exponential backoff.
func WithRetryDelay(base, max time.Duration) EngineOption {
	return func(e *Engine) {
		e.retryBaseDelay = base
		e.maxRetryDelay = max
	}
}

// NewEngine creates a new NAT engine.
func NewEngine(cfg *config.Config, opts ...EngineOption) *Engine {
	dnat := NewDNATTable()
	dnat.LoadRules(cfg.PortForwards)

	e := &Engine{
		cfg:                   cfg,
		table:                 NewConnTrackTable(),
		dnatTable:             dnat,
		matcher:               NewRuleMatcher(cfg),
		tcpTimeout:            5 * time.Minute,
		udpTimeout:            30 * time.Second,
		icmpTimeout:           30 * time.Second,
		tcpEstablishedTimeout: 2 * time.Hour, // Long-lived connections timeout after 2 hours of inactivity
		maxRetries:            5,
		retryBaseDelay:        100 * time.Millisecond,
		maxRetryDelay:         5 * time.Second,
	}

	// Collect all NAT IPs (default + per-rule)
	e.allNATIPs = []net.IP{cfg.NATIP}
	for _, rule := range cfg.Rules {
		if rule.NATIP != nil {
			found := false
			for _, ip := range e.allNATIPs {
				if ip.Equal(rule.NATIP) {
					found = true
					break
				}
			}
			if !found {
				e.allNATIPs = append(e.allNATIPs, rule.NATIP)
			}
		}
	}

	for _, opt := range opts {
		opt(e)
	}

	if e.logger == nil {
		e.logger = log.Default()
	}

	return e
}

// Start begins packet capture and NAT processing.
func (e *Engine) Start(ctx context.Context) error {
	// Build filters for outbound, inbound, and ICMP
	outboundFilter, inboundFilter, icmpOutboundFilter := e.cfg.BuildTripleFilters()
	e.logger.Printf("[INFO] [ENGINE] Starting with triple-layer capture")
	e.logger.Printf("[INFO] [ENGINE] Outbound filter (Forward, TCP/UDP): %s", outboundFilter)
	e.logger.Printf("[INFO] [ENGINE] Inbound filter (Network): %s", inboundFilter)
	e.logger.Printf("[INFO] [ENGINE] ICMP outbound filter (Network): %s", icmpOutboundFilter)

	// Open outbound handle (LayerNetworkForward) - captures VM -> Internet TCP/UDP traffic
	// Priority 0 (higher priority)
	outboundHandle, err := windivert.Open(outboundFilter, windivert.LayerNetworkForward, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to open outbound WinDivert handle: %w", err)
	}
	e.outboundHandle = outboundHandle
	e.logger.Printf("[INFO] [ENGINE] Outbound handle opened (LayerNetworkForward)")

	// Open inbound handle (LayerNetwork) - captures Internet -> NAT IP traffic
	// Priority 1 (lower priority than outbound)
	inboundHandle, err := windivert.Open(inboundFilter, windivert.LayerNetwork, 1, 0)
	if err != nil {
		e.outboundHandle.Close()
		return fmt.Errorf("failed to open inbound WinDivert handle: %w", err)
	}
	e.inboundHandle = inboundHandle
	e.logger.Printf("[INFO] [ENGINE] Inbound handle opened (LayerNetwork)")

	// Open ICMP handle (LayerNetworkForward) - captures VM -> Internet ICMP traffic
	// Priority 2 (lower priority)
	// Must use LayerNetworkForward because VM traffic is forwarded, not local to host
	icmpHandle, err := windivert.Open(icmpOutboundFilter, windivert.LayerNetworkForward, 2, 0)
	if err != nil {
		e.outboundHandle.Close()
		e.inboundHandle.Close()
		return fmt.Errorf("failed to open ICMP WinDivert handle: %w", err)
	}
	e.icmpHandle = icmpHandle
	e.logger.Printf("[INFO] [ENGINE] ICMP handle opened (LayerNetworkForward)")

	e.logger.Printf("[INFO] [ENGINE] Default NAT IP: %s, Internal Network: %s", e.cfg.NATIP, e.cfg.InternalNetwork)
	if len(e.allNATIPs) > 1 {
		for i, ip := range e.allNATIPs {
			e.logger.Printf("[INFO] [ENGINE]   NAT IP %d: %s", i+1, ip)
		}
	}

	// Log port forwarding rules
	if len(e.cfg.PortForwards) > 0 {
		e.logger.Printf("[INFO] [ENGINE] Port forwarding rules:")
		for _, pf := range e.cfg.PortForwards {
			e.logger.Printf("[INFO] [ENGINE]   %s: %s/%d -> %s:%d",
				pf.Name, pf.Protocol, pf.ExternalPort, pf.InternalIP, pf.InternalPort)
		}
	}

	// Start cleanup goroutine
	go e.cleanupLoop(ctx)

	// Start inbound processing goroutine
	go e.processInboundLoop(ctx)

	// Start ICMP processing goroutine
	go e.processICMPLoop(ctx)

	// Main outbound packet processing loop
	return e.processOutboundLoop(ctx)
}

// Stop closes the WinDivert handles and stops processing.
func (e *Engine) Stop() {
	if e.outboundHandle != nil {
		e.outboundHandle.Close()
		e.outboundHandle = nil
	}
	if e.inboundHandle != nil {
		e.inboundHandle.Close()
		e.inboundHandle = nil
	}
	if e.icmpHandle != nil {
		e.icmpHandle.Close()
		e.icmpHandle = nil
	}
	e.logger.Printf("[INFO] [ENGINE] Stopped")
}

// Stats returns engine statistics.
func (e *Engine) Stats() (processed, natted, bypassed, dropped uint64) {
	return atomic.LoadUint64(&e.packetsProcessed),
		atomic.LoadUint64(&e.packetsNATted),
		atomic.LoadUint64(&e.packetsBypassed),
		atomic.LoadUint64(&e.packetsDropped)
}

// ErrorsRecovered returns the number of errors that were recovered via retry.
func (e *Engine) ErrorsRecovered() uint64 {
	return atomic.LoadUint64(&e.errorsRecovered)
}

// calculateBackoff calculates exponential backoff delay.
func (e *Engine) calculateBackoff(attempt int) time.Duration {
	delay := e.retryBaseDelay * time.Duration(1<<uint(attempt-1))
	if delay > e.maxRetryDelay {
		delay = e.maxRetryDelay
	}
	return delay
}

// processOutboundLoop handles outbound packets (VM -> Internet) on LayerNetworkForward
func (e *Engine) processOutboundLoop(ctx context.Context) error {
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if handle was closed
		if e.outboundHandle == nil {
			return nil
		}

		// Read packet from outbound handle
		pkt, err := e.outboundHandle.Recv()
		if err != nil {
			// Handle closed or context cancelled - exit gracefully
			if e.outboundHandle == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Error recovery with exponential backoff
			consecutiveErrors++
			if consecutiveErrors > e.maxRetries {
				e.logger.Printf("[ERROR] [ENGINE] Outbound recv error after %d retries: %v", e.maxRetries, err)
				return err
			}

			atomic.AddUint64(&e.errorsRecovered, 1)
			delay := e.calculateBackoff(consecutiveErrors)
			e.logger.Printf("[WARN] [ENGINE] Outbound recv error (attempt %d/%d), retrying in %v: %v",
				consecutiveErrors, e.maxRetries, delay, err)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				continue
			}
		}

		// Reset error counter on success
		consecutiveErrors = 0
		atomic.AddUint64(&e.packetsProcessed, 1)

		// Process outbound packet
		if err := e.processOutboundPacket(pkt); err != nil {
			if e.verbose {
				e.logger.Printf("[DEBUG] [ENGINE] Outbound process error: %v", err)
			}
			atomic.AddUint64(&e.packetsDropped, 1)
			continue
		}
	}
}

// processInboundLoop handles inbound packets (Internet -> NAT IP) on LayerNetwork
func (e *Engine) processInboundLoop(ctx context.Context) {
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check if handle was closed
		if e.inboundHandle == nil {
			return
		}

		// Read packet from inbound handle
		pkt, err := e.inboundHandle.Recv()
		if err != nil {
			// Handle closed or context cancelled - exit gracefully
			if e.inboundHandle == nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Error recovery with exponential backoff
			consecutiveErrors++
			if consecutiveErrors > e.maxRetries {
				e.logger.Printf("[ERROR] [ENGINE] Inbound recv error after %d retries: %v", e.maxRetries, err)
				return
			}

			atomic.AddUint64(&e.errorsRecovered, 1)
			delay := e.calculateBackoff(consecutiveErrors)
			e.logger.Printf("[WARN] [ENGINE] Inbound recv error (attempt %d/%d), retrying in %v: %v",
				consecutiveErrors, e.maxRetries, delay, err)

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				continue
			}
		}

		// Reset error counter on success
		consecutiveErrors = 0
		atomic.AddUint64(&e.packetsProcessed, 1)

		// Process inbound packet
		if err := e.processInboundPacket(pkt); err != nil {
			if e.verbose {
				e.logger.Printf("[DEBUG] [ENGINE] Inbound process error: %v", err)
			}
			atomic.AddUint64(&e.packetsDropped, 1)
			continue
		}
	}
}

// processOutboundPacket handles packets captured on LayerNetworkForward (VM -> Internet)
// Note: This only handles TCP and UDP. ICMP is handled by processICMPLoop on LayerNetwork.
func (e *Engine) processOutboundPacket(divertPkt *windivert.Packet) error {
	// Parse packet
	pkt, err := packet.ParseIPv4(divertPkt.Data)
	if err != nil {
		// Can't parse, just forward as-is
		return e.sendOutbound(divertPkt)
	}

	// Only process TCP and UDP (ICMP is handled by separate ICMP handle)
	if pkt.IPv4.Protocol != packet.ProtocolTCP &&
		pkt.IPv4.Protocol != packet.ProtocolUDP {
		return e.sendOutbound(divertPkt)
	}

	// Check if from internal network
	if !e.cfg.InternalNetwork.Contains(pkt.IPv4.SrcIP) {
		return e.sendOutbound(divertPkt)
	}

	return e.processOutbound(pkt, divertPkt)
}

// processICMPLoop handles outbound ICMP packets (VM -> Internet) on LayerNetworkForward
func (e *Engine) processICMPLoop(ctx context.Context) {
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check if handle was closed
		if e.icmpHandle == nil {
			return
		}

		// Read packet from ICMP handle
		pkt, err := e.icmpHandle.Recv()
		if err != nil {
			// Handle closed or context cancelled - exit gracefully
			if e.icmpHandle == nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Error recovery with exponential backoff
			consecutiveErrors++
			if consecutiveErrors > e.maxRetries {
				e.logger.Printf("[ERROR] [ENGINE] ICMP recv error after %d retries: %v", e.maxRetries, err)
				return
			}

			atomic.AddUint64(&e.errorsRecovered, 1)
			delay := e.calculateBackoff(consecutiveErrors)
			e.logger.Printf("[WARN] [ENGINE] ICMP recv error (attempt %d/%d), retrying in %v: %v",
				consecutiveErrors, e.maxRetries, delay, err)

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				continue
			}
		}

		// Reset error counter on success
		consecutiveErrors = 0
		atomic.AddUint64(&e.packetsProcessed, 1)

		// Process ICMP packet (same as outbound)
		if err := e.processICMPPacket(pkt); err != nil {
			if e.verbose {
				e.logger.Printf("[DEBUG] [ENGINE] ICMP process error: %v", err)
			}
			atomic.AddUint64(&e.packetsDropped, 1)
			continue
		}
	}
}

// processICMPPacket handles ICMP packets captured on LayerNetworkForward
func (e *Engine) processICMPPacket(divertPkt *windivert.Packet) error {
	// Parse packet
	pkt, err := packet.ParseIPv4(divertPkt.Data)
	if err != nil {
		// Can't parse, just forward as-is
		return e.sendICMP(divertPkt)
	}

	// Should only be ICMP but double-check
	if pkt.IPv4.Protocol != packet.ProtocolICMP || pkt.ICMP == nil {
		return e.sendICMP(divertPkt)
	}

	// Only process Echo Request (ping)
	if !pkt.ICMP.IsEchoRequest() {
		return e.sendICMP(divertPkt)
	}

	// Check if from internal network
	if !e.cfg.InternalNetwork.Contains(pkt.IPv4.SrcIP) {
		return e.sendICMP(divertPkt)
	}

	// Process ICMP outbound (similar to processOutbound but uses sendICMP)
	return e.processICMPOutbound(pkt, divertPkt)
}

// processICMPOutbound handles outbound ICMP packets (uses icmpHandle for sending)
func (e *Engine) processICMPOutbound(pkt *packet.ParsedPacket, divertPkt *windivert.Packet) error {
	destIP := pkt.IPv4.DstIP

	// Check rules
	result := e.matcher.Match(destIP)

	if result.Action == config.ActionBypass {
		// Bypass - forward without modification
		// Note: Bypass destinations are excluded from ICMP filter,
		// so this code path should not be reached. But keep it for safety.
		if e.verbose {
			e.logger.Printf("[DEBUG] [BYPASS] %s %s → %s (ID:%d, rule: %s)",
				protoName(pkt.IPv4.Protocol),
				pkt.IPv4.SrcIP,
				destIP,
				pkt.ICMP.Identifier,
				result.RuleName)
		}
		atomic.AddUint64(&e.packetsBypassed, 1)
		return e.sendOutbound(divertPkt)
	}

	// NAT - apply source NAT with rule-specific NAT IP
	return e.applyICMPNAT(pkt, divertPkt, result.NATIP)
}

// applyICMPNAT applies NAT to ICMP packets (uses icmpHandle for sending)
func (e *Engine) applyICMPNAT(pkt *packet.ParsedPacket, divertPkt *windivert.Packet, natIP net.IP) error {
	proto := pkt.IPv4.Protocol
	srcIP := pkt.IPv4.SrcIP
	dstIP := pkt.IPv4.DstIP
	srcPort := pkt.ICMP.Identifier // Original ICMP ID
	dstPort := uint16(0)           // ICMP has no destination port

	// Lookup or create entry
	entry := e.table.Lookup(proto, srcIP, srcPort, dstIP, dstPort)
	if entry == nil {
		var err error
		entry, err = e.table.Create(proto, srcIP, srcPort, dstIP, dstPort)
		if err != nil {
			return fmt.Errorf("failed to create NAT entry: %w", err)
		}
		e.logger.Printf("[INFO] [NAT] New %s %s → %s (ID:%d mapped to ID:%d, NAT IP: %s)",
			protoName(proto), srcIP, dstIP, srcPort, entry.NATPort, natIP)
	}

	// Touch entry
	e.table.Touch(entry)

	// Apply NAT with rule-specific NAT IP
	pkt.ApplyNAT(natIP, entry.NATPort)

	// Recalculate checksums
	pkt.ClearChecksums()
	windivert.CalcChecksums(pkt.Raw, &divertPkt.Address, 0)

	atomic.AddUint64(&e.packetsNATted, 1)

	if e.verbose {
		e.logger.Printf("[DEBUG] [NAT] Outbound %s %s → %s (ID:%d → NAT ID:%d, NAT IP: %s)",
			protoName(proto), srcIP, dstIP, srcPort, entry.NATPort, natIP)
	}

	divertPkt.Data = pkt.Raw

	// If using a non-default NAT IP (e.g., TailScale IP), inject via LayerNetwork
	// so the packet goes through Windows routing stack properly
	if !natIP.Equal(e.cfg.NATIP) {
		divertPkt.Address.Outbound = 1
		return e.sendInbound(divertPkt)
	}

	return e.sendICMP(divertPkt)
}

func (e *Engine) sendICMP(pkt *windivert.Packet) error {
	_, err := e.icmpHandle.Send(pkt)
	if err != nil && e.verbose {
		e.logger.Printf("[ERROR] [SEND] Failed to send ICMP packet: %v", err)
	}
	return err
}

// processInboundPacket handles packets captured on LayerNetwork (Internet -> NAT IP)
func (e *Engine) processInboundPacket(divertPkt *windivert.Packet) error {
	// Parse packet
	pkt, err := packet.ParseIPv4(divertPkt.Data)
	if err != nil {
		// Can't parse, just forward as-is
		return e.sendInbound(divertPkt)
	}

	// Only process TCP, UDP, and ICMP
	if pkt.IPv4.Protocol != packet.ProtocolTCP &&
		pkt.IPv4.Protocol != packet.ProtocolUDP &&
		pkt.IPv4.Protocol != packet.ProtocolICMP {
		return e.sendInbound(divertPkt)
	}

	// For ICMP, only process Echo Reply (ping response)
	if pkt.ICMP != nil && !pkt.ICMP.IsEchoReply() {
		return e.sendInbound(divertPkt)
	}

	// Check if destined for any of our NAT IPs (default + per-rule)
	isNATIP := false
	for _, natIP := range e.allNATIPs {
		if pkt.IPv4.DstIP.Equal(natIP) {
			isNATIP = true
			break
		}
	}
	if !isNATIP {
		return e.sendInbound(divertPkt)
	}

	return e.processInbound(pkt, divertPkt)
}

func (e *Engine) processOutbound(pkt *packet.ParsedPacket, divertPkt *windivert.Packet) error {
	destIP := pkt.IPv4.DstIP
	proto := pkt.IPv4.Protocol
	srcIP := pkt.IPv4.SrcIP

	// 1. Check if this is a response for an active DNAT session
	if pkt.ICMP == nil {
		srcPort := pkt.SrcPort()
		dstPort := pkt.DstPort()
		session := e.dnatTable.LookupSession(proto, srcIP, srcPort, destIP, dstPort)
		if session != nil {
			e.dnatTable.TouchSession(session)

			// Apply Source NAT to translate internal server back to external NAT port
			pkt.ApplyNAT(e.cfg.NATIP, session.NATPort)

			if e.verbose {
				e.logger.Printf("[DEBUG] [DNAT] Outbound %s %s:%d → %s:%d (mapped back to :%d)",
					protoName(proto), srcIP, srcPort, destIP, dstPort, session.NATPort)
			}

			// Recalculate checksums
			pkt.ClearChecksums()
			windivert.CalcChecksums(pkt.Raw, &divertPkt.Address, 0)

			divertPkt.Data = pkt.Raw
			return e.sendOutbound(divertPkt)
		}
	}

	// 2. Original SNAT logic
	// Check rules
	result := e.matcher.Match(destIP)

	if result.Action == config.ActionBypass {
		// Bypass - forward without modification
		if e.verbose {
			if pkt.ICMP != nil {
				e.logger.Printf("[DEBUG] [BYPASS] %s %s → %s (ID:%d, rule: %s)",
					protoName(pkt.IPv4.Protocol),
					pkt.IPv4.SrcIP,
					destIP,
					pkt.ICMP.Identifier,
					result.RuleName)
			} else {
				e.logger.Printf("[DEBUG] [BYPASS] %s %s:%d → %s:%d (rule: %s)",
					protoName(pkt.IPv4.Protocol),
					pkt.IPv4.SrcIP, pkt.SrcPort(),
					destIP, pkt.DstPort(),
					result.RuleName)
			}
		}
		atomic.AddUint64(&e.packetsBypassed, 1)
		return e.sendOutbound(divertPkt)
	}

	// NAT - apply source NAT with rule-specific NAT IP
	return e.applyNAT(pkt, divertPkt, result.NATIP)
}

func (e *Engine) applyNAT(pkt *packet.ParsedPacket, divertPkt *windivert.Packet, natIP net.IP) error {
	proto := pkt.IPv4.Protocol
	srcIP := pkt.IPv4.SrcIP
	dstIP := pkt.IPv4.DstIP

	// For ICMP, use Identifier instead of port
	var srcPort, dstPort uint16
	if pkt.ICMP != nil {
		srcPort = pkt.ICMP.Identifier // Original ICMP ID
		dstPort = 0                   // ICMP has no destination port
	} else {
		srcPort = pkt.SrcPort()
		dstPort = pkt.DstPort()
	}

	// Lookup or create entry
	entry := e.table.Lookup(proto, srcIP, srcPort, dstIP, dstPort)
	if entry == nil {
		var err error
		entry, err = e.table.Create(proto, srcIP, srcPort, dstIP, dstPort)
		if err != nil {
			return fmt.Errorf("failed to create NAT entry: %w", err)
		}
		if pkt.ICMP != nil {
			e.logger.Printf("[INFO] [NAT] New %s %s → %s (ID:%d mapped to ID:%d, NAT IP: %s)",
				protoName(proto), srcIP, dstIP, srcPort, entry.NATPort, natIP)
		} else {
			e.logger.Printf("[INFO] [NAT] New %s %s:%d → %s:%d (mapped to :%d, NAT IP: %s)",
				protoName(proto), srcIP, srcPort, dstIP, dstPort, entry.NATPort, natIP)
		}
	}

	// Update TCP state if applicable
	if pkt.TCP != nil {
		e.updateTCPState(entry, pkt.TCP, true)
	}

	// Touch entry
	e.table.Touch(entry)

	// Apply NAT with rule-specific NAT IP
	pkt.ApplyNAT(natIP, entry.NATPort)

	// Recalculate checksums
	pkt.ClearChecksums()
	windivert.CalcChecksums(pkt.Raw, &divertPkt.Address, 0)

	atomic.AddUint64(&e.packetsNATted, 1)

	if e.verbose {
		if pkt.ICMP != nil {
			e.logger.Printf("[DEBUG] [NAT] Outbound %s %s → %s (ID:%d → NAT ID:%d, NAT IP: %s)",
				protoName(proto), srcIP, dstIP, srcPort, entry.NATPort, natIP)
		} else {
			e.logger.Printf("[DEBUG] [NAT] Outbound %s %s:%d → %s:%d (NAT port: %d, NAT IP: %s)",
				protoName(proto), srcIP, srcPort, dstIP, dstPort, entry.NATPort, natIP)
		}
	}

	divertPkt.Data = pkt.Raw

	// If using a non-default NAT IP (e.g., TailScale IP), inject via LayerNetwork
	// so the packet goes through Windows routing stack properly
	if !natIP.Equal(e.cfg.NATIP) {
		// Set as outbound local packet for proper routing
		divertPkt.Address.Outbound = 1
		return e.sendInbound(divertPkt)
	}

	return e.sendOutbound(divertPkt)
}

func (e *Engine) processInbound(pkt *packet.ParsedPacket, divertPkt *windivert.Packet) error {
	proto := pkt.IPv4.Protocol
	srcIP := pkt.IPv4.SrcIP

	// For ICMP, use Identifier for lookup; for TCP/UDP use ports
	var natID, srcPort uint16
	if pkt.ICMP != nil {
		natID = pkt.ICMP.Identifier // NAT ID in the reply
		srcPort = 0                 // ICMP has no source port
	} else {
		natID = pkt.DstPort()  // NAT port
		srcPort = pkt.SrcPort() // External source port
	}

	// 1. Check SNAT table (Reverse lookup)
	entry := e.table.LookupReverse(proto, natID, srcIP, srcPort)
	if entry != nil {
		// Update TCP state if applicable
		if pkt.TCP != nil {
			e.updateTCPState(entry, pkt.TCP, false)
		}

		// Touch entry
		e.table.Touch(entry)

		// Reverse NAT - change destination from NAT IP to internal VM IP
		pkt.ReverseNAT(entry.InternalIP, entry.InternalPort)

		if e.verbose {
			if pkt.ICMP != nil {
				e.logger.Printf("[DEBUG] [NAT] Reverse %s %s → %s (NAT ID:%d → ID:%d)",
					protoName(proto), srcIP, pkt.IPv4.DstIP,
					natID, entry.InternalPort)
			} else {
				e.logger.Printf("[DEBUG] [NAT] Reverse %s %s:%d → %s:%d (entry: %s:%d, NAT port: %d)",
					protoName(proto), srcIP, srcPort, pkt.IPv4.DstIP, pkt.DstPort(),
					entry.InternalIP, entry.InternalPort, entry.NATPort)
			}
		}
	} else {
		// 2. Check DNAT table (Port Forwarding)
		// Currently only TCP/UDP DNAT is supported
		if pkt.ICMP == nil {
			// Check for existing DNAT session
			session := e.dnatTable.LookupSessionInbound(proto, natID, srcIP, srcPort)
			if session == nil {
				// No existing session, check rules
				rule := e.dnatTable.LookupRuleByProto(proto, natID)
				if rule != nil {
					// Found a rule! Create session
					session = e.dnatTable.CreateSession(proto, srcIP, srcPort, rule.InternalIP, rule.InternalPort, natID)
					e.logger.Printf("[INFO] [DNAT] New %s connection %s:%d → %s:%d (forwarded to %s:%d)",
						protoName(proto), srcIP, srcPort, pkt.IPv4.DstIP, natID,
						rule.InternalIP, rule.InternalPort)
				}
			}

			if session != nil {
				e.dnatTable.TouchSession(session)

				// Apply DNAT - change destination to internal VM
				pkt.ReverseNAT(session.InternalIP, session.InternalPort)

				if e.verbose {
					e.logger.Printf("[DEBUG] [DNAT] Inbound %s %s:%d → %s:%d (to %s:%d)",
						protoName(proto), srcIP, srcPort, pkt.IPv4.DstIP, natID,
						session.InternalIP, session.InternalPort)
				}
			} else {
				// No entry and no rule - this is traffic to NAT IP that wasn't NAT'd by us
				return e.sendInbound(divertPkt)
			}
		} else {
			return e.sendInbound(divertPkt)
		}
	}

	// Recalculate checksums
	pkt.ClearChecksums()
	windivert.CalcChecksums(pkt.Raw, &divertPkt.Address, 0)

	divertPkt.Data = pkt.Raw

	// After translation, the packet's destination is now the internal VM IP.
	// We need to re-inject this packet so it gets routed to the VM.
	// Set Outbound flag to indicate this packet should be sent out (to VM).
	divertPkt.Address.Outbound = 1

	// Send via inbound handle (LayerNetwork) with Outbound=1 to route to VM
	return e.sendInbound(divertPkt)
}

func (e *Engine) sendOutbound(pkt *windivert.Packet) error {
	_, err := e.outboundHandle.Send(pkt)
	if err != nil && e.verbose {
		e.logger.Printf("[ERROR] [SEND] Failed to send outbound packet: %v", err)
	}
	return err
}

func (e *Engine) sendInbound(pkt *windivert.Packet) error {
	_, err := e.inboundHandle.Send(pkt)
	if err != nil && e.verbose {
		e.logger.Printf("[ERROR] [SEND] Failed to send inbound packet: %v", err)
	}
	return err
}

func (e *Engine) updateTCPState(entry *ConnTrackEntry, tcp *packet.TCPHeader, isOutbound bool) {
	// Simplified TCP state machine
	currentState := entry.State
	var newState ConnState

	if tcp.IsRST() {
		newState = StateClosed
	} else if isOutbound {
		switch currentState {
		case StateNew:
			if tcp.IsSYN() {
				newState = StateSynSent
			}
		case StateSynReceived:
			if tcp.HasFlag(packet.TCPFlagACK) {
				newState = StateEstablished
			}
		case StateEstablished:
			if tcp.IsFIN() {
				newState = StateFinWait1
			}
		case StateCloseWait:
			if tcp.IsFIN() {
				newState = StateLastAck
			}
		default:
			return // No state change
		}
	} else { // Inbound
		switch currentState {
		case StateSynSent:
			if tcp.IsSYNACK() {
				newState = StateSynReceived
			}
		case StateEstablished:
			if tcp.IsFIN() {
				newState = StateCloseWait
			}
		case StateFinWait1:
			if tcp.HasFlag(packet.TCPFlagACK) {
				newState = StateFinWait2
			}
		case StateFinWait2:
			if tcp.IsFIN() {
				newState = StateTimeWait
			}
		case StateLastAck:
			if tcp.HasFlag(packet.TCPFlagACK) {
				newState = StateClosed
			}
		default:
			return // No state change
		}
	}

	if newState != currentState && newState != 0 {
		e.table.UpdateState(entry, newState)
		e.logger.Printf("[DEBUG] [TABLE] TCP state: %s → %s", currentState, newState)
	}
}

func (e *Engine) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if e.verbose {
				e.logger.Printf("[DEBUG] [ENGINE] Running cleanup check...")
			}
			cleaned := e.table.CleanupExpiredWithEstablished(
				e.tcpTimeout,
				e.udpTimeout,
				e.icmpTimeout,
				e.tcpEstablishedTimeout,
			)
			dnatCleaned := e.dnatTable.CleanupExpiredSessions(e.tcpTimeout, e.udpTimeout)
			if cleaned > 0 || dnatCleaned > 0 {
				e.logger.Printf("[INFO] [TABLE] Cleaned %d expired entries (%d DNAT), %d SNAT remaining, %d DNAT remaining",
					cleaned+dnatCleaned, dnatCleaned, e.table.Count(), e.dnatTable.SessionCount())
			} else if e.verbose {
				e.logger.Printf("[DEBUG] [TABLE] Cleanup finished, nothing to clean (%d active)", e.table.Count())
			}
		}
	}
}

func protoName(proto uint8) string {
	switch proto {
	case packet.ProtocolTCP:
		return "TCP"
	case packet.ProtocolUDP:
		return "UDP"
	case packet.ProtocolICMP:
		return "ICMP"
	default:
		return fmt.Sprintf("Proto%d", proto)
	}
}

// TableStats returns connection table statistics.
func (e *Engine) TableStats() (active, total uint64) {
	return e.table.Stats()
}

// DumpTable prints all active connections for debugging.
func (e *Engine) DumpTable() {
	e.logger.Printf("[INFO] [TABLE] Active connections:")
	e.table.ForEach(func(entry *ConnTrackEntry) {
		e.logger.Printf("  %s", entry.String())
	})
}

// ConnectionInfo represents a single NAT connection for IPC.
type ConnectionInfo struct {
	Protocol     string
	InternalIP   string
	InternalPort uint16
	ExternalIP   string
	ExternalPort uint16
	NATPort      uint16
	State        string
	IdleSeconds  int64
}

// UpdateRules updates the NAT rules without restarting the engine.
// Only rules can be hot-reloaded; NAT IP and internal network changes require restart.
func (e *Engine) UpdateRules(cfg *config.Config) error {
	// Check if NAT IP or internal network changed (these require restart)
	if !e.cfg.NATIP.Equal(cfg.NATIP) {
		return fmt.Errorf("NAT IP changed from %s to %s; restart required", e.cfg.NATIP, cfg.NATIP)
	}
	if e.cfg.InternalNetwork.String() != cfg.InternalNetwork.String() {
		return fmt.Errorf("internal network changed from %s to %s; restart required", 
			e.cfg.InternalNetwork, cfg.InternalNetwork)
	}

	// Update rules (thread-safe via RuleMatcher)
	newMatcher := NewRuleMatcher(cfg)

	// Collect all NAT IPs (default + per-rule)
	newNATIPs := []net.IP{cfg.NATIP}
	for _, rule := range cfg.Rules {
		if rule.NATIP != nil {
			found := false
			for _, ip := range newNATIPs {
				if ip.Equal(rule.NATIP) {
					found = true
					break
				}
			}
			if !found {
				newNATIPs = append(newNATIPs, rule.NATIP)
			}
		}
	}

	// Atomic swap
	e.matcher = newMatcher
	e.allNATIPs = newNATIPs
	e.cfg = cfg

	// Update DNAT rules
	e.dnatTable.LoadRules(cfg.PortForwards)

	e.logger.Printf("[INFO] [ENGINE] Rules hot-reloaded successfully")
	for i, rule := range cfg.Rules {
		e.logger.Printf("[INFO] [ENGINE]   %d. %s: %s -> %s", i+1, rule.Name, rule.Destination, rule.Action)
	}
	
	return nil
}

// GetConnections returns all active connections for status display.
func (e *Engine) GetConnections() []ConnectionInfo {
	var conns []ConnectionInfo
	now := time.Now()

	e.table.ForEach(func(entry *ConnTrackEntry) {
		conns = append(conns, ConnectionInfo{
			Protocol:     protoName(entry.Protocol),
			InternalIP:   entry.InternalIP.String(),
			InternalPort: entry.InternalPort,
			ExternalIP:   entry.ExternalIP.String(),
			ExternalPort: entry.ExternalPort,
			NATPort:      entry.NATPort,
			State:        entry.State.String(),
			IdleSeconds:  int64(now.Sub(entry.LastSeen).Seconds()),
		})
	})

	return conns
}

// PortForwardInfo represents a port forwarding rule for status display.
type PortForwardInfo struct {
	Name         string
	Protocol     string
	ExternalPort uint16
	InternalIP   string
	InternalPort uint16
}

// GetPortForwardRules returns all port forwarding rules.
func (e *Engine) GetPortForwardRules() []PortForwardInfo {
	rules := e.dnatTable.GetRules()
	result := make([]PortForwardInfo, 0, len(rules))

	for _, rule := range rules {
		result = append(result, PortForwardInfo{
			Name:         rule.Name,
			Protocol:     rule.Protocol,
			ExternalPort: rule.ExternalPort,
			InternalIP:   rule.InternalIP.String(),
			InternalPort: rule.InternalPort,
		})
	}

	return result
}

// DNATSessionInfo represents an active DNAT session for status display.
type DNATSessionInfo struct {
	Protocol     string
	ExternalIP   string
	ExternalPort uint16
	InternalIP   string
	InternalPort uint16
	NATPort      uint16
	IdleSeconds  int64
}

// GetDNATSessions returns all active DNAT sessions.
func (e *Engine) GetDNATSessions() []DNATSessionInfo {
	var sessions []DNATSessionInfo
	now := time.Now()

	e.dnatTable.ForEachSession(func(session *DNATSession) {
		sessions = append(sessions, DNATSessionInfo{
			Protocol:     protoName(session.Protocol),
			ExternalIP:   session.ExternalIP.String(),
			ExternalPort: session.ExternalPort,
			InternalIP:   session.InternalIP.String(),
			InternalPort: session.InternalPort,
			NATPort:      session.NATPort,
			IdleSeconds:  int64(now.Sub(session.LastSeen).Seconds()),
		})
	})

	return sessions
}

// DNATSessionCount returns the number of active DNAT sessions.
func (e *Engine) DNATSessionCount() int {
	return e.dnatTable.SessionCount()
}
