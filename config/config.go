// Package config handles parsing and validation of Hyper-NAT configuration files.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action represents what to do with matched traffic.
type Action string

const (
	ActionBypass Action = "bypass" // Pass through without NAT
	ActionNAT    Action = "nat"    // Apply NAT
)

// Rule defines a routing rule for traffic matching.
type Rule struct {
	Name        string     `yaml:"name"`
	Destination *net.IPNet `yaml:"-"`
	DestStr     string     `yaml:"destination"` // For YAML parsing
	Action      Action     `yaml:"action"`
	NATIP       net.IP     `yaml:"-"`
	NATIPStr    string     `yaml:"nat_ip,omitempty"` // Optional per-rule NAT IP
}

// Config holds the complete configuration for Hyper-NAT.
type Config struct {
	NATIP              net.IP     `yaml:"-"`
	NATIPStr           string     `yaml:"nat_ip"`
	InternalNetwork    *net.IPNet `yaml:"-"`
	InternalNetworkStr string     `yaml:"internal_network"`
	HostInternalIP     net.IP     `yaml:"-"`
	HostInternalIPStr  string     `yaml:"host_internal_ip"`
	Rules              []Rule     `yaml:"rules"`
}

// Load reads and parses a configuration file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return Parse(data)
}

// Parse parses configuration from YAML data.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Parse NAT IP
	cfg.NATIP = net.ParseIP(cfg.NATIPStr)
	if cfg.NATIP == nil {
		return nil, fmt.Errorf("invalid nat_ip: %s", cfg.NATIPStr)
	}
	// Ensure it's IPv4
	if cfg.NATIP.To4() == nil {
		return nil, fmt.Errorf("nat_ip must be IPv4: %s", cfg.NATIPStr)
	}
	cfg.NATIP = cfg.NATIP.To4()

	// Parse internal network
	_, network, err := net.ParseCIDR(cfg.InternalNetworkStr)
	if err != nil {
		return nil, fmt.Errorf("invalid internal_network: %w", err)
	}
	cfg.InternalNetwork = network

	// Parse host internal IP (optional)
	if cfg.HostInternalIPStr != "" {
		cfg.HostInternalIP = net.ParseIP(cfg.HostInternalIPStr)
		if cfg.HostInternalIP == nil {
			return nil, fmt.Errorf("invalid host_internal_ip: %s", cfg.HostInternalIPStr)
		}
		cfg.HostInternalIP = cfg.HostInternalIP.To4()
	}

	// Parse and validate rules
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]

		// Parse destination CIDR
		_, destNet, err := net.ParseCIDR(rule.DestStr)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid destination %q: %w", rule.Name, rule.DestStr, err)
		}
		rule.Destination = destNet

		// Validate action
		if rule.Action != ActionBypass && rule.Action != ActionNAT {
			return nil, fmt.Errorf("rule %q: invalid action %q (must be 'bypass' or 'nat')", rule.Name, rule.Action)
		}

		// Parse per-rule NAT IP (optional)
		if rule.NATIPStr != "" {
			rule.NATIP = net.ParseIP(rule.NATIPStr)
			if rule.NATIP == nil {
				return nil, fmt.Errorf("rule %q: invalid nat_ip %q", rule.Name, rule.NATIPStr)
			}
			if rule.NATIP.To4() == nil {
				return nil, fmt.Errorf("rule %q: nat_ip must be IPv4: %s", rule.Name, rule.NATIPStr)
			}
			rule.NATIP = rule.NATIP.To4()
		}
	}

	return &cfg, nil
}

// Validate performs additional validation on the configuration.
func (c *Config) Validate() error {
	// Check that NAT IP is not within internal network
	if c.InternalNetwork.Contains(c.NATIP) {
		return fmt.Errorf("nat_ip (%s) should not be within internal_network (%s)", c.NATIP, c.InternalNetwork)
	}

	return nil
}

// BuildWinDivertFilter constructs a WinDivert filter string for this configuration.
// The filter captures:
// 1. Outbound packets from internal network (excluding host's internal IP)
// 2. Inbound packets to NAT IP on NAT port range (40000-60000) for reverse NAT
//
// By excluding the host's internal IP, we avoid capturing host's own traffic.
// By limiting inbound capture to the NAT port range, we avoid capturing host's own
// internet traffic which uses different port ranges.
func (c *Config) BuildWinDivertFilter() string {
	// Get the IP range for internal network
	startIP := c.InternalNetwork.IP.To4()
	mask := c.InternalNetwork.Mask

	// Calculate end IP
	endIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		endIP[i] = startIP[i] | ^mask[i]
	}

	// Build outbound filter - exclude host internal IP if configured
	var outboundFilter string
	if c.HostInternalIP != nil {
		// Capture internal network traffic EXCEPT from host's internal IP
		outboundFilter = fmt.Sprintf(
			"(ip.SrcAddr >= %s and ip.SrcAddr <= %s and ip.SrcAddr != %s)",
			startIP.String(),
			endIP.String(),
			c.HostInternalIP.String(),
		)
	} else {
		outboundFilter = fmt.Sprintf(
			"(ip.SrcAddr >= %s and ip.SrcAddr <= %s)",
			startIP.String(),
			endIP.String(),
		)
	}

	// WinDivert doesn't support CIDR notation, use IP range
	// Filter logic:
	// 1. Outbound: Source is from internal network (VM traffic going out), excluding host
	// 2. Inbound: Destination is NAT IP AND destination port is in NAT range (40000-60000)
	//    AND it's TCP or UDP (we only NAT these protocols)
	//
	// NAT port range: 40000-60000 (matches nat/table.go)
	filter := fmt.Sprintf(
		"%s or (ip.DstAddr == %s and tcp.DstPort >= 40000 and tcp.DstPort <= 60000) or (ip.DstAddr == %s and udp.DstPort >= 40000 and udp.DstPort <= 60000)",
		outboundFilter,
		c.NATIP.String(),
		c.NATIP.String(),
	)

	return filter
}

// BuildTripleFilters constructs three WinDivert filter strings:
// - Outbound filter (LayerNetworkForward): Captures TCP/UDP/ICMP VM traffic being forwarded
// - Inbound filter (LayerNetwork): Captures TCP/UDP/ICMP responses coming to NAT IP
// - ICMP outbound filter (LayerNetworkForward): Same as outbound but ICMP only (for separate handle)
//
// All VM traffic must be captured on LayerNetworkForward because LayerNetwork
// only captures host's own traffic, not forwarded VM traffic.
func (c *Config) BuildTripleFilters() (outboundFilter, inboundFilter, icmpOutboundFilter string) {
	// Get the IP range for internal network
	startIP := c.InternalNetwork.IP.To4()
	mask := c.InternalNetwork.Mask

	// Calculate end IP
	endIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		endIP[i] = startIP[i] | ^mask[i]
	}

	// Outbound filter for LayerNetworkForward (TCP/UDP only)
	// Captures packets from internal network (excluding host's internal IP)
	if c.HostInternalIP != nil {
		outboundFilter = fmt.Sprintf(
			"ip.SrcAddr >= %s and ip.SrcAddr <= %s and ip.SrcAddr != %s and (tcp or udp)",
			startIP.String(),
			endIP.String(),
			c.HostInternalIP.String(),
		)
	} else {
		outboundFilter = fmt.Sprintf(
			"ip.SrcAddr >= %s and ip.SrcAddr <= %s and (tcp or udp)",
			startIP.String(),
			endIP.String(),
		)
	}

	// Collect all NAT IPs (default + per-rule)
	natIPs := []net.IP{c.NATIP}
	for _, rule := range c.Rules {
		if rule.NATIP != nil {
			// Check for duplicates
			found := false
			for _, ip := range natIPs {
				if ip.Equal(rule.NATIP) {
					found = true
					break
				}
			}
			if !found {
				natIPs = append(natIPs, rule.NATIP)
			}
		}
	}

	// Inbound filter for LayerNetwork
	// Captures packets destined for any NAT IP:
	// - TCP/UDP on NAT port range (40000-60000)
	// - ICMP Echo Reply (type 0) for ping responses
	// Must also be inbound (!outbound) to avoid capturing outgoing packets
	var inboundParts []string
	for _, ip := range natIPs {
		inboundParts = append(inboundParts, fmt.Sprintf(
			"(ip.DstAddr == %s and ((tcp.DstPort >= 40000 and tcp.DstPort <= 60000) or (udp.DstPort >= 40000 and udp.DstPort <= 60000) or (icmp.Type == 0)))",
			ip.String(),
		))
	}
	inboundFilter = "!outbound and (" + strings.Join(inboundParts, " or ") + ")"

	// ICMP outbound filter for LayerNetworkForward
	// Captures ICMP Echo Request (type 8) from internal network
	// Must use LayerNetworkForward because VM traffic is forwarded, not local
	// Excludes NAT IP (host itself) to avoid re-injection loop
	if c.HostInternalIP != nil {
		icmpOutboundFilter = fmt.Sprintf(
			"icmp.Type == 8 and ip.SrcAddr >= %s and ip.SrcAddr <= %s and ip.SrcAddr != %s and ip.DstAddr != %s",
			startIP.String(),
			endIP.String(),
			c.HostInternalIP.String(),
			c.NATIP.String(),
		)
	} else {
		icmpOutboundFilter = fmt.Sprintf(
			"icmp.Type == 8 and ip.SrcAddr >= %s and ip.SrcAddr <= %s and ip.DstAddr != %s",
			startIP.String(),
			endIP.String(),
			c.NATIP.String(),
		)
	}

	return outboundFilter, inboundFilter, icmpOutboundFilter
}
