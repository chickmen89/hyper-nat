package config

import (
	"net"
	"testing"
)

func TestParse(t *testing.T) {
	yamlData := []byte(`
nat_ip: 172.16.1.100
internal_network: 172.23.240.0/24
rules:
  - name: "호스트 네트워크"
    destination: 172.16.0.0/21
    action: bypass
  - name: "인터넷"
    destination: 0.0.0.0/0
    action: nat
`)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Check NAT IP
	expectedNATIP := net.ParseIP("172.16.1.100").To4()
	if !cfg.NATIP.Equal(expectedNATIP) {
		t.Errorf("NATIP = %v, want %v", cfg.NATIP, expectedNATIP)
	}

	// Check internal network
	_, expectedNetwork, _ := net.ParseCIDR("172.23.240.0/24")
	if cfg.InternalNetwork.String() != expectedNetwork.String() {
		t.Errorf("InternalNetwork = %v, want %v", cfg.InternalNetwork, expectedNetwork)
	}

	// Check rules count
	if len(cfg.Rules) != 2 {
		t.Fatalf("Rules count = %d, want 2", len(cfg.Rules))
	}

	// Check first rule
	if cfg.Rules[0].Name != "호스트 네트워크" {
		t.Errorf("Rules[0].Name = %q, want %q", cfg.Rules[0].Name, "호스트 네트워크")
	}
	if cfg.Rules[0].Action != ActionBypass {
		t.Errorf("Rules[0].Action = %q, want %q", cfg.Rules[0].Action, ActionBypass)
	}

	// Check second rule
	if cfg.Rules[1].Name != "인터넷" {
		t.Errorf("Rules[1].Name = %q, want %q", cfg.Rules[1].Name, "인터넷")
	}
	if cfg.Rules[1].Action != ActionNAT {
		t.Errorf("Rules[1].Action = %q, want %q", cfg.Rules[1].Action, ActionNAT)
	}
}

func TestParseInvalidNATIP(t *testing.T) {
	yamlData := []byte(`
nat_ip: invalid-ip
internal_network: 172.23.240.0/24
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: nat
`)

	_, err := Parse(yamlData)
	if err == nil {
		t.Error("Expected error for invalid NAT IP, got nil")
	}
}

func TestParseInvalidInternalNetwork(t *testing.T) {
	yamlData := []byte(`
nat_ip: 172.16.1.100
internal_network: invalid-cidr
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: nat
`)

	_, err := Parse(yamlData)
	if err == nil {
		t.Error("Expected error for invalid internal network, got nil")
	}
}

func TestParseInvalidAction(t *testing.T) {
	yamlData := []byte(`
nat_ip: 172.16.1.100
internal_network: 172.23.240.0/24
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: invalid
`)

	_, err := Parse(yamlData)
	if err == nil {
		t.Error("Expected error for invalid action, got nil")
	}
}

func TestParseNoRules(t *testing.T) {
	yamlData := []byte(`
nat_ip: 172.16.1.100
internal_network: 172.23.240.0/24
rules: []
`)

	_, err := Parse(yamlData)
	if err == nil {
		t.Error("Expected error for empty rules, got nil")
	}
}

func TestValidate(t *testing.T) {
	// Valid config
	yamlData := []byte(`
nat_ip: 172.16.1.100
internal_network: 172.23.240.0/24
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: nat
`)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate failed: %v", err)
	}
}

func TestValidateNATIPInInternalNetwork(t *testing.T) {
	// NAT IP inside internal network (invalid)
	yamlData := []byte(`
nat_ip: 172.23.240.100
internal_network: 172.23.240.0/24
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: nat
`)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation error for NAT IP in internal network, got nil")
	}
}

func TestBuildWinDivertFilter(t *testing.T) {
	yamlData := []byte(`
nat_ip: 172.16.1.100
internal_network: 172.23.240.0/24
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: nat
`)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	filter := cfg.BuildWinDivertFilter()
	// Filter now includes port ranges for TCP/UDP
	expected := "(ip.SrcAddr >= 172.23.240.0 and ip.SrcAddr <= 172.23.240.255) or (ip.DstAddr == 172.16.1.100 and tcp.DstPort >= 40000 and tcp.DstPort <= 60000) or (ip.DstAddr == 172.16.1.100 and udp.DstPort >= 40000 and udp.DstPort <= 60000)"

	if filter != expected {
		t.Errorf("Filter = %q, want %q", filter, expected)
	}
}

func TestBuildWinDivertFilterDifferentMask(t *testing.T) {
	yamlData := []byte(`
nat_ip: 10.0.0.1
internal_network: 192.168.0.0/16
rules:
  - name: "test"
    destination: 0.0.0.0/0
    action: nat
`)

	cfg, err := Parse(yamlData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	filter := cfg.BuildWinDivertFilter()
	// Filter now includes port ranges for TCP/UDP
	expected := "(ip.SrcAddr >= 192.168.0.0 and ip.SrcAddr <= 192.168.255.255) or (ip.DstAddr == 10.0.0.1 and tcp.DstPort >= 40000 and tcp.DstPort <= 60000) or (ip.DstAddr == 10.0.0.1 and udp.DstPort >= 40000 and udp.DstPort <= 60000)"

	if filter != expected {
		t.Errorf("Filter = %q, want %q", filter, expected)
	}
}
