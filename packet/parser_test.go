package packet

import (
	"net"
	"testing"
)

// buildIPv4Header creates a minimal IPv4 header for testing
func buildIPv4Header(protocol uint8, srcIP, dstIP net.IP) []byte {
	header := make([]byte, 20)
	header[0] = 0x45        // Version 4, IHL 5 (20 bytes)
	header[1] = 0x00        // TOS
	header[8] = 64          // TTL
	header[9] = protocol    // Protocol
	copy(header[12:16], srcIP.To4())
	copy(header[16:20], dstIP.To4())
	return header
}

// buildTCPHeader creates a minimal TCP header for testing
func buildTCPHeader(srcPort, dstPort uint16, flags uint8) []byte {
	header := make([]byte, 20)
	header[0] = byte(srcPort >> 8)
	header[1] = byte(srcPort)
	header[2] = byte(dstPort >> 8)
	header[3] = byte(dstPort)
	header[12] = 0x50 // Data offset 5 (20 bytes)
	header[13] = flags
	return header
}

// buildUDPHeader creates a minimal UDP header for testing
func buildUDPHeader(srcPort, dstPort uint16) []byte {
	header := make([]byte, 8)
	header[0] = byte(srcPort >> 8)
	header[1] = byte(srcPort)
	header[2] = byte(dstPort >> 8)
	header[3] = byte(dstPort)
	header[4] = 0x00
	header[5] = 0x08 // Length = 8
	return header
}

// buildICMPHeader creates a minimal ICMP Echo Request header for testing
func buildICMPHeader(icmpType uint8, identifier, sequence uint16) []byte {
	header := make([]byte, 8)
	header[0] = icmpType
	header[1] = 0 // Code
	header[4] = byte(identifier >> 8)
	header[5] = byte(identifier)
	header[6] = byte(sequence >> 8)
	header[7] = byte(sequence)
	return header
}

func TestParseIPv4_TCP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4 failed: %v", err)
	}

	if parsed.IPv4.Version != 4 {
		t.Errorf("Expected version 4, got %d", parsed.IPv4.Version)
	}
	if parsed.IPv4.Protocol != ProtocolTCP {
		t.Errorf("Expected protocol TCP (6), got %d", parsed.IPv4.Protocol)
	}
	if !parsed.IPv4.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP: expected %v, got %v", srcIP, parsed.IPv4.SrcIP)
	}
	if !parsed.IPv4.DstIP.Equal(dstIP) {
		t.Errorf("DstIP: expected %v, got %v", dstIP, parsed.IPv4.DstIP)
	}

	if parsed.TCP == nil {
		t.Fatal("TCP header not parsed")
	}
	if parsed.TCP.SrcPort != 12345 {
		t.Errorf("TCP SrcPort: expected 12345, got %d", parsed.TCP.SrcPort)
	}
	if parsed.TCP.DstPort != 443 {
		t.Errorf("TCP DstPort: expected 443, got %d", parsed.TCP.DstPort)
	}
	if !parsed.TCP.IsSYN() {
		t.Error("Expected SYN flag to be set")
	}
}

func TestParseIPv4_UDP(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.5").To4()
	dstIP := net.ParseIP("8.8.4.4").To4()

	ipHeader := buildIPv4Header(ProtocolUDP, srcIP, dstIP)
	udpHeader := buildUDPHeader(54321, 53)
	packet := append(ipHeader, udpHeader...)

	parsed, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4 failed: %v", err)
	}

	if parsed.IPv4.Protocol != ProtocolUDP {
		t.Errorf("Expected protocol UDP (17), got %d", parsed.IPv4.Protocol)
	}

	if parsed.UDP == nil {
		t.Fatal("UDP header not parsed")
	}
	if parsed.UDP.SrcPort != 54321 {
		t.Errorf("UDP SrcPort: expected 54321, got %d", parsed.UDP.SrcPort)
	}
	if parsed.UDP.DstPort != 53 {
		t.Errorf("UDP DstPort: expected 53, got %d", parsed.UDP.DstPort)
	}
}

func TestParseIPv4_ICMP(t *testing.T) {
	srcIP := net.ParseIP("172.16.0.10").To4()
	dstIP := net.ParseIP("1.1.1.1").To4()

	ipHeader := buildIPv4Header(ProtocolICMP, srcIP, dstIP)
	icmpHeader := buildICMPHeader(ICMPTypeEchoRequest, 1234, 1)
	packet := append(ipHeader, icmpHeader...)

	parsed, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4 failed: %v", err)
	}

	if parsed.IPv4.Protocol != ProtocolICMP {
		t.Errorf("Expected protocol ICMP (1), got %d", parsed.IPv4.Protocol)
	}

	if parsed.ICMP == nil {
		t.Fatal("ICMP header not parsed")
	}
	if parsed.ICMP.Type != ICMPTypeEchoRequest {
		t.Errorf("ICMP Type: expected %d, got %d", ICMPTypeEchoRequest, parsed.ICMP.Type)
	}
	if parsed.ICMP.Identifier != 1234 {
		t.Errorf("ICMP Identifier: expected 1234, got %d", parsed.ICMP.Identifier)
	}
	if !parsed.ICMP.IsEchoRequest() {
		t.Error("Expected IsEchoRequest() to return true")
	}
}

func TestParseIPv4_TooShort(t *testing.T) {
	data := []byte{0x45, 0x00, 0x00} // Too short

	_, err := ParseIPv4(data)
	if err != ErrPacketTooShort {
		t.Errorf("Expected ErrPacketTooShort, got %v", err)
	}
}

func TestParseIPv4_InvalidVersion(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 0x65 // Version 6

	_, err := ParseIPv4(data)
	if err != ErrInvalidIPVersion {
		t.Errorf("Expected ErrInvalidIPVersion, got %v", err)
	}
}

func TestParseIPv4_TCPTooShort(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)

	// Only 10 bytes of TCP (needs at least 20)
	tcpPartial := make([]byte, 10)
	packet := append(ipHeader, tcpPartial...)

	_, err := ParseIPv4(packet)
	if err != ErrPacketTooShort {
		t.Errorf("Expected ErrPacketTooShort for short TCP, got %v", err)
	}
}

func TestParseIPv4_UDPTooShort(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	ipHeader := buildIPv4Header(ProtocolUDP, srcIP, dstIP)

	// Only 4 bytes of UDP (needs at least 8)
	udpPartial := make([]byte, 4)
	packet := append(ipHeader, udpPartial...)

	_, err := ParseIPv4(packet)
	if err != ErrPacketTooShort {
		t.Errorf("Expected ErrPacketTooShort for short UDP, got %v", err)
	}
}

func TestParseIPv4_ICMPTooShort(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	ipHeader := buildIPv4Header(ProtocolICMP, srcIP, dstIP)

	// Only 4 bytes of ICMP (needs at least 8)
	icmpPartial := make([]byte, 4)
	packet := append(ipHeader, icmpPartial...)

	_, err := ParseIPv4(packet)
	if err != ErrPacketTooShort {
		t.Errorf("Expected ErrPacketTooShort for short ICMP, got %v", err)
	}
}

func TestTCPHeader_Flags(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint8
		isSYN    bool
		isSYNACK bool
		isFIN    bool
		isRST    bool
	}{
		{"SYN only", TCPFlagSYN, true, false, false, false},
		{"SYN+ACK", TCPFlagSYN | TCPFlagACK, false, true, false, false},
		{"FIN", TCPFlagFIN, false, false, true, false},
		{"FIN+ACK", TCPFlagFIN | TCPFlagACK, false, false, true, false},
		{"RST", TCPFlagRST, false, false, false, true},
		{"ACK only", TCPFlagACK, false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := &TCPHeader{Flags: tt.flags}
			if tcp.IsSYN() != tt.isSYN {
				t.Errorf("IsSYN(): expected %v, got %v", tt.isSYN, tcp.IsSYN())
			}
			if tcp.IsSYNACK() != tt.isSYNACK {
				t.Errorf("IsSYNACK(): expected %v, got %v", tt.isSYNACK, tcp.IsSYNACK())
			}
			if tcp.IsFIN() != tt.isFIN {
				t.Errorf("IsFIN(): expected %v, got %v", tt.isFIN, tcp.IsFIN())
			}
			if tcp.IsRST() != tt.isRST {
				t.Errorf("IsRST(): expected %v, got %v", tt.isRST, tcp.IsRST())
			}
		})
	}
}

func TestICMPHeader_Types(t *testing.T) {
	echoReq := &ICMPHeader{Type: ICMPTypeEchoRequest}
	if !echoReq.IsEchoRequest() {
		t.Error("IsEchoRequest() should return true for Echo Request")
	}
	if echoReq.IsEchoReply() {
		t.Error("IsEchoReply() should return false for Echo Request")
	}

	echoReply := &ICMPHeader{Type: ICMPTypeEchoReply}
	if echoReply.IsEchoRequest() {
		t.Error("IsEchoRequest() should return false for Echo Reply")
	}
	if !echoReply.IsEchoReply() {
		t.Error("IsEchoReply() should return true for Echo Reply")
	}
}

func TestParsedPacket_SrcPort_DstPort(t *testing.T) {
	// TCP packet
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(8080, 443, TCPFlagACK)
	tcpPacket := append(ipHeader, tcpHeader...)

	parsedTCP, _ := ParseIPv4(tcpPacket)
	if parsedTCP.SrcPort() != 8080 {
		t.Errorf("TCP SrcPort(): expected 8080, got %d", parsedTCP.SrcPort())
	}
	if parsedTCP.DstPort() != 443 {
		t.Errorf("TCP DstPort(): expected 443, got %d", parsedTCP.DstPort())
	}

	// UDP packet
	ipHeader2 := buildIPv4Header(ProtocolUDP, srcIP, dstIP)
	udpHeader := buildUDPHeader(5353, 53)
	udpPacket := append(ipHeader2, udpHeader...)

	parsedUDP, _ := ParseIPv4(udpPacket)
	if parsedUDP.SrcPort() != 5353 {
		t.Errorf("UDP SrcPort(): expected 5353, got %d", parsedUDP.SrcPort())
	}
	if parsedUDP.DstPort() != 53 {
		t.Errorf("UDP DstPort(): expected 53, got %d", parsedUDP.DstPort())
	}

	// ICMP packet (should return 0)
	ipHeader3 := buildIPv4Header(ProtocolICMP, srcIP, dstIP)
	icmpHeader := buildICMPHeader(ICMPTypeEchoRequest, 1000, 1)
	icmpPacket := append(ipHeader3, icmpHeader...)

	parsedICMP, _ := ParseIPv4(icmpPacket)
	if parsedICMP.SrcPort() != 0 {
		t.Errorf("ICMP SrcPort(): expected 0, got %d", parsedICMP.SrcPort())
	}
	if parsedICMP.DstPort() != 0 {
		t.Errorf("ICMP DstPort(): expected 0, got %d", parsedICMP.DstPort())
	}
}

func TestParsedPacket_IsFromInternalNetwork(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/24")

	// Internal source
	internalIP := net.ParseIP("10.0.0.50").To4()
	externalIP := net.ParseIP("8.8.8.8").To4()
	ipHeader := buildIPv4Header(ProtocolTCP, internalIP, externalIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	if !parsed.IsFromInternalNetwork(internalNet) {
		t.Error("Expected IsFromInternalNetwork() to return true for internal source")
	}

	// External source
	ipHeader2 := buildIPv4Header(ProtocolTCP, externalIP, internalIP)
	packet2 := append(ipHeader2, tcpHeader...)

	parsed2, _ := ParseIPv4(packet2)
	if parsed2.IsFromInternalNetwork(internalNet) {
		t.Error("Expected IsFromInternalNetwork() to return false for external source")
	}
}

func TestIPv4Header_HeaderLength(t *testing.T) {
	header := &IPv4Header{IHL: 5}
	if header.HeaderLength() != 20 {
		t.Errorf("Expected 20 bytes, got %d", header.HeaderLength())
	}

	headerWithOptions := &IPv4Header{IHL: 6}
	if headerWithOptions.HeaderLength() != 24 {
		t.Errorf("Expected 24 bytes, got %d", headerWithOptions.HeaderLength())
	}
}

func TestTCPHeader_HeaderLength(t *testing.T) {
	header := &TCPHeader{DataOffset: 5}
	if header.HeaderLength() != 20 {
		t.Errorf("Expected 20 bytes, got %d", header.HeaderLength())
	}

	headerWithOptions := &TCPHeader{DataOffset: 8}
	if headerWithOptions.HeaderLength() != 32 {
		t.Errorf("Expected 32 bytes, got %d", headerWithOptions.HeaderLength())
	}
}

func TestParseIPv4_UnsupportedProtocol(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	ipHeader := buildIPv4Header(50, srcIP, dstIP) // Protocol 50 = ESP

	payload := []byte{0x01, 0x02, 0x03, 0x04}
	packet := append(ipHeader, payload...)

	parsed, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4 should not fail for unsupported protocol: %v", err)
	}

	if parsed.TCP != nil || parsed.UDP != nil || parsed.ICMP != nil {
		t.Error("No transport layer should be parsed for unsupported protocol")
	}
	if len(parsed.Payload) != 4 {
		t.Errorf("Expected payload length 4, got %d", len(parsed.Payload))
	}
}

func TestParsedPacket_Protocol(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(80, 8080, TCPFlagACK)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	if parsed.Protocol() != ProtocolTCP {
		t.Errorf("Protocol(): expected %d, got %d", ProtocolTCP, parsed.Protocol())
	}
}
