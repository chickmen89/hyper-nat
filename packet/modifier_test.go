package packet

import (
	"net"
	"testing"
)

func TestModifySourceIP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	newSrcIP := net.ParseIP("10.0.0.1").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4 failed: %v", err)
	}

	parsed.ModifySourceIP(newSrcIP)

	// Check parsed struct
	if !parsed.IPv4.SrcIP.Equal(newSrcIP) {
		t.Errorf("IPv4.SrcIP: expected %v, got %v", newSrcIP, parsed.IPv4.SrcIP)
	}

	// Check raw bytes
	rawSrcIP := net.IP(parsed.Raw[12:16])
	if !rawSrcIP.Equal(newSrcIP) {
		t.Errorf("Raw SrcIP: expected %v, got %v", newSrcIP, rawSrcIP)
	}
}

func TestModifyDestinationIP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	newDstIP := net.ParseIP("1.1.1.1").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ModifyDestinationIP(newDstIP)

	if !parsed.IPv4.DstIP.Equal(newDstIP) {
		t.Errorf("IPv4.DstIP: expected %v, got %v", newDstIP, parsed.IPv4.DstIP)
	}

	rawDstIP := net.IP(parsed.Raw[16:20])
	if !rawDstIP.Equal(newDstIP) {
		t.Errorf("Raw DstIP: expected %v, got %v", newDstIP, rawDstIP)
	}
}

func TestModifySourcePort_TCP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ModifySourcePort(45000)

	if parsed.TCP.SrcPort != 45000 {
		t.Errorf("TCP.SrcPort: expected 45000, got %d", parsed.TCP.SrcPort)
	}

	// Check raw bytes (TCP header starts at offset 20)
	rawPort := uint16(parsed.Raw[20])<<8 | uint16(parsed.Raw[21])
	if rawPort != 45000 {
		t.Errorf("Raw SrcPort: expected 45000, got %d", rawPort)
	}
}

func TestModifySourcePort_UDP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolUDP, srcIP, dstIP)
	udpHeader := buildUDPHeader(54321, 53)
	packet := append(ipHeader, udpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ModifySourcePort(40000)

	if parsed.UDP.SrcPort != 40000 {
		t.Errorf("UDP.SrcPort: expected 40000, got %d", parsed.UDP.SrcPort)
	}
}

func TestModifyDestinationPort_TCP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ModifyDestinationPort(8080)

	if parsed.TCP.DstPort != 8080 {
		t.Errorf("TCP.DstPort: expected 8080, got %d", parsed.TCP.DstPort)
	}

	// Check raw bytes (dst port at offset 22-23)
	rawPort := uint16(parsed.Raw[22])<<8 | uint16(parsed.Raw[23])
	if rawPort != 8080 {
		t.Errorf("Raw DstPort: expected 8080, got %d", rawPort)
	}
}

func TestModifyDestinationPort_UDP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolUDP, srcIP, dstIP)
	udpHeader := buildUDPHeader(54321, 53)
	packet := append(ipHeader, udpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ModifyDestinationPort(5353)

	if parsed.UDP.DstPort != 5353 {
		t.Errorf("UDP.DstPort: expected 5353, got %d", parsed.UDP.DstPort)
	}
}

func TestModifyICMPIdentifier(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolICMP, srcIP, dstIP)
	icmpHeader := buildICMPHeader(ICMPTypeEchoRequest, 1234, 1)
	packet := append(ipHeader, icmpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ModifyICMPIdentifier(50000)

	if parsed.ICMP.Identifier != 50000 {
		t.Errorf("ICMP.Identifier: expected 50000, got %d", parsed.ICMP.Identifier)
	}

	// Check raw bytes (identifier at offset 24-25)
	rawID := uint16(parsed.Raw[24])<<8 | uint16(parsed.Raw[25])
	if rawID != 50000 {
		t.Errorf("Raw Identifier: expected 50000, got %d", rawID)
	}
}

func TestApplyNAT_TCP(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.50").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	natIP := net.ParseIP("192.168.1.1").To4()
	natPort := uint16(45000)

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ApplyNAT(natIP, natPort)

	if !parsed.IPv4.SrcIP.Equal(natIP) {
		t.Errorf("After NAT, SrcIP: expected %v, got %v", natIP, parsed.IPv4.SrcIP)
	}
	if parsed.TCP.SrcPort != natPort {
		t.Errorf("After NAT, SrcPort: expected %d, got %d", natPort, parsed.TCP.SrcPort)
	}

	// DstIP should be unchanged
	if !parsed.IPv4.DstIP.Equal(dstIP) {
		t.Errorf("DstIP should not change: expected %v, got %v", dstIP, parsed.IPv4.DstIP)
	}
}

func TestApplyNAT_UDP(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.50").To4()
	dstIP := net.ParseIP("8.8.4.4").To4()
	natIP := net.ParseIP("192.168.1.1").To4()
	natPort := uint16(40000)

	ipHeader := buildIPv4Header(ProtocolUDP, srcIP, dstIP)
	udpHeader := buildUDPHeader(54321, 53)
	packet := append(ipHeader, udpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ApplyNAT(natIP, natPort)

	if !parsed.IPv4.SrcIP.Equal(natIP) {
		t.Errorf("After NAT, SrcIP: expected %v, got %v", natIP, parsed.IPv4.SrcIP)
	}
	if parsed.UDP.SrcPort != natPort {
		t.Errorf("After NAT, SrcPort: expected %d, got %d", natPort, parsed.UDP.SrcPort)
	}
}

func TestApplyNAT_ICMP(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.50").To4()
	dstIP := net.ParseIP("1.1.1.1").To4()
	natIP := net.ParseIP("192.168.1.1").To4()
	natID := uint16(55000)

	ipHeader := buildIPv4Header(ProtocolICMP, srcIP, dstIP)
	icmpHeader := buildICMPHeader(ICMPTypeEchoRequest, 1234, 1)
	packet := append(ipHeader, icmpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ApplyNAT(natIP, natID)

	if !parsed.IPv4.SrcIP.Equal(natIP) {
		t.Errorf("After NAT, SrcIP: expected %v, got %v", natIP, parsed.IPv4.SrcIP)
	}
	if parsed.ICMP.Identifier != natID {
		t.Errorf("After NAT, ICMP Identifier: expected %d, got %d", natID, parsed.ICMP.Identifier)
	}
}

func TestReverseNAT_TCP(t *testing.T) {
	srcIP := net.ParseIP("8.8.8.8").To4()
	natIP := net.ParseIP("192.168.1.1").To4()
	internalIP := net.ParseIP("10.0.0.50").To4()
	natPort := uint16(45000)
	internalPort := uint16(12345)

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, natIP)
	tcpHeader := buildTCPHeader(443, natPort, TCPFlagSYN|TCPFlagACK)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ReverseNAT(internalIP, internalPort)

	if !parsed.IPv4.DstIP.Equal(internalIP) {
		t.Errorf("After ReverseNAT, DstIP: expected %v, got %v", internalIP, parsed.IPv4.DstIP)
	}
	if parsed.TCP.DstPort != internalPort {
		t.Errorf("After ReverseNAT, DstPort: expected %d, got %d", internalPort, parsed.TCP.DstPort)
	}

	// SrcIP should be unchanged
	if !parsed.IPv4.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP should not change: expected %v, got %v", srcIP, parsed.IPv4.SrcIP)
	}
}

func TestReverseNAT_ICMP(t *testing.T) {
	srcIP := net.ParseIP("1.1.1.1").To4()
	natIP := net.ParseIP("192.168.1.1").To4()
	internalIP := net.ParseIP("10.0.0.50").To4()
	natID := uint16(55000)
	internalID := uint16(1234)

	ipHeader := buildIPv4Header(ProtocolICMP, srcIP, natIP)
	icmpHeader := buildICMPHeader(ICMPTypeEchoReply, natID, 1)
	packet := append(ipHeader, icmpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ReverseNAT(internalIP, internalID)

	if !parsed.IPv4.DstIP.Equal(internalIP) {
		t.Errorf("After ReverseNAT, DstIP: expected %v, got %v", internalIP, parsed.IPv4.DstIP)
	}
	if parsed.ICMP.Identifier != internalID {
		t.Errorf("After ReverseNAT, ICMP Identifier: expected %d, got %d", internalID, parsed.ICMP.Identifier)
	}
}

func TestClearChecksums_TCP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	// Set fake checksums
	ipHeader[10] = 0xAB
	ipHeader[11] = 0xCD

	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	// Set fake TCP checksum (offset 16-17 in TCP header)
	tcpHeader[16] = 0xEF
	tcpHeader[17] = 0x12

	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ClearChecksums()

	// Check IP checksum is cleared
	if parsed.Raw[10] != 0 || parsed.Raw[11] != 0 {
		t.Errorf("IP checksum not cleared: %02x%02x", parsed.Raw[10], parsed.Raw[11])
	}

	// Check TCP checksum is cleared (at offset 20+16=36)
	if parsed.Raw[36] != 0 || parsed.Raw[37] != 0 {
		t.Errorf("TCP checksum not cleared: %02x%02x", parsed.Raw[36], parsed.Raw[37])
	}
}

func TestClearChecksums_UDP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolUDP, srcIP, dstIP)
	ipHeader[10] = 0xAB
	ipHeader[11] = 0xCD

	udpHeader := buildUDPHeader(54321, 53)
	// Set fake UDP checksum (offset 6-7 in UDP header)
	udpHeader[6] = 0xEF
	udpHeader[7] = 0x12

	packet := append(ipHeader, udpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ClearChecksums()

	// Check IP checksum is cleared
	if parsed.Raw[10] != 0 || parsed.Raw[11] != 0 {
		t.Error("IP checksum not cleared")
	}

	// Check UDP checksum is cleared (at offset 20+6=26)
	if parsed.Raw[26] != 0 || parsed.Raw[27] != 0 {
		t.Errorf("UDP checksum not cleared: %02x%02x", parsed.Raw[26], parsed.Raw[27])
	}
}

func TestClearChecksums_ICMP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolICMP, srcIP, dstIP)
	ipHeader[10] = 0xAB
	ipHeader[11] = 0xCD

	icmpHeader := buildICMPHeader(ICMPTypeEchoRequest, 1234, 1)
	// Set fake ICMP checksum (offset 2-3 in ICMP header)
	icmpHeader[2] = 0xEF
	icmpHeader[3] = 0x12

	packet := append(ipHeader, icmpHeader...)

	parsed, _ := ParseIPv4(packet)
	parsed.ClearChecksums()

	// Check IP checksum is cleared
	if parsed.Raw[10] != 0 || parsed.Raw[11] != 0 {
		t.Error("IP checksum not cleared")
	}

	// Check ICMP checksum is cleared (at offset 20+2=22)
	if parsed.Raw[22] != 0 || parsed.Raw[23] != 0 {
		t.Errorf("ICMP checksum not cleared: %02x%02x", parsed.Raw[22], parsed.Raw[23])
	}
}

func TestModifySourceIP_InvalidIP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)

	// Try to set IPv6 address (should be handled gracefully)
	parsed.ModifySourceIP(net.ParseIP("::1"))

	// Should remain unchanged
	if !parsed.IPv4.SrcIP.Equal(srcIP) {
		t.Error("SrcIP should not change when given invalid IPv4")
	}
}

func TestModifyICMPIdentifier_NonICMP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()

	ipHeader := buildIPv4Header(ProtocolTCP, srcIP, dstIP)
	tcpHeader := buildTCPHeader(12345, 443, TCPFlagSYN)
	packet := append(ipHeader, tcpHeader...)

	parsed, _ := ParseIPv4(packet)

	// Should not panic when called on non-ICMP packet
	parsed.ModifyICMPIdentifier(50000)
}
