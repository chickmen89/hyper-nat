package packet

import (
	"encoding/binary"
	"net"
)

// ModifySourceIP changes the source IP address in the packet.
// This modifies the packet in place.
func (p *ParsedPacket) ModifySourceIP(newIP net.IP) {
	newIP = newIP.To4()
	if newIP == nil || len(p.Raw) < 16 {
		return
	}
	copy(p.Raw[12:16], newIP)
	p.IPv4.SrcIP = newIP
}

// ModifyDestinationIP changes the destination IP address in the packet.
// This modifies the packet in place.
func (p *ParsedPacket) ModifyDestinationIP(newIP net.IP) {
	newIP = newIP.To4()
	if newIP == nil || len(p.Raw) < 20 {
		return
	}
	copy(p.Raw[16:20], newIP)
	p.IPv4.DstIP = newIP
}

// ModifySourcePort changes the source port in TCP/UDP packets.
// This modifies the packet in place.
func (p *ParsedPacket) ModifySourcePort(newPort uint16) {
	offset := p.IPv4.HeaderLength()
	if len(p.Raw) < offset+2 {
		return
	}

	binary.BigEndian.PutUint16(p.Raw[offset:offset+2], newPort)

	if p.TCP != nil {
		p.TCP.SrcPort = newPort
	} else if p.UDP != nil {
		p.UDP.SrcPort = newPort
	}
}

// ModifyDestinationPort changes the destination port in TCP/UDP packets.
// This modifies the packet in place.
func (p *ParsedPacket) ModifyDestinationPort(newPort uint16) {
	offset := p.IPv4.HeaderLength() + 2
	if len(p.Raw) < offset+2 {
		return
	}

	binary.BigEndian.PutUint16(p.Raw[offset:offset+2], newPort)

	if p.TCP != nil {
		p.TCP.DstPort = newPort
	} else if p.UDP != nil {
		p.UDP.DstPort = newPort
	}
}

// ModifyICMPIdentifier changes the ICMP identifier in Echo Request/Reply packets.
// This modifies the packet in place.
func (p *ParsedPacket) ModifyICMPIdentifier(newID uint16) {
	if p.ICMP == nil {
		return
	}
	offset := p.IPv4.HeaderLength() + 4 // ICMP Identifier is at offset 4-5 from ICMP header start
	if len(p.Raw) < offset+2 {
		return
	}
	binary.BigEndian.PutUint16(p.Raw[offset:offset+2], newID)
	p.ICMP.Identifier = newID
}

// ApplyNAT modifies the packet for outbound NAT:
// - Changes source IP to NAT IP
// - Changes source port to NAT port (or ICMP ID for ICMP)
func (p *ParsedPacket) ApplyNAT(natIP net.IP, natPort uint16) {
	p.ModifySourceIP(natIP)
	if p.ICMP != nil {
		p.ModifyICMPIdentifier(natPort) // Use natPort as NAT ID for ICMP
	} else {
		p.ModifySourcePort(natPort)
	}
}

// ReverseNAT modifies the packet for inbound reverse NAT:
// - Changes destination IP to original internal IP
// - Changes destination port to original internal port (or ICMP ID for ICMP)
func (p *ParsedPacket) ReverseNAT(internalIP net.IP, internalPort uint16) {
	p.ModifyDestinationIP(internalIP)
	if p.ICMP != nil {
		p.ModifyICMPIdentifier(internalPort) // Restore original ICMP ID
	} else {
		p.ModifyDestinationPort(internalPort)
	}
}

// ClearChecksums zeros out the checksums so WinDivert can recalculate them.
// WinDivert's CalcChecksums expects checksums to be zero for recalculation.
func (p *ParsedPacket) ClearChecksums() {
	// Clear IP checksum (bytes 10-11)
	if len(p.Raw) >= 12 {
		p.Raw[10] = 0
		p.Raw[11] = 0
	}

	offset := p.IPv4.HeaderLength()

	// Clear TCP/UDP/ICMP checksum
	if p.TCP != nil && len(p.Raw) >= offset+18 {
		// TCP checksum at offset 16-17 from TCP header start
		p.Raw[offset+16] = 0
		p.Raw[offset+17] = 0
	} else if p.UDP != nil && len(p.Raw) >= offset+8 {
		// UDP checksum at offset 6-7 from UDP header start
		p.Raw[offset+6] = 0
		p.Raw[offset+7] = 0
	} else if p.ICMP != nil && len(p.Raw) >= offset+4 {
		// ICMP checksum at offset 2-3 from ICMP header start
		p.Raw[offset+2] = 0
		p.Raw[offset+3] = 0
	}
}
