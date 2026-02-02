// Package packet provides packet parsing and modification utilities.
package packet

import (
	"encoding/binary"
	"errors"
	"net"
)

// Common errors
var (
	ErrPacketTooShort   = errors.New("packet too short")
	ErrInvalidIPVersion = errors.New("invalid IP version")
	ErrUnsupportedProto = errors.New("unsupported protocol")
)

// Protocol constants
const (
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
	ProtocolICMP uint8 = 1
)

// TCP flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// IPv4Header represents an IPv4 header.
type IPv4Header struct {
	Version        uint8
	IHL            uint8  // Internet Header Length (in 32-bit words)
	TOS            uint8  // Type of Service
	TotalLength    uint16 // Total length including header and data
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
	Options        []byte
}

// HeaderLength returns the header length in bytes.
func (h *IPv4Header) HeaderLength() int {
	return int(h.IHL) * 4
}

// TCPHeader represents a TCP header.
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // Header length in 32-bit words
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
	Options    []byte
}

// HeaderLength returns the header length in bytes.
func (h *TCPHeader) HeaderLength() int {
	return int(h.DataOffset) * 4
}

// HasFlag checks if a specific flag is set.
func (h *TCPHeader) HasFlag(flag uint8) bool {
	return h.Flags&flag != 0
}

// IsSYN returns true if SYN flag is set (and ACK is not).
func (h *TCPHeader) IsSYN() bool {
	return h.HasFlag(TCPFlagSYN) && !h.HasFlag(TCPFlagACK)
}

// IsSYNACK returns true if both SYN and ACK flags are set.
func (h *TCPHeader) IsSYNACK() bool {
	return h.HasFlag(TCPFlagSYN) && h.HasFlag(TCPFlagACK)
}

// IsFIN returns true if FIN flag is set.
func (h *TCPHeader) IsFIN() bool {
	return h.HasFlag(TCPFlagFIN)
}

// IsRST returns true if RST flag is set.
func (h *TCPHeader) IsRST() bool {
	return h.HasFlag(TCPFlagRST)
}

// UDPHeader represents a UDP header.
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// ICMP types
const (
	ICMPTypeEchoReply   uint8 = 0
	ICMPTypeEchoRequest uint8 = 8
)

// ICMPHeader represents an ICMP header.
type ICMPHeader struct {
	Type       uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16 // Used for Echo Request/Reply
	Sequence   uint16 // Used for Echo Request/Reply
}

// IsEchoRequest returns true if this is an Echo Request.
func (h *ICMPHeader) IsEchoRequest() bool {
	return h.Type == ICMPTypeEchoRequest
}

// IsEchoReply returns true if this is an Echo Reply.
func (h *ICMPHeader) IsEchoReply() bool {
	return h.Type == ICMPTypeEchoReply
}

// ParsedPacket holds parsed packet information.
type ParsedPacket struct {
	Raw           []byte
	IPv4          *IPv4Header
	TCP           *TCPHeader
	UDP           *UDPHeader
	ICMP          *ICMPHeader
	Payload       []byte
	PayloadOffset int // Offset to payload in raw packet
}

// ParseIPv4 parses an IPv4 packet from raw bytes.
func ParseIPv4(data []byte) (*ParsedPacket, error) {
	if len(data) < 20 {
		return nil, ErrPacketTooShort
	}

	// Check IP version
	version := data[0] >> 4
	if version != 4 {
		return nil, ErrInvalidIPVersion
	}

	ihl := data[0] & 0x0F
	headerLen := int(ihl) * 4
	if len(data) < headerLen {
		return nil, ErrPacketTooShort
	}

	ipHeader := &IPv4Header{
		Version:        version,
		IHL:            ihl,
		TOS:            data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		Identification: binary.BigEndian.Uint16(data[4:6]),
		Flags:          uint8(data[6] >> 5),
		FragmentOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:            data[8],
		Protocol:       data[9],
		Checksum:       binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IP(data[12:16]),
		DstIP:          net.IP(data[16:20]),
	}

	if headerLen > 20 {
		ipHeader.Options = data[20:headerLen]
	}

	pkt := &ParsedPacket{
		Raw:  data,
		IPv4: ipHeader,
	}

	// Parse transport layer
	transportData := data[headerLen:]
	switch ipHeader.Protocol {
	case ProtocolTCP:
		tcp, payloadOffset, err := parseTCP(transportData)
		if err != nil {
			return nil, err
		}
		pkt.TCP = tcp
		pkt.PayloadOffset = headerLen + payloadOffset
		if pkt.PayloadOffset < len(data) {
			pkt.Payload = data[pkt.PayloadOffset:]
		}

	case ProtocolUDP:
		udp, err := parseUDP(transportData)
		if err != nil {
			return nil, err
		}
		pkt.UDP = udp
		pkt.PayloadOffset = headerLen + 8 // UDP header is always 8 bytes
		if pkt.PayloadOffset < len(data) {
			pkt.Payload = data[pkt.PayloadOffset:]
		}

	case ProtocolICMP:
		icmp, err := parseICMP(transportData)
		if err != nil {
			return nil, err
		}
		pkt.ICMP = icmp
		pkt.PayloadOffset = headerLen + 8 // ICMP header is 8 bytes for Echo
		if pkt.PayloadOffset < len(data) {
			pkt.Payload = data[pkt.PayloadOffset:]
		}

	default:
		// For unsupported protocols, just store raw data
		pkt.PayloadOffset = headerLen
		pkt.Payload = transportData
	}

	return pkt, nil
}

func parseTCP(data []byte) (*TCPHeader, int, error) {
	if len(data) < 20 {
		return nil, 0, ErrPacketTooShort
	}

	dataOffset := (data[12] >> 4) * 4
	if int(dataOffset) > len(data) {
		return nil, 0, ErrPacketTooShort
	}

	tcp := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}

	if dataOffset > 20 {
		tcp.Options = data[20:dataOffset]
	}

	return tcp, int(dataOffset), nil
}

func parseUDP(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, ErrPacketTooShort
	}

	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

func parseICMP(data []byte) (*ICMPHeader, error) {
	if len(data) < 8 {
		return nil, ErrPacketTooShort
	}

	return &ICMPHeader{
		Type:       data[0],
		Code:       data[1],
		Checksum:   binary.BigEndian.Uint16(data[2:4]),
		Identifier: binary.BigEndian.Uint16(data[4:6]),
		Sequence:   binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

// IsFromInternalNetwork checks if packet source is from the internal network.
func (p *ParsedPacket) IsFromInternalNetwork(internalNet *net.IPNet) bool {
	return internalNet.Contains(p.IPv4.SrcIP)
}

// Protocol returns the transport protocol.
func (p *ParsedPacket) Protocol() uint8 {
	return p.IPv4.Protocol
}

// SrcPort returns the source port for TCP/UDP packets.
func (p *ParsedPacket) SrcPort() uint16 {
	if p.TCP != nil {
		return p.TCP.SrcPort
	}
	if p.UDP != nil {
		return p.UDP.SrcPort
	}
	return 0
}

// DstPort returns the destination port for TCP/UDP packets.
func (p *ParsedPacket) DstPort() uint16 {
	if p.TCP != nil {
		return p.TCP.DstPort
	}
	if p.UDP != nil {
		return p.UDP.DstPort
	}
	return 0
}

