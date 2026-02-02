// Package ipc provides inter-process communication for hyper-nat status queries.
package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// PipeName is the named pipe path for IPC communication.
	// On Windows, we use a TCP port since named pipes require more complex handling.
	DefaultPort = 47847 // "HYNAT" on phone keypad
	DefaultAddr = "127.0.0.1:47847"
)

// StatusResponse contains the current status of the NAT engine.
type StatusResponse struct {
	Running          bool              `json:"running"`
	Uptime           time.Duration     `json:"uptime"`
	UptimeStr        string            `json:"uptime_str"`
	PacketsProcessed uint64            `json:"packets_processed"`
	PacketsNATted    uint64            `json:"packets_natted"`
	PacketsBypassed  uint64            `json:"packets_bypassed"`
	PacketsDropped   uint64            `json:"packets_dropped"`
	ErrorsRecovered  uint64            `json:"errors_recovered"`
	ActiveConns      uint64            `json:"active_connections"`
	TotalConns       uint64            `json:"total_connections"`
	NATIP            string            `json:"nat_ip"`
	InternalNetwork  string            `json:"internal_network"`
	Connections      []ConnectionInfo  `json:"connections,omitempty"`
	PortForwards     []PortForwardInfo `json:"port_forwards,omitempty"`
	DNATSessions     []DNATSessionInfo `json:"dnat_sessions,omitempty"`
	ActiveDNATConns  int               `json:"active_dnat_connections"`
}

// ConnectionInfo represents a single NAT connection.
type ConnectionInfo struct {
	Protocol     string    `json:"protocol"`
	InternalIP   string    `json:"internal_ip"`
	InternalPort uint16    `json:"internal_port"`
	ExternalIP   string    `json:"external_ip"`
	ExternalPort uint16    `json:"external_port"`
	NATPort      uint16    `json:"nat_port"`
	State        string    `json:"state"`
	LastSeen     time.Time `json:"last_seen"`
	IdleSeconds  int64     `json:"idle_seconds"`
}

// PortForwardInfo represents a port forwarding (DNAT) rule.
type PortForwardInfo struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	ExternalPort uint16 `json:"external_port"`
	InternalIP   string `json:"internal_ip"`
	InternalPort uint16 `json:"internal_port"`
}

// DNATSessionInfo represents an active DNAT session.
type DNATSessionInfo struct {
	Protocol     string `json:"protocol"`
	ExternalIP   string `json:"external_ip"`
	ExternalPort uint16 `json:"external_port"`
	InternalIP   string `json:"internal_ip"`
	InternalPort uint16 `json:"internal_port"`
	NATPort      uint16 `json:"nat_port"`
	IdleSeconds  int64  `json:"idle_seconds"`
}

// Request represents an IPC request.
type Request struct {
	Command string `json:"command"` // "status", "connections", "ping"
}

// Server provides an IPC server for status queries.
type Server struct {
	listener    net.Listener
	statusFunc  func() *StatusResponse
	mu          sync.Mutex
	running     bool
	stopChan    chan struct{}
}

// NewServer creates a new IPC server.
func NewServer(statusFunc func() *StatusResponse) *Server {
	return &Server{
		statusFunc: statusFunc,
		stopChan:   make(chan struct{}),
	}
}

// Start begins listening for IPC connections.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	listener, err := net.Listen("tcp", DefaultAddr)
	if err != nil {
		return fmt.Errorf("failed to start IPC server: %w", err)
	}

	s.listener = listener
	s.running = true

	go s.acceptLoop()
	return nil
}

// Stop stops the IPC server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		// Set accept timeout
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Check if server was stopped
			select {
			case <-s.stopChan:
				return
			default:
				// Timeout or temporary error, continue
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read request
	decoder := json.NewDecoder(conn)
	var req Request
	if err := decoder.Decode(&req); err != nil {
		return
	}

	// Process request
	var response interface{}
	switch req.Command {
	case "ping":
		response = map[string]string{"status": "ok"}
	case "status", "connections":
		if s.statusFunc != nil {
			response = s.statusFunc()
		} else {
			response = map[string]string{"error": "status function not set"}
		}
	default:
		response = map[string]string{"error": "unknown command"}
	}

	// Send response
	encoder := json.NewEncoder(conn)
	encoder.Encode(response)
}

// Client provides an IPC client for status queries.
type Client struct {
	addr string
}

// NewClient creates a new IPC client.
func NewClient() *Client {
	return &Client{addr: DefaultAddr}
}

// Ping checks if the server is running.
func (c *Client) Ping() error {
	conn, err := net.DialTimeout("tcp", c.addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("hyper-nat is not running: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send ping request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(Request{Command: "ping"}); err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp map[string]string
	if err := decoder.Decode(&resp); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp["status"] != "ok" {
		return fmt.Errorf("unexpected response: %v", resp)
	}

	return nil
}

// GetStatus retrieves the current status from the running instance.
func (c *Client) GetStatus() (*StatusResponse, error) {
	conn, err := net.DialTimeout("tcp", c.addr, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("hyper-nat is not running: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send status request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(Request{Command: "status"}); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp StatusResponse
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
}
