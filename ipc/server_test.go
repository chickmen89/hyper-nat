package ipc

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	statusFunc := func() *StatusResponse {
		return &StatusResponse{Running: true}
	}
	server := NewServer(statusFunc)

	if server == nil {
		t.Fatal("NewServer returned nil")
	}
	if server.statusFunc == nil {
		t.Error("statusFunc not set")
	}
	if server.stopChan == nil {
		t.Error("stopChan not initialized")
	}
}

func TestServerStartStop(t *testing.T) {
	statusFunc := func() *StatusResponse {
		return &StatusResponse{Running: true}
	}
	server := NewServer(statusFunc)

	// Start server
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Check server is running
	if !server.running {
		t.Error("Server should be running")
	}

	// Try to start again (should fail)
	err = server.Start()
	if err == nil {
		t.Error("Starting server twice should return error")
	}

	// Stop server
	server.Stop()
	if server.running {
		t.Error("Server should not be running after Stop()")
	}

	// Stop again (should not panic)
	server.Stop()
}

func TestServerPingCommand(t *testing.T) {
	statusFunc := func() *StatusResponse {
		return &StatusResponse{Running: true}
	}
	server := NewServer(statusFunc)

	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect and send ping
	conn, err := net.DialTimeout("tcp", DefaultAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send ping request
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(Request{Command: "ping"})
	if err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp map[string]string
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", resp["status"])
	}
}

func TestServerStatusCommand(t *testing.T) {
	expectedStatus := &StatusResponse{
		Running:          true,
		PacketsProcessed: 100,
		PacketsNATted:    80,
		PacketsBypassed:  15,
		PacketsDropped:   5,
		ActiveConns:      10,
		TotalConns:       50,
		NATIP:            "192.168.1.1",
		InternalNetwork:  "10.0.0.0/24",
	}

	statusFunc := func() *StatusResponse {
		return expectedStatus
	}
	server := NewServer(statusFunc)

	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	// Connect and send status request
	conn, err := net.DialTimeout("tcp", DefaultAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(Request{Command: "status"})
	if err != nil {
		t.Fatalf("Failed to send status request: %v", err)
	}

	decoder := json.NewDecoder(conn)
	var resp StatusResponse
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.PacketsProcessed != expectedStatus.PacketsProcessed {
		t.Errorf("PacketsProcessed: expected %d, got %d",
			expectedStatus.PacketsProcessed, resp.PacketsProcessed)
	}
	if resp.NATIP != expectedStatus.NATIP {
		t.Errorf("NATIP: expected %s, got %s", expectedStatus.NATIP, resp.NATIP)
	}
}

func TestServerUnknownCommand(t *testing.T) {
	server := NewServer(func() *StatusResponse { return nil })

	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", DefaultAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(Request{Command: "unknown"})
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	decoder := json.NewDecoder(conn)
	var resp map[string]string
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["error"] != "unknown command" {
		t.Errorf("Expected error 'unknown command', got '%s'", resp["error"])
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.addr != DefaultAddr {
		t.Errorf("Expected addr %s, got %s", DefaultAddr, client.addr)
	}
}

func TestClientPing(t *testing.T) {
	server := NewServer(func() *StatusResponse { return &StatusResponse{Running: true} })
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	client := NewClient()
	err = client.Ping()
	if err != nil {
		t.Errorf("Ping failed: %v", err)
	}
}

func TestClientPingNoServer(t *testing.T) {
	client := NewClient()
	err := client.Ping()
	if err == nil {
		t.Error("Ping should fail when no server is running")
	}
}

func TestClientGetStatus(t *testing.T) {
	expectedStatus := &StatusResponse{
		Running:          true,
		PacketsProcessed: 200,
		NATIP:            "10.0.0.1",
	}

	server := NewServer(func() *StatusResponse { return expectedStatus })
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	client := NewClient()
	status, err := client.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}

	if status.PacketsProcessed != expectedStatus.PacketsProcessed {
		t.Errorf("PacketsProcessed: expected %d, got %d",
			expectedStatus.PacketsProcessed, status.PacketsProcessed)
	}
	if status.NATIP != expectedStatus.NATIP {
		t.Errorf("NATIP: expected %s, got %s", expectedStatus.NATIP, status.NATIP)
	}
}

func TestClientGetStatusNoServer(t *testing.T) {
	client := NewClient()
	_, err := client.GetStatus()
	if err == nil {
		t.Error("GetStatus should fail when no server is running")
	}
}

func TestConnectionInfo(t *testing.T) {
	info := ConnectionInfo{
		Protocol:     "TCP",
		InternalIP:   "10.0.0.5",
		InternalPort: 12345,
		ExternalIP:   "8.8.8.8",
		ExternalPort: 443,
		NATPort:      45000,
		State:        "ESTABLISHED",
		IdleSeconds:  30,
	}

	// Test JSON marshaling
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal ConnectionInfo: %v", err)
	}

	var decoded ConnectionInfo
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal ConnectionInfo: %v", err)
	}

	if decoded.Protocol != info.Protocol {
		t.Errorf("Protocol: expected %s, got %s", info.Protocol, decoded.Protocol)
	}
	if decoded.NATPort != info.NATPort {
		t.Errorf("NATPort: expected %d, got %d", info.NATPort, decoded.NATPort)
	}
}
