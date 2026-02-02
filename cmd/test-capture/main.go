// Test program to verify WinDivert captures forwarded packets
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/igjeong/hyper-nat/windivert"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// Simple filter: capture all forwarded IPv4 packets
	filter := "true"

	logger.Printf("Opening WinDivert with filter: %s (LayerNetworkForward)", filter)

	handle, err := windivert.Open(filter, windivert.LayerNetworkForward, 0, 0)
	if err != nil {
		logger.Fatalf("Failed to open WinDivert: %v", err)
	}
	defer handle.Close()

	logger.Printf("WinDivert opened successfully. Waiting for forwarded packets...")
	logger.Printf("Try to send traffic from VM (172.17.240.21) to external IPs")

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Printf("Shutting down...")
		handle.Close()
		os.Exit(0)
	}()

	count := 0
	for {
		pkt, err := handle.Recv()
		if err != nil {
			logger.Printf("Recv error: %v", err)
			continue
		}

		count++

		// Parse basic IP info
		if len(pkt.Data) >= 20 {
			srcIP := net.IP(pkt.Data[12:16])
			dstIP := net.IP(pkt.Data[16:20])
			proto := pkt.Data[9]

			protoName := "OTHER"
			switch proto {
			case 6:
				protoName = "TCP"
			case 17:
				protoName = "UDP"
			case 1:
				protoName = "ICMP"
			}

			logger.Printf("[%d] %s %s → %s (len=%d, outbound=%d)",
				count, protoName, srcIP, dstIP, len(pkt.Data), pkt.Address.Outbound)
		}

		// Forward the packet as-is
		_, err = handle.Send(pkt)
		if err != nil {
			logger.Printf("Send error: %v", err)
		}
	}
}
