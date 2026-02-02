// Package windivert provides Go bindings for WinDivert 2.x
package windivert

import (
	"sync"
	"syscall"
)

var (
	windivertDLL            *syscall.DLL
	windivertOpen           *syscall.Proc
	windivertClose          *syscall.Proc
	windivertRecv           *syscall.Proc
	windivertSend           *syscall.Proc
	windivertHelperCalcChecksums *syscall.Proc
	
	once sync.Once
	initErr error
)

// Layer constants
const (
	LayerNetwork        = 0
	LayerNetworkForward = 1
	LayerFlow           = 2
	LayerSocket         = 3
	LayerReflect        = 4
)

// Flag constants
const (
	FlagDefault   = 0x0000
	FlagSniff     = 0x0001
	FlagDrop      = 0x0002
	FlagRecvOnly  = 0x0004
	FlagSendOnly  = 0x0008
	FlagNoInstall = 0x0010
	FlagFragments = 0x0020
)

// Address represents WinDivert address structure
type Address struct {
	Timestamp int64
	Layer     uint8
	Event     uint8
	Sniffed   uint8
	Outbound  uint8
	Loopback  uint8
	Impostor  uint8
	IPv6      uint8
	IPChecksum uint8
	TCPChecksum uint8
	UDPChecksum uint8
	Reserved1 uint8
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
}

// Handle represents a WinDivert handle
type Handle struct {
	handle syscall.Handle
	mu     sync.Mutex
}

// Packet represents a captured packet with its address
type Packet struct {
	Data    []byte
	Address Address
}

func initDLL() error {
	once.Do(func() {
		windivertDLL, initErr = syscall.LoadDLL("WinDivert.dll")
		if initErr != nil {
			return
		}
		
		windivertOpen, initErr = windivertDLL.FindProc("WinDivertOpen")
		if initErr != nil {
			return
		}
		windivertClose, initErr = windivertDLL.FindProc("WinDivertClose")
		if initErr != nil {
			return
		}
		windivertRecv, initErr = windivertDLL.FindProc("WinDivertRecv")
		if initErr != nil {
			return
		}
		windivertSend, initErr = windivertDLL.FindProc("WinDivertSend")
		if initErr != nil {
			return
		}
		windivertHelperCalcChecksums, initErr = windivertDLL.FindProc("WinDivertHelperCalcChecksums")
	})
	return initErr
}
