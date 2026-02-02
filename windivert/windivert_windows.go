// +build windows

package windivert

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Open opens a WinDivert handle
func Open(filter string, layer uint8, priority int16, flags uint64) (*Handle, error) {
	if err := initDLL(); err != nil {
		return nil, fmt.Errorf("failed to load WinDivert.dll: %w", err)
	}

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	ret, _, err := windivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)

	handle := syscall.Handle(ret)
	if handle == syscall.InvalidHandle {
		return nil, fmt.Errorf("WinDivertOpen failed: %v", err)
	}

	return &Handle{handle: handle}, nil
}

// Close closes the WinDivert handle
func (h *Handle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.handle == syscall.InvalidHandle {
		return nil
	}

	ret, _, err := windivertClose.Call(uintptr(h.handle))
	if ret == 0 {
		return fmt.Errorf("WinDivertClose failed: %v", err)
	}

	h.handle = syscall.InvalidHandle
	return nil
}

// Recv receives a packet
// Note: No mutex lock here to allow Close() to interrupt blocking Recv()
func (h *Handle) Recv() (*Packet, error) {
	buf := make([]byte, 65535)
	var addr Address
	var recvLen uint32

	ret, _, err := windivertRecv.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("WinDivertRecv failed: %v", err)
	}

	pkt := &Packet{
		Data:    make([]byte, recvLen),
		Address: addr,
	}
	copy(pkt.Data, buf[:recvLen])

	return pkt, nil
}

// Send sends a packet
func (h *Handle) Send(pkt *Packet) (uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var sendLen uint32

	ret, _, err := windivertSend.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&pkt.Data[0])),
		uintptr(len(pkt.Data)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&pkt.Address)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("WinDivertSend failed: %v", err)
	}

	return sendLen, nil
}

// CalcChecksums recalculates packet checksums
func CalcChecksums(data []byte, addr *Address, flags uint64) bool {
	if err := initDLL(); err != nil {
		return false
	}

	ret, _, _ := windivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)

	return ret != 0
}
