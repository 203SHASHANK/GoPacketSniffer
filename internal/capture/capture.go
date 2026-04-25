// Package capture handles raw socket creation and packet capture on Linux
// using AF_PACKET sockets (requires root / CAP_NET_RAW).
package capture

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenRawSocket creates an AF_PACKET raw socket bound to the given interface.
// It returns the file descriptor or an error.
//
// AF_PACKET gives access to raw Ethernet frames before the kernel processes them.
// Reference: man 7 packet
func OpenRawSocket(interfaceName string) (int, error) {
	// ETH_P_ALL (0x0003 in host byte order) captures every Ethernet frame type.
	// htons converts to network byte order.
	ethPAll := htons(unix.ETH_P_ALL)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(ethPAll))
	if err != nil {
		return 0, fmt.Errorf("socket(AF_PACKET): %w (are you root?)", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("interface %q not found: %w", interfaceName, err)
	}

	// Bind the socket to the specific interface so we only receive its traffic.
	addr := unix.SockaddrLinklayer{
		Protocol: ethPAll,
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("bind to %s: %w", interfaceName, err)
	}

	return fd, nil
}

// SetPromiscuousMode enables promiscuous mode on the interface so the NIC
// passes all frames to the socket, not just those addressed to this host.
func SetPromiscuousMode(interfaceName string, fd int) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", interfaceName, err)
	}

	// packet_mreq tells the kernel to add/drop the interface from a multicast
	// group; PACKET_MR_PROMISC enables promiscuous mode.
	mreq := unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	err = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	if err != nil {
		return fmt.Errorf("setsockopt PACKET_MR_PROMISC: %w", err)
	}
	return nil
}

// CaptureLoop reads raw Ethernet frames from fd and sends copies to packetChan.
// It returns when the done channel is closed or a fatal read error occurs.
//
// Each packet is a fresh []byte slice — the caller owns the memory.
func CaptureLoop(fd int, packetChan chan<- []byte, done <-chan struct{}) error {
	// 65535 bytes is the maximum Ethernet jumbo frame size.
	const maxFrameSize = 65535
	buf := make([]byte, maxFrameSize)

	for {
		select {
		case <-done:
			return nil
		default:
		}

		bytesRead, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-done:
				return nil // shutdown in progress — not an error
			default:
				return fmt.Errorf("recvfrom: %w", err)
			}
		}

		// Copy the frame so the ring buffer owns independent memory.
		frame := make([]byte, bytesRead)
		copy(frame, buf[:bytesRead])

		select {
		case packetChan <- frame:
		default:
			// Channel full — drop packet rather than block the capture goroutine.
		}
	}
}

// Close releases the raw socket file descriptor.
func Close(fd int) {
	unix.Close(fd)
}

// htons converts a uint16 from host to network byte order (big-endian).
func htons(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return uint16(b[0])<<8 | uint16(b[1])
}
