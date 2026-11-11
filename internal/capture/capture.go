// Package capture handles raw socket creation and packet capture on Linux
// using AF_PACKET sockets (requires root or CAP_NET_RAW).
package capture

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxFrameSize is the size of the receive buffer. Regular Ethernet frames are
// at most ~1514 bytes and jumbo frames ~9 KB, but with GRO/TSO offloading the
// kernel can hand us aggregated frames of up to 64 KB.
const maxFrameSize = 65535

// readTimeout bounds how long Recvfrom may block. Closing a socket from
// another goroutine does not reliably wake a blocked recvfrom(2) on Linux, so
// the capture loop wakes up on this interval to check whether it should stop.
const readTimeout = 200 * time.Millisecond

// Frame is a single captured Ethernet frame together with the time it was
// read from the socket.
type Frame struct {
	Data      []byte
	Timestamp time.Time
}

// OpenRawSocket creates an AF_PACKET raw socket bound to the given interface
// and returns its file descriptor.
//
// AF_PACKET gives access to complete Ethernet frames, including the link
// layer header. See packet(7).
func OpenRawSocket(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return -1, fmt.Errorf("interface %q not found: %w", interfaceName, err)
	}

	// ETH_P_ALL asks for every EtherType. The protocol argument must be in
	// network byte order, hence htons.
	ethPAll := htons(unix.ETH_P_ALL)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(ethPAll))
	if err != nil {
		return -1, fmt.Errorf("socket(AF_PACKET): %w (are you root?)", err)
	}

	// Bind to the interface so we only receive its traffic. Without the bind
	// the socket would see frames from every interface on the host.
	addr := unix.SockaddrLinklayer{
		Protocol: ethPAll,
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &addr); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("bind to %s: %w", interfaceName, err)
	}

	// On loopback every packet passes the socket twice, once on its way out
	// and once on its way back in. Ask the kernel to skip the outgoing copy
	// so each packet is seen exactly once. The option needs Linux 4.20+; on
	// older kernels the duplicates remain, which is harmless.
	if iface.Flags&net.FlagLoopback != 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
	}

	// A receive timeout lets CaptureLoop notice a shutdown request even when
	// no traffic is arriving.
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	return fd, nil
}

// SetPromiscuousMode enables promiscuous mode on the interface so the NIC
// passes all frames to the socket, not just those addressed to this host.
//
// The membership is tied to the socket: the kernel turns promiscuous mode
// off again automatically when fd is closed.
func SetPromiscuousMode(interfaceName string, fd int) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", interfaceName, err)
	}

	mreq := unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		return fmt.Errorf("setsockopt PACKET_MR_PROMISC: %w", err)
	}
	return nil
}

// CaptureLoop reads raw Ethernet frames from fd and sends them to frames.
// It returns nil once done is closed, or an error if the socket fails.
//
// The send is non-blocking: when the consumer falls behind and the channel is
// full, the frame is discarded and onDrop (if non-nil) is called, so the
// socket keeps being drained instead of stalling the capture.
//
// Every Frame carries its own freshly allocated buffer, so the receiver owns
// the memory and may keep it for as long as it likes.
func CaptureLoop(fd int, frames chan<- Frame, done <-chan struct{}, onDrop func()) error {
	buf := make([]byte, maxFrameSize)

	for {
		select {
		case <-done:
			return nil
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// EAGAIN is the receive timeout expiring and EINTR is a signal
			// interrupting the call. Neither is a failure; loop around and
			// re-check done.
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n == 0 {
			continue
		}
		ts := time.Now()

		// buf is reused for the next read, so the frame needs its own copy.
		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case frames <- Frame{Data: data, Timestamp: ts}:
		default:
			if onDrop != nil {
				onDrop()
			}
		}
	}
}

// Close releases the raw socket file descriptor.
func Close(fd int) error {
	return unix.Close(fd)
}

// htons converts a uint16 from host to network (big-endian) byte order.
// It reads the value's bytes in memory order and reassembles them as a
// big-endian number, which swaps on little-endian CPUs and is a no-op on
// big-endian ones.
func htons(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return uint16(b[0])<<8 | uint16(b[1])
}
