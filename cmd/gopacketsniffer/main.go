package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopacketsniffer/internal/capture"
	"gopacketsniffer/internal/display"
	"gopacketsniffer/internal/parser"
	"gopacketsniffer/internal/pcap"
	"gopacketsniffer/internal/stats"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	iface := flag.String("i", "", "Network interface to capture on (e.g. eth0)")
	verbose := flag.Bool("v", false, "Print each decoded packet")
	filter := flag.String("f", "", "BPF filter expression (e.g. \"tcp port 80\")")
	writeTo := flag.String("w", "", "Save packets to a .pcap file")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "Usage: gopacketsniffer -i <interface> [-v] [-f <filter>] [-w <file.pcap>]")
		os.Exit(1)
	}

	fd, err := capture.OpenRawSocket(*iface)
	if err != nil {
		log.Fatalf("open socket: %v", err)
	}

	if err := capture.SetPromiscuousMode(*iface, fd); err != nil {
		log.Fatalf("promiscuous mode: %v", err)
	}

	// Attach BPF filter if requested — kernel drops non-matching packets.
	if *filter != "" {
		if err := capture.AttachBPFFilter(fd, *filter); err != nil {
			log.Fatalf("BPF filter: %v", err)
		}
		log.Printf("BPF filter active: %s\n", *filter)
	}

	// Open PCAP writer if -w was given.
	var pcapWriter *pcap.Writer
	if *writeTo != "" {
		pcapWriter, err = pcap.NewWriter(*writeTo)
		if err != nil {
			log.Fatalf("pcap writer: %v", err)
		}
		log.Printf("Saving packets to %s\n", *writeTo)
	}

	log.Printf("Capturing on %s — press Ctrl+C to stop\n", *iface)

	done := make(chan struct{})
	packetChan := make(chan []byte, 4096)
	metrics := stats.New()
	var wg sync.WaitGroup

	// ── Capture goroutine ────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := capture.CaptureLoop(fd, packetChan, done); err != nil {
			log.Printf("capture error: %v", err)
		}
		close(packetChan)
	}()

	// ── Parse worker ─────────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		for frame := range packetChan {
			ts := time.Now()

			// Write raw frame to PCAP before decoding.
			if pcapWriter != nil {
				if err := pcapWriter.WritePacket(ts, frame); err != nil {
					log.Printf("pcap write: %v", err)
				}
			}

			info, err := parser.DecodePacket(frame, ts)
			if err != nil {
				metrics.RecordDrop()
				continue
			}

			// Update core metrics.
			metrics.Record(info.Protocol, info.SrcIP, info.TotalBytes)

			// Update TCP flow tracker.
			if info.Protocol == "TCP" {
				metrics.FlowTracker.Update(
					info.SrcIP, info.DstIP,
					info.SrcPort, info.DstPort,
					"TCP", info.TCPRawFlags, info.TotalBytes,
				)
			}

			// Record HTTP stats if detected.
			if info.HTTP != nil {
				metrics.RecordHTTP(info.HTTP.IsRequest, info.HTTP.StatusCode)
			}

			if *verbose {
				display.PrintPacket(info)
			}

			// Return PacketInfo to pool — must be last use of info.
			parser.PutPacketInfo(info)
		}
	}()

	// ── Display goroutine ─────────────────────────────────────────────────────
	if !*verbose {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					display.PrintStats(*iface, metrics.GetSnapshot())
				}
			}
		}()
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	close(done)
	capture.Close(fd)
	wg.Wait()

	if pcapWriter != nil {
		if err := pcapWriter.Close(); err != nil {
			log.Printf("pcap close: %v", err)
		}
	}

	snap := metrics.GetSnapshot()
	fmt.Printf("\nFinal: %d packets | %d dropped | uptime %s\n",
		snap.TotalPackets, snap.DroppedPackets, formatElapsed(snap.Elapsed))
}

func formatElapsed(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
