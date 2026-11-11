// Command gopacketsniffer captures live traffic from a network interface
// through a raw AF_PACKET socket, decodes it, and shows either a statistics
// dashboard or a per-packet listing.
package main

import (
	"errors"
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

const (
	// frameQueueSize is how many captured frames may wait for the parser
	// before the capture loop starts dropping.
	frameQueueSize = 4096

	// refreshInterval is how often the dashboard is redrawn. It is also the
	// window over which the current bandwidth is averaged.
	refreshInterval = time.Second
)

// options holds the parsed command-line flags.
type options struct {
	iface   string
	verbose bool
	filter  string
	writeTo string
}

func main() {
	var opts options
	showVersion := flag.Bool("version", false, "Print the version and exit")
	flag.StringVar(&opts.iface, "i", "", "Network interface to capture on (e.g. eth0)")
	flag.BoolVar(&opts.verbose, "v", false, "Print each decoded packet instead of the dashboard")
	flag.StringVar(&opts.filter, "f", "", `Capture filter (e.g. "tcp port 80", "host 10.0.0.1")`)
	flag.StringVar(&opts.writeTo, "w", "", "Also save captured packets to this .pcap file")
	flag.Usage = func() {
		_, _ = fmt.Fprintln(flag.CommandLine.Output(),
			"Usage: gopacketsniffer -i <interface> [-v] [-f <filter>] [-w <file.pcap>]")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("gopacketsniffer", version)
		return
	}
	if opts.iface == "" || flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "gopacketsniffer:", err)
		os.Exit(1)
	}
}

// run sets up the capture pipeline and blocks until the user interrupts it
// or the capture fails.
//
// The pipeline has three goroutines:
//
//	capture  reads frames from the socket into a buffered channel
//	parse    decodes each frame and updates the statistics
//	display  redraws the dashboard once per refreshInterval
func run(opts options) error {
	fd, err := capture.OpenRawSocket(opts.iface)
	if err != nil {
		return fmt.Errorf("open socket: %w", err)
	}
	defer func() {
		if err := capture.Close(fd); err != nil {
			log.Printf("close socket: %v", err)
		}
	}()

	if err := capture.SetPromiscuousMode(opts.iface, fd); err != nil {
		return fmt.Errorf("promiscuous mode: %w", err)
	}

	if opts.filter != "" {
		if err := capture.AttachBPFFilter(fd, opts.filter); err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		log.Printf("BPF filter active: %s", opts.filter)
	}

	var pcapWriter *pcap.Writer
	if opts.writeTo != "" {
		pcapWriter, err = pcap.NewWriter(opts.writeTo)
		if err != nil {
			return err
		}
		log.Printf("Saving packets to %s", opts.writeTo)
	}

	// Register for signals before any goroutine starts so an early Ctrl+C
	// still goes through the orderly shutdown below.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	log.Printf("Capturing on %s (Ctrl+C to stop)", opts.iface)

	var (
		wg         sync.WaitGroup
		done       = make(chan struct{}) // closed to stop every goroutine
		frames     = make(chan capture.Frame, frameQueueSize)
		captureErr = make(chan error, 1)
		metrics    = stats.New()
	)

	// Capture: socket -> frames channel. Closing the channel on exit is what
	// lets the parse goroutine finish once it has drained the queue.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(frames)
		captureErr <- capture.CaptureLoop(fd, frames, done, metrics.RecordDrop)
	}()

	// Parse: frames channel -> statistics (and pcap file / verbose output).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for frame := range frames {
			// Save the raw frame first so the file also contains packets
			// the decoder rejects.
			if pcapWriter != nil {
				if err := pcapWriter.WritePacket(frame.Timestamp, frame.Data); err != nil {
					// Typically a full disk. Report once and stop writing
					// instead of logging the same failure per packet.
					log.Printf("pcap write failed, no further packets will be saved: %v", err)
					if err := pcapWriter.Close(); err != nil {
						log.Printf("pcap close: %v", err)
					}
					pcapWriter = nil
				}
			}
			processFrame(frame, metrics, opts.verbose)
		}
	}()

	// Display: periodic dashboard. Verbose mode prints per packet instead.
	if !opts.verbose {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					display.PrintStats(opts.iface, version, metrics.GetSnapshot())
				}
			}
		}()
	}

	// Wait for a signal, or for the capture loop to give up on its own
	// (for example when the interface disappears).
	var runErr error
	select {
	case <-sigCh:
		fmt.Println("\nShutting down...")
	case err := <-captureErr:
		if err != nil {
			runErr = fmt.Errorf("capture: %w", err)
		}
	}

	// Shutdown order matters: stop the goroutines, wait until the parser has
	// drained the queue, and only then close the pcap file it writes to.
	close(done)
	wg.Wait()

	if pcapWriter != nil {
		if err := pcapWriter.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("pcap close: %w", err))
		}
	}

	snap := metrics.GetSnapshot()
	fmt.Printf("\nFinal: %d packets | %d dropped | uptime %s\n",
		snap.TotalPackets, snap.DroppedPackets, display.FormatDuration(snap.Elapsed))

	return runErr
}

// processFrame decodes one frame and feeds the result into the statistics.
func processFrame(frame capture.Frame, metrics *stats.Statistics, verbose bool) {
	info, err := parser.DecodePacket(frame.Data, frame.Timestamp)
	if err != nil {
		// Truncated or malformed frame.
		metrics.RecordDrop()
		return
	}
	// info comes from a pool and must not be used after this function.
	defer parser.PutPacketInfo(info)

	metrics.Record(info.Protocol, info.SrcIP, info.TotalBytes)

	// Later IP fragments have no TCP header, so they cannot be matched to a
	// flow or advance its state.
	if info.Protocol == "TCP" && !info.IsFragment {
		metrics.FlowTracker.Update(
			info.SrcIP, info.DstIP,
			info.SrcPort, info.DstPort,
			info.Protocol, info.TCPRawFlags, info.TotalBytes,
		)
	}

	if info.HTTP != nil {
		metrics.RecordHTTP(info.HTTP.IsRequest, info.HTTP.StatusCode)
	}

	if verbose {
		display.PrintPacket(info)
	}
}
