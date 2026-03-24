package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	host "github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	echoProtocol   = protocol.ID("/echo/1.0.0")
	defaultMessage = "hello from go-libp2p"
)

var (
	defaultServerListen = []string{
		"/ip4/0.0.0.0/tcp/4001",
		"/ip4/0.0.0.0/udp/4001/quic-v1",
		"/ip6/::/tcp/4001",
		"/ip6/::/udp/4001/quic-v1",
	}
	defaultClientListen = []string{
		"/ip4/0.0.0.0/tcp/0",
		"/ip4/0.0.0.0/udp/0/quic-v1",
		"/ip6/::/tcp/0",
		"/ip6/::/udp/0/quic-v1",
	}
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	log.SetFlags(0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(ctx, os.Args[2:])
	case "ping-client":
		err = runPingClient(ctx, os.Args[2:])
	case "echo-client":
		err = runEchoClient(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s server [--listen <multiaddr> ...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s ping-client --target <multiaddr> [--count 5] [--settle 200ms]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s echo-client --target <multiaddr> [--message text] [--settle 200ms]\n", os.Args[0])
}

func newHost(listenAddrs []string) (host.Host, error) {
	opts := make([]libp2p.Option, 0, 3)
	if len(listenAddrs) > 0 {
		opts = append(opts, libp2p.ListenAddrStrings(listenAddrs...))
	}
	opts = append(opts,
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
	)
	return libp2p.New(opts...)
}

func installServerProtocols(h host.Host) {
	ping.NewPingService(h)
	h.SetStreamHandler(echoProtocol, func(s network.Stream) {
		defer s.Close()
		if _, err := io.Copy(s, s); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("echo handler error: %v", err)
		}
	})
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var listen stringListFlag
	fs.Var(&listen, "listen", "listen multiaddr (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(listen) == 0 {
		listen = append(listen, defaultServerListen...)
	}

	h, err := newHost(listen)
	if err != nil {
		return err
	}
	defer h.Close()

	installServerProtocols(h)

	fmt.Printf("GO_PEER_ID=%s\n", h.ID())
	for _, addr := range h.Addrs() {
		fmt.Printf("GO_LISTEN_ADDR=%s/p2p/%s\n", addr, h.ID())
	}
	fmt.Println("GO_READY=1")

	<-ctx.Done()
	fmt.Println("Shutting down go-libp2p node...")
	return nil
}

func runPingClient(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("ping-client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "target multiaddr with /p2p/<peer-id>")
	count := fs.Int("count", 5, "number of pings")
	settle := fs.Duration("settle", 200*time.Millisecond, "delay after connect before starting ping")
	timeout := fs.Duration("timeout", 15*time.Second, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" && fs.NArg() > 0 {
		*target = fs.Arg(0)
	}
	if *target == "" {
		return fmt.Errorf("missing --target")
	}

	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()

	h, err := newHost(defaultClientListen)
	if err != nil {
		return err
	}
	defer h.Close()

	installServerProtocols(h)

	fmt.Printf("Local Peer ID: %s\n", h.ID())
	fmt.Printf("Dialing %s ...\n", *target)

	info, err := connect(ctx, h, *target)
	if err != nil {
		return err
	}

	fmt.Printf("Connected to %s\n", info.ID)
	time.Sleep(*settle)

	pinger := ping.NewPingService(h)
	results := pinger.Ping(ctx, info.ID)
	for i := 1; i <= *count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case res, ok := <-results:
			if !ok {
				return fmt.Errorf("ping stream ended early")
			}
			if res.Error != nil {
				return fmt.Errorf("ping failed: %w", res.Error)
			}
			us := res.RTT.Microseconds()
			fmt.Printf("ping %d/%d: RTT = %d us (%.2f ms)\n", i, *count, us, float64(us)/1000.0)
		}
	}

	fmt.Println("Done.")
	return nil
}

func runEchoClient(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("echo-client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "target multiaddr with /p2p/<peer-id>")
	message := fs.String("message", defaultMessage, "message to send")
	settle := fs.Duration("settle", 200*time.Millisecond, "delay after connect before opening echo stream")
	timeout := fs.Duration("timeout", 15*time.Second, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" && fs.NArg() > 0 {
		*target = fs.Arg(0)
	}
	if *message == defaultMessage && fs.NArg() > 1 {
		*message = fs.Arg(1)
	}
	if *target == "" {
		return fmt.Errorf("missing --target")
	}

	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()

	h, err := newHost(defaultClientListen)
	if err != nil {
		return err
	}
	defer h.Close()

	installServerProtocols(h)

	fmt.Printf("Local Peer ID: %s\n", h.ID())
	fmt.Printf("Dialing %s ...\n", *target)
	fmt.Printf("Sending: %s\n", *message)

	info, err := connect(ctx, h, *target)
	if err != nil {
		return err
	}

	fmt.Printf("Connected to %s\n", info.ID)
	time.Sleep(*settle)

	stream, err := h.NewStream(ctx, info.ID, echoProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()

	if _, err := io.WriteString(stream, *message); err != nil {
		return err
	}
	if cw, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	reply := make([]byte, len(*message))
	if _, err := io.ReadFull(stream, reply); err != nil {
		return err
	}

	fmt.Printf("Echoed: %s\n", string(reply))
	return nil
}

func connect(ctx context.Context, h host.Host, target string) (*peer.AddrInfo, error) {
	maddr, err := ma.NewMultiaddr(target)
	if err != nil {
		return nil, err
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, err
	}

	if err := h.Connect(ctx, *info); err != nil {
		return nil, err
	}

	return info, nil
}
