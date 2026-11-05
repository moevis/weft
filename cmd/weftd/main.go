package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"weft/internal/hub"
)

func main() {
	listen := flag.String("listen", ":8443", "relay TCP listen address")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "weftd: unexpected arguments")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", *listen)
	if err == nil {
		fmt.Fprintln(os.Stderr, "Listening ·", listener.Addr())
		err = hub.Serve(ctx, listener)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "weftd:", err)
		os.Exit(1)
	}
}
