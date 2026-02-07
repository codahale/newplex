// Command pt_connect makes a plaintext connection to a server, writes stdin to the server, and reads data to stdout.
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
)

func main() {
	log := slog.New(slog.Default().Handler())

	addr := flag.String("addr", "127.0.0.1:6060", "the address to connect to")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	log.InfoContext(ctx, "connecting", "addr", *addr)
	dialer := new(net.Dialer)
	conn, err := dialer.DialContext(ctx, "tcp", *addr)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = conn.Close()
		log.Info("closed connection")
	}()

	go func() {
		if _, err := io.Copy(conn, os.Stdin); err != nil {
			log.ErrorContext(ctx, "error reading from stdin", "err", err)
		}
		cancel()
	}()
	go func() {
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			log.ErrorContext(ctx, "error writing to stdout", "err", err)
		}
		cancel()
	}()
	<-ctx.Done()
}
