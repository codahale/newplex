// Command pt_echo listens for plaintext connections, reads data, and writes the same data back.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
)

func main() {
	log := slog.New(slog.Default().Handler())

	addr := flag.String("addr", "127.0.0.1:4040", "the address to listen on")

	listenConfig := new(net.ListenConfig)
	listener, err := listenConfig.Listen(context.Background(), "tcp", *addr)
	if err != nil {
		panic(err)
	}
	log.Info("listening", "addr", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error("failed to accept connection", "err", err)
			continue
		}

		go func() {
			log.Info("accepted new connection")
			defer func() {
				_ = conn.Close()
				log.Info("closed connection")
			}()

			for {
				buf := make([]byte, 1024)
				size, err := conn.Read(buf)
				if err != nil {
					return
				}
				data := buf[:size]
				if _, err := conn.Write(data); err != nil {
					log.Error("error writing data", "err", err)
				}
			}
		}()
	}
}
