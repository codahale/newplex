// Command ae_reverse_proxy is a Newplex/Ristretto255 authenticated encryption reverse proxy which terminates plaintext
// connections and makes handshake/aestream connections.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"

	"github.com/codahale/newplex/aestream"
	"github.com/codahale/newplex/handshake"
	"github.com/gtank/ristretto255"
)

//nolint:funlen // it's complicated
func main() {
	var (
		listen  = flag.String("listen", "127.0.0.1:5050", "the address to listen on")
		connect = flag.String("connect", "127.0.0.1:4040", "the address to connect to")
	)

	flag.Parse()
	log := slog.New(slog.Default().Handler())

	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	dRS, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
	qRS := ristretto255.NewIdentityElement().ScalarBaseMult(dRS)
	log.Info("starting", "pk", hex.EncodeToString(qRS.Bytes()))

	listenConfig := new(net.ListenConfig)
	listener, err := listenConfig.Listen(context.Background(), "tcp", *listen)
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
			log.Info("accepted new connection", "addr", conn.RemoteAddr())
			defer func() {
				_ = conn.Close()
				log.Info("closed connection")
			}()

			request := make([]byte, handshake.RequestSize)
			_, err = io.ReadFull(conn, request)
			if err != nil {
				log.Error("error connecting", "err", err)
				return
			}
			finish, response, err := handshake.Respond("newplex.ae_proxy", rand.Reader, dRS, request)
			if err != nil {
				log.Error("error connecting", "err", err)
				return
			}
			_, err = conn.Write(response)
			if err != nil {
				log.Error("error connecting", "err", err)
				return
			}
			confirmation := make([]byte, handshake.ConfirmationSize)
			_, err = io.ReadFull(conn, confirmation)
			if err != nil {
				log.Error("error connecting", "err", err)
				return
			}
			send, recv, qIS, err := finish(confirmation)
			if err != nil {
				log.Error("error connecting", "err", err)
				return
			}
			log.Info("handshake established", "pk", hex.EncodeToString(qIS.Bytes()))

			r := aestream.NewReader(recv, conn, aestream.MaxBlockSize)
			w := aestream.NewWriter(send, conn, aestream.MaxBlockSize)
			defer func() {
				log.Info("closing aestream")
				err = w.Close()
				if err != nil {
					log.Error("error closing aestream", "err", err)
				}
			}()

			log.Info("connecting", "addr", *connect)
			dialer := new(net.Dialer)
			client, err := dialer.DialContext(context.Background(), "tcp", *connect)
			if err != nil {
				log.Error("error connecting", "err", err)
				return
			}
			defer func() {
				_ = client.Close()
			}()

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				if _, err := io.Copy(client, r); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Error("error reading from client", "err", err)
				}
				cancel()
			}()
			go func() {
				if _, err := io.Copy(w, client); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Error("error writing to server", "err", err)
				}
				cancel()
			}()
			<-ctx.Done()
		}()
	}
}
