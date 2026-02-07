// Command ae_proxy is a Newplex/Ristretto255 authenticated encryption proxy which terminates handshake/aestream
// connections and makes plaintext connections.
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
	"github.com/codahale/newplex/aestream/ecdhratchet"
	"github.com/codahale/newplex/handshake"
	"github.com/gtank/ristretto255"
)

//nolint:funlen // it's just complicated
func main() {
	var (
		listen  = flag.String("listen", "127.0.0.1:6060", "the address to listen on")
		connect = flag.String("connect", "127.0.0.1:5050", "the address to connect to")
	)
	flag.Parse()

	log := slog.New(slog.Default().Handler())

	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	dIS, _ := ristretto255.NewScalar().SetUniformBytes(b[:])
	qIS := ristretto255.NewIdentityElement().ScalarBaseMult(dIS)
	log.Info("starting", "pk", hex.EncodeToString(qIS.Bytes()))

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
				log.Info("closed connection", "addr", conn.RemoteAddr())
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

			finish, request, err := handshake.Initiate("newplex.ae_proxy", dIS, rand.Reader)
			if err != nil {
				panic(err)
			}
			_, err = client.Write(request)
			if err != nil {
				panic(err)
			}
			response := make([]byte, handshake.ResponseSize)
			_, err = io.ReadFull(client, response)
			if err != nil {
				panic(err)
			}
			send, recv, qRS, confirmation, err := finish(response)
			if err != nil {
				panic(err)
			}
			log.Info("handshake established", "pk", hex.EncodeToString(qRS.Bytes()))
			_, err = client.Write(confirmation)
			if err != nil {
				panic(err)
			}

			ratchet := &ecdhratchet.Ratchet{
				Receiver: dIS,
				Sender:   qRS,
			}
			r := aestream.NewReader(recv, client, aestream.MaxBlockSize)
			r.Ratchet = ratchet
			w := aestream.NewWriter(send, client, aestream.MaxBlockSize)
			w.Ratchet = ratchet
			defer func() {
				log.Info("closing aestream")
				err = w.Close()
				if err != nil {
					log.Error("error closing aestream", "err", err)
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				if _, err := io.Copy(w, conn); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Error("error reading from client", "err", err)
				}
				cancel()
			}()
			go func() {
				if _, err := io.Copy(conn, r); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Error("error writing to server", "err", err)
				}
				cancel()
			}()
			<-ctx.Done()
		}()
	}
}
