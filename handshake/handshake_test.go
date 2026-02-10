package handshake_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/codahale/newplex/handshake"
	"github.com/codahale/newplex/internal/testdata"
)

func TestInitiate(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		drbg := testdata.New("newplex handshake")
		dIS, _ := drbg.KeyPair()

		finish, request, err := handshake.Initiate("example", dIS, drbg.Reader())
		if err != nil {
			t.Fatalf("Initiate failed: %v", err)
		}

		if len(request) != handshake.RequestSize {
			t.Errorf("expected request size %d, got %d", handshake.RequestSize, len(request))
		}

		if finish == nil {
			t.Error("expected finish function, got nil")
		}
	})

	t.Run("rand failure", func(t *testing.T) {
		drbg := testdata.New("newplex handshake")
		dIS, _ := drbg.KeyPair()

		_, _, err := handshake.Initiate("example", dIS, &errReader{})
		if err == nil {
			t.Error("expected error from rand failure, got nil")
		}
	})
}

func TestRespond(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		drbg := testdata.New("newplex handshake")
		dRS, _ := drbg.KeyPair()
		_, qIE := drbg.KeyPair()
		request := qIE.Bytes()

		finish, response, err := handshake.Respond("example", drbg.Reader(), dRS, request)
		if err != nil {
			t.Fatalf("Respond failed: %v", err)
		}

		if len(response) != handshake.ResponseSize {
			t.Errorf("expected response size %d, got %d", handshake.ResponseSize, len(response))
		}

		if finish == nil {
			t.Error("expected finish function, got nil")
		}
	})

	t.Run("invalid request", func(t *testing.T) {
		drbg := testdata.New("newplex handshake")
		dRS, _ := drbg.KeyPair()
		request := make([]byte, handshake.RequestSize)
		for i := range request {
			request[i] = 0xff
		}

		_, _, err := handshake.Respond("example", drbg.Reader(), dRS, request)
		if !errors.Is(err, handshake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})

	t.Run("rand failure", func(t *testing.T) {
		drbg := testdata.New("newplex handshake")
		dRS, _ := drbg.KeyPair()
		_, qIE := drbg.KeyPair()
		request := qIE.Bytes()

		_, _, err := handshake.Respond("example", &errReader{}, dRS, request)
		if err == nil {
			t.Error("expected error from rand failure, got nil")
		}
	})
}

func TestHandshake(t *testing.T) {
	drbg := testdata.New("newplex handshake")
	dIS, qIS := drbg.KeyPair()
	dRS, qRS := drbg.KeyPair()

	t.Run("successful round trip", func(t *testing.T) {
		iFinish, req, err := handshake.Initiate("example", dIS, drbg.Reader())
		if err != nil {
			t.Fatal(err)
		}

		rFinish, resp, err := handshake.Respond("example", drbg.Reader(), dRS, req)
		if err != nil {
			t.Fatal(err)
		}

		iSend, iRecv, gotQRS, conf, err := iFinish(resp)
		if err != nil {
			t.Fatalf("initiator finish failed: %v", err)
		}

		if gotQRS.Equal(qRS) == 0 {
			t.Errorf("mismatched responder public key")
		}

		rSend, rRecv, gotQIS, err := rFinish(conf)
		if err != nil {
			t.Fatalf("responder finish failed: %v", err)
		}

		if gotQIS.Equal(qIS) == 0 {
			t.Errorf("mismatched initiator public key")
		}

		// Verify keys derived from both ends match
		if !bytes.Equal(iSend.Derive("test", nil, 32), rRecv.Derive("test", nil, 32)) {
			t.Error("mismatched iSend/rRecv")
		}
		if !bytes.Equal(rSend.Derive("test", nil, 32), iRecv.Derive("test", nil, 32)) {
			t.Error("mismatched rSend/iRecv")
		}
	})

	t.Run("tampered response", func(t *testing.T) {
		iFinish, req, _ := handshake.Initiate("example", dIS, drbg.Reader())
		_, resp, _ := handshake.Respond("example", drbg.Reader(), dRS, req)

		resp[len(resp)-1] ^= 1 // tamper with the tag

		_, _, _, _, err := iFinish(resp)
		if !errors.Is(err, handshake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})

	t.Run("tampered confirmation", func(t *testing.T) {
		iFinish, req, _ := handshake.Initiate("example", dIS, drbg.Reader())
		rFinish, resp, _ := handshake.Respond("example", drbg.Reader(), dRS, req)
		_, _, _, conf, _ := iFinish(resp)

		conf[len(conf)-1] ^= 1 // tamper with the tag

		_, _, _, err := rFinish(conf)
		if !errors.Is(err, handshake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})

	t.Run("domain mismatch", func(t *testing.T) {
		iFinish, req, _ := handshake.Initiate("domain A", dIS, drbg.Reader())
		_, resp, _ := handshake.Respond("domain B", drbg.Reader(), dRS, req)

		_, _, _, _, err := iFinish(resp)
		if !errors.Is(err, handshake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})

	t.Run("invalid responder ephemeral key", func(t *testing.T) {
		iFinish, req, _ := handshake.Initiate("example", dIS, drbg.Reader())
		_, resp, _ := handshake.Respond("example", drbg.Reader(), dRS, req)

		copy(resp[:32], make([]byte, 32)) // invalid Ristretto point

		_, _, _, _, err := iFinish(resp)
		if !errors.Is(err, handshake.ErrInvalidHandshake) {
			t.Errorf("expected ErrInvalidHandshake, got %v", err)
		}
	})
}

type errReader struct{}

func (e *errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("reader error")
}

func Example() {
	drbg := testdata.New("newplex handshake")
	dRS, _ := drbg.KeyPair()
	dIS, _ := drbg.KeyPair()

	// Initiator starts a handshake.
	initiatorFinish, out, err := handshake.Initiate("example", dIS, drbg.Reader())
	if err != nil {
		panic(err)
	}

	// Initiator sends out to the responder.

	// Responder accepts the handshake and responds.
	responderFinish, out, err := handshake.Respond("example", drbg.Reader(), dRS, out)
	if err != nil {
		panic(err)
	}

	// Responder sends out to the initiator.

	// Initiator finishes the handshake.
	iSend, iRecv, qRS, out, err := initiatorFinish(out)
	if err != nil {
		panic(err)
	}
	fmt.Printf("responder: %x\n", qRS.Bytes())

	// Initiator sends out to the responder.

	// Responder finishes the handshake.
	rSend, rRecv, qIS, err := responderFinish(out)
	if err != nil {
		panic(err)
	}
	fmt.Printf("initiator: %x\n", qIS.Bytes())

	// Now both the initiator and sender have two synchronized protocols: one for sending, one for receiving.
	fmt.Printf("responder send: %x\n", rSend.Derive("test", nil, 16))
	fmt.Printf("initiator recv: %x\n", iRecv.Derive("test", nil, 16))
	fmt.Printf("initiator send: %x\n", iSend.Derive("test", nil, 16))
	fmt.Printf("responder recv: %x\n", rRecv.Derive("test", nil, 16))

	// Output:
	// responder: 8c7d6822f5ad36aebf115ef5c90ce95147f40ed6bf3dd4953cf92827fbf72c7c
	// initiator: 768d2a68dc4a6f3c8e8a7737044d3d80b6ece637da643bf61abc62893b364575
	// responder send: ef46331e27b2264707dd34bfd22e1b6d
	// initiator recv: ef46331e27b2264707dd34bfd22e1b6d
	// initiator send: b69de2cc2ca3f4680a0a28321788b306
	// responder recv: b69de2cc2ca3f4680a0a28321788b306
}
