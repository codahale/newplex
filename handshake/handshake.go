// Package handshake implements a mutually-authenticated static-ephemeral handshake using Ristretto255 and Newplex.
//
// This handshake provides mutual authentication, forward secrecy, and key compromise impersonation resistance for both
// initiator and responder. It is equivalent to the "XX" handshake from the [Noise Protocol Framework]:
//
//	XX:
//	-> e
//	<- e, ee, s, es
//	-> s, se
//
// [Noise Protocol Framework]: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
package handshake

import (
	"errors"
	"io"

	"github.com/codahale/newplex"
	"github.com/gtank/ristretto255"
)

const (
	// RequestSize is the size, in bytes, of the initiator's request.
	RequestSize = 32
	// ResponseSize is the size, in bytes, of the responder's response.
	ResponseSize = 32 + 32 + newplex.TagSize
	// ConfirmationSize is the size, in bytes, of the initiator's confirmation.
	ConfirmationSize = 32 + newplex.TagSize
)

// ErrInvalidHandshake is returned when some aspect of the handshake is cryptographically invalid.
var ErrInvalidHandshake = errors.New("newplex/handshake: invalid handshake")

// InitiatorFinish is a callback which accepts a payload from a responder and completes the handshake, returning a pair
// of keyed protocols for sending and receiving, plus the responder's static public key.
type InitiatorFinish = func(in []byte) (send, recv *newplex.Protocol, qRS *ristretto255.Element, out []byte, err error)

// Initiate starts the handshake from the initiator role, returning a finish function, a payload, and potentially an
// error. If no error is returned, the payload should be transmitted to the responder.
func Initiate(domain string, dIS *ristretto255.Scalar, rand io.Reader) (finish InitiatorFinish, request []byte, err error) {
	// Initialize a protocol.
	p := newplex.NewProtocol(domain)

	// Generate an ephemeral key pair.
	var r [64]byte
	if _, err := io.ReadFull(rand, r[:]); err != nil {
		return nil, nil, err
	}
	dIE, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qIE := ristretto255.NewIdentityElement().ScalarBaseMult(dIE)
	request = qIE.Bytes()

	// Mix the initiator's ephemeral public key into the protocol.
	p.Mix("ie", request)

	// Wait for the responder's response.
	finish = func(response []byte) (send, recv *newplex.Protocol, qRS *ristretto255.Element, confirmation []byte, err error) {
		qIS := ristretto255.NewIdentityElement().ScalarBaseMult(dIS)

		// Decode the responder's ephemeral public key.
		qRE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(response[:32])
		if qRE == nil {
			return nil, nil, nil, nil, ErrInvalidHandshake
		}

		// Mix in the responder's ephemeral public key.
		p.Mix("re", qRE.Bytes())

		// Calculate and mix in the ephemeral-ephemeral shared secret.
		iErE := ristretto255.NewIdentityElement().ScalarMult(dIE, qRE)
		p.Mix("ie-re", iErE.Bytes())

		// Open the responder's static public key.
		response, err = p.Open("rs", nil, response[32:])
		if err != nil {
			return nil, nil, nil, nil, ErrInvalidHandshake
		}

		// Decode the responder's static public key.
		qRS, _ = ristretto255.NewIdentityElement().SetCanonicalBytes(response)
		if qRS == nil {
			return nil, nil, nil, nil, ErrInvalidHandshake
		}

		// Calculate and mix in the ephemeral-static shared secret.
		iErS := ristretto255.NewIdentityElement().ScalarMult(dIE, qRS)
		p.Mix("ie-rs", iErS.Bytes())

		// Seal the initiator's static public key.
		confirmation = p.Seal("is", nil, qIS.Bytes())

		// Calculate and mix in the static-ephemral shared secret.
		iSrE := ristretto255.NewIdentityElement().ScalarMult(dIS, qRE)
		p.Mix("is-re", iSrE.Bytes())

		// Fork the protocol into recv and send clones.
		a, b := p.Clone(), p.Clone()
		send, recv = &a, &b
		send.Mix("sender", []byte("initiator"))
		recv.Mix("sender", []byte("responder"))

		// Return the forked protocols and the confirmation.
		return send, recv, qRS, confirmation, nil
	}

	// Return the finish function and the initiate message.
	return finish, request, nil
}

// ResponderFinish is a callback which accepts a payload from an initiator and completes the handshake, returning a pair
// of keyed protocols for sending and receiving, plus the initiator's static public key.
type ResponderFinish = func(confirmation []byte) (send, recv *newplex.Protocol, qIS *ristretto255.Element, err error)

// Respond accepts the handshake from the responder's role, given a domain separation string, a source of random data,
// a static private key, and the initiator's payload. Returns a finish function and a payload to be transmitted to the
// initiator.
func Respond(domain string, rand io.Reader, dRS *ristretto255.Scalar, request []byte) (finish ResponderFinish, response []byte, err error) {
	qRS := ristretto255.NewIdentityElement().ScalarBaseMult(dRS)

	// Decode the initiator's ephemeral public key.
	qIE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(request)
	if qIE == nil {
		return nil, nil, err
	}

	// Initialize a protocol.
	p := newplex.NewProtocol(domain)

	// Mix the initiator's ephemeral public key into the protocol.
	p.Mix("ie", qIE.Bytes())

	// Generate an ephemeral key pair.
	var r [64]byte
	if _, err := io.ReadFull(rand, r[:]); err != nil {
		return nil, nil, err
	}
	dRE, _ := ristretto255.NewScalar().SetUniformBytes(r[:])
	qRE := ristretto255.NewIdentityElement().ScalarBaseMult(dRE)
	response = qRE.Bytes()

	// Mix in the responder's ephemeral public key.
	p.Mix("re", response)

	// Calculate and mix in the ephemeral-ephemeral shared secret.
	iErE := ristretto255.NewIdentityElement().ScalarMult(dRE, qIE)
	p.Mix("ie-re", iErE.Bytes())

	// Seal the responder's static public key.
	response = p.Seal("rs", response, qRS.Bytes())

	// Calculate and mix in the ephemeral-static shared secret.
	iErS := ristretto255.NewIdentityElement().ScalarMult(dRS, qIE)
	p.Mix("ie-rs", iErS.Bytes())

	// Wait for the initiator's confirmation.
	finish = func(confirmation []byte) (send, recv *newplex.Protocol, qIS *ristretto255.Element, err error) {
		// Open the initiator's static public key.
		confirmation, err = p.Open("is", nil, confirmation)
		if err != nil {
			return nil, nil, nil, ErrInvalidHandshake
		}

		// Decode the initiator's static public key.
		qIS, _ = ristretto255.NewIdentityElement().SetCanonicalBytes(confirmation)
		if qIS == nil {
			return nil, nil, nil, ErrInvalidHandshake
		}

		// Calculate and mix in the static-ephemeral shared secret.
		iSrE := ristretto255.NewIdentityElement().ScalarMult(dRE, qIS)
		p.Mix("is-re", iSrE.Bytes())

		// Fork the protocol into recv and send clones.
		a, b := p.Clone(), p.Clone()
		send, recv = &a, &b
		send.Mix("sender", []byte("responder"))
		recv.Mix("sender", []byte("initiator"))

		// Return the forked protocols and the initiator's public key.
		return send, recv, qIS, nil
	}

	// Return the finish function and the response.
	return finish, response, nil
}
