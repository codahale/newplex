package newplex //nolint:testpackage // testing internals
import (
	"encoding/hex"
)

// State renders the duplex's state as a string.
func State(d *Duplex) string {
	return hex.EncodeToString(d.state[:d.pos]) + "^" + hex.EncodeToString(d.state[d.pos:rate]) + "|" + hex.EncodeToString(d.state[rate:])
}
