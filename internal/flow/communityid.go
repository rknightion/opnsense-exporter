package flow

import (
	"crypto/sha1" //nolint:gosec // community-id v1 specifies SHA-1; it is an interop identifier, not a security primitive
	"encoding/base64"
	"encoding/binary"
)

// communityIDVersion prefixes every rendered id, per the spec.
const communityIDVersion = "1:"

// CommunityID computes the Corelight community-id v1 of a canonical tuple.
//
// The scheme exists so independent tools observing the same conversation derive the
// same identifier, which is exactly what phase 3 needs to join a Zenarmor conn
// record to the NetFlow records describing the same connection.
//
// Zenarmor emits a field called community_id, and we do NOT use or compare against
// it: a sweep of all 65,536 seeds against five real Zenarmor documents matched none
// of them, so whatever Zenarmor computes, it is not community-id v1 over the
// 5-tuple. We compute our own for both sources, which is what makes the join key
// consistent across them.
//
// Wire layout (v1): seed | addr_a | addr_b | proto | 0 | port_a | port_b, all
// big-endian, endpoints already ordered by CanonicalTuple. SHA-1 over that, base64
// of the digest, prefixed "1:".
//
// ICMP CAVEAT: the spec maps ICMP type/code onto the two port slots. This does not,
// because neither of our sources supplies type or code — Zenarmor reports ports of
// 0/0 on ICMP, and OPNsense's NetFlow v9 export carries no ICMP type/code element
// at all (#346). The published ICMP reference vector nevertheless passes here, but
// it passes BY COINCIDENCE: its type is 8, whose spec counterpart is 0, and its
// code is also 0, so the mapping is the identity for that one case. Do not read the
// green test as ICMP conformance. The divergence is self-consistent across our two
// sources, which is what the key is for; a future lane that does carry type/code
// must implement the mapping properly rather than assume this already does.
func CommunityID(t Tuple, seed uint16) string {
	h := sha1.New() //nolint:gosec // see above

	var scratch [2]byte
	binary.BigEndian.PutUint16(scratch[:], seed)
	_, _ = h.Write(scratch[:])

	// Both addresses take the same branch: mixing a 4-byte and a 16-byte encoding
	// inside one hash would be meaningless. CanonicalTuple has already Unmapped them,
	// so a v4-mapped IPv6 address arrives here in its plain v4 form and hashes
	// identically to the same host seen as v4 — the 16-byte branch would give one
	// host two different ids and split the phase-3 join.
	if t.AAddr.Is4() && t.BAddr.Is4() {
		a, b := t.AAddr.As4(), t.BAddr.As4()
		_, _ = h.Write(a[:])
		_, _ = h.Write(b[:])
	} else {
		a, b := t.AAddr.As16(), t.BAddr.As16()
		_, _ = h.Write(a[:])
		_, _ = h.Write(b[:])
	}

	// The zero byte is the spec's padding between the protocol and the ports.
	_, _ = h.Write([]byte{t.Proto, 0})

	binary.BigEndian.PutUint16(scratch[:], t.APort)
	_, _ = h.Write(scratch[:])
	binary.BigEndian.PutUint16(scratch[:], t.BPort)
	_, _ = h.Write(scratch[:])

	return communityIDVersion + base64.StdEncoding.EncodeToString(h.Sum(nil))
}
