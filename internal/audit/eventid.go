package audit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// NewEventID returns a 16-byte id encoded as 22 base64url characters.
//
// Four bytes of unix seconds give rough emit-time sortability when reading a
// log by eye; twelve bytes of crypto/rand carry the uniqueness. The shape
// deliberately matches the capability JTI and the pending-approval id so an
// operator sees one visual style of identifier across the whole audit log
// rather than three.
//
// On a randomness failure this returns the empty string rather than an error.
// An id exists to correlate a decision with the response it produced; losing
// that correlation must never be a reason to drop the audit event itself,
// which is the record that actually matters.
func NewEventID() string {
	var b [16]byte
	binary.BigEndian.PutUint32(b[:4], uint32(time.Now().UTC().Unix()))
	if _, err := rand.Read(b[4:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
