package hummingbird

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
)

const (
	// LineLen is the number of bytes in a line as considered by CurrHF in the PathMEtaHeader
	LineLen = 4
	// Length in bytes of a FlyoverHopField
	FlyoverLen = 20
	// HopLen is the size of a HopField in bytes.
	HopLen = 12
	// MacOffset is the offset of the MAC field from the beginning of the HopField
	MacOffset = 6
	// The number of lines in a hopfield
	HopLines = 3
	// The number of lines in a flyoverhopfield
	FlyoverLines = 5
)

type FlyoverHopField struct {
	// SCiON Hopfield part of the FlyoverHopField
	HopField path.HopField
	// True if flyover is present
	Flyover bool
	// ResID is the Reservation ID of the flyover
	ResID uint32
	// Bw is the reserved banwidth of the flyover
	Bw uint16
	// ResStartTime is the start time of the reservation
	// As a negative offset from the BaseTimeStamp in the PathMetaHdr
	ResStartTime uint16
	// Duration is the duration of the reservation
	Duration uint16
}

// DecodeFromBytes populates the fields from a raw buffer.
// The buffer must be of length >= HopLen if the Flyover bit is false
// The buffer must be of length >= FlyoverLen if the Flyover bit is set
// DecodeFromBytes modifies the fields of *h and reads (but does not modify) the contents of raw.
// When a call that satisfies the precondition (len(raw) >= HopLen) is made,
// the return value is guaranteed to be nil.
// Calls to DecodeFromBytes are always guaranteed to terminate.
func (h *FlyoverHopField) DecodeFromBytes(raw []byte) (err error) {
	if err := h.HopField.DecodeFromBytes(raw); err != nil {
		return err
	}
	h.Flyover = raw[0]&0x80 == 0x80
	if h.Flyover {
		if len(raw) < FlyoverLen {
			return serrors.New("FlyoverHopField raw too short", "expected",
				FlyoverLen, "actual", len(raw))
		}
		h.ResID = binary.BigEndian.Uint32(raw[12:16]) >> 10
		h.Bw = binary.BigEndian.Uint16(raw[14:16]) & 0x03ff
		h.ResStartTime = binary.BigEndian.Uint16(raw[16:18])
		h.Duration = binary.BigEndian.Uint16(raw[18:20])
	}
	return nil
}

// SerializeTo writes the fields into the provided buffer.
// The buffer must be of length >= HopLen if the Flyover bit is false
// The buffer must be of length >= FlyoverLen if the Flyover bit is set
// SerializeTo reads (but does not modify) the fields of *h and writes to the contents of b.
// When a call that satisfies the precondition (len(b) >= HopLen) is made,
// the return value is guaranteed to be nil.
// Calls to SerializeTo are guaranteed to terminate.
func (h *FlyoverHopField) SerializeTo(b []byte) (err error) {
	if err := h.HopField.SerializeTo(b); err != nil {
		return err
	}

	if h.Flyover {
		if len(b) < FlyoverLen {
			return serrors.New("buffer for FlyoverHopField too short", "expected",
				FlyoverLen, "actual", len(b))
		}
		b[0] |= 0x80
		binary.BigEndian.PutUint32(b[12:16], h.ResID<<10+uint32(h.Bw))
		binary.BigEndian.PutUint16(b[16:18], h.ResStartTime)
		binary.BigEndian.PutUint16(b[18:20], h.Duration)
	}

	return nil
}
