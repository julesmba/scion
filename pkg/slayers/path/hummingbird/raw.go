package hummingbird

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// Raw is a raw representation of the Hummingbird (data-plane) path type. It is designed to parse as
// little as possible and should be used if performance matters.
type Raw struct {
	Base
	Raw []byte
}

// DecodeFromBytes only decodes the PathMetaHeader. Otherwise the nothing is decoded and simply kept
// as raw bytes.
func (s *Raw) DecodeFromBytes(data []byte) error {
	if err := s.Base.DecodeFromBytes(data); err != nil {
		return err
	}
	pathLen := s.Len()
	if len(data) < pathLen {
		return serrors.New("RawPath raw too short", "expected", pathLen, "actual", len(data))
	}
	s.Raw = data[:pathLen]
	return nil
}

// SerializeTo writes the path to a slice. The slice must be big enough to hold the entire data,
// otherwise an error is returned.
func (s *Raw) SerializeTo(b []byte) error {
	if s.Raw == nil {
		return serrors.New("raw is nil")
	}
	if minLen := s.Len(); len(b) < minLen {
		return serrors.New("buffer too small", "expected", minLen, "actual", len(b))
	}
	// XXX(roosd): This modifies the underlying buffer. Consider writing to data
	// directly.
	if err := s.PathMeta.SerializeTo(s.Raw[:MetaLen]); err != nil {
		return err
	}

	copy(b, s.Raw)
	return nil
}

// Reverse reverses the path such that it can be used in the reverse direction.
func (s *Raw) Reverse() (path.Path, error) {
	// XXX(shitz): The current implementation is not the most performant, since it parses the entire
	// path first. If this becomes a performance bottleneck, the implementation should be changed to
	// work directly on the raw representation.

	decoded, err := s.ToDecoded()
	if err != nil {
		return nil, err
	}
	reversed, err := decoded.Reverse()
	if err != nil {
		return nil, err
	}
	if err := reversed.SerializeTo(s.Raw); err != nil {
		return nil, err
	}
	err = s.DecodeFromBytes(s.Raw)
	return s, err
}

// ToDecoded transforms a scion.Raw to a scion.Decoded.
func (s *Raw) ToDecoded() (*Decoded, error) {
	// Serialize PathMeta to ensure potential changes are reflected Raw.

	if err := s.PathMeta.SerializeTo(s.Raw[:MetaLen]); err != nil {
		return nil, err
	}

	decoded := &Decoded{}
	if err := decoded.DecodeFromBytes(s.Raw); err != nil {
		return nil, err
	}
	return decoded, nil
}

// IncPath increments the path by n and writes it to the buffer.
func (s *Raw) IncPath(n int) error {
	if err := s.Base.IncPath(n); err != nil {
		return err
	}

	return s.PathMeta.SerializeTo(s.Raw[:MetaLen])
}

// GetInfoField returns the InfoField at a given index.
func (s *Raw) GetInfoField(idx int) (path.InfoField, error) {
	if idx >= s.NumINF {
		return path.InfoField{},
			serrors.New("InfoField index out of bounds", "max", s.NumINF-1, "actual", idx)
	}
	infOffset := MetaLen + idx*path.InfoLen
	info := path.InfoField{}
	if err := info.DecodeFromBytes(s.Raw[infOffset : infOffset+path.InfoLen]); err != nil {
		return path.InfoField{}, err
	}
	return info, nil
}

// GetCurrentInfoField is a convenience method that returns the current hop field pointed to by the
// CurrINF index in the path meta header.
func (s *Raw) GetCurrentInfoField() (path.InfoField, error) {
	return s.GetInfoField(int(s.PathMeta.CurrINF))
}

// Returns whether the hopfield at the given index is in construction direction
func (s *Raw) isConsdir(idx uint8) bool {
	hopIdx := s.Base.InfIndexForHF(idx)
	infOffset := MetaLen + hopIdx*path.InfoLen
	return s.Raw[infOffset]&0x1 == 0x1

}

// SetInfoField updates the InfoField at a given index.
func (s *Raw) SetInfoField(info path.InfoField, idx int) error {
	if idx >= s.NumINF {
		return serrors.New("InfoField index out of bounds", "max", s.NumINF-1, "actual", idx)
	}
	infOffset := MetaLen + idx*path.InfoLen
	return info.SerializeTo(s.Raw[infOffset : infOffset+path.InfoLen])
}

// GetHopField returns the HopField at a given index.
func (s *Raw) GetHopField(idx int) (FlyoverHopField, error) {
	if idx >= s.NumLines-HopLines+1 {
		return FlyoverHopField{},
			serrors.New("HopField index out of bounds", "max", s.NumLines-HopLines, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	hop := FlyoverHopField{}
	// Let the decoder read a big enough slice in case it is a FlyoverHopField
	maxHopLen := FlyoverLen
	if idx > s.NumLines-FlyoverLines {
		if idx == s.NumLines-HopLines {
			maxHopLen = HopLen
		} else {
			return FlyoverHopField{}, serrors.New(
				"Invalid hopfield index", "NumHops", s.NumLines, "index", idx)
		}
	}
	if err := hop.DecodeFromBytes(s.Raw[hopOffset : hopOffset+maxHopLen]); err != nil {
		return FlyoverHopField{}, err
	}
	return hop, nil
}

// GetCurrentHopField is a convenience method that returns the current hop field pointed to by the
// CurrHF index in the path meta header.
func (s *Raw) GetCurrentHopField() (FlyoverHopField, error) {
	return s.GetHopField(int(s.PathMeta.CurrHF))
}

func (s *Raw) replacMac(idx int, mac []byte) error {
	if idx >= s.NumLines-HopLines+1 {
		return serrors.New("HopField index out of bounds", "max",
			s.NumLines-HopLines, "actual", idx)
	}
	offset := s.NumINF*path.InfoLen + MetaLen + idx*LineLen + MacOffset
	if n := copy(s.Raw[offset:offset+path.MacLen], mac[:path.MacLen]); n != path.MacLen {
		return serrors.New("copied worng number of bytes for mac replacement",
			"expected", path.MacLen, "actual", n)
	}
	return nil
}

// SetCurrentMac replaces the Mac of the current hopfield by a new mac
func (s *Raw) ReplaceCurrentMac(mac []byte) error {
	return s.replacMac(int(s.PathMeta.CurrHF), mac)
}

// Returns a slice of the MAC of the hopfield starting at index idx
func (s *Raw) GetMac(idx int) ([]byte, error) {
	if idx >= s.NumLines-HopLines+1 {
		return nil, serrors.New("HopField index out of bounds",
			"max", s.NumLines-HopLines, "actual", idx)
	}
	offset := s.NumINF*path.InfoLen + MetaLen + idx*LineLen + MacOffset
	return s.Raw[offset : offset+path.MacLen], nil
}

// SetHopField updates the HopField at a given index.
// For Hummingbird paths the index is the offset in 4 byte lines
//
// If replacing a FlyoverHopField with a Hopfield,
// it is replaced by a FlyoverHopField with dummy values.
// This works for SCMP packets as Flyover hops are removed later
// in the process of building a SCMP packet.
func (s *Raw) SetHopField(hop FlyoverHopField, idx int) error {
	if idx >= s.NumLines-HopLines+1 {
		return serrors.New("HopField index out of bounds",
			"max", s.NumLines-HopLines, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x80 {
		// IF the current hop is a flyover, the flyover bit of the new hop is set to 1
		// 	in order to preserve correctness of the path
		//
		// The reservation data of the new hop is dummy data and invalid.
		// This works because SetHopField is currently only used to prepare a SCMP packet,
		// 	and all flyovers are removed later in that process
		//
		// IF this is ever used for something else, this function needs to be re-written
		hop.Flyover = true
	}
	if hop.Flyover {
		if idx >= s.NumLines-FlyoverLines+1 {
			return serrors.New("FlyoverHopField index out of bounds",
				"max", s.NumLines-FlyoverLines, "actual", idx)
		}
		hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
		if s.Raw[hopOffset]&0x80 == 0x00 {
			return serrors.New(
				"Setting FlyoverHopField over Hopfield with setHopField not supported")
		}
		return hop.SerializeTo(s.Raw[hopOffset : hopOffset+FlyoverLen])
	}
	return hop.SerializeTo(s.Raw[hopOffset : hopOffset+HopLen])
}

// IsFirstHop returns whether the current hop is the first hop on the path.
func (s *Raw) IsFirstHop() bool {
	return s.PathMeta.CurrHF == 0
}

// IsLastHop returns whether the current hop is the last hop on the path.
func (s *Raw) IsLastHop() bool {
	return int(s.PathMeta.CurrHF) == (s.NumLines-HopLines) ||
		int(s.PathMeta.CurrHF) == (s.NumLines-FlyoverLines)
}

// Returns the egress interface of the next hop
func (s *Raw) GetNextEgress() (uint16, error) {
	idx := int(s.Base.PathMeta.CurrHF)
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x80 {
		idx += FlyoverLines
		hopOffset += FlyoverLines * LineLen
	} else {
		idx += HopLines
		hopOffset += HopLines * LineLen
	}
	if idx >= s.NumLines-2 {
		return 0, serrors.New("HopField index out of bounds", "max",
			s.NumLines-HopLines, "actual", idx)
	}
	if s.isConsdir(uint8(idx)) {
		return binary.BigEndian.Uint16(s.Raw[hopOffset+4 : hopOffset+6]), nil
	}
	return binary.BigEndian.Uint16(s.Raw[hopOffset+2 : hopOffset+4]), nil
}

// Returns the ingress interface of the previous hop
// Assumes the previous hop is NOT a flyoverhop
func (s *Raw) GetPreviousIngress() (uint16, error) {
	idx := int(s.Base.PathMeta.CurrHF) - HopLines
	if idx < 0 {
		return 0, serrors.New("HopField index out of bounds", "min", 0, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.isConsdir(uint8(idx)) {
		return binary.BigEndian.Uint16(s.Raw[hopOffset+2 : hopOffset+4]), nil
	}
	return binary.BigEndian.Uint16(s.Raw[hopOffset+4 : hopOffset+6]), nil
}

// Attaches current flyoverfield to next hopfield.
// DOES NOT adapt MACS.
func (s *Raw) DoFlyoverXover() error {
	idx := int(s.Base.PathMeta.CurrHF)
	if idx >= s.NumLines-7 {
		return serrors.New("CurrHF out of bounds for flyover crossover",
			"max", s.NumLines-7, "actual", idx)
	}
	if s.PathMeta.CurrINF == 2 {
		return serrors.New("Cannot do FlyoverXover if CurrINF = 2")
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x00 {
		return serrors.New("Current hop does not have a Flyover")
	}
	if s.Raw[hopOffset+FlyoverLen]&0x80 != 0x00 {
		return serrors.New("Hop after Crossover has Flyover")
	}
	// buffer flyover and copy data
	var t [2 * LineLen]byte
	copy(t[:], s.Raw[hopOffset+HopLen:hopOffset+FlyoverLen])
	copy(s.Raw[hopOffset+HopLen:hopOffset+2*HopLen],
		s.Raw[hopOffset+FlyoverLen:hopOffset+FlyoverLen+HopLen])
	copy(s.Raw[hopOffset+2*HopLen:hopOffset+HopLen+FlyoverLen], t[:])

	// Unset and Set Flyoverbits
	s.Raw[hopOffset] &= 0x7f
	s.Raw[hopOffset+HopLen] |= 0x80
	// Adatp seglens
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF] -= 2
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF+1] += 2
	return nil
}

// Attaches current flyoverfield to previous hopfield
// DOES NOT adapt MACs
func (s *Raw) ReverseFlyoverXover() error {
	idx := int(s.Base.PathMeta.CurrHF)
	if idx < 6 {
		return serrors.New("CurrHF too small for reversing flyover crossover",
			"min", 6, "actual", idx)
	}
	if s.PathMeta.CurrINF == 0 {
		return serrors.New("Cannot reverse Flyover Xover when CurrINF = 0")
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x00 {
		return serrors.New("Current hop does not have a Flyover")
	}
	if s.Raw[hopOffset-HopLen]&0x80 != 0x00 {
		return serrors.New(
			"Cannot Reverse Flyover Crossover, flyover bit set where previous hop should be")
	}
	var t [FlyoverLen - HopLen]byte
	copy(t[:], s.Raw[hopOffset+HopLen:hopOffset+FlyoverLen])
	copy(s.Raw[hopOffset+FlyoverLen-HopLen:hopOffset+FlyoverLen],
		s.Raw[hopOffset:hopOffset+HopLen])
	copy(s.Raw[hopOffset:hopOffset+FlyoverLen-HopLen], t[:])
	// Set and Unset Flyoverbits
	s.Raw[hopOffset-HopLen] |= 0x80
	s.Raw[hopOffset+FlyoverLen-HopLen] &= 0x7f
	// Adapt Seglens and CurrHF
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF] -= 2
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF-1] += 2
	s.Base.PathMeta.CurrHF += 2
	return nil
}
