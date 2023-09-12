package hummingbird

import (
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

// IncPath increments the path and writes it to the buffer.
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
	if idx >= s.NumHops-2 {
		return FlyoverHopField{},
			serrors.New("HopField index out of bounds", "max", s.NumHops-3, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*path.LineLen
	hop := FlyoverHopField{}
	// Let the decoder read a big enough slice in case it is a FlyoverHopField
	maxHopLen := path.FlyoverLen
	if idx > s.NumHops-5 {
		if idx == s.NumHops-3 {
			maxHopLen = path.HopLen
		} else {
			return FlyoverHopField{}, serrors.New("Invalid hopfield index", "NumHops", s.NumHops, "index", idx)
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

func (s *Raw) ReplacMac(idx int, mac []byte) error {
	if idx >= s.NumHops-2 {
		return serrors.New("HopField index out of bounds", "max", s.NumHops-3, "actual", idx)
	}
	offset := s.NumINF*path.InfoLen + path.MacOffset
	offset += MetaLen + idx*path.LineLen
	if n := copy(s.Raw[offset:offset+path.MacLen], mac[:path.MacLen]); n != path.MacLen {
		return serrors.New("copied worng number of bytes for mac replacement", "expected", path.MacLen, "actual", n)
	}
	return nil
}

// SetCurrentMac replaces the Mac of the current hopfield by a new mac
func (s *Raw) ReplaceCurrentMac(mac []byte) error {
	return s.ReplacMac(int(s.PathMeta.CurrHF), mac)
}

// SetHopField updates the HopField at a given index.
// For Hummingbird paths the index is the offset in 4 byte lines
//
// If replacing a FlyoverHopField with a Hopfield, it is replaced by a FlyoverHopField with dummy values.
// This works for SCMP packets as Flyover hops are removed later in the process of building a SCMP packet.
func (s *Raw) SetHopField(hop FlyoverHopField, idx int) error {
	if idx >= s.NumHops-2 {
		return serrors.New("HopField index out of bounds", "max", s.NumHops-3, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*path.LineLen
	if s.Raw[hopOffset]&0x80 == 0x80 {
		// IF the current hop is a flyover, the flyover bit of the new hop is set to 1 in order to preserve correctness of the path
		// The reservation data of the new hop is dummy data and invalid.
		// This works because SetHopField is currently only used to prepare a SCMP packet, and all flyovers are removed later in that process
		//
		// IF this is ever used for something else, this function needs to be re-written
		hop.Flyover = true
	}
	if hop.Flyover {
		if idx >= s.NumHops-4 {
			return serrors.New("FlyoverHopField index out of bounds", "max", s.NumHops-5, "actual", idx)
		}
		hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*path.LineLen
		if s.Raw[hopOffset]&0x80 == 0x00 {
			return serrors.New("Setting FlyoverHopField over Hopfield with setHopField not supported")
		}
		return hop.SerializeTo(s.Raw[hopOffset : hopOffset+path.FlyoverLen])
	}
	return hop.SerializeTo(s.Raw[hopOffset : hopOffset+path.HopLen])
}

// IsFirstHop returns whether the current hop is the first hop on the path.
func (s *Raw) IsFirstHop() bool {
	return s.PathMeta.CurrHF == 0
}

// IsLastHop returns whether the current hop is the last hop on the path.
func (s *Raw) IsLastHop() bool {
	return int(s.PathMeta.CurrHF) == (s.NumHops-3) || int(s.PathMeta.CurrHF) == (s.NumHops-5)
}
