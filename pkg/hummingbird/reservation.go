// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hummingbird

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

type ReservationJuanDeleteme struct {
	SCIONPath path.Path
	Flyovers  []*BaseHop
	Ratio     float64 // flyover/hops ratio
}

// HopCount returns the number of hops in this path, as understood by a hop in a regular SCION path.
func (r ReservationJuanDeleteme) HopCount() int {
	return len(r.SCIONPath.Meta.Interfaces)
}

func (r ReservationJuanDeleteme) FlyoverCount() int {
	return len(r.Flyovers)
}

func (r ReservationJuanDeleteme) LessThan(other *ReservationJuanDeleteme) bool {
	return r.Ratio < other.Ratio
}

// Reservation represents a possibly partially reserved path, with zero or more flyovers.
// TODO(juagargi) refactor functionality in two types: Reservation and move the rest to sciond.
type Reservation struct {
	dec     hummingbird.Decoded // caches a decoded path for multiple uses
	hops    []Hop               // possible flyovers
	counter uint32              // duplicate detection counter

	now        time.Time // the current time
	interfaces []snet.PathInterface
	flyovers   FlyoverSet // the flyovers used to creatre this reservation
}

type Hop struct {
	BaseHop

	hopfield *hummingbird.FlyoverHopField // dataplane hop field
	flyover  *Flyover                     // flyover used to build this hop
}

func NewReservation(opts ...reservationModFcn) (*Reservation, error) {
	c := &Reservation{
		now: time.Now(),
	}
	// Run all options on this object.
	for _, fcn := range opts {
		if err := fcn(c); err != nil {
			return nil, err
		}
	}

	// Create reservation.
	c.prepareHbirdPath()
	c.applyFlyovers()

	return c, nil
}

type reservationModFcn func(*Reservation) error

func WithPath(p snet.Path) reservationModFcn {
	return func(r *Reservation) error {
		switch p := p.Dataplane().(type) {
		case path.SCION:
			scion := scion.Decoded{}
			if err := scion.DecodeFromBytes(p.Raw); err != nil {
				return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
			}
			r.dec = hummingbird.Decoded{}
			r.dec.ConvertFromScionDecoded(scion)
		default:
			return serrors.New("Unsupported path type")
		}
		// We use the path metadata to get the IA from it. This sequence of interfaces does not
		// include the egress-to-ingress crossed over interfaces in the core AS.
		r.interfaces = p.Metadata().Interfaces

		return nil
	}
}

type FlyoverSet map[BaseHop][]*Flyover

func WithFlyovers(flyovers FlyoverSet) reservationModFcn {
	return func(r *Reservation) error {
		r.flyovers = flyovers
		return nil
	}
}

func WithNow(now time.Time) reservationModFcn {
	return func(r *Reservation) error {
		r.now = now
		return nil
	}
}

// func (c *Reservation) prepareHbirdPath(p snet.Path) error {
func (r *Reservation) prepareHbirdPath() {
	r.dec.PathMeta.SegLen[0] += 2
	r.hops = append(r.hops, newHop(
		r.interfaces[0].IA,
		0,
		uint16(r.interfaces[0].ID),
		// 0,
		&r.dec.HopFields[0],
	))

	// The dataplane path in c.dec contains inf fields and cross-over hops.
	// Do each segment at a time to ignore the first hop of every segment except the first.
	hopIdx := 1 // the index of the current hop in the dataplane.
	for infIdx := 0; infIdx < r.dec.NumINF; infIdx, hopIdx = infIdx+1, hopIdx+1 {
		// Preserve the hopcount locally, as we modify it inside the loop itself.
		hopCount := int(r.dec.Base.PathMeta.SegLen[infIdx]) / hummingbird.HopLines
		for i := 1; i < hopCount; i, hopIdx = i+1, hopIdx+1 {
			r.dec.PathMeta.SegLen[infIdx] += 2
			r.hops = append(r.hops, newHop(
				r.interfaces[len(r.hops)*2-1].IA,
				uint16(r.interfaces[len(r.hops)*2-1].ID),
				egressID(r.interfaces, len(r.hops)),
				&r.dec.HopFields[hopIdx],
			))
		}
	}
}

func (r *Reservation) Destination() addr.IA {
	return r.hops[len(r.hops)-1].IA
}

func (r *Reservation) applyFlyovers() {
	now := uint32(r.now.Unix())
	for i, h := range r.hops {
		flyovers := r.flyovers[h.BaseHop]
		for _, flyover := range flyovers {
			if flyover.StartTime <= now && uint32(flyover.Duration) >= now-flyover.StartTime {
				r.hops[i].flyover = flyover
				r.hops[i].hopfield.Flyover = true
				r.dec.NumLines += 2
				r.hops[i].hopfield.Bw = flyover.Bw
				r.hops[i].hopfield.Duration = flyover.Duration
				r.hops[i].hopfield.ResID = flyover.ResID
				break
			}
		}
	}
}

// Sets pathmeta timestamps and increments duplicate detection counter.
// Updates MACs of all flyoverfields
// replaces the dataplane of the input snet.path with the finished hummingbird path
func (r *Reservation) DeriveDataPlanePath(p snet.Path, pktLen uint16,
	timeStamp time.Time) (snet.Path, error) {
	if p == nil {
		return nil, serrors.New("snet path is nil")
	}
	var dphb path.Hummingbird

	// Update timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1000) << 22
	millis |= r.counter
	r.dec.Base.PathMeta.BaseTS = secs
	r.dec.Base.PathMeta.HighResTS = millis
	//increment counter for next packet
	if r.counter >= 1<<22-1 {
		r.counter = 0
	} else {
		r.counter += 1
	}
	// compute Macs for Flyovers
	var byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	var xkbuffer [hummingbird.XkBufferSize]uint32
	for _, h := range r.hops {
		if !h.hopfield.Flyover {
			continue
		}
		h.hopfield.ResStartTime = uint16(secs - h.flyover.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(h.flyover.Ak[:], r.Destination(), pktLen,
			h.hopfield.ResStartTime, millis, byteBuffer[:], xkbuffer[:])

		binary.BigEndian.PutUint32(h.hopfield.HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(h.hopfield.HopField.Mac[:4]))
		binary.BigEndian.PutUint16(h.hopfield.HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(h.hopfield.HopField.Mac[4:]))
	}
	dphb.Raw = make([]byte, r.dec.Len())
	if err := r.dec.SerializeTo(dphb.Raw); err != nil {
		return nil, err
	}
	switch v := p.(type) {
	case path.Path:
		v.DataplanePath = dphb
		p = v
	default:
		return nil, serrors.New("Unsupported snet path struct", "path", p)
	}

	return p, nil
}

func newHop(ia addr.IA, in, eg uint16, hf *hummingbird.FlyoverHopField) Hop {
	return Hop{
		BaseHop: BaseHop{
			IA:      ia,
			Ingress: in,
			Egress:  eg,
		},
		hopfield: hf,
	}
}

// egressID returns the egress ID from a sequence of IDs (such as that in the metadata field
// of a snet.Path) given its index. If index is past the length of the sequence, the egress
// ID 0 is returning, meaning egress ID is that last AS.
func egressID(ifaces []snet.PathInterface, idx int) uint16 {
	i := idx * 2
	if i >= len(ifaces) {
		return 0
	}
	return uint16(ifaces[i].ID)
}
