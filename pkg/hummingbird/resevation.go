// Copyright 2023 ETH Zurich
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
	"github.com/scionproto/scion/pkg/log"
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
	dec        hummingbird.Decoded // caches a decoded path for multiple uses
	hops       []Hop               // possible flyovers
	counter    uint32              // duplicate detection counter
	byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	xkbuffer   [hummingbird.XkBufferSize]uint32
}

type Hop struct {
	BaseHop

	// The FlyoverHopField in the path associated to this hop.
	hopfield *hummingbird.FlyoverHopField
	// The Index of the Segment the above hopfield is part of.
	infIdx int
	// The reservations that can be used for this hop.
	// The reservation at index 0 is the one used to build the path
	// MUST be non-empty if hopfield.Flyiver == true
	reservations []Flyover
	// The original scion mac of the corresponding hopfield.
	scionMac [6]byte
}

func NewReservation(p snet.Path, flyovers map[addr.IA][]*Flyover) (*Reservation, error) {
	// deleteme
	// func NewReservation(p snet.Path) (*Reservation, error) {
	c := &Reservation{}
	err := c.prepareHbirdPath(p)
	if err == nil {
		c.applyFlyovers(flyovers)
	}
	return c, err
}

// prepareHbirdPathOlD prepares as hummingbird path and initializes the Resevation object.
func (c *Reservation) prepareHbirdPathOlD(p snet.Path) error {
	if p == nil {
		return serrors.New("Empty path")
	}
	c.dec = hummingbird.Decoded{}
	switch v := p.Dataplane().(type) {
	case path.SCION:
		// Convert path to decoded hbird path
		scionDec := scion.Decoded{}
		if err := scionDec.DecodeFromBytes(v.Raw); err != nil {
			return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
		c.dec.ConvertFromScionDecoded(scionDec)
	case path.Hummingbird:
		if err := c.dec.DecodeFromBytes(v.Raw); err != nil {
			return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
	default:
		return serrors.New("Unsupported path type")
	}

	// Initialize a hop for each traversed AS.
	infIdx := 0
	for i := 0; i < len(c.dec.HopFields); i++ {
		// Determine the segment index and whether the hop is a cross over or not.
		var xover bool
		for ; infIdx < 2; infIdx++ {
			if i < int(c.dec.FirstHopPerSeg[infIdx]) {
				if !c.dec.InfoFields[infIdx].Peer {
					xover = (i == int(c.dec.FirstHopPerSeg[infIdx])-1) &&
						i < len(c.dec.HopFields)-1
				}
				break
			}
		}

		// If not first segment, check if this hop is the first one after a xover.
		if infIdx > 0 &&
			!c.dec.InfoFields[infIdx].Peer &&
			i == int(c.dec.FirstHopPerSeg[infIdx-1]) &&
			i < len(c.dec.HopFields)-1 {

			// First hop after Crossover, nothing to be done.
			continue
		}

		// Setting egress: if crossing over then egress ID comes from the next hop in next segment.
		offset := 0
		if xover {
			offset = 1
		}
		// We use the path metadata to get the IA from it. This sequence of interfaces does not
		// include the egress-to-ingress crossed over in the core AS.
		pathInterfaces := p.Metadata().Interfaces

		c.hops = append(c.hops, Hop{
			BaseHop: BaseHop{
				// To get the current PathInterface we use `len(c.hops)` instead of `i` because
				// we want to skip those crossed-over interfaces.
				IA:      pathInterfaces[hopIndexToPathInterfaceIndex(len(c.hops))].IA,
				Ingress: getIfaceID(c.dec, infIdx, i, false),
				Egress:  getIfaceID(c.dec, infIdx+offset, i+offset, true),
			},
			infIdx:       infIdx,
			hopfield:     &c.dec.HopFields[i],
			scionMac:     c.dec.HopFields[i].HopField.Mac,
			reservations: make([]Flyover, 0, 2),
		})
	}

	return nil
}

func (c *Reservation) prepareHbirdPath(p snet.Path) error {
	switch p := p.Dataplane().(type) {
	case path.SCION:
		scion := scion.Decoded{}
		if err := scion.DecodeFromBytes(p.Raw); err != nil {
			return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
		c.dec = hummingbird.Decoded{}
		c.dec.ConvertFromScionDecoded(scion)
	default:
		return serrors.New("Unsupported path type")
	}

	// We use the path metadata to get the IA from it. This sequence of interfaces does not
	// include the egress-to-ingress crossed over interfaces in the core AS.
	pathInterfaces := p.Metadata().Interfaces

	c.hops = append(c.hops, newHop(
		pathInterfaces[0].IA,
		0,
		uint16(pathInterfaces[0].ID),
		0,
		&c.dec.HopFields[0],
	))

	// The dataplane path in c.dec contains inf fields and cross-over hops.
	// Do each segment at a time to ignore the first hop of every segment except the first.
	hopIdx := 1 // the index of the current hop in the dataplane.
	for infIdx := 0; infIdx < c.dec.NumINF; infIdx, hopIdx = infIdx+1, hopIdx+1 {
		for i := 1; i < int(
			c.dec.Base.PathMeta.SegLen[infIdx])/hummingbird.HopLines; i, hopIdx = i+1, hopIdx+1 {

			c.hops = append(c.hops, newHop(
				pathInterfaces[len(c.hops)*2-1].IA,
				uint16(pathInterfaces[len(c.hops)*2-1].ID),
				egressID(pathInterfaces, len(c.hops)),
				infIdx,
				&c.dec.HopFields[hopIdx],
			))
		}
	}
	return nil
}

func iaID(ifaces []snet.PathInterface, idx int) addr.IA {
	i := idx*2 - 1
	if i < 0 {
		i = 0
	}
	return ifaces[i].IA
}

func ingressID(ifaces []snet.PathInterface, idx int) uint16 {
	i := idx*2 - 1
	if i < 0 {
		return 0
	}
	return uint16(ifaces[i].ID)
}

// For each hop in the path, returns a reservation containing the AS, Ingress and Egress of that hop
func (c *Reservation) GetPathASes() []BaseHop {
	hops := make([]BaseHop, len(c.hops))
	for i, h := range c.hops {
		hops[i].IA = h.IA
		hops[i].Ingress = h.Ingress
		hops[i].Egress = h.Egress
	}
	return hops
}

func (c *Reservation) Destination() addr.IA {
	return c.hops[len(c.hops)-1].IA
}

// Request reservations for the full path
// bw: the bandwidth to request
// start: The start time of the reservation, in unix seconds
// duration: The duration of the reservation in seconds
// TODO: add async version once we have request api
func (c *Reservation) RequestReservationsAllHops(
	bw uint16, start uint32, duration uint16) ([]Flyover, error) {
	hops := make([]BaseHop, len(c.hops))
	for i, h := range c.hops {
		hops[i].IA = h.IA
		hops[i].Ingress = h.Ingress
		hops[i].Egress = h.Egress
	}

	return RequestReservationForASes(hops, bw, start, duration)
}

// Requests new reservations for the listed Hops and returns them once they are obtained
// TODO: add timeout after which already received reservations
// (if any) are returned once we have actual requests
// TODO: add fully async version of this
func RequestReservationForASes(
	hops []BaseHop, bw uint16, start uint32, duration uint16) ([]Flyover, error) {

	log.Debug("Requesting reservations for", "Hops", hops)
	reservations := make([]Flyover, len(hops))
	for i, h := range hops {
		//TODO: Once we have API for requests
		// Request (AS, ingress, egress, bw, start, duration)

		// Temporary Cheating
		// Current implementation cheats by writing data directly into c.hops instead

		reservations[i].IA = h.IA
		reservations[i].Ingress = h.Ingress
		reservations[i].Egress = h.Egress
		reservations[i].Bw = bw
		reservations[i].StartTime = start
		reservations[i].Duration = duration

		var err error
		reservations[i], err = cheat_auth_key(&reservations[i])
		if err != nil {
			return nil, err
		}
	}
	return reservations, nil
}

// Adds the listed reservations to the path
func (c *Reservation) ApplyReservations(flyovers []Flyover) error {
	log.Debug("Applying reservations", "reservations", flyovers)
	for _, f := range flyovers {
		for j, h := range c.hops {
			if f.IA == h.IA {
				if f.Ingress == h.Ingress && f.Egress == h.Egress {
					c.hops[j].reservations = append(c.hops[j].reservations, f)
					if len(c.hops[j].reservations) == 1 {
						c.hops[j].hopfield.Flyover = true
						c.dec.NumLines += 2
						c.dec.PathMeta.SegLen[h.infIdx] += 2
						c.hops[j].hopfield.Bw = f.Bw
						c.hops[j].hopfield.Duration = f.Duration
						c.hops[j].hopfield.ResID = f.ResID
					}
				} else {
					// TODO: inform caller that this reservation cannot be set on this path
					break
				}
			}
		}
	}
	return nil
}

func (c *Reservation) applyFlyovers(flyovers map[addr.IA][]*Flyover) {
	for i, h := range c.hops {
		flyovers := flyovers[h.IA]
		for _, flyover := range flyovers {
			if flyover.Ingress == h.Ingress && flyover.Egress == h.Egress {
				c.hops[i].reservations = append(c.hops[i].reservations, *flyover)
				c.hops[i].hopfield.Flyover = true
				c.dec.NumLines += 2
				c.dec.PathMeta.SegLen[h.infIdx] += 2
				c.hops[i].hopfield.Bw = flyover.Bw
				c.hops[i].hopfield.Duration = flyover.Duration
				c.hops[i].hopfield.ResID = flyover.ResID
				break
			}
		}
	}
}

// Returns all the reservations that the client may currently use
// If there are multiple reservations for a hop,
// The one currently used is the first appearing in the returned array
func (c *Reservation) GetUsedReservations() []Flyover {
	res := make([]Flyover, 0, len(c.hops))
	for _, h := range c.hops {
		res = append(res, h.reservations...)
	}
	return res
}

// Removes the reservation with the given resID from a hop
func (c *Reservation) removeReservation(hopIdx int, resID uint32) {
	h := &c.hops[hopIdx]
	for i, r := range h.reservations {
		if r.ResID == resID {
			if i == 0 {
				if len(h.reservations) == 1 {
					h.hopfield.Flyover = false
					c.dec.NumLines -= 2
					c.dec.PathMeta.SegLen[c.hops[hopIdx].infIdx] -= 2
					h.reservations = []Flyover{}
				} else {
					copy(h.reservations[:], h.reservations[1:])
					h.reservations = h.reservations[:len(h.reservations)-1]
					h.hopfield.Bw = h.reservations[0].Bw
					h.hopfield.ResID = h.reservations[0].ResID
					h.hopfield.Duration = h.reservations[0].Duration
				}
			} else {
				if i < len(h.reservations)-1 {
					copy(h.reservations[i:], h.reservations[i+1:])
				}
				h.reservations = h.reservations[:len(h.reservations)-1]
			}
			break
		}
	}
}

// Removes res from the reservations the client is allowed to use
// Reservations are identified based on their AS and ResID
// Does NOT check for validity of remaining reservations
func (c *Reservation) RemoveReservations(res []Flyover) error {
	for _, r := range res {
		for i, h := range c.hops {
			if r.IA == h.IA {
				c.removeReservation(i, r.ResID)
				break
			}
		}
	}
	return nil
}

// Checks whether any current reservation that has expired or will expire in t seconds
// If yes, remove reservation from list of used reservations
func (c *Reservation) CheckExpiry(t uint32) {
	now := uint32(time.Now().Unix())
	for i := range c.hops {

		// Remove expired reservations
		for j := 0; j < len(c.hops[i].reservations); {
			if c.hops[i].reservations[j].StartTime+uint32(c.hops[i].reservations[j].Duration) <
				(now + t) {
				copy(c.hops[i].reservations[j:], c.hops[i].reservations[j+1:])
				c.hops[i].reservations = c.hops[i].reservations[:len(c.hops[i].reservations)-1]
			} else {
				j++
			}
		}

		if len(c.hops[i].reservations) == 0 {
			if c.hops[i].hopfield.Flyover {
				c.hops[i].hopfield.Flyover = false
				c.dec.NumLines -= 2
				c.dec.PathMeta.SegLen[c.hops[i].infIdx] -= 2
			}
			continue
		}
		// If there's any currently valid reservation, put it to the front
		if !(c.hops[i].reservations[0].StartTime <= now) {
			for j := 1; j < len(c.hops[i].reservations); j++ {
				if c.hops[i].reservations[j].StartTime <= now {
					temp := c.hops[i].reservations[0]
					c.hops[i].reservations[0] = c.hops[i].reservations[j]
					c.hops[i].reservations[j] = temp
					break
				}
			}
		}

		// Check whether reservation at the front is currently valid
		if c.hops[i].reservations[0].StartTime <= now {
			if !c.hops[i].hopfield.Flyover {
				c.hops[i].hopfield.Flyover = true
				c.dec.NumLines += 2
				c.dec.PathMeta.SegLen[c.hops[i].infIdx] += 2
			}
			c.hops[i].hopfield.Bw = c.hops[i].reservations[0].Bw
			c.hops[i].hopfield.Duration = c.hops[i].reservations[0].Duration
			c.hops[i].hopfield.ResID = c.hops[i].reservations[0].ResID
		} else {
			if c.hops[i].hopfield.Flyover {
				c.hops[i].hopfield.Flyover = false
				c.dec.NumLines -= 2
				c.dec.PathMeta.SegLen[c.hops[i].infIdx] -= 2
			}
		}
	}
}

// Sets pathmeta timestamps and increments duplicate detection counter.
// Updates MACs of all flyoverfields
// replaces the dataplane of the input snet.path with the finished hummingbird path
func (c *Reservation) FinalizePath(p snet.Path, pktLen uint16,
	timeStamp time.Time) (snet.Path, error) {
	if p == nil {
		return nil, serrors.New("snet path is nil")
	}
	var dphb path.Hummingbird

	// Update timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1000) << 22
	millis |= c.counter
	c.dec.Base.PathMeta.BaseTS = secs
	c.dec.Base.PathMeta.HighResTS = millis
	//increment counter for next packet
	if c.counter >= 1<<22-1 {
		c.counter = 0
	} else {
		c.counter += 1
	}
	// compute Macs for Flyovers
	for _, h := range c.hops {
		if !h.hopfield.Flyover {
			continue
		}
		res := h.reservations[0]
		h.hopfield.ResStartTime = uint16(secs - res.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(res.Ak[:], c.Destination(), pktLen,
			h.hopfield.ResStartTime, millis, c.byteBuffer[:], c.xkbuffer[:])

		binary.BigEndian.PutUint32(h.hopfield.HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(h.scionMac[:4]))
		binary.BigEndian.PutUint16(h.hopfield.HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(h.scionMac[4:]))
	}
	dphb.Raw = make([]byte, c.dec.Len())
	if err := c.dec.SerializeTo(dphb.Raw); err != nil {
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

func newHop(ia addr.IA, in, eg uint16, infIdx int, hf *hummingbird.FlyoverHopField) Hop {
	return Hop{
		BaseHop: BaseHop{
			IA:      ia,
			Ingress: in,
			Egress:  eg,
		},
		infIdx:       infIdx,
		hopfield:     hf,
		scionMac:     hf.HopField.Mac,
		reservations: make([]Flyover, 0, 2),
	}
}

func getIfaceID(dec hummingbird.Decoded, segIdx, hopIdx int, returnEgress bool) uint16 {
	in := dec.HopFields[hopIdx].HopField.ConsIngress
	eg := dec.HopFields[hopIdx].HopField.ConsEgress
	if !dec.InfoFields[segIdx].ConsDir {
		returnEgress = !returnEgress
	}
	if returnEgress {
		in = eg
	}
	return in
}

// hopIndexToPathInterfaceIndex converts an index of a hummingbird hop into its corresponding
// index in the PathInterface sequence (found e.g. in snet.Path.Metadata()).
// This is not straightforward, as the PathInterface sequence omits the starting interface
// (its ID. is always 0 and same IA as next one), and ending interface (its ID is always 0 and
// the same IA as the previous one).
// Example: if we have four hummingbird hops, indexed as. 0,1,2,3, their corresponding indices
// in a PathInterface sequence would be 0,1,3,5.
func hopIndexToPathInterfaceIndex(i int) int {
	idx := i*2 - 1
	if idx < 0 {
		idx = 0
	}
	return idx
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
