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
	// The flyovers that can be used for this hop.
	// The flyover at index 0 is the one used to build the path
	// MUST be non-empty if hopfield.Flyiver == true
	flyovers []Flyover
	// The original scion mac of the corresponding hopfield.
	scionMac [6]byte
}

func NewReservation(p snet.Path, flyovers map[addr.IA][]*Flyover) (*Reservation, error) {
	c := &Reservation{}
	err := c.prepareHbirdPath(p)
	if err != nil {
		return nil, err
	}
	c.applyFlyovers(flyovers)
	return c, nil
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

// For each hop in the path, returns a flyover containing the AS, Ingress and Egress of that hop
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

// Request flyovers for the full path
// bw: the bandwidth to request
// start: The start time of the flyover, in unix seconds
// duration: The duration of the flyover in seconds
// TODO: add async version once we have request api
func (c *Reservation) RequestFlyoversAllHops(
	bw uint16, start uint32, duration uint16) ([]Flyover, error) {
	hops := make([]BaseHop, len(c.hops))
	for i, h := range c.hops {
		hops[i].IA = h.IA
		hops[i].Ingress = h.Ingress
		hops[i].Egress = h.Egress
	}

	return RequestFlyoversForASes(hops, bw, start, duration)
}

// Requests new flyovers for the listed Hops and returns them once they are obtained
// TODO: add timeout after which already received flyovers
// (if any) are returned once we have actual requests
// TODO: add fully async version of this
func RequestFlyoversForASes(
	hops []BaseHop, bw uint16, start uint32, duration uint16) ([]Flyover, error) {

	log.Debug("Requesting flyovers for", "Hops", hops)
	flyovers := make([]Flyover, len(hops))
	for i, h := range hops {
		//TODO: Once we have API for requests
		// Request (AS, ingress, egress, bw, start, duration)

		// Temporary Cheating
		// Current implementation cheats by writing data directly into c.hops instead

		flyovers[i].IA = h.IA
		flyovers[i].Ingress = h.Ingress
		flyovers[i].Egress = h.Egress
		flyovers[i].Bw = bw
		flyovers[i].StartTime = start
		flyovers[i].Duration = duration

		var err error
		flyovers[i], err = cheat_auth_key(&flyovers[i])
		if err != nil {
			return nil, err
		}
	}
	return flyovers, nil
}

// Adds the listed reservations to the path
func (c *Reservation) Applyflyovers(flyovers []Flyover) error {
	log.Debug("Applying flyovers", "flyovers", flyovers)
	for _, f := range flyovers {
		for j, h := range c.hops {
			if f.IA == h.IA {
				if f.Ingress == h.Ingress && f.Egress == h.Egress {
					c.hops[j].flyovers = append(c.hops[j].flyovers, f)
					if len(c.hops[j].flyovers) == 1 {
						c.hops[j].hopfield.Flyover = true
						c.dec.NumLines += 2
						c.dec.PathMeta.SegLen[h.infIdx] += 2
						c.hops[j].hopfield.Bw = f.Bw
						c.hops[j].hopfield.Duration = f.Duration
						c.hops[j].hopfield.ResID = f.ResID
					}
				} else {
					// TODO: inform caller that this flyover cannot be set on this path
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
				c.hops[i].flyovers = append(c.hops[i].flyovers, *flyover)
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

// Returns all the flyovers that the client may currently use
// If there are multiple flyovers for a hop,
// The one currently used is the first appearing in the returned array
func (c *Reservation) GetUsedFlyovers() []Flyover {
	res := make([]Flyover, 0, len(c.hops))
	for _, h := range c.hops {
		res = append(res, h.flyovers...)
	}
	return res
}

// Removes the flyovers with the given resID from a hop.
func (c *Reservation) removeFlyover(hopIdx int, resID uint32) {
	h := &c.hops[hopIdx]
	for i, r := range h.flyovers {
		if r.ResID == resID {
			if i == 0 {
				if len(h.flyovers) == 1 {
					h.hopfield.Flyover = false
					c.dec.NumLines -= 2
					c.dec.PathMeta.SegLen[c.hops[hopIdx].infIdx] -= 2
					h.flyovers = []Flyover{}
				} else {
					copy(h.flyovers[:], h.flyovers[1:])
					h.flyovers = h.flyovers[:len(h.flyovers)-1]
					h.hopfield.Bw = h.flyovers[0].Bw
					h.hopfield.ResID = h.flyovers[0].ResID
					h.hopfield.Duration = h.flyovers[0].Duration
				}
			} else {
				if i < len(h.flyovers)-1 {
					copy(h.flyovers[i:], h.flyovers[i+1:])
				}
				h.flyovers = h.flyovers[:len(h.flyovers)-1]
			}
			break
		}
	}
}

// Removes res from the flyovers the client is allowed to use
// Flyovers are identified based on their AS and ResID
// Does NOT check for validity of remaining flyovers.
func (c *Reservation) RemoveFlyovers(flyovers []Flyover) error {
	for _, r := range flyovers {
		for i, h := range c.hops {
			if r.IA == h.IA {
				c.removeFlyover(i, r.ResID)
				break
			}
		}
	}
	return nil
}

// Checks whether any current flyover that has expired or will expire in t seconds
// If yes, remove flyover from list of used flyovers.
func (c *Reservation) CheckExpiry(duration uint32) {
	now := uint32(time.Now().Unix())
	for i := range c.hops {

		// Remove expired flyovers.
		for j := 0; j < len(c.hops[i].flyovers); {
			if c.hops[i].flyovers[j].StartTime+uint32(c.hops[i].flyovers[j].Duration) <
				(now + duration) {
				copy(c.hops[i].flyovers[j:], c.hops[i].flyovers[j+1:])
				c.hops[i].flyovers = c.hops[i].flyovers[:len(c.hops[i].flyovers)-1]
			} else {
				j++
			}
		}

		if len(c.hops[i].flyovers) == 0 {
			if c.hops[i].hopfield.Flyover {
				c.hops[i].hopfield.Flyover = false
				c.dec.NumLines -= 2
				c.dec.PathMeta.SegLen[c.hops[i].infIdx] -= 2
			}
			continue
		}
		// If there's any currently valid flyover, put it to the front
		if !(c.hops[i].flyovers[0].StartTime <= now) {
			for j := 1; j < len(c.hops[i].flyovers); j++ {
				if c.hops[i].flyovers[j].StartTime <= now {
					temp := c.hops[i].flyovers[0]
					c.hops[i].flyovers[0] = c.hops[i].flyovers[j]
					c.hops[i].flyovers[j] = temp
					break
				}
			}
		}

		// Check whether flyover at the front is currently valid
		if c.hops[i].flyovers[0].StartTime <= now {
			if !c.hops[i].hopfield.Flyover {
				c.hops[i].hopfield.Flyover = true
				c.dec.NumLines += 2
				c.dec.PathMeta.SegLen[c.hops[i].infIdx] += 2
			}
			c.hops[i].hopfield.Bw = c.hops[i].flyovers[0].Bw
			c.hops[i].hopfield.Duration = c.hops[i].flyovers[0].Duration
			c.hops[i].hopfield.ResID = c.hops[i].flyovers[0].ResID
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
		res := h.flyovers[0]
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
		infIdx:   infIdx,
		hopfield: hf,
		scionMac: hf.HopField.Mac,
		flyovers: make([]Flyover, 0, 2),
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
