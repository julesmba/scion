package hummingbird

import (
	"crypto/aes"
	"encoding/binary"
	"math/rand"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/router/control"
)

type Reservation struct {
	// AS denotes the AS for which a reservation is valid
	AS addr.IA
	// ResID is the reservation ID of the reservation. It is unique PER AS
	ResID uint32
	// Ak is the authentication key of the reservation
	Ak [16]byte
	// Bw is the reserved Bandwidth
	Bw uint16
	// StartTime is the unix timestamp for the start of the reservation
	StartTime uint32
	// Duration is the duration of the reservation in seconds
	Duration uint16
	// EndTime is the unix timestamp at which the reservation ends.
	// Is not strictly necessary but included for simplicity
	EndTime uint32
	// Ingress is the ingress interface for the reserved hop
	Ingress uint16
	// Egress is the egress interface of the reserved hop
	Egress uint16
}

// Describes a pair of Ingress and Egress interfaces in a specific AS
type Hop struct {
	AS      addr.IA
	Ingress uint16
	Egress  uint16
}

type hbirdHop struct {
	// The FlyoverHopField in the path associated to this hop
	hopfield *hummingbird.FlyoverHopField
	// The Index of the Segment the aboe hopfield is part of
	infIdx int
	// The AS this hop traverses
	as addr.IA
	// The ingress used by packets traversing this hop
	ingress uint16
	// The egress used by packets traversing this hop
	egress uint16
	// The reservations that can be used for this hop
	reservations []Reservation
	// The original scion mac of the corresponding hopfield
	scionMac [6]byte
}

// Temporary cheating function until the system to request keys is available
// return true if successful
func cheat_auth_key(res *Reservation) (Reservation, error) {
	// ResID is set by seller, pick random
	res.ResID = uint32(rand.Int31() >> 10)

	asstr := res.AS.String()
	asstr = strings.ReplaceAll(asstr, ":", "_")
	asstr = strings.TrimLeft(asstr, "1234567890-")
	fpath := "gen/AS" + asstr + "/keys"
	mkeys, err := keyconf.LoadMaster(fpath)
	if err != nil {
		return *res, err
	}
	key0 := control.DeriveHbirdSecretValue(mkeys.Key0)
	prf, _ := aes.NewCipher(key0)
	buffer := make([]byte, 16)
	ak := hummingbird.DeriveAuthKey(prf, res.ResID, res.Bw, res.Ingress, res.Egress,
		res.StartTime, res.Duration, buffer)
	copy(res.Ak[:], ak[0:16])
	return *res, nil
}

// Requests a reservation for each given reservation.
// Expects AS, Bw, StartTime, EndTime, Ingress and Egress to be filled in
func RequestReservations(rs []Reservation) {

}

// Adds a reservation to be used for transmission
func AddReservation(res Reservation) error {
	return nil
}

// Converts a SCiON path to a Hummingbird path without adding any reservations
// Relaces the SCiON dataplane path by a Hummingbird path
func ConvertToHbirdPath(p snet.Path) (snet.Path, error) {
	if p == nil {
		return nil, serrors.New("Cannot convert nil path")
	}
	dpath, ok := p.Dataplane().(snetpath.SCION)
	if !ok {
		return nil, serrors.New("Can only convert SCiON paths to Hummingbird")
	}
	dec, err := convertSCIONToHbirdDecoded(dpath.Raw)
	if err != nil {
		return nil, err
	}

	hbird, err := snetpath.NewHbirdFromDecoded(&dec)
	if err != nil {
		return nil, err
	}
	// update dataplane path
	switch v := p.(type) {
	case snetpath.Path:
		v.DataplanePath = hbird
		p = v
	default:
		return nil, serrors.New("Unsupported snet path struct", "path", p)
	}
	return p, nil
}

func convertSCIONToHbirdDecoded(p []byte) (hummingbird.Decoded, error) {

	scionDec := scion.Decoded{}
	if err := scionDec.DecodeFromBytes(p); err != nil {
		return hummingbird.Decoded{}, err
	}

	hbirdDec := hummingbird.Decoded{}
	hbirdDec.ConvertFromScionDecoded(scionDec)
	return hbirdDec, nil
}

type HummingbirdClient struct {
	// caches a decoded path for multiple uses
	dec hummingbird.Decoded
	// Destination of the path
	dest addr.IA
	// The hops for which it is possible to add reservations
	hops []hbirdHop
	// counter for duplicate detection
	counter uint32
	// buffers for computing Vk
	byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	xkbuffer   [hummingbird.XkBufferSize]uint32
}

func (c *HummingbirdClient) parseIAs(ifs []snet.PathInterface) error {
	c.hops[0].as = ifs[0].IA
	i, j := 1, 1
	for i < len(c.hops) && j < len(ifs) {
		if ifs[j].IA == ifs[j-1].IA {
			// Ignore duplicates
			j++
		} else {
			c.hops[i].as = ifs[j].IA
			i++
			j++
		}
	}
	if i < len(c.hops) {
		return serrors.New("Not enough ASes for this path")
	}
	return nil
}

// Prepares as hummingbird path and initializes the fields of the hummingbirdClient struct
// Returns an array of Hops containing the AS, Ingress and Egress of each hop on the path
func (c *HummingbirdClient) PrepareHbirdPath(p snet.Path) ([]Hop, error) {
	if p == nil {
		return nil, serrors.New("Empty path")
	}
	c.dec = hummingbird.Decoded{}
	switch v := p.Dataplane().(type) {
	case snetpath.SCION:
		// Convert path to decoded hbird path
		scionDec := scion.Decoded{}
		if err := scionDec.DecodeFromBytes(v.Raw); err != nil {
			return nil, serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
		c.dec.ConvertFromScionDecoded(scionDec)
	case snetpath.Hummingbird:
		if err := c.dec.DecodeFromBytes(v.Raw); err != nil {
			return nil, serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
	default:
		return nil, serrors.New("Unsupported path type")
	}
	// Initialize a hop for each traversed as
	c.hops = make([]hbirdHop, len(c.dec.HopFields))
	j := 0
	for i := 0; i < len(c.dec.HopFields); i++ {
		var xover bool
		var infIdx int
		if i < int(c.dec.FirstHopPerSeg[0]) {
			infIdx = 0
			if !c.dec.InfoFields[0].Peer {
				xover = (i == int(c.dec.FirstHopPerSeg[0])-1) &&
					i < len(c.dec.HopFields)-1
			}
		} else if i < int(c.dec.FirstHopPerSeg[1]) {
			infIdx = 1
			if !c.dec.InfoFields[1].Peer {
				if i == int(c.dec.FirstHopPerSeg[0]) {
					// First hop after Crossover, nothing to be done
					continue
				}
				xover = i == int(c.dec.FirstHopPerSeg[1])-1 &&
					i < len(c.dec.HopFields)-1
			}
		} else {
			infIdx = 2
			if c.dec.InfoFields[2].Peer {
				return nil, serrors.New("Invalid path, cannot have 3 segments on peering path")
			}
			if i == int(c.dec.FirstHopPerSeg[1]) && i < len(c.dec.HopFields)-1 {
				// First hop after Crossover, nothing to be done
				continue
			}
		}
		c.hops[j].infIdx = infIdx
		c.hops[j].hopfield = &c.dec.HopFields[i]
		// Set ingress/egress
		if xover {
			if c.dec.InfoFields[infIdx].ConsDir {
				c.hops[j].ingress = c.dec.HopFields[i].HopField.ConsIngress
			} else {
				c.hops[j].ingress = c.dec.HopFields[i].HopField.ConsEgress
			}
			if c.dec.InfoFields[infIdx+1].ConsDir {
				c.hops[j].egress = c.dec.HopFields[i+1].HopField.ConsEgress
			} else {
				c.hops[j].egress = c.dec.HopFields[i+1].HopField.ConsIngress
			}
		} else {
			if c.dec.InfoFields[infIdx].ConsDir {
				c.hops[j].ingress = c.dec.HopFields[i].HopField.ConsIngress
				c.hops[j].egress = c.dec.HopFields[i].HopField.ConsEgress
			} else {
				c.hops[j].ingress = c.dec.HopFields[i].HopField.ConsEgress
				c.hops[j].egress = c.dec.HopFields[i].HopField.ConsIngress
			}
		}
		// cache scion mac
		copy(c.hops[j].scionMac[:], c.hops[j].hopfield.HopField.Mac[:])
		// Initialiaze reservations
		c.hops[j].reservations = make([]Reservation, 0, 2)
		j++
	}
	c.hops = c.hops[:j]
	// Parse the list of ASes on path
	if err := c.parseIAs(p.Metadata().Interfaces); err != nil {
		return nil, serrors.Join(err, serrors.New("Malformed path"))
	}
	c.dest = c.hops[len(c.hops)-1].as

	return c.GetPathASes(), nil
}

// For each hop in the path, returns a reservation containing the AS, Ingress and Egress of that hop
func (c *HummingbirdClient) GetPathASes() []Hop {
	hops := make([]Hop, len(c.hops))
	for i, h := range c.hops {
		hops[i].AS = h.as
		hops[i].Ingress = h.ingress
		hops[i].Egress = h.egress
	}
	return hops
}

// Request reservations for the full path
// bw: the bandwidth to request
// start: The start time of the reservation, in unix seconds
// duration: The duration of the reservation in seconds
// TODO: add async version once we have request api
func (c *HummingbirdClient) RequestReservationsAllHops(
	bw uint16, start uint32, duration uint16) ([]Reservation, error) {
	hops := make([]Hop, len(c.hops))
	for i, h := range c.hops {
		hops[i].AS = h.as
		hops[i].Ingress = h.ingress
		hops[i].Egress = h.egress
	}

	return RequestReservationForASes(hops[:], bw, start, duration)
}

// Requests new reservations for the listed Hops and returns them once they are obtained
// TODO: add timeout after which already received reservations (if any) are returned once we have actual requests
// TODO: add fully async version of this
func RequestReservationForASes(
	hops []Hop, bw uint16, start uint32, duration uint16) ([]Reservation, error) {

	log.Debug("Requesting reservations for", "Hops", hops)
	reservations := make([]Reservation, len(hops))
	for i, h := range hops {
		//TODO: Once we have API for requests
		// Request (AS, ingress, egress, bw, start, duration)

		// Temporary Cheating
		// Current implementation cheats by writing data directly into c.hops instead

		reservations[i].AS = h.AS
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

// Return all Reservations present in the database
func GetAllReservations() ([]Reservation, error) {
	return nil, serrors.New("Not Implemented")
}

// Returns all reservations in the database that can be used for the current path
func (c *HummingbirdClient) GetAvailableReservations() ([]Reservation, error) {
	// Return all reservations in the data base
	//TODO: return all reservations in the db that fit the path (AS, ingress egress)

	//TODO: incorporate into integration test once we have async version of previous functions

	return nil, serrors.New("Not Implemented")
}

// Adds the listed reservations to the path
func (c *HummingbirdClient) ApplyReservations(res []Reservation) error {
	log.Debug("Applying reservations", "reservations", res)
	for _, r := range res {
		for j, h := range c.hops {
			if r.AS == h.as {
				if r.Ingress == h.ingress && r.Egress == h.egress {
					// TODO: If there are already reservations present, order by validity/bandwidth?
					c.hops[j].reservations = append(c.hops[j].reservations, r)

					// TODO: Only modify flyoverhopfield if new reservation becomes primary reservation
					c.hops[j].hopfield.Flyover = true
					c.dec.NumLines += 2
					c.dec.PathMeta.SegLen[h.infIdx] += 2
					c.hops[j].hopfield.Bw = r.Bw
					c.hops[j].hopfield.Duration = r.Duration
					c.hops[j].hopfield.ResID = r.ResID
				} else {
					// TODO: inform caller that this reservation cannot be set on this path
					break
				}
			}
		}
	}
	return nil
}

// Checks whether any current reservation has arrived at expiration
// If yes, disable reservation
// TODO: add mechanism to automatically replace it
func (c *HummingbirdClient) checkExpiry() {

}

// Sets pathmeta timestamps and increments duplicate detection counter.
// Updates MACs of all flyoverfields
// replaces the dataplane of the inut snet.path with the finished hummingbird path
func (c *HummingbirdClient) FinalizePath(p snet.Path, pktLen uint16) (snet.Path, error) {
	if p == nil {
		return nil, serrors.New("snet path is nil")
	}
	var dphb snetpath.Hummingbird

	// Update timestamps
	now := time.Now()
	secs := uint32(now.Unix())
	millis := uint32(now.Nanosecond()/1000) << 22
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
		flyovermac := hummingbird.FullFlyoverMac(res.Ak[:], c.dest, pktLen,
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
	case snetpath.Path:
		v.DataplanePath = dphb
		p = v
	default:
		return nil, serrors.New("Unsupported snet path struct", "path", p)
	}

	return p, nil
}
