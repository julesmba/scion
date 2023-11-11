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
	// caches the list of ASes on path
	ases []addr.IA
	// Cached scion MACs for each hop
	macs [][6]byte
	//TODO: replace by db
	reservations []Reservation
	// counter for duplicate detection
	counter uint32
	// buffers for computing Vk
	byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	xkbuffer   [hummingbird.XkBufferSize]uint32
}

func (c *HummingbirdClient) parseIAs(ifs []snet.PathInterface) error {
	c.ases = make([]addr.IA, len(c.dec.HopFields))
	c.ases[0] = ifs[0].IA
	i, j := 1, 1
	for i < len(c.ases) && j < len(ifs) {

		switch true {
		// First hop after Crossover always has same as as previous hop
		case (i == int(c.dec.FirstHopPerSeg[0]) && !c.dec.InfoFields[1].Peer) ||
			(i == int(c.dec.FirstHopPerSeg[1])):
			c.ases[i] = c.ases[i-1]
			i++
		// Skip duplicates interfaces.
		// Only duplicates we want are those for Xovers, and we already add these manually above
		case ifs[j].IA == ifs[j-1].IA:
			j++
		default:
			c.ases[i] = ifs[j].IA
			i++
			j++
		}

	}
	if i < len(c.ases)-1 {
		return serrors.New("Not enough ASes for this path")
	}
	return nil
}

func (c *HummingbirdClient) PrepareHbirdPath(p snet.Path) error {
	if p == nil {
		return serrors.New("Empty path")
	}
	c.dec = hummingbird.Decoded{}
	switch v := p.Dataplane().(type) {
	case snetpath.SCION:
		// Convert path to decoded hbird path
		scionDec := scion.Decoded{}
		if err := scionDec.DecodeFromBytes(v.Raw); err != nil {
			return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
		c.dec.ConvertFromScionDecoded(scionDec)
	case snetpath.Hummingbird:
		if err := c.dec.DecodeFromBytes(v.Raw); err != nil {
			return serrors.Join(err, serrors.New("Failed to Prepare Hummingbird Path"))
		}
	default:
		return serrors.New("Unsupported path type")
	}
	log.Debug("parsing AS")
	// Parse the list of ASes on path
	if err := c.parseIAs(p.Metadata().Interfaces); err != nil {
		return serrors.Join(err, serrors.New("Malformed path"))
	}
	c.dest = c.ases[len(c.ases)-1]
	// cache Scion Hopfield macs
	c.macs = make([][6]byte, len(c.dec.HopFields))
	for i, hop := range c.dec.HopFields {
		copy(c.macs[i][:], hop.HopField.Mac[:])
	}
	log.Debug("path ASes", "ASes", c.ases)
	// prepare reservations data structure
	c.reservations = make([]Reservation, len(c.dec.HopFields))
	// Initialize expected AS, ingress and egress for each reservation
	// keep all fields 0 for second crossover hop where no reservation in allowed
	for i, hop := range c.dec.HopFields {
		var infIdx int
		var xover bool
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
				return serrors.New("Invalid path, cannot have 3 segments on peering path")
			}
			if i == int(c.dec.FirstHopPerSeg[1]) && i < len(c.dec.HopFields)-1 {
				// First hop after Crossover, nothing to be done
				continue
			}
		}
		// set AS
		c.reservations[i].AS = c.ases[i]
		// Set ingress/egress
		if xover {
			if c.dec.InfoFields[infIdx].ConsDir {
				c.reservations[i].Ingress = hop.HopField.ConsIngress
			} else {
				c.reservations[i].Ingress = hop.HopField.ConsEgress
			}
			if c.dec.InfoFields[infIdx+1].ConsDir {
				c.reservations[i].Egress = c.dec.HopFields[i+1].HopField.ConsEgress
			} else {
				c.reservations[i].Egress = c.dec.HopFields[i+1].HopField.ConsIngress
			}
		} else {
			if c.dec.InfoFields[infIdx].ConsDir {
				c.reservations[i].Ingress = hop.HopField.ConsIngress
				c.reservations[i].Egress = hop.HopField.ConsEgress
			} else {
				c.reservations[i].Ingress = hop.HopField.ConsEgress
				c.reservations[i].Egress = hop.HopField.ConsIngress
			}
		}
	}
	return nil
}

// Returns a copy of all ASes on the current path in order without duplicates
func (c *HummingbirdClient) GetPathASes() []addr.IA {
	ascopy := make([]addr.IA, len(c.ases))
	j := 0
	for i := range c.ases {
		if i == 0 || c.ases[i] != c.ases[i-1] {
			ascopy[j] = c.ases[i]
			j++
		}
	}
	return ascopy[:j]
}

func (c *HummingbirdClient) RequestReservationsAllHops(
	bw uint16, start uint32, duration uint16) error {
	ascopy := make([]addr.IA, len(c.ases))
	j := 0
	for i := range c.ases {
		if i == 0 || c.ases[i] != c.ases[i-1] {
			ascopy[j] = c.ases[i]
			j++
		}
	}
	return c.RequestReservationForASes(ascopy[:j], bw, start, duration)
}

// Requests new reservations for this path for the listed ASes
// Expects them to be in order without duplicates
func (c *HummingbirdClient) RequestReservationForASes(
	asin []addr.IA, bw uint16, start uint32, duration uint16) error {
	log.Debug("Requesting reservations for", "AS", asin)
	j := 0
	for i := range c.dec.HopFields {
		if j >= len(asin) {
			break
		}
		if asin[j] != c.ases[i] {
			continue
		}

		if (i == int(c.dec.FirstHopPerSeg[0]) && !c.dec.InfoFields[1].Peer) ||
			(i == int(c.dec.FirstHopPerSeg[1])) {
			// Ignore the second hops after crossover
			continue
		}

		// TODO: request reservations
		// Current implementation cheats by writing data into c.reservations instead
		//c.reservations[i].AS = c.ases[i]
		c.reservations[i].Bw = bw
		c.reservations[i].StartTime = start
		c.reservations[i].Duration = duration

		var err error
		c.reservations[i], err = cheat_auth_key(&c.reservations[i])
		if err != nil {
			return err
		}
		j++
	}

	return nil
}

// Return all Reservations present in the database
func GetAllReservations() ([]Reservation, error) {
	return nil, serrors.New("Not Implemented")
}

// Returns all reservations in the database that can be used for the current path
func (c *HummingbirdClient) GetAvailableReservations() ([]Reservation, error) {
	// Return all reservations in the data base
	//TODO: return all reservations in the db that fit the path (AS, ingress egress)

	// Unti we have access to the daemon db, we cheat and return  the data written into c.reservations in request
	res := make([]Reservation, len(c.reservations))
	j := 0
	for _, r := range c.reservations {
		if r.Bw != 0 {
			res[j] = r
			j++
		}
	}
	log.Debug("getting available reservations", "reservations", res)
	return res[:j], nil
}

// Adds the listed reservations to the path
// Expects them to be in order
func (c *HummingbirdClient) ApplyReservations(res []Reservation) error {
	log.Debug("Applying reservations", "reservations", res)
	for i, j := 0, 0; i < len(c.reservations) && j < len(res); i++ {
		if res[j].AS == c.reservations[i].AS {
			if res[j].Ingress == c.reservations[i].Ingress && res[j].Egress == c.reservations[i].Egress {
				//TODO: handle case of multiple reservations for one hop (different validiy windows)
				c.reservations[i] = res[j]
				c.dec.HopFields[i].Flyover = true
				c.dec.NumLines += 2
				// increment corresponding segLen
				switch true {
				case i < int(c.dec.FirstHopPerSeg[0]):
					c.dec.PathMeta.SegLen[0] += 2
				case i < int(c.dec.FirstHopPerSeg[1]):
					c.dec.PathMeta.SegLen[1] += 2
				default:
					c.dec.PathMeta.SegLen[2] += 2
				}
				// Set other fields
				c.dec.HopFields[i].Bw = res[j].Bw
				c.dec.HopFields[i].Duration = res[j].Duration
				c.dec.HopFields[i].ResID = res[j].ResID
			}
			//TODO: else inform user at the end that this reservations does not fit he path

			j++
		}
	}
	return nil
}

// Checks whether any current reservation has arrived at expiration
// If yes, disable reservation
// TODO: add mechanism to automatically replace it
func (c *HummingbirdClient) checkExpiry() {
	now := uint32(time.Now().Unix())
	for i := range c.reservations {
		if c.reservations[i].EndTime < now {
			c.dec.HopFields[i].Flyover = false
		}
	}
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
	for i := range c.dec.HopFields {
		if !c.dec.HopFields[i].Flyover {
			continue
		}
		res := c.reservations[i]
		c.dec.HopFields[i].ResStartTime = uint16(secs - res.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(res.Ak[:], c.dest, pktLen,
			c.dec.HopFields[i].ResStartTime, millis, c.byteBuffer[:], c.xkbuffer[:])
		binary.BigEndian.PutUint32(c.dec.HopFields[i].HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(c.macs[i][:4]))
		binary.BigEndian.PutUint16(c.dec.HopFields[i].HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(c.macs[i][4:]))
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
