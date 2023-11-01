package hummingbird

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
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
	// StartTime is the unix timestamp for teh start of the reservation
	StartTime uint32
	// Duration is the duration of the reservation in seconds
	Duration uint16
	// EndTime is the unix timestamp at which the reservation ends. Is not strictly necessary but included for simplicity
	EndTime uint32
	// Ingress is the ingress interface for the reserved hop
	Ingress uint16
	// Egress is the egress interface of the reserved hop
	Egress uint16
}

// Temporary cheating function until the system to request keys is available
// return true if successfull
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
	key0 := control.DeriveHFMacKey(mkeys.Key0)
	prf, _ := aes.NewCipher(key0)
	buffer := make([]byte, 16)

	log.Debug("Computing AK", "ResID", res.ResID, "bw", res.Bw, "ingress", res.Ingress, "Egress", res.Egress, "start", res.StartTime, "Duration", res.Duration)
	ak := hummingbird.DeriveAuthKey(prf, res.ResID, res.Bw, res.Ingress, res.Egress, res.StartTime, res.Duration, buffer)
	copy(res.Ak[:], ak[0:16])
	return *res, nil
}

// Requests a reservation for each given reservation. Expects AS, Bw, StartTime, EndTime, Ingress and Egress to be filled in
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
	dec := convertSCIONToHbirdDecoded(dpath.Raw)

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

func convertSCIONToHbirdDecoded(p []byte) hummingbird.Decoded {

	scionDec := scion.Decoded{}
	scionDec.DecodeFromBytes(p)

	hbirdDec := hummingbird.Decoded{}
	hbirdDec.ConvertFromScionDecoded(scionDec)
	return hbirdDec
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
	byteBuffer [16]byte
	xkbuffer   [44]uint32
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
		scionDec.DecodeFromBytes(v.Raw)
		for _, hop := range scionDec.HopFields {
			log.Debug("Decoded Scion", "mac", fmt.Sprintf("%x", hop.Mac[:]))
		}
		c.dec.ConvertFromScionDecoded(scionDec)
	case snetpath.Hummingbird:
		c.dec.DecodeFromBytes(v.Raw)
	default:
		return serrors.New("Unsupported path type")
	}
	// Parse the list of ASes on path
	c.ases = make([]addr.IA, len(p.Metadata().Interfaces))
	for i, ia := range p.Metadata().Interfaces {
		c.ases[i] = ia.IA
	}
	c.dest = c.ases[len(c.ases)-1]
	// cache Scion Hopfield macs
	c.macs = make([][6]byte, len(c.dec.HopFields))
	for i, hop := range c.dec.HopFields {
		copy(c.macs[i][:], hop.HopField.Mac[:])
		log.Debug("Scion MAC in prepare", "c.macs i", fmt.Sprintf("%x", c.macs[i]))
	}
	// prepare reservations data structure
	c.reservations = make([]Reservation, len(c.dec.HopFields))
	return nil
}

func (c *HummingbirdClient) RequestReservationsAllHops(bw uint16, start uint32, duration uint16) error {
	inf := 0
	currseg := 0
	for i := range c.dec.HopFields {
		res := Reservation{
			AS:        c.ases[i],
			Bw:        bw,
			StartTime: start,
			Duration:  duration,
			Ingress:   c.dec.HopFields[i].HopField.ConsIngress,
			Egress:    c.dec.HopFields[i].HopField.ConsEgress,
		}
		var err error
		c.reservations[i], err = cheat_auth_key(&res)
		if err != nil {
			return err
		}
		// set flyover to true and adapt metahdr
		c.dec.HopFields[i].Flyover = true
		c.dec.NumHops += 2
		c.dec.PathMeta.SegLen[inf] += 2
		currseg += 5
		if c.dec.PathMeta.SegLen[inf] <= uint8(currseg) {
			currseg = 0
			inf += 1
		}
		// set other fields
		c.dec.HopFields[i].Bw = res.Bw
		c.dec.HopFields[i].Duration = res.Duration
		c.dec.HopFields[i].ResID = res.ResID
	}
	return nil
}

// Returns a copy of all ASes on the current path in order
func (c *HummingbirdClient) GetPathASes() []addr.IA {
	ascopy := make([]addr.IA, len(c.ases))
	copy(ascopy, c.ases)
	return ascopy
}

// Requests new reservations for this path for the listed ASes
// Expects them to be in order.
func (c *HummingbirdClient) RequestReservationForASes(asin []addr.IA, bw uint16, start uint32, duration uint16) error {
	j := 0
	for i := range c.dec.HopFields {
		if c.ases[i] == asin[j] {
			c.reservations[i].AS = asin[j]
			c.reservations[i].Bw = bw
			c.reservations[i].StartTime = start
			c.reservations[i].Duration = duration
			c.reservations[i].Ingress = c.dec.HopFields[i].HopField.ConsIngress
			c.reservations[i].Egress = c.dec.HopFields[i].HopField.ConsEgress
			var err error
			c.reservations[i], err = cheat_auth_key(&c.reservations[i])
			if err != nil {
				return err
			}
			// set flyover
			c.dec.HopFields[i].Flyover = true
			c.dec.NumHops += 2
			if i < int(c.dec.FirstHopPerSeg[0]) {
				c.dec.PathMeta.SegLen[0] += 2
			} else if i < int(c.dec.FirstHopPerSeg[1]) {
				c.dec.PathMeta.SegLen[1] += 2
			} else {
				c.dec.PathMeta.SegLen[2] += 2
			}
			// set other fields
			c.dec.HopFields[i].Bw = c.reservations[i].Bw
			c.dec.HopFields[i].Duration = c.reservations[i].Duration
			c.dec.HopFields[i].ResID = c.reservations[i].ResID
		}

	}
	return nil
}

// Return all Reservations present in the database
func GetAllReservations() ([]Reservation, error) {
	return nil, serrors.New("Not Implemented")
}

// Returns all reservations in the database that are applicable to the current path
func (c *HummingbirdClient) GetAllReservations() ([]Reservation, error) {
	// Return all reservations in the data base
	return nil, serrors.New("Not Implemented")
}

// Adds the listed reservations to the path
func (c *HummingbirdClient) ApplyReservations(res []Reservation) error {
	return serrors.New("Not Implemented")
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
	for i, _ := range c.dec.HopFields {
		if !c.dec.HopFields[i].Flyover {
			continue
		}
		res := c.reservations[i]
		c.dec.HopFields[i].ResStartTime = uint16(secs - res.StartTime)
		log.Debug("Computing flyoverMac", "AK", res.Ak[:], "dest", c.dest, "length", pktLen, "start", c.dec.HopFields[i].ResStartTime, "highResTS", millis)
		flyovermac := hummingbird.FullFlyoverMac(res.Ak[:], c.dest, pktLen, c.dec.HopFields[i].ResStartTime, millis, c.byteBuffer[:], c.xkbuffer[:])
		log.Debug("Scion MAC in finalize", "c.macs i", fmt.Sprintf("%x", c.macs[i]))
		binary.BigEndian.PutUint32(c.dec.HopFields[i].HopField.Mac[:4], binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(c.macs[i][:4]))
		binary.BigEndian.PutUint16(c.dec.HopFields[i].HopField.Mac[4:], binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(c.macs[i][4:]))
		log.Debug("Aggregated MAc", "mac", fmt.Sprintf("%x", c.dec.HopFields[i].HopField.Mac[:6]))
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
