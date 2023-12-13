package hummingbird

import (
	"crypto/aes"
	"math/rand"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/router/control"
)

// Describes a pair of Ingress and Egress interfaces in a specific AS
type BaseHop struct {
	// IA denotes the IA for which a reservation is valid
	IA addr.IA
	// Ingress is the ingress interface for the reserved hop
	Ingress uint16
	// Egress is the egress interface of the reserved hop
	Egress uint16
}

type Flyover struct {
	BaseHop

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
}

// Temporary cheating function until the system to request keys is available
// return true if successful
func cheat_auth_key(res *Flyover) (Flyover, error) {
	// ResID is set by seller, pick random
	res.ResID = uint32(rand.Int31() >> 10)

	asstr := res.IA.String()
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
func RequestReservations(rs []Flyover) {

}

// Adds a reservation to be used for transmission
func AddReservation(res Flyover) error {
	return nil
}

// Converts a SCiON path to a Hummingbird path without adding any reservations
// Relaces the SCiON dataplane path by a Hummingbird path
func ConvertToHbirdPath(p snet.Path, timeStamp time.Time) (snet.Path, error) {
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
	// set metaheader timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1000) << 22
	dec.PathMeta.BaseTS = secs
	dec.PathMeta.HighResTS = millis

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
