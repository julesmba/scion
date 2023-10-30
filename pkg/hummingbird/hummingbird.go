package hummingbird

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
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
	dpath.Raw = hbird.Raw
	return p, nil
}

func convertSCIONToHbirdDecoded(p []byte) hummingbird.Decoded {

	scionDec := scion.Decoded{}
	scionDec.DecodeFromBytes(p)

	hbirdDec := hummingbird.Decoded{}
	hbirdDec.ConvertFromScionDecoded(scionDec)
	return hbirdDec
}
