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
	"github.com/scionproto/scion/pkg/addr"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
)

func ConvertFlyoverToPB(f *Flyover) *sdpb.Flyover {
	if f == nil {
		return nil
	}
	ret := &sdpb.Flyover{
		Ia:        uint64(f.IA),
		Ingress:   uint32(f.Ingress),
		Egress:    uint32(f.Egress),
		Bw:        uint32(f.Bw),
		ResId:     f.ResID,
		StartTime: f.StartTime,
		Duration:  uint32(f.Duration),
		Ak:        append([]byte{}, f.Ak[:]...),
	}

	return ret
}

func ConvertFlyoversToPB(flyovers []*Flyover) []*sdpb.Flyover {
	ret := make([]*sdpb.Flyover, len(flyovers))
	for i, f := range flyovers {
		ret[i] = ConvertFlyoverToPB(f)
	}
	return ret
}

func ConvertFlyoverFromPB(f *sdpb.Flyover) *Flyover {
	if f == nil {
		return nil
	}
	ret := &Flyover{
		BaseHop: BaseHop{
			IA:      addr.IA(f.Ia),
			Ingress: uint16(f.Ingress),
			Egress:  uint16(f.Egress),
		},
		Bw:        uint16(f.Bw),
		ResID:     f.ResId,
		StartTime: f.StartTime,
		Duration:  uint16(f.Duration),
	}
	copy(ret.Ak[:], f.Ak)
	return ret
}
func ConvertFlyoversFromPB(flyovers []*sdpb.Flyover) []*Flyover {
	ret := make([]*Flyover, len(flyovers))
	for i, f := range flyovers {
		ret[i] = ConvertFlyoverFromPB(f)
	}
	return ret
}

func ConvertReservationToPB(r *Reservation) (*sdpb.Reservation, error) {
	// Prepare the hummingbird path.
	p := r.GetHummingbirdPath()
	raw := make([]byte, p.Len())
	if err := p.SerializeTo(raw); err != nil {
		return nil, err
	}

	// Prepare the flyovers.
	flyovers := r.FlyoverPerHopField()
	numF, numHF := r.FlyoverAndHFCount()

	return &sdpb.Reservation{
		Raw:      raw,
		Ratio:    float64(numF) / float64(numHF),
		Flyovers: ConvertFlyoversToPB(flyovers),
	}, nil
}
