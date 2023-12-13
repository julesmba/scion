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

package servers

import (
	"context"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

type HummingbirdFetcher interface {
	ListFlyovers(ctx context.Context, owners []addr.IA) ([]*hummingbird.BaseHop, error)
}

func (s *DaemonServer) StoreFlyovers(
	ctx context.Context,
	req *sdpb.StoreFlyoversRequest,
) (*sdpb.StoreFlyoversResponse, error) {
	return nil, nil
}
func (s *DaemonServer) ListFlyovers(
	ctx context.Context,
	req *sdpb.ListFlyoversRequest,
) (*sdpb.ListFlyoversResponse, error) {
	return nil, nil
}

func (s *DaemonServer) GetReservations(
	ctx context.Context,
	req *sdpb.GetReservationsRequest,
) (*sdpb.GetReservationsResponse, error) {

	// Get SCION paths.
	paths, err := s.getScionPaths(ctx, addr.IA(req.SourceIsdAs), addr.IA(req.DestinationIsdAs),
		req.Refresh)
	if err != nil {
		return nil, err
	}

	// Obtain reservations composing flyovers for those paths.
	rsvs, err := s.getReservations(ctx, paths)
	if err != nil {
		return nil, err
	}

	// Prepare response.
	res := &sdpb.GetReservationsResponse{
		Reservations: make([]*sdpb.Reservation, len(paths)),
	}

	_ = rsvs

	return res, nil
}

func (s *DaemonServer) getScionPaths(
	ctx context.Context,
	src, dst addr.IA,
	refresh bool,
) ([]path.Path, error) {
	pathReq := &sdpb.PathsRequest{
		SourceIsdAs:      uint64(src),
		DestinationIsdAs: uint64(dst),
		Refresh:          refresh,
		Hidden:           false,
	}
	pathRes, err := s.paths(ctx, pathReq)
	err = unwrapMetricsError(err)
	if err != nil {
		return nil, serrors.WrapStr("obtaining reservations", err)
	}

	// Unwrap the response to a slice of path.Path
	paths := make([]path.Path, len(pathRes.Paths))
	for i, p := range pathRes.Paths {
		paths[i], err = convertPath(p, dst)
		if err != nil {
			return nil, err
		}
	}

	return paths, nil
}

func (s *DaemonServer) getReservations(
	ctx context.Context,
	paths []path.Path,
) ([]*hummingbird.ReservationJuanDeleteme, error) {

	// Make a set with all appearing IASet. Then a slice of them to obtain flyovers.
	IASet := make(map[addr.IA]struct{}, 0)
	for _, p := range paths {
		for _, iface := range p.Meta.Interfaces {
			IASet[iface.IA] = struct{}{}
		}
	}
	IAs := make([]addr.IA, 0, len(IASet))
	for ia := range IASet {
		IAs = append(IAs, ia)
	}

	// Get flyovers on any AS present in the paths.
	flyovers, err := s.HummingbirdFetcher.ListFlyovers(ctx, IAs)
	if err != nil {
		return nil, err
	}
	mFlyovers := flyoversToMap(flyovers)

	// For each path, try to assign as many flyovers as possible.
	reservations := make([]*hummingbird.ReservationJuanDeleteme, len(paths))
	for i, p := range paths {
		flyovers, ratio := assignFlyovers(p.Meta.Interfaces, mFlyovers)
		reservations[i] = &hummingbird.ReservationJuanDeleteme{
			SCIONPath: p,
			Flyovers:  flyovers,
			Ratio:     ratio,
		}
	}

	// Rank the reservations by flyover / hop ratio.
	sort.Slice(reservations, func(i, j int) bool {
		return reservations[i].LessThan(reservations[j])
	})

	return reservations, nil
}

func convertPath(p *sdpb.Path, dst addr.IA) (path.Path, error) {
	expiry := time.Unix(p.Expiration.Seconds, int64(p.Expiration.Nanos))
	if len(p.Interfaces) == 0 {
		return path.Path{
			Src: dst,
			Dst: dst,
			Meta: snet.PathMetadata{
				MTU:    uint16(p.Mtu),
				Expiry: expiry,
			},
			DataplanePath: path.Empty{},
		}, nil
	}
	underlayA, err := net.ResolveUDPAddr("udp", p.Interface.Address.Address)
	if err != nil {
		return path.Path{}, serrors.WrapStr("resolving underlay", err)
	}
	interfaces := make([]snet.PathInterface, len(p.Interfaces))
	for i, pi := range p.Interfaces {
		interfaces[i] = snet.PathInterface{
			ID: common.IFIDType(pi.Id),
			IA: addr.IA(pi.IsdAs),
		}
	}
	latency := make([]time.Duration, len(p.Latency))
	for i, v := range p.Latency {
		latency[i] = time.Second*time.Duration(v.Seconds) + time.Duration(v.Nanos)
	}
	geo := make([]snet.GeoCoordinates, len(p.Geo))
	for i, v := range p.Geo {
		geo[i] = snet.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]snet.LinkType, len(p.LinkType))
	for i, v := range p.LinkType {
		linkType[i] = linkTypeFromPB(v)
	}

	res := path.Path{
		Src: interfaces[0].IA,
		Dst: dst,
		DataplanePath: path.SCION{
			Raw: p.Raw,
		},
		NextHop: underlayA,
		Meta: snet.PathMetadata{
			Interfaces:   interfaces,
			MTU:          uint16(p.Mtu),
			Expiry:       expiry,
			Latency:      latency,
			Bandwidth:    p.Bandwidth,
			Geo:          geo,
			LinkType:     linkType,
			InternalHops: p.InternalHops,
			Notes:        p.Notes,
		},
	}

	if p.EpicAuths == nil {
		return res, nil
	}
	res.Meta.EpicAuths = snet.EpicAuths{
		AuthPHVF: append([]byte(nil), p.EpicAuths.AuthPhvf...),
		AuthLHVF: append([]byte(nil), p.EpicAuths.AuthLhvf...),
	}
	return res, nil
}

func linkTypeFromPB(lt sdpb.LinkType) snet.LinkType {
	switch lt {
	case sdpb.LinkType_LINK_TYPE_DIRECT:
		return snet.LinkTypeDirect
	case sdpb.LinkType_LINK_TYPE_MULTI_HOP:
		return snet.LinkTypeMultihop
	case sdpb.LinkType_LINK_TYPE_OPEN_NET:
		return snet.LinkTypeOpennet
	default:
		return snet.LinkTypeUnset
	}
}

// flyoverMapKey is a map of flyovers keyed by IA, ingress, and egress.
// The assumption is that at most one hop field exists per triplet.
type flyoverMapKey struct {
	IA      addr.IA
	Ingress uint16
	Egress  uint16
}
type flyoverMap map[flyoverMapKey]*hummingbird.BaseHop

func flyoversToMap(flyovers []*hummingbird.BaseHop) flyoverMap {
	ret := make(flyoverMap)
	for _, flyover := range flyovers {
		k := flyoverMapKey{
			IA:      flyover.IA,
			Ingress: flyover.Ingress,
			Egress:  flyover.Egress,
		}
		ret[k] = flyover
	}
	return ret
}

// assignFlyovers assigns as flyovers to as many hops of a path as possible.
// The first returned value is a slice of flyovers, with the same length as the hop sequence,
// and when not nil, it points to a Flyover that can be used in the hop of that specific index.
// As SCION hops appear twice per ingress/egress pairs (with the exception of the first and
// last ones), the flyovers are never located on tbe egress index, which means, always located
// on odd indices.
// The second returned value is the ratio of flyovers (1.0 being all, 0.0 being none) that exist
// for that path.
func assignFlyovers(
	hopSequence []snet.PathInterface,
	flyovers flyoverMap,
) ([]*hummingbird.BaseHop, float64) {

	ret := make([]*hummingbird.BaseHop, len(hopSequence))
	flyoverExistsCount := 0

	// Do the first flyover apart.
	k := flyoverMapKey{
		IA:      hopSequence[0].IA,
		Ingress: 0,
		Egress:  uint16(hopSequence[0].ID),
	}
	ret[0] = flyovers[k]
	if ret[0] != nil {
		flyoverExistsCount++
	}

	// Do everything in the middle, except the last flyover.
	for i := 1; i < len(hopSequence)-1; i += 2 {
		// Prepare to look for the next flyover.
		hop := hopSequence[i]
		k = flyoverMapKey{
			IA:      hop.IA,
			Ingress: uint16(hop.ID),
			Egress:  uint16(hopSequence[i+1].ID),
		}

		// Find out if there's any flyover we can use.
		ret[i] = flyovers[k]
		if ret[i] != nil {
			flyoverExistsCount++
		}
	}

	// Do the last flyover.
	k = flyoverMapKey{
		IA:      hopSequence[len(hopSequence)-1].IA,
		Ingress: uint16(hopSequence[len(hopSequence)-1].ID),
		Egress:  0,
	}
	ret[len(ret)-1] = flyovers[k]
	if ret[len(ret)-1] != nil {
		flyoverExistsCount++
	}

	return ret, float64(flyoverExistsCount) / float64(len(hopSequence)/2)
}
