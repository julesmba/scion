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
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/require"
)

// TestGetReservation checks that given a set of SCION paths, the functions getting the
// reservation correctly finds the appropriate flyovers and uses them.
func TestGetReservation(t *testing.T) {
	cases := map[string]struct {
		// paths' hops, like { {0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 0} , ... }
		scionPaths [][]any
		expected   [][]any // this is a slice of flyovers with nils in it
		flyoverDB  [][]any
	}{
		"onepath_oneflyover": {
			scionPaths: [][]any{
				{0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 0},
			},
			expected: [][]any{
				{0, "1-ff00:0:1", 1, nil},
			},
			flyoverDB: [][]any{
				{0, "1-ff00:0:1", 1},
				{0, "1-ff00:0:2", 1},
				{0, "1-ff00:0:3", 1},
			},
		},
		"onepath_twoflyovers": {
			scionPaths: [][]any{
				{0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 3, 4, "1-ff00:0:3", 0},
			},
			expected: [][]any{
				{
					0, "1-ff00:0:1", 1,
					2, "1-ff00:0:2", 3,
					nil,
					nil,
				},
			},
			flyoverDB: [][]any{
				{0, "1-ff00:0:1", 1},
				{2, "1-ff00:0:2", 3},
				{0, "1-ff00:0:2", 1},
				{0, "1-ff00:0:3", 1},
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deadline, _ := t.Deadline()
			ctx, cancelF := context.WithDeadline(context.Background(), deadline)
			defer cancelF()

			flyoverDB := make([]*hummingbird.BaseHop, len(tc.flyoverDB))
			for i, flyoverDesc := range tc.flyoverDB {
				flyover := getMockFlyovers(t, flyoverDesc...)
				require.Len(t, flyover, 1, "bad test")
				flyoverDB[i] = flyover[0]
			}
			mockHbirdServer := &mockServer{
				Flyovers: flyoverDB,
			}
			s := &DaemonServer{
				HummingbirdFetcher: mockHbirdServer,
			}
			scion := getMockScionPaths(t, tc.scionPaths)
			rsvs, err := s.getReservations(ctx, scion)
			require.NoError(t, err)

			// Check the size.
			require.Len(t, rsvs, len(scion))

			// For each path, check the flyovers.
			for i, p := range scion {
				// Same hop count in both SCION path and reservation.
				ifaces := p.Meta.Interfaces
				require.Equal(t, len(ifaces), len(rsvs[i].Flyovers))

				expected := getMockFlyovers(t, tc.expected[i]...)
				require.Equal(t, expected, rsvs[i].Flyovers)
			}
		})
	}
}

func getMockScionPaths(t require.TestingT, paths [][]any) []path.Path {
	ret := make([]path.Path, len(paths))
	for i, p := range paths {
		ret[i] = *getMockScionPath(t, p...)
	}
	return ret
}

// getMockScionPath returns a snet.path.Path that resembles a SCION path, with appropriate
// metadata included.
// The parameter `hops` must be of the form (0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 0) to indicate
// one hop between those two ASes. For more ASes, add more hops in the middle.
// First and last interface IDs must always be 0.
func getMockScionPath(t require.TestingT, hops ...any) *path.Path {
	// Check the arguments.
	require.Equal(t, 0, len(hops)%3, "invalid hops field")
	require.Equal(t, 0, hops[0].(int))
	require.Equal(t, 0, hops[len(hops)-1].(int))
	for i := 0; i < len(hops); i += 3 {
		require.IsType(t, 0, hops[i])
		require.IsType(t, "", hops[i+1])
		require.IsType(t, 0, hops[i+2])
	}

	// Parse hops argument.
	interfaces := make([]snet.PathInterface, len(hops)/3*2) // SCION interfaces plus src and dst
	for i := 0; i < len(hops); i += 3 {
		in := hops[i].(int)
		ia := xtest.MustParseIA(hops[i+1].(string))
		eg := hops[i+2].(int)

		interfaces[i/3*2].IA = ia
		interfaces[i/3*2].ID = common.IFIDType(in)
		interfaces[i/3*2+1].IA = ia
		interfaces[i/3*2+1].ID = common.IFIDType(eg)
	}

	path := &path.Path{
		Src: interfaces[0].IA,
		Dst: interfaces[len(interfaces)-1].IA,
		Meta: snet.PathMetadata{
			// Remove the extra start and end hops.
			Interfaces: interfaces[1 : len(interfaces)-1],
		},
	}
	return path
}

func getMockFlyovers(t require.TestingT, hops ...any) []*hummingbird.BaseHop {
	// Parse hops argument.
	flyovers := make([]*hummingbird.BaseHop, 0)
	for i := 0; i < len(hops); i++ {
		var f *hummingbird.BaseHop
		if hops[i] != nil {
			in := hops[i].(int)
			ia := xtest.MustParseIA(hops[i+1].(string))
			eg := hops[i+2].(int)
			f = &hummingbird.BaseHop{
				IA:      ia,
				Ingress: uint16(in),
				Egress:  uint16(eg),
			}
			i += 2 // advance faster
		}
		flyovers = append(flyovers, f)
	}
	return flyovers
}

type mockServer struct {
	Flyovers []*hummingbird.BaseHop
}

func (m *mockServer) ListFlyovers(
	ctx context.Context,
	owners []addr.IA,
) ([]*hummingbird.BaseHop, error) {

	// Create a set of the requested IAs.
	ownerMap := make(map[addr.IA]struct{})
	for _, o := range owners {
		ownerMap[o] = struct{}{}
	}

	// Find any flyover with any such IA and return it.
	ret := make([]*hummingbird.BaseHop, 0)
	for _, f := range m.Flyovers {
		if _, ok := ownerMap[f.IA]; ok {
			ret = append(ret, f)
		}
	}
	return ret, nil
}
