// Copyright 2020 Anapaya Systems
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

package router_test

import (
	"crypto/aes"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/mock_router"
)

func TestDataPlaneSetSecretValue(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetHbirdKey([]byte("dummy")))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetHbirdKey(nil))
	})
	t.Run("single set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetHbirdKey([]byte("dummy key xxxxxx")))
	})
	t.Run("double set fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetHbirdKey([]byte("dummy key xxxxxx")))
		assert.Error(t, d.SetHbirdKey([]byte("dummy key xxxxxx")))
	})
}

func TestProcessHbirdPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")
	now := time.Now()

	testCases := map[string]struct {
		mockMsg         func(bool) *ipv4.Message
		prepareDP       func(*gomock.Controller) *router.DataPlane
		srcInterface    uint16
		egressInterface uint16
		assertFunc      assert.ErrorAssertionFunc
	}{
		"inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}},
				}
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil

				}
				return ret
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(hummingbird.HopLines)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    0,
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"brtransit": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.CurrHF = 3
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(hummingbird.HopLines)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					}, nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1}},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.CurrHF = 3
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath(hummingbird.HopLines))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"astransit direct": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(3): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 3}},
					{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
				}
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"astransit xover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						51: topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(51): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF: 3,
							SegLen: [3]uint8{6, 6, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
						{HopField: path.HopField{ConsIngress: 51, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 3}},
					},
				}
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath(hummingbird.HopLines))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    31,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"invalid dest": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.SVC][]*net.UDPAddr{},
					xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:f1")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 404}},
					{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0}},
				}
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
		"brtransit peering consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet just left segment 0 which ends at
				// (peering) hop 0 and is landing on segment 1 which
				// begins at (peering) hop 1. We do not care what hop 0
				// looks like. The forwarding code is looking at hop 1 and
				// should leave the message in shape to be processed at hop 2.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 6, 0},
						},
						NumINF:   2,
						NumLines: 9,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the second one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(hummingbird.HopLines)

				// ... The SegID accumulator wasn't updated from HF[1],
				// it is still the same. That is the key behavior.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1, // from peering link
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit peering non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet lands on the last (peering) hop of
				// segment 0. After processing, the packet is ready to
				// be processed by the first (peering) hop of segment 1.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{6, 3, 0},
						},
						NumINF:   2,
						NumLines: 9,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (0 and 1) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the first one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[0].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)

				// We're going against construction order, so the accumulator
				// value is that of the previous hop in traversal order. The
				// story starts with the packet arriving at hop 1, so the
				// accumulator value must match hop field 0. In this case,
				// it is identical to that for hop field 1, which we made
				// identical to the original SegID. So, we're all set.
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}

				_ = dpath.IncPath(hummingbird.HopLines)

				// The SegID should not get updated on arrival. If it is, then MAC validation
				// of HF1 will fail. Otherwise, this isn't visible because we changed segment.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    2, // from child link
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"peering consdir downstream": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  6,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 9, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// There has to be a 4th hop to make
						// the 3rd router agree that the packet
						// is not at destination yet.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The router shouldn't need to
				// know this or do anything special. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				if !afterProcessing {
					// The SegID we provide is that of HF[2] which happens to be SEG[1]'s SegID,
					// so, already set.
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(hummingbird.HopLines)

				// ... The SegID accumulator should have been updated.
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"peering non consdir upstream": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet lands on the second (non-peering) hop of
				// segment 0 (a peering segment). After processing, the packet
				// is ready to be processed by the third (peering) hop of segment 0.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{9, 3, 0},
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// The second segment (4th hop) has to be
						// there but the packet isn't processed
						// at that hop for this test.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The SegID accumulator value can
				// be anything (it comes from the parent hop of HF[1]
				// in the original beaconned segment, which is not in
				// the path). So, we use one from an info field because
				// computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[0], dpath.HopFields[2].HopField)

				if !afterProcessing {
					// We're going against construction order, so the
					// before-processing accumulator value is that of
					// the previous hop in traversal order. The story
					// starts with the packet arriving at hop 1, so the
					// accumulator value must match hop field 0, which
					// derives from hop field[1]. HopField[0]'s MAC is
					// not checked during this test.
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)

					return toMsg(t, spkt, dpath)
				}

				_ = dpath.IncPath(hummingbird.HopLines)

				// After-processing, the SegID should have been updated
				// (on ingress) to be that of HF[1], which happens to be
				// the Segment's SegID. That is what we already have as
				// we only change it in the before-processing version
				// of the packet.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    2, // from child link
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"inbound flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0},
						ResStartTime: 123, Duration: 304, Bw: 16},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				if afterProcessing {
					dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[2].HopField)
					ret := toMsg(t, spkt, dpath)
					ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
					return ret
				}
				return toMsg(t, spkt, dpath)
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"outbound flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 1},
						ResStartTime: 123, Duration: 304, Bw: 16},
					{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 30},
						ResStartTime: 123, Duration: 304, Bw: 16},
					{Flyover: true, HopField: path.HopField{ConsIngress: 41, ConsEgress: 40},
						ResStartTime: 123, Duration: 304, Bw: 16},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.Base.PathMeta.SegLen[0] = 15
				dpath.NumLines = 15
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[0], dpath.Base.PathMeta)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				_ = dpath.IncPath(hummingbird.FlyoverLines)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    0,
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"reservation expired": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
					nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0},
						ResStartTime: 5, Duration: 2},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
		},
		"brtransit flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
						Bw: 5, ResStartTime: 123, Duration: 304},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.PathMeta.CurrHF = 3
				dpath.Base.NumLines = 11
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				_ = dpath.IncPath(hummingbird.FlyoverLines)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit non consdir flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					}, nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{Flyover: true, HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
						ResID: 42, ResStartTime: 5, Duration: 301, Bw: 16},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.CurrHF = 3
				dpath.Base.NumLines = 11
				dpath.Base.PathMeta.SegLen[0] = 11

				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(computeMAC(t, key, dpath.InfoFields[0],
						dpath.HopFields[1].HopField))
					return toMsg(t, spkt, dpath)
				}
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"astransit direct flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(3): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepHbirdMsg(now)
				dpath.HopFields = []hummingbird.FlyoverHopField{
					{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
					{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 3},
						ResID: 42, ResStartTime: 5, Duration: 301, Bw: 16},
					{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.NumLines = 11
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				if afterProcessing {
					ret := toMsg(t, spkt, dpath)
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
					return ret
				}
				return toMsg(t, spkt, dpath)
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"astransit xover flyover ingress": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						51: topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF: 3,
							SegLen: [3]uint8{8, 6, 0},
							BaseTS: util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 14,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}}, // IA 110
						{Flyover: true, HopField: path.HopField{ConsIngress: 51, ConsEgress: 0},
							Bw: 5, ResStartTime: 5, Duration: 310}, // Src
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}}, // Dst
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},  // IA 110
					},
				}
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)
				dpath.HopFields[1].HopField.Mac = computeAggregateMacXover(t, key, sv,
					spkt.DstIA, spkt.PayloadLen, 51, 31,
					dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				if !afterProcessing {

					return toMsg(t, spkt, dpath)
				}
				dpath.HopFields[1].Flyover = false
				dpath.HopFields[2].Flyover = true
				dpath.HopFields[2].Bw = 5
				dpath.HopFields[2].ResStartTime = 5
				dpath.HopFields[2].Duration = 310

				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeAggregateMacXover(t, key, sv,
					spkt.DstIA, spkt.PayloadLen, 51, 31,
					dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
				dpath.PathMeta.SegLen[0] -= 2
				dpath.PathMeta.SegLen[1] += 2
				require.NoError(t, dpath.IncPath(hummingbird.HopLines))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    51,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"astransit xover flyover egress": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						51: topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(51): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepHbirdMsg(now)
				spkt.SrcIA = 109
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  6,
							CurrINF: 1,
							SegLen:  [3]uint8{6, 8, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 14,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},  // Src
						{HopField: path.HopField{ConsIngress: 51, ConsEgress: 0}}, // IA 110
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 31},
							Bw: 5, ResStartTime: 5, Duration: 310}, // IA 110
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}}, // Dst
					},
				}
				dpath.HopFields[2].HopField.Mac = computeAggregateMacXover(t, key, sv,
					spkt.DstIA, spkt.PayloadLen, 51, 31,
					dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
				if !afterProcessing {
					ret := toMsg(t, spkt, dpath)
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
					return ret
				}
				dpath.HopFields[2].Flyover = false
				dpath.HopFields[1].Flyover = true
				dpath.HopFields[1].Bw = 5
				dpath.HopFields[1].ResStartTime = 5
				dpath.HopFields[1].Duration = 310

				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				require.NoError(t, dpath.IncPath(hummingbird.FlyoverLines))
				dpath.PathMeta.SegLen[0] += 2
				dpath.PathMeta.SegLen[1] -= 2
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    0,
			egressInterface: 31,
			assertFunc:      assert.NoError,
		},
		"brtransit peering consdir flyovers": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet just left segment 0 which ends at
				// (peering) hop 0 and is landing on segment 1 which
				// begins at (peering) hop 1. We do not care what hop 0
				// looks like. The forwarding code is looking at hop 1 and
				// should leave the message in shape to be processed at hop 2.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 8, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 11,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the second one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[1], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[1], dpath.HopFields[2].HopField)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(hummingbird.FlyoverLines)
				// deaggregate MAC
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				// ... The SegID accumulator wasn't updated from HF[1],
				// it is still the same. That is the key behavior.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1, // from peering link
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit peering non consdir flyovers": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet lands on the last (peering) hop of
				// segment 0. After processing, the packet is ready to
				// be processed by the first (peering) hop of segment 1.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{8, 3, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 11,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (0 and 1) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the first one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[0].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)

				// We're going against construction order, so the accumulator
				// value is that of the previous hop in traversal order. The
				// story starts with the packet arriving at hop 1, so the
				// accumulator value must match hop field 0. In this case,
				// it is identical to that for hop field 1, which we made
				// identical to the original SegID. So, we're all set.
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}

				_ = dpath.IncPath(hummingbird.FlyoverLines)
				// deaggregate MAc
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)

				// The SegID should not get updated on arrival. If it is, then MAC validation
				// of HF1 will fail. Otherwise, this isn't visible because we changed segment.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    2, // from child link
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"peering consdir downstream flyovers": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  6,
							CurrINF: 1,
							SegLen:  [3]uint8{3, 11, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 14,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// There has to be a 4th hop to make
						// the 3rd router agree that the packet
						// is not at destination yet.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The router shouldn't need to
				// know this or do anything special. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[1], dpath.HopFields[1].HopField)
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[1], dpath.HopFields[2], dpath.PathMeta)
				if !afterProcessing {
					// The SegID we provide is that of HF[2] which happens to be SEG[1]'s SegID,
					// so, already set.
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(hummingbird.FlyoverLines)
				// mac should be deaggregated, and used for updateSegID
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[2].HopField)

				// ... The SegID accumulator should have been updated.
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"peering non consdir upstream flyovers": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet lands on the second (non-peering) hop of
				// segment 0 (a peering segment). After processing, the packet
				// is ready to be processed by the third (peering) hop of segment 0.
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF:  3,
							CurrINF: 0,
							SegLen:  [3]uint8{11, 3, 0},
							BaseTS:  util.TimeToSecs(now),
						},
						NumINF:   2,
						NumLines: 14,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
						{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
						// The second segment (4th hop) has to be
						// there but the packet isn't processed
						// at that hop for this test.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The SegID accumulator value can
				// be anything (it comes from the parent hop of HF[1]
				// in the original beaconned segment, which is not in
				// the path). So, we use one from an info field because
				// computeMAC makes that easy.
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
					spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.PathMeta)
				dpath.HopFields[2].HopField.Mac = computeMAC(
					t, sv, dpath.InfoFields[0], dpath.HopFields[2].HopField)

				if !afterProcessing {
					// We're going against construction order, so the
					// before-processing accumulator value is that of
					// the previous hop in traversal order. The story
					// starts with the packet arriving at hop 1, so the
					// accumulator value must match hop field 0, which
					// derives from hop field[1]. HopField[0]'s MAC is
					// not checked during this test.
					// Use de-aggregated MAC value for segID update
					scionMac := computeMAC(
						t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
					dpath.InfoFields[0].UpdateSegID(scionMac)

					return toMsg(t, spkt, dpath)
				}

				_ = dpath.IncPath(hummingbird.FlyoverLines)
				// deaggregate MAC)
				dpath.HopFields[1].HopField.Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)

				// After-processing, the SegID should have been updated
				// (on ingress) to be that of HF[1], which happens to be
				// the Segment's SegID. That is what we already have as
				// we only change it in the before-processing version
				// of the packet.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    2, // from child link
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP(ctrl)
			input, want := tc.mockMsg(false), tc.mockMsg(true)
			result, err := dp.ProcessPkt(tc.srcInterface, input)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			outPkt := &ipv4.Message{
				Buffers: [][]byte{result.OutPkt},
				Addr:    result.OutAddr,
			}
			if result.OutAddr == nil {
				outPkt.Addr = nil
			}
			assert.Equal(t, want, outPkt)
			assert.Equal(t, tc.egressInterface, result.EgressID)
		})
	}
}

func TestHbirdPacketPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")
	now := time.Now()

	testCases := map[string]struct {
		mockMsg       func() *ipv4.Message
		prepareDPs    func(*gomock.Controller) []*router.DataPlane
		srcInterfaces []uint16
	}{
		"two hops consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("1-ff00:0:110"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{6, 0, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   1,
						NumLines: 6,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
						{HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				// Reset SegID to original value
				dpath.InfoFields[0].SegID = 0x111
				ret := toMsg(t, spkt, dpath)
				return ret

			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [2]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(01): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						01: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

				return dps[:]
			},
			srcInterfaces: []uint16{0, 01},
		},
		"two hops non consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:111"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{6, 0, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   1,
						NumLines: 6,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)

				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				//dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)

				ret := toMsg(t, spkt, dpath)
				return ret

			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [2]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(01): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						01: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				return dps[:]
			},
			srcInterfaces: []uint16{0, 40},
		},
		"six hops astransit xover consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("3-ff00:0:333"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{9, 9, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 18,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 31}},
						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
						{HopField: path.HopField{ConsIngress: 11, ConsEgress: 8}},
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[5].HopField)
				// Reset SegID to original value
				dpath.InfoFields[0].SegID = 0x111
				dpath.InfoFields[1].SegID = 0x222
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [7]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
						uint16(1):  mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						31: topology.Parent,
						1:  topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)

				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(11): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[6] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)

				return dps[:]
			}, // middle hop of second segment is astransit
			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
		},
		"six hops astransit xover non consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("3-ff00:0:333"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{9, 9, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 18,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 1}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 5}},
						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 8, ConsEgress: 11}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 3}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[5].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[5].HopField.Mac)
				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				// Reset SegID to original value
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [7]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
						uint16(1):  mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						31: topology.Parent,
						1:  topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)

				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(11): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[6] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)

				return dps[:]
			}, // middle hop of second segment is astransit
			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
		},
		"six hops brtransit xover mixed consdir": {
			// up segment non consdir, down segment consdir
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("3-ff00:0:333"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{9, 9, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 18,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 1}},
						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 5}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
						{HopField: path.HopField{ConsIngress: 11, ConsEgress: 8}},
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[5].HopField)
				// Reset SegID to original value
				dpath.InfoFields[1].SegID = 0x222
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [5]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
						uint16(1):  mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						31: topology.Parent,
						1:  topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)

				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8):  mock_router.NewMockBatchConn(ctrl),
						uint16(11): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Child,
						11: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)

				return dps[:]
			}, // middle hop of second segment is astransit
			srcInterfaces: []uint16{0, 1, 5, 11, 3},
		},
		"six hops three segs mixed consdir": {
			// two crossovers, first crossover is brtransit, second one is astransit
			// core segment is non consdir
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{6, 6, 6},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   3,
						NumLines: 18,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x333, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 8}},
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[2].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
					dpath.HopFields[5].HopField)
				// Reset SegID to original value
				dpath.InfoFields[0].SegID = 0x111
				dpath.InfoFields[2].SegID = 0x333
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [5]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Child,
						5: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 1, 31, 0, 3},
		},
		"three hops peering brtransit consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{3, 6},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 9,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[1].HopField)
				// No Segment update here as the second hop of a peering path
				// Uses the same segID as it's following hop
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [3]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Peer,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 1, 5},
		},
		"three hops peering brtransit non consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{3, 6},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 9,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 5}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[1].HopField)
				// No Segment update here as the second hop of a peering path
				// Uses the same segID as it's following hop

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [3]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Peer,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 1, 5},
		},
		"four hops peering astransit consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{6, 6},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 40}},
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 7}},
						{HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}},
						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)

				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)
				// No Segment update here
				// the second hop of a peering path uses the same segID as it's following hop
				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				// reset segID
				dpath.InfoFields[0].SegID = 0x111

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [6]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
		},
		"four hops peering astransit non consdir": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{6, 6},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 12,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 40, ConsEgress: 0}},
						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 31}},
						{HopField: path.HopField{ConsIngress: 2, ConsEgress: 1}},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 5}},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				// No Segment update here
				// the second hop of a peering path uses the same segID as it's following hop
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [6]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
		},
		"two hops consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("1-ff00:0:110"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{10, 0, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   1,
						NumLines: 10,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				// add flyover macs
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 0,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				// Reset SegID to original value
				dpath.InfoFields[0].SegID = 0x111
				ret := toMsg(t, spkt, dpath)
				return ret

			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [2]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(01): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						01: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

				return dps[:]
			},
			srcInterfaces: []uint16{0, 01},
		},
		"two hops non consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:111"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{10, 0, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   1,
						NumLines: 10,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				// aggregate macs
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 1,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 40, 0,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)

				ret := toMsg(t, spkt, dpath)
				return ret

			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [2]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(01): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						01: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				return dps[:]
			},
			srcInterfaces: []uint16{0, 40},
		},
		"six hops astransit xover consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("3-ff00:0:333"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{15, 13, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 28,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 31},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 5, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 11, ConsEgress: 8},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[5].HopField)
				// Reset SegID to original value
				dpath.InfoFields[0].SegID = 0x111
				dpath.InfoFields[1].SegID = 0x222
				// aggregate flyover macs
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 31,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 7,
					dpath.InfoFields[0], &dpath.HopFields[2], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 11, 8,
					dpath.InfoFields[1], &dpath.HopFields[4], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
					dpath.InfoFields[1], &dpath.HopFields[5], dpath.PathMeta)
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [7]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
						uint16(1):  mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						31: topology.Parent,
						1:  topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)

				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(11): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[6] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)

				return dps[:]
			}, // middle hop of second segment is astransit
			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
		},
		"six hops astransit xover non consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("3-ff00:0:333"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{15, 13, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 28,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 1},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 7, ConsEgress: 0}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 8, ConsEgress: 11},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 3},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[5].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[5].HopField.Mac)
				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				// aggregate with flyover macs
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 31,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 7,
					dpath.InfoFields[0], &dpath.HopFields[2], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 11, 8,
					dpath.InfoFields[1], &dpath.HopFields[4], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
					dpath.InfoFields[1], &dpath.HopFields[5], dpath.PathMeta)
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [7]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
						uint16(1):  mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						31: topology.Parent,
						1:  topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)

				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(5): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(11): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Core,
						11: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(11): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[6] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)

				return dps[:]
			}, // middle hop of second segment is astransit
			srcInterfaces: []uint16{0, 1, 5, 0, 11, 0, 3},
		},
		"six hops brtransit xover mixed consdir flyovers": {
			// up segment non consdir, down segment consdir
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:111"),
					xtest.MustParseIA("3-ff00:0:333"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{15, 13, 0},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 28,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 1},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 7}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 11, ConsEgress: 8},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[5].HopField)
				// Reset SegID to original value
				dpath.InfoFields[1].SegID = 0x222

				//aggregate MACs
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 31,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 7,
					dpath.InfoFields[0], &dpath.HopFields[2], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 11, 8,
					dpath.InfoFields[1], &dpath.HopFields[4], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
					dpath.InfoFields[1], &dpath.HopFields[5], dpath.PathMeta)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [5]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
						uint16(1):  mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						31: topology.Parent,
						1:  topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)

				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Child,
						7: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)

				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8):  mock_router.NewMockBatchConn(ctrl),
						uint16(11): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Child,
						11: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("2-ff00:0:222"), nil, key, sv)

				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("3-ff00:0:333"), nil, key, sv)

				return dps[:]
			}, // middle hop of second segment is astransit
			srcInterfaces: []uint16{0, 1, 5, 11, 3},
		},
		"six hops three segs mixed consdir flyovers": {
			// two crossovers, first crossover is brtransit, second one is astransit
			// core segment is non consdir
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{10, 8, 8},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   3,
						NumLines: 26,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x333, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 5, ConsEgress: 0}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 31},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 8}},
						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				dpath.HopFields[4].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
					dpath.HopFields[4].HopField)
				dpath.InfoFields[2].UpdateSegID(dpath.HopFields[4].HopField.Mac)
				dpath.HopFields[5].HopField.Mac = computeMAC(t, key, dpath.InfoFields[2],
					dpath.HopFields[5].HopField)
				// Reset SegID to original value
				dpath.InfoFields[0].SegID = 0x111
				dpath.InfoFields[2].SegID = 0x333
				// aggregate flyover macs
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 5,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 31, 8,
					dpath.InfoFields[1], &dpath.HopFields[3], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 3, 0,
					dpath.InfoFields[2], &dpath.HopFields[5], dpath.PathMeta)
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [5]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Child,
						5: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(8): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(8): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						8:  topology.Child,
						31: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(3): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						3: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 1, 31, 0, 3},
		},
		"three hops peering brtransit consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{5, 10},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 15,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 5, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[1].HopField)
				// No Segment update here
				// The second hop of a peering path uses the same segID as it's following hop
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
					dpath.InfoFields[1], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [3]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Peer,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 1, 5},
		},
		"three hops peering brtransit non consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{5, 10},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 15,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[1].HopField)
				// No Segment update here
				// The second hop of a peering path uses the same segID as it's following hop

				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
					dpath.InfoFields[1], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [3]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Peer,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 1, 5},
		},
		"four hops peering astransit consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{10, 10},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 20,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: true, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 40},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 7},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 5, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)

				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)
				// No Segment update here
				// The second hop of a peering path uses the same segID as it's following hop
				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				// reset segID
				dpath.InfoFields[0].SegID = 0x111

				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 31, 7,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
					dpath.InfoFields[1], &dpath.HopFields[3], dpath.PathMeta)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [6]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
		},
		"four hops peering astransit non consdir flyovers": {
			mockMsg: func() *ipv4.Message {
				spkt := prepHbirdSlayers(xtest.MustParseIA("1-ff00:0:110"),
					xtest.MustParseIA("1-ff00:0:113"))
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)

				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrINF:   0,
							CurrHF:    0,
							SegLen:    [3]uint8{10, 10},
							BaseTS:    util.TimeToSecs(now),
							HighResTS: 500 << 22,
						},
						NumINF:   2,
						NumLines: 20,
					},
					InfoFields: []path.InfoField{
						{SegID: 0x111, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						{SegID: 0x222, Peer: true, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},

					HopFields: []hummingbird.FlyoverHopField{
						{Flyover: true, HopField: path.HopField{ConsIngress: 40, ConsEgress: 0},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 7, ConsEgress: 31},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 2, ConsEgress: 1},
							Bw: 5, ResStartTime: 123, Duration: 304},
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 5},
							Bw: 5, ResStartTime: 123, Duration: 304},
					},
				}
				// Compute MACs and increase SegID while doing so
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[1].HopField)
				// No Segment update here
				// The second hop of a peering path uses the same segID as it's following hop
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0],
					dpath.HopFields[0].HopField)

				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[3].HopField)
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[3].HopField.Mac)
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1],
					dpath.HopFields[2].HopField)

				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 0, 40,
					dpath.InfoFields[0], &dpath.HopFields[0], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 31, 7,
					dpath.InfoFields[0], &dpath.HopFields[1], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 1, 2,
					dpath.InfoFields[1], &dpath.HopFields[2], dpath.PathMeta)
				aggregateOntoScionMac(t, sv, spkt.DstIA, spkt.PayloadLen, 5, 0,
					dpath.InfoFields[1], &dpath.HopFields[3], dpath.PathMeta)

				ret := toMsg(t, spkt, dpath)
				return ret
			},
			prepareDPs: func(*gomock.Controller) []*router.DataPlane {
				var dps [6]*router.DataPlane
				dps[0] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(40): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						40: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
				dps[1] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(31): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[2] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(7): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						7:  topology.Peer,
						31: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(31): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)
				dps[3] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(2): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[4] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(1): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:112"), nil, key, sv)
				dps[5] = router.NewDP(
					map[uint16]router.BatchConn{
						uint16(5): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						5: topology.Parent,
					},
					mock_router.NewMockBatchConn(ctrl),
					nil, nil, xtest.MustParseIA("1-ff00:0:113"), nil, key, sv)
				return dps[:]
			},
			srcInterfaces: []uint16{0, 31, 0, 1, 0, 5},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dps := tc.prepareDPs(ctrl)
			input := tc.mockMsg()
			for i, dp := range dps {
				result, err := dp.ProcessPkt(tc.srcInterfaces[i], input)
				assert.NoError(t, err)

				input = &ipv4.Message{
					Buffers: [][]byte{result.OutPkt},
					Addr:    result.OutAddr,
					N:       len(result.OutPkt),
				}
			}
		})
	}
}

// TODO(juagargi): write test for concurrent bandwidth check calls

func TestBandwidthCheck(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")
	now := time.Now()

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(2): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			1: topology.Parent,
			2: topology.Child,
		},
		nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

	spkt, dpath := prepHbirdMsg(now)
	dpath.HopFields = []hummingbird.FlyoverHopField{
		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
		{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResID: 42,
			Bw: 2, ResStartTime: 123, Duration: 304},
		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
	}
	dpath.Base.PathMeta.SegLen[0] = 11
	dpath.Base.PathMeta.CurrHF = 3
	dpath.Base.NumLines = 11

	spkt.PayloadLen = 120
	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

	msg := toLongMsg(t, spkt, dpath)

	_, err := dp.ProcessPkt(1, msg)
	assert.NoError(t, err)

	msg = toLongMsg(t, spkt, dpath)
	_, err = dp.ProcessPkt(1, msg)
	assert.Error(t, err)

	time.Sleep(time.Duration(1) * time.Second)

	msg = toLongMsg(t, spkt, dpath)
	_, err = dp.ProcessPkt(1, msg)
	assert.NoError(t, err)
}

func TestBandwidthCheckDifferentResID(t *testing.T) {
	// Verifies that packets of one reservation do not affect
	// available bandwidth of another reservation
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")
	now := time.Now()

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(2): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			1: topology.Parent,
			2: topology.Child,
		},
		nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

	spkt, dpath := prepHbirdMsg(now)
	dpath.HopFields = []hummingbird.FlyoverHopField{
		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
		{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResID: 24,
			Bw: 2, ResStartTime: 123, Duration: 304},
		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
	}
	dpath.Base.PathMeta.SegLen[0] = 11
	dpath.Base.PathMeta.CurrHF = 3
	dpath.Base.NumLines = 11

	spkt.PayloadLen = 120
	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

	msg := toLongMsg(t, spkt, dpath)

	_, err := dp.ProcessPkt(1, msg)
	assert.NoError(t, err)

	dpath.HopFields[1].ResID = 32
	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

	msg = toLongMsg(t, spkt, dpath)
	_, err = dp.ProcessPkt(1, msg)
	assert.NoError(t, err)

	dpath.HopFields[1].ResID = 42
	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

	msg = toLongMsg(t, spkt, dpath)
	_, err = dp.ProcessPkt(1, msg)
	assert.NoError(t, err)
}

func TestBandwidthCheckDifferentEgress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")
	now := time.Now()

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(2): mock_router.NewMockBatchConn(ctrl),
			uint16(3): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			1: topology.Parent,
			2: topology.Child,
			3: topology.Child,
		},
		nil, nil, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

	spkt, dpath := prepHbirdMsg(now)
	dpath.HopFields = []hummingbird.FlyoverHopField{
		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
		{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResID: 42,
			Bw: 2, ResStartTime: 123, Duration: 304},
		{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
	}
	dpath.Base.PathMeta.SegLen[0] = 11
	dpath.Base.PathMeta.CurrHF = 3
	dpath.Base.NumLines = 11

	spkt.PayloadLen = 120
	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)

	msg := toLongMsg(t, spkt, dpath)

	_, err := dp.ProcessPkt(1, msg)
	assert.NoError(t, err)

	msg = toLongMsg(t, spkt, dpath)
	_, err = dp.ProcessPkt(1, msg)
	assert.Error(t, err)

	// Reservation with same resID but different Ingress/Egress pair is a different reservation
	dpath.HopFields[1].HopField.ConsEgress = 3
	spkt.PayloadLen = 120
	dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA,
		spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
	msg = toLongMsg(t, spkt, dpath)
	_, err = dp.ProcessPkt(1, msg)
	assert.NoError(t, err)
}

func toLongMsg(t *testing.T, spkt *slayers.SCION, dpath path.Path) *ipv4.Message {
	t.Helper()
	ret := &ipv4.Message{}
	spkt.Path = dpath
	buffer := gopacket.NewSerializeBuffer()
	payload := [120]byte{}
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, gopacket.Payload(payload[:]))
	require.NoError(t, err)
	raw := buffer.Bytes()
	ret.Buffers = make([][]byte, 1)
	ret.Buffers[0] = make([]byte, 1500)
	copy(ret.Buffers[0], raw)
	ret.N = len(raw)
	ret.Buffers[0] = ret.Buffers[0][:ret.N]
	return ret
}

func prepHbirdMsg(now time.Time) (*slayers.SCION, *hummingbird.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &hummingbird.Raw{},
		PayloadLen:   18,
	}

	dpath := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF:    3,
				SegLen:    [3]uint8{9, 0, 0},
				BaseTS:    util.TimeToSecs(now),
				HighResTS: 500 << 22,
			},
			NumINF:   1,
			NumLines: 9,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{},
	}
	return spkt, dpath
}

func prepHbirdSlayers(src, dst addr.IA) *slayers.SCION {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     hummingbird.PathType,
		DstIA:        dst,
		SrcIA:        src,
		Path:         &hummingbird.Raw{},
		PayloadLen:   18,
	}
	return spkt
}

func computeAggregateMac(t *testing.T, key, sv []byte, dst addr.IA, l uint16, info path.InfoField,
	hf hummingbird.FlyoverHopField, meta hummingbird.MetaHdr) [path.MacLen]byte {

	scionMac := computeMAC(t, key, info, hf.HopField)

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)

	ingress, egress := hf.HopField.ConsIngress, hf.HopField.ConsEgress
	if !info.ConsDir {
		ingress, egress = egress, ingress
	}
	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i, b := range scionMac {
		scionMac[i] = b ^ flyoverMac[i]
	}
	return scionMac
}

func computeAggregateMacXover(t *testing.T, key, sv []byte, dst addr.IA, l, hin, heg uint16,
	info path.InfoField, hf hummingbird.FlyoverHopField,
	meta hummingbird.MetaHdr) [path.MacLen]byte {

	scionMac := computeMAC(t, key, info, hf.HopField)

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	ingress, egress := hin, heg
	if !info.ConsDir {
		ingress, egress = egress, ingress
	}

	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i, b := range scionMac {
		scionMac[i] = b ^ flyoverMac[i]
	}
	return scionMac
}

// Computes flyovermac and aggregates it to existing mac in hopfield
func aggregateOntoScionMac(t *testing.T, sv []byte, dst addr.IA, l, hin, heg uint16,
	info path.InfoField, hf *hummingbird.FlyoverHopField, meta hummingbird.MetaHdr) {
	block, err := aes.NewCipher(sv)
	require.NoError(t, err)
	ingress, egress := hin, heg

	akBuffer := make([]byte, hummingbird.AkBufferSize)
	macBuffer := make([]byte, hummingbird.FlyoverMacBufferSize)
	xkBuffer := make([]uint32, hummingbird.XkBufferSize)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, ingress, egress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, akBuffer)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, macBuffer, xkBuffer)

	for i := range hf.HopField.Mac {
		hf.HopField.Mac[i] ^= flyoverMac[i]
	}
}
