package router_test

import (
	"crypto/aes"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/mock_router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func TestDataPlaneSetSecretValue(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetSecretValue([]byte("dummy")))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetSecretValue(nil))
	})
	t.Run("single set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetSecretValue([]byte("dummy key xxxxxx")))
	})
	t.Run("double set fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetSecretValue([]byte("dummy key xxxxxx")))
		assert.Error(t, d.SetSecretValue([]byte("dummy key xxxxxx")))
	})
}

func TestProcessHbirdPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")
	now := time.Now()

	testCases := map[string]struct {
		mockMsg      func(bool) *ipv4.Message
		prepareDP    func(*gomock.Controller) *router.DataPlane
		srcInterface uint16
		assertFunc   assert.ErrorAssertionFunc
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
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2].HopField)
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil

				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
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
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(3)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 0,
			assertFunc:   assert.NoError,
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
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath(3)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
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
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath(3))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
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
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"astransit xover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(3): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF: 6,
							SegLen: [3]uint8{6, 6, 0},
						},
						NumINF:  2,
						NumHops: 12,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},  // IA 110
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 0}}, // Src
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 51}}, // Dst
						{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},  // IA 110
					},
				}
				dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2].HopField)
				dpath.HopFields[3].HopField.Mac = computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[3].HopField)

				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath(3))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 51,
			assertFunc:   assert.NoError,
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
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				ret := toMsg(t, spkt, dpath)
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.Error,
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
					{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}, ResStartTime: 123, Duration: 304},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.NumHops = 11
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				if afterProcessing {
					dpath.HopFields[2].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2].HopField)
					ret := toMsg(t, spkt, dpath)
					ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
					return ret
				}
				return toMsg(t, spkt, dpath)
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
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
					{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}, ResStartTime: 123, Duration: 304},
					{Flyover: true, HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}, ResStartTime: 123, Duration: 304},
					{Flyover: true, HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}, ResStartTime: 123, Duration: 304},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.Base.PathMeta.SegLen[0] = 15
				dpath.NumHops = 15
				dpath.HopFields[0].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[0], dpath.Base.PathMeta)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.HopFields[0].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0].HopField)
				_ = dpath.IncPath(5)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 0,
			assertFunc:   assert.NoError,
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
					{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}, ResStartTime: 5, Duration: 2},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.NumHops = 11
				dpath.Base.PathMeta.CurrHF = 6
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
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
					{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 2}, ResStartTime: 123, Duration: 304},
					{HopField: path.HopField{ConsIngress: 40, ConsEgress: 41}},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.PathMeta.CurrHF = 3
				dpath.Base.NumHops = 11
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.HopFields[1].HopField.Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
				_ = dpath.IncPath(5)
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].HopField.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
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
					{Flyover: true, HopField: path.HopField{ConsIngress: 1, ConsEgress: 3}, ResStartTime: 5, Duration: 301},
					{HopField: path.HopField{ConsIngress: 50, ConsEgress: 51}},
				}
				dpath.Base.PathMeta.SegLen[0] = 11
				dpath.Base.NumHops = 11
				dpath.HopFields[1].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[1], dpath.Base.PathMeta)
				if afterProcessing {
					// dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
					ret := toMsg(t, spkt, dpath)
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
					return ret
				}
				return toMsg(t, spkt, dpath)
			},
			srcInterface: 1,
			assertFunc:   assert.NoError,
		},
		"astransit xover flyover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(nil,
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(3): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepHbirdMsg(now)
				dpath := &hummingbird.Decoded{
					Base: hummingbird.Base{
						PathMeta: hummingbird.MetaHdr{
							CurrHF: 6,
							SegLen: [3]uint8{6, 10, 0},
							BaseTS: util.TimeToSecs(now),
						},
						NumINF:  2,
						NumHops: 16,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []hummingbird.FlyoverHopField{
						{HopField: path.HopField{ConsIngress: 0, ConsEgress: 1}},                                                 // IA 110
						{HopField: path.HopField{ConsIngress: 31, ConsEgress: 0}},                                                // Src
						{Flyover: true, HopField: path.HopField{ConsIngress: 0, ConsEgress: 51}, ResStartTime: 5, Duration: 310}, // Dst
						{Flyover: true, HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}, ResStartTime: 5, Duration: 410},  // IA 110
					},
				}
				dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
				dpath.HopFields[3].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[1], dpath.HopFields[3], dpath.PathMeta)
				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].HopField.Mac)

					return toMsg(t, spkt, dpath)
				}
				//dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				//dpath.HopFields[3].Mac = computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[3])
				require.NoError(t, dpath.IncPath(5))
				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface: 51,
			assertFunc:   assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		if name == "reservation expired" || name == "invalid dest" {
			// TODO: make scmp packets work with hbird paths to re-enable these
			continue
		}
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
		})
	}
}

// func TestFlyoverPathReverseLength(t *testing.T) {
// 	//Performs test by provoking an error and checking the length of the returned SCMP packet
// 	//Does this with two different length paths, which should be reduced to identical length due to flyover removal
// 	//TODO: Fix scmp packets for hbirdpath to make test work
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	key := []byte("testkey_xxxxxxxx")
// 	sv := []byte("test_secretvalue")
// 	now := time.Now()

// 	//prepare datalane
// 	dp := router.NewDP(nil, nil, mock_router.NewMockBatchConn(ctrl), nil,
// 		nil, xtest.MustParseIA("1-ff00:0:110"), nil, key, sv)

// 	//prepare input message 1
// 	spkt, dpath := prepHbirdMsg(now)
// 	spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
// 	dst := addr.MustParseHost("10.0.100.100")
// 	_ = spkt.SetDstAddr(dst)
// 	dpath.HopFields = []hummingbird.FlyoverHopField{
// 		{Flyover: true, HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}, ResStartTime: 5, Duration: 200},
// 		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
// 		{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}, ResStartTime: 5, Duration: 2},
// 	}
// 	dpath.Base.PathMeta.SegLen[0] = 13
// 	dpath.Base.NumHops = 13
// 	dpath.Base.PathMeta.CurrHF = 8
// 	dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
// 	inputLong := toMsg(t, spkt, dpath)

// 	//input message 2
// 	spkt, dpath = prepHbirdMsg(now)
// 	spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
// 	dst = addr.MustParseHost("10.0.100.100")
// 	_ = spkt.SetDstAddr(dst)
// 	dpath.HopFields = []hummingbird.FlyoverHopField{
// 		{HopField: path.HopField{ConsIngress: 41, ConsEgress: 40}},
// 		{HopField: path.HopField{ConsIngress: 31, ConsEgress: 30}},
// 		{Flyover: true, HopField: path.HopField{ConsIngress: 01, ConsEgress: 0}, ResStartTime: 5, Duration: 2},
// 	}
// 	dpath.Base.PathMeta.SegLen[0] = 11
// 	dpath.Base.NumHops = 11
// 	dpath.Base.PathMeta.CurrHF = 6
// 	dpath.HopFields[2].HopField.Mac = computeAggregateMac(t, key, sv, spkt.DstIA, spkt.PayloadLen, dpath.InfoFields[0], dpath.HopFields[2], dpath.PathMeta)
// 	inputShort := toMsg(t, spkt, dpath)
// 	fmt.Printf("inputShort: %x\n", inputShort)
// 	fmt.Printf("inputLong: %x\n", inputLong)

// 	//set src interface
// 	var srcInterface uint16 = 1
// 	res, _ := dp.ProcessPkt(srcInterface, inputLong)
// 	res2, _ := dp.ProcessPkt(srcInterface, inputShort)

// 	layer1 := slayers.SCION{}
// 	layer1.RecyclePaths()
// 	layer1.DecodeFromBytes(res.OutPkt, gopacket.NilDecodeFeedback)

// 	layer2 := slayers.SCION{}
// 	layer2.RecyclePaths()
// 	layer2.DecodeFromBytes(res2.OutPkt, gopacket.NilDecodeFeedback)
// 	assert.Equal(t, layer1.Path.Len(), layer2.Path.Len())
// 	assert.Equal(t, 56, layer1.Path.Len())
// }

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
			NumINF:  1,
			NumHops: 9,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{},
	}
	return spkt, dpath
}

func computeAggregateMac(t *testing.T, key, sv []byte, dst addr.IA, l uint16, info path.InfoField, hf hummingbird.FlyoverHopField, meta hummingbird.MetaHdr) [path.MacLen]byte {

	scionMac := computeMAC(t, key, info, hf.HopField)

	block, err := aes.NewCipher(sv)
	require.NoError(t, err)

	ak := hummingbird.DeriveAuthKey(block, hf.ResID, hf.Bw, hf.HopField.ConsIngress, hf.HopField.ConsEgress,
		meta.BaseTS-uint32(hf.ResStartTime), hf.Duration, nil)
	flyoverMac := hummingbird.FullFlyoverMac(ak, dst, l, hf.ResStartTime,
		meta.HighResTS, nil, nil)

	for i, b := range scionMac {
		scionMac[i] = b ^ flyoverMac[i]
	}
	return scionMac
}
