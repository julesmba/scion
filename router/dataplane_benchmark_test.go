package router_test

import (
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/mock_router"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

const (
	benchmarkPayloadLen = 120
)

// We measure the time necessary to process 100 packets (process function and reset function in between)
// This allows to differentiate between different space usages of bandwidth (TODO: what sizes are relevant???)

// standard SCION benchmark for reference
func BenchmarkProcessScion(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Core,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 3, 0},
			},
			NumINF:  2,
			NumHops: 6,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 2},
			{ConsIngress: 7, ConsEgress: 31},
			{ConsIngress: 3, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 6},
			{ConsIngress: 8, ConsEgress: 9},
			{ConsIngress: 11, ConsEgress: 0},
		},
	}

	dpath.HopFields[1].Mac = benchmarkScionMac(b, key, dpath.InfoFields[0], dpath.HopFields[1])
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

func BenchmarkProcessScionXover(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Child,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   benchmarkPayloadLen,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 2,
				SegLen: [3]uint8{3, 3, 0},
			},
			NumINF:  2,
			NumHops: 6,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{
			{ConsIngress: 0, ConsEgress: 2},
			{ConsIngress: 3, ConsEgress: 4},
			{ConsIngress: 7, ConsEgress: 0},
			{ConsIngress: 0, ConsEgress: 31},
			{ConsIngress: 8, ConsEgress: 9},
			{ConsIngress: 11, ConsEgress: 0},
		},
	}

	dpath.HopFields[2].Mac = benchmarkScionMac(b, key, dpath.InfoFields[0], dpath.HopFields[2])
	dpath.HopFields[3].Mac = benchmarkScionMac(b, key, dpath.InfoFields[1], dpath.HopFields[3])
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

// standard Hbird packet, no flyover
func BenchmarkProcessHbirdFlyoverless(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Core,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

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
				CurrHF: 3,
				SegLen: [3]uint8{9, 9, 0},
			},
			NumINF:   2,
			NumLines: 18,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 7, ConsEgress: 31}},
			{HopField: path.HopField{ConsIngress: 3, ConsEgress: 0}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 6}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[1].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[0], dpath.HopFields[1].HopField)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		//require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

func BenchmarkProcessHbirdFlyoverlessXover(b *testing.B) {
	// prepare Dataplane
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	sv := []byte("test_secretvalue")

	dp := router.NewDP(
		map[uint16]router.BatchConn{
			uint16(31): mock_router.NewMockBatchConn(ctrl),
		},
		map[uint16]topology.LinkType{
			7:  topology.Core,
			31: topology.Child,
		},
		mock_router.NewMockBatchConn(ctrl),
		map[uint16]*net.UDPAddr{
			uint16(7): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
		}, nil, xtest.MustParseIA("1-ff00:0:111"), nil, key, sv)

	// prepare PacketProcessor
	pp := dp.NewBenchmarkPP()

	// prepare packet
	now := time.Now()

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
				CurrHF: 6,
				SegLen: [3]uint8{9, 9, 0},
			},
			NumINF:   2,
			NumLines: 18,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
			{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []hummingbird.FlyoverHopField{
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 2}},
			{HopField: path.HopField{ConsIngress: 3, ConsEgress: 4}},
			{HopField: path.HopField{ConsIngress: 7, ConsEgress: 0}},
			{HopField: path.HopField{ConsIngress: 0, ConsEgress: 31}},
			{HopField: path.HopField{ConsIngress: 8, ConsEgress: 9}},
			{HopField: path.HopField{ConsIngress: 11, ConsEgress: 0}},
		},
	}

	dpath.HopFields[2].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[0], dpath.HopFields[2].HopField)
	dpath.HopFields[3].HopField.Mac = benchmarkScionMac(b, key, dpath.InfoFields[1], dpath.HopFields[3].HopField)
	msg := toBenchmarkMsg(b, spkt, dpath)

	backup := make([]byte, len(msg.Buffers[0]))
	copy(backup, msg.Buffers[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(msg.Buffers[0], backup)
		pp.ProcessPkt(7, msg)
		// DO NOT check for errors when getting actual numbers from benchmark
		// require.NoError(b, err) // verify no failures on repeated usage of same packet
	}
}

// Helper Functions for Benchmarking

func toBenchmarkMsg(b *testing.B, spkt *slayers.SCION, dpath path.Path) *ipv4.Message {
	b.Helper()
	ret := &ipv4.Message{}
	spkt.Path = dpath
	buffer := gopacket.NewSerializeBuffer()
	spkt.PayloadLen = benchmarkPayloadLen
	payload := [benchmarkPayloadLen]byte{}
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, gopacket.Payload(payload[:]))
	require.NoError(b, err)
	raw := buffer.Bytes()
	ret.Buffers = make([][]byte, 1)
	ret.Buffers[0] = make([]byte, 1500)
	copy(ret.Buffers[0], raw)
	ret.N = len(raw)
	ret.Buffers[0] = ret.Buffers[0][:ret.N]
	return ret
}

func benchmarkScionMac(b *testing.B, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(b, err)
	buffer := [path.MacLen]byte{}
	return path.MAC(mac, info, hf, buffer[:])
}
