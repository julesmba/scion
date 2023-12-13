package hummingbird_test

import (
	"time"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

var fixedTime = time.Unix(1136239445, 432)

var testInfoFields = []path.InfoField{
	{
		Peer:      false,
		ConsDir:   false,
		SegID:     0x111,
		Timestamp: 0x100,
	},
	{
		Peer:      false,
		ConsDir:   true,
		SegID:     0x222,
		Timestamp: 0x100,
	},
}

var testHopFields = []path.HopField{
	{
		ExpTime:     63,
		ConsIngress: 1,
		ConsEgress:  0,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 3,
		ConsEgress:  2,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 0,
		ConsEgress:  4,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
	{
		ExpTime:     63,
		ConsIngress: 5,
		ConsEgress:  0,
		Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
	},
}

var testFlyoverFields = []hummingbird.FlyoverHopField{
	{
		HopField: testHopFields[0],
		Flyover:  false,
	},
	{
		HopField: testHopFields[1],
		Flyover:  false,
	},
	{
		HopField: testHopFields[2],
		Flyover:  false,
	},
	{
		HopField: testHopFields[3],
		Flyover:  false,
	},
}

var testFlyoverFieldsReserved = []hummingbird.FlyoverHopField{
	{
		HopField:     testHopFields[0],
		Flyover:      true,
		ResID:        1234,
		Bw:           16,
		Duration:     120,
		ResStartTime: 10,
	},
	{
		HopField:     testHopFields[1],
		Flyover:      true,
		ResID:        42,
		Bw:           16,
		Duration:     180,
		ResStartTime: 32,
	},
	{
		HopField: testHopFields[2],
		Flyover:  false,
	},
	{
		HopField:     testHopFields[3],
		Flyover:      true,
		ResID:        365,
		Bw:           20,
		Duration:     150,
		ResStartTime: 80,
	},
}

var decodedTestPath = &scion.Decoded{
	Base: scion.Base{
		PathMeta: scion.MetaHdr{
			CurrINF: 0,
			CurrHF:  0,
			SegLen:  [3]uint8{2, 2, 0},
		},

		NumINF:  2,
		NumHops: 4,
	},
	InfoFields: testInfoFields,
	HopFields:  testHopFields,
}

var interfacesTest = []snet.PathInterface{
	{
		IA: 12,
		ID: 1,
	},
	{
		IA: 13,
		ID: 2,
	},
	{
		IA: 13,
		ID: 4,
	},
	{
		IA: 14,
		ID: 5,
	},
}

var decodedHbirdTestPath = &hummingbird.Decoded{
	Base: hummingbird.Base{
		PathMeta: hummingbird.MetaHdr{
			CurrINF: 0,
			CurrHF:  0,
			SegLen:  [3]uint8{6, 6, 0},
		},
		NumINF:   2,
		NumLines: 12,
	},
	InfoFields:     testInfoFields,
	HopFields:      testFlyoverFields,
	FirstHopPerSeg: [2]uint8{2, 4},
}

var decodedHbirdTestPathFlyovers = &hummingbird.Decoded{
	Base: hummingbird.Base{
		PathMeta: hummingbird.MetaHdr{
			CurrINF: 0,
			CurrHF:  0,
			SegLen:  [3]uint8{10, 8, 0},
		},
		NumINF:   2,
		NumLines: 18,
	},
	InfoFields:     testInfoFields,
	HopFields:      testFlyoverFieldsReserved,
	FirstHopPerSeg: [2]uint8{2, 4},
}

func getRawScionPath(d scion.Decoded) ([]byte, error) {
	b := make([]byte, d.Len())
	err := d.SerializeTo(b)
	return b, err
}

func getScionSnetPath() (snetpath.Path, error) {
	rawScion, err := getRawScionPath(*decodedTestPath)
	p := snetpath.Path{
		Src: interfacesTest[0].IA,
		Dst: interfacesTest[len(interfacesTest)-1].IA,
		DataplanePath: snetpath.SCION{
			Raw: rawScion,
		},
		Meta: snet.PathMetadata{
			Interfaces: interfacesTest,
		},
	}
	return p, err
}

func getRawHbirdPath(h hummingbird.Decoded) ([]byte, error) {
	b := make([]byte, h.Len())
	err := h.SerializeTo(b)
	return b, err
}

func getHbirdNoFlyoversSnetPath(t time.Time) (snetpath.Path, error) {
	decoded := *decodedHbirdTestPath
	secs := uint32(t.Unix())
	millis := uint32(t.Nanosecond()/1000) << 22
	decoded.Base.PathMeta.BaseTS = secs
	decoded.Base.PathMeta.HighResTS = millis

	rawHbird, err := getRawHbirdPath(decoded)
	p := snetpath.Path{
		Src: interfacesTest[0].IA,
		Dst: interfacesTest[len(interfacesTest)-1].IA,
		DataplanePath: snetpath.Hummingbird{
			Raw: rawHbird,
		},
		Meta: snet.PathMetadata{
			Interfaces: interfacesTest,
		},
	}
	return p, err
}

func getHbirdFlyoversSnetPath(t time.Time) (snetpath.Path, error) {
	decoded := *decodedHbirdTestPathFlyovers
	secs := uint32(t.Unix())
	millis := uint32(t.Nanosecond()/1000) << 22
	decoded.Base.PathMeta.BaseTS = secs
	decoded.Base.PathMeta.HighResTS = millis

	xkBuffer := make([]uint32, hummingbird.XkBufferSize)
	macBuffer0 := make([]byte, hummingbird.FlyoverMacBufferSize)
	macBuffer1 := make([]byte, hummingbird.FlyoverMacBufferSize)
	macBuffer2 := make([]byte, hummingbird.FlyoverMacBufferSize)

	ak0 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	flyover0 := hummingbird.FullFlyoverMac(ak0, interfacesTest[len(interfacesTest)-1].IA,
		16, decoded.HopFields[0].ResStartTime,
		millis, macBuffer0, xkBuffer)

	ak1 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0}
	flyover1 := hummingbird.FullFlyoverMac(ak1, interfacesTest[len(interfacesTest)-1].IA,
		16, decoded.HopFields[1].ResStartTime,
		millis, macBuffer1, xkBuffer)

	ak2 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	flyover2 := hummingbird.FullFlyoverMac(ak2, interfacesTest[len(interfacesTest)-1].IA,
		16, decoded.HopFields[3].ResStartTime,
		millis, macBuffer2, xkBuffer)

	for i := 0; i < 6; i++ {
		decoded.HopFields[0].HopField.Mac[i] = decoded.HopFields[0].HopField.Mac[i] ^ flyover0[i]
		decoded.HopFields[1].HopField.Mac[i] = decoded.HopFields[1].HopField.Mac[i] ^ flyover1[i]
		decoded.HopFields[3].HopField.Mac[i] = decoded.HopFields[3].HopField.Mac[i] ^ flyover2[i]
	}

	rawHbird, err := getRawHbirdPath(decoded)
	p := snetpath.Path{
		Src: interfacesTest[0].IA,
		Dst: interfacesTest[len(interfacesTest)-1].IA,
		DataplanePath: snetpath.Hummingbird{
			Raw: rawHbird,
		},
		Meta: snet.PathMetadata{
			Interfaces: interfacesTest,
		},
	}
	return p, err
}

func decodeDataplane(raw []byte) (hummingbird.Decoded, error) {
	dec := hummingbird.Decoded{}
	err := dec.DecodeFromBytes(raw)
	return dec, err
}
