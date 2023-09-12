package hummingbird_test

import (
	"fmt"
	"testing"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/stretchr/testify/assert"
)

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

var testFlyoverFields = []hummingbird.FlyoverHopField{
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 2,
		Duration:     1,
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 3,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 0,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 0,
		Duration:     1,
	},
}

var decodedHbirdTestPath = &hummingbird.Decoded{
	Base: hummingbird.Base{
		PathMeta: hummingbird.MetaHdr{
			CurrINF:   0,
			CurrHF:    0,
			SegLen:    [3]uint8{8, 8, 0},
			BaseTS:    808,
			HighResTS: 1234,
		},
		NumINF:  2,
		NumHops: 16,
	},
	InfoFields: testInfoFields,
	HopFields:  testFlyoverFields,
}

var emptyDecodedTestPath = &hummingbird.Decoded{
	Base:       hummingbird.Base{},
	InfoFields: []path.InfoField{},
	HopFields:  []hummingbird.FlyoverHopField{},
}

var rawHbirdPath = []byte("\x00\x02\x04\x00\x00\x00\x03\x28\x00\x00\x04\xd2" + //Pathmeta header
	"\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00\x01\x00" + //Infofields
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x02\x00\x01" + //flyoverfield 0
	"\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06" + //hopfield 1
	"\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06" + //hopfield 2
	"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x00\x00\x01") //flyoverfield 3

type hbirdPathCase struct {
	infos []bool
	hops  [][][]uint16
}

var pathReverseCasesHbird = map[string]struct {
	input    hbirdPathCase
	want     hbirdPathCase
	inIdxs   [][2]int
	wantIdxs [][2]int
}{
	"1 segment, 2 hops": {
		input:    hbirdPathCase{[]bool{true}, [][][]uint16{{{11, 0}, {12, 1}}}},
		want:     hbirdPathCase{[]bool{false}, [][][]uint16{{{12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 3}},
		wantIdxs: [][2]int{{0, 3}, {0, 0}},
	},
	"1 segment, 5 hops": {
		input:    hbirdPathCase{[]bool{true}, [][][]uint16{{{11, 1}, {12, 1}, {13, 0}, {14, 1}, {15, 0}}}},
		want:     hbirdPathCase{[]bool{false}, [][][]uint16{{{15, 0}, {14, 0}, {13, 0}, {12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 5}, {0, 10}, {0, 13}, {0, 18}},
		wantIdxs: [][2]int{{0, 12}, {0, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"2 segments, 5 hops": {
		input:    hbirdPathCase{[]bool{true, false}, [][][]uint16{{{11, 0}, {12, 0}}, {{13, 1}, {14, 1}, {15, 0}}}},
		want:     hbirdPathCase{[]bool{true, false}, [][][]uint16{{{15, 0}, {14, 0}, {13, 0}}, {{12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 3}, {1, 6}, {1, 11}, {1, 16}},
		wantIdxs: [][2]int{{1, 12}, {1, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"3 segments, 9 hops": {
		input: hbirdPathCase{
			[]bool{true, false, false},
			[][][]uint16{
				{{11, 1}, {12, 0}},
				{{13, 0}, {14, 1}, {15, 1}, {16, 0}},
				{{17, 0}, {18, 1}, {19, 1}},
			},
		},
		want: hbirdPathCase{
			[]bool{true, true, false},
			[][][]uint16{
				{{19, 0}, {18, 0}, {17, 0}},
				{{16, 0}, {15, 0}, {14, 0}, {13, 0}},
				{{12, 0}, {11, 0}},
			},
		},
		inIdxs: [][2]int{
			{0, 0}, {0, 5}, {1, 8}, {1, 11}, {1, 16}, {1, 21}, {2, 24}, {2, 27}, {2, 32},
		},
		wantIdxs: [][2]int{
			{2, 24}, {2, 21}, {1, 18}, {1, 15}, {1, 12}, {1, 9}, {0, 6}, {0, 3}, {0, 0},
		},
	},
}

func TestDecodedSerializeHbird(t *testing.T) {
	b := make([]byte, decodedHbirdTestPath.Len())
	assert.NoError(t, decodedHbirdTestPath.SerializeTo(b))
	assert.Equal(t, rawHbirdPath, b)
}

func TestDecodedDecodeFromBytesHbird(t *testing.T) {
	s := &hummingbird.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(rawHbirdPath))
	assert.Equal(t, decodedHbirdTestPath, s)
}

func TestDecodedSerializeDecodeHbird(t *testing.T) {
	b := make([]byte, decodedHbirdTestPath.Len())
	assert.NoError(t, decodedHbirdTestPath.SerializeTo(b))
	s := &hummingbird.Decoded{}
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, decodedHbirdTestPath, s)
}

func TestDecodedReverseHbird(t *testing.T) {
	for name, tc := range pathReverseCasesHbird {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				inputPath := mkDecodedHbirdPath(t, tc.input, uint8(tc.inIdxs[i][0]),
					uint8(tc.inIdxs[i][1]))
				wantPath := mkDecodedHbirdPath(t, tc.want, uint8(tc.wantIdxs[i][0]),
					uint8(tc.wantIdxs[i][1]))
				revPath, err := inputPath.Reverse()
				assert.NoError(t, err)
				assert.Equal(t, wantPath, revPath)
			})
		}
	}
}

func TestEmptyDecodedReverse(t *testing.T) {
	_, err := emptyDecodedTestPath.Reverse()
	assert.Error(t, err)
}

func TestDecodedToRawHbird(t *testing.T) {
	raw, err := decodedHbirdTestPath.ToRaw()
	assert.NoError(t, err)
	assert.Equal(t, rawHbirdTestPath, raw)
}

func mkDecodedHbirdPath(t *testing.T, pcase hbirdPathCase, infIdx, hopIdx uint8) *hummingbird.Decoded {
	t.Helper()
	s := &hummingbird.Decoded{}
	meta := hummingbird.MetaHdr{
		CurrINF:   infIdx,
		CurrHF:    hopIdx,
		BaseTS:    14,
		HighResTS: 15,
	}
	for _, dir := range pcase.infos {
		s.InfoFields = append(s.InfoFields, path.InfoField{ConsDir: dir})
	}
	i := 0
	for j, hops := range pcase.hops {
		for _, hop := range hops {
			f := hop[1] == 1
			s.HopFields = append(s.HopFields, hummingbird.FlyoverHopField{
				HopField: path.HopField{ConsIngress: hop[0], ConsEgress: hop[0], Mac: [6]byte{1, 2, 3, 4, 5, 6}},
				Flyover:  f,
				Duration: 2})
			if f {
				i += 5
				meta.SegLen[j] += 5
			} else {
				i += 3
				meta.SegLen[j] += 3
			}
		}
	}
	s.PathMeta = meta
	s.NumINF = len(pcase.infos)
	s.NumHops = i

	return s
}
