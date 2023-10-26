package hummingbird_test

import (
	"fmt"
	"testing"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var emptyRawTestPath = &hummingbird.Raw{
	Base: hummingbird.Base{
		PathMeta: hummingbird.MetaHdr{
			CurrINF: 0,
			CurrHF:  0,
			SegLen:  [3]uint8{0, 0, 0},
		},
		NumINF:  0,
		NumHops: 0,
	},
	Raw: make([]byte, hummingbird.MetaLen),
}

var rawHbirdTestPath = &hummingbird.Raw{
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
	Raw: rawHbirdPath,
}

func TestRawSerializeHbird(t *testing.T) {
	b := make([]byte, rawHbirdTestPath.Len())
	assert.NoError(t, rawHbirdTestPath.SerializeTo(b))
	assert.Equal(t, rawHbirdPath, b)
}

func TestRawDecodeFromBytesHbird(t *testing.T) {
	s := &hummingbird.Raw{}
	assert.NoError(t, s.DecodeFromBytes(rawHbirdPath))
	assert.Equal(t, rawHbirdTestPath, s)
}

func TestRawSerializeDecodeHbird(t *testing.T) {
	b := make([]byte, rawHbirdTestPath.Len())
	assert.NoError(t, rawHbirdTestPath.SerializeTo(b))
	s := &hummingbird.Raw{}
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, rawHbirdTestPath, s)
}

func TestRawReverseHbird(t *testing.T) {
	for name, tc := range pathReverseCasesHbird {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				//t.Parallel()
				input := mkRawHbirdPath(t, tc.input, uint8(tc.inIdxs[i][0]), uint8(tc.inIdxs[i][1]))
				want := mkRawHbirdPath(t, tc.want, uint8(tc.wantIdxs[i][0]), uint8(tc.wantIdxs[i][1]))
				revPath, err := input.Reverse()
				assert.NoError(t, err)
				assert.Equal(t, want, revPath)
			})
		}
	}
}

func TestEmptyRawReverse(t *testing.T) {
	_, err := emptyRawTestPath.Reverse()
	assert.Error(t, err)
}

func TestRawToDecodedHbird(t *testing.T) {
	decoded, err := rawHbirdTestPath.ToDecoded()
	assert.NoError(t, err)
	assert.Equal(t, decodedHbirdTestPath, decoded)
}

func TestGetInfoField(t *testing.T) {
	testCases := map[string]struct {
		idx       int
		want      path.InfoField
		errorFunc assert.ErrorAssertionFunc
	}{
		"first info": {
			idx:       0,
			want:      testInfoFields[0],
			errorFunc: assert.NoError,
		},
		"second info": {
			idx:       1,
			want:      testInfoFields[1],
			errorFunc: assert.NoError,
		},
		"out of bounds": {
			idx:       2,
			want:      path.InfoField{},
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc

		t.Run(name+" hummingbird", func(t *testing.T) {
			t.Parallel()
			got, err := rawHbirdTestPath.GetInfoField(tc.idx)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetHbirdHopField(t *testing.T) {
	testCases := map[string]struct {
		idx       int
		want      hummingbird.FlyoverHopField
		errorFunc assert.ErrorAssertionFunc
	}{
		"first hop": {
			idx:       0,
			want:      testFlyoverFields[0],
			errorFunc: assert.NoError,
		},
		"fourth hop": {
			idx:       11,
			want:      testFlyoverFields[3],
			errorFunc: assert.NoError,
		},
		"invalid index": {
			idx:       12,
			errorFunc: assert.Error,
		},
		"out of bounds": {
			idx:       14,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := rawHbirdTestPath.GetHopField(tc.idx)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

//TODO: SetHopField test

func TestLastHop(t *testing.T) {
	testCases := map[*hummingbird.Raw]bool{
		createHbirdPath(3, 9):  false,
		createHbirdPath(3, 11): false,
		createHbirdPath(3, 12): false,
		createHbirdPath(6, 9):  true,
		createHbirdPath(6, 11): true,
	}
	for scionRaw, want := range testCases {
		got := scionRaw.IsLastHop()
		assert.Equal(t, want, got)
	}
}

func mkRawHbirdPath(t *testing.T, pcase hbirdPathCase, infIdx, hopIdx uint8) *hummingbird.Raw {
	t.Helper()
	decoded := mkDecodedHbirdPath(t, pcase, infIdx, hopIdx)
	raw, err := decoded.ToRaw()
	require.NoError(t, err)
	return raw
}

func createHbirdPath(currHF uint8, numHops int) *hummingbird.Raw {
	hbirdRaw := &hummingbird.Raw{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrHF: currHF,
			},
			NumHops: numHops,
		},
	}
	return hbirdRaw
}
