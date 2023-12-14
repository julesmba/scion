// Copyright 2024 ETH Zurich
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

package hummingbird_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	dphbird "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deleteme remove this test
func TestPrepareHbirdPath(t *testing.T) {
	scionPath := getScionSnetPath(t)
	now := time.Now()

	flyovers := flyoverSliceToMap(testFlyovers)
	flyovers = nil
	c, err := hummingbird.NewReservation(scionPath, flyovers)
	require.NoError(t, err)
	scionPath = getScionSnetPath(t)
	output, err := c.FinalizePath(scionPath, 0, now)
	assert.NoError(t, err)
	expectecPath, err := getHbirdNoFlyoversSnetPath(now)
	assert.NoError(t, err)
	assert.Equal(t, expectecPath, output)
}

// deleteme rename this test as TestPrepareHbirdPath
func TestApplyReservations(t *testing.T) {
	scionPath := getScionSnetPath(t)

	c, err := hummingbird.NewReservation(scionPath, flyoverSliceToMap(testFlyovers))
	require.NoError(t, err)

	scionPath = getScionSnetPath(t)
	assert.NoError(t, err)

	hbirdPath, err := getHbirdFlyoversSnetPath(fixedTime)
	assert.NoError(t, err)

	output, err := c.FinalizePath(scionPath, 16, fixedTime)
	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, output)
}

func TestCheckReservationExpiry(t *testing.T) {

	tnow := time.Now()
	now := uint32(tnow.Unix())

	// hop1: first reservation expired, second ok
	// hop2: first reservation expired, second not started, third expired, fourth ok
	// hop3: first not yet valid, second expired
	input := []hummingbird.Flyover{
		{
			BaseHop:   testHops[0],
			ResID:     1234,
			Duration:  70,
			StartTime: now - 80,
		},
		{
			BaseHop:   testHops[0],
			ResID:     34,
			Duration:  560,
			StartTime: now - 10,
		},
		{
			BaseHop:   testHops[1],
			ResID:     42,
			Duration:  80,
			StartTime: now - 100,
		},
		{
			BaseHop:   testHops[1],
			ResID:     31,
			Duration:  389,
			StartTime: now + 50,
		},
		{
			BaseHop:   testHops[1],
			ResID:     12,
			Duration:  64,
			StartTime: now - 60,
		},
		{
			BaseHop:   testHops[1],
			ResID:     5,
			Duration:  180,
			StartTime: now - 30,
		},
		{
			BaseHop:   testHops[2],
			ResID:     365,
			Duration:  150,
			StartTime: now + 60,
		},
		{
			BaseHop:   testHops[2],
			ResID:     345,
			Duration:  150,
			StartTime: now - 345,
		},
	}

	expected := []hummingbird.Flyover{
		{
			BaseHop:   testHops[0],
			ResID:     34,
			Duration:  560,
			StartTime: now - 10,
		},
		{
			BaseHop:   testHops[1],
			ResID:     5,
			Duration:  180,
			StartTime: now - 30,
		},
		{
			BaseHop:   testHops[1],
			ResID:     31,
			Duration:  389,
			StartTime: now + 50,
		},
		{
			BaseHop:   testHops[2],
			ResID:     365,
			Duration:  150,
			StartTime: now + 60,
		},
	}

	scionPath := getScionSnetPath(t)

	c, err := hummingbird.NewReservation(scionPath, nil)
	assert.NoError(t, err)

	err = c.ApplyReservations(input)
	assert.NoError(t, err)

	c.CheckExpiry(5)
	assert.Equal(t, expected, c.GetUsedReservations())

	// Verify last reservation is unused as it is not yet valid
	scionPath = getScionSnetPath(t)

	outPath, err := c.FinalizePath(scionPath, 16, tnow)
	assert.NoError(t, err)

	raw := outPath.Dataplane().(snetpath.Hummingbird).Raw

	dec := decodeDataplane(t, raw)
	assert.True(t, dec.HopFields[0].Flyover)
	assert.True(t, dec.HopFields[1].Flyover)
	assert.False(t, dec.HopFields[2].Flyover)
	assert.False(t, dec.HopFields[3].Flyover)
}

func TestRemoveReservations(t *testing.T) {
	scionPath := getScionSnetPath(t)

	c, err := hummingbird.NewReservation(scionPath, nil)
	require.NoError(t, err)

	err = c.ApplyReservations(testFlyovers)
	assert.NoError(t, err)

	remove := []hummingbird.Flyover{
		{
			BaseHop: hummingbird.BaseHop{
				IA: testHops[0].IA,
			},
			ResID: 1234,
		},
		{
			BaseHop: hummingbird.BaseHop{
				IA: testHops[1].IA,
			},
			ResID: 53,
		},
		{
			BaseHop: hummingbird.BaseHop{
				IA: testHops[2].IA,
			},
			ResID: 365,
		},
	}

	expected := []hummingbird.Flyover{
		{
			BaseHop:   testHops[1],
			ResID:     42,
			Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0},
			Bw:        16,
			Duration:  180,
			StartTime: uint32(fixedTime.Unix()) - 32,
		},
		{
			BaseHop:   testHops[2],
			ResID:     21,
			Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
			Bw:        20,
			Duration:  150,
			StartTime: uint32(fixedTime.Unix()) - 10,
		},
	}

	err = c.RemoveReservations(remove)
	assert.NoError(t, err)

	output := c.GetUsedReservations()
	assert.Equal(t, expected, output)

	// Verify removal has resulted in correct path
	scionPath = getScionSnetPath(t)

	outPath, err := c.FinalizePath(scionPath, 16, time.Now())
	assert.NoError(t, err)

	raw := outPath.Dataplane().(snetpath.Hummingbird).Raw

	dec := decodeDataplane(t, raw)
	assert.False(t, dec.HopFields[0].Flyover)
	assert.True(t, dec.HopFields[1].Flyover)
	assert.False(t, dec.HopFields[2].Flyover)
	assert.True(t, dec.HopFields[3].Flyover)
}

func decodeDataplane(t *testing.T, raw []byte) dphbird.Decoded {
	t.Helper()
	dec := dphbird.Decoded{}
	err := dec.DecodeFromBytes(raw)
	assert.NoError(t, err)
	return dec
}

func flyoverSliceToMap(flyovers []hummingbird.Flyover) map[addr.IA][]*hummingbird.Flyover {
	m := make(map[addr.IA][]*hummingbird.Flyover)
	for _, flyover := range flyovers {
		clone := flyover
		m[clone.IA] = append(m[clone.IA], &clone)
	}
	return m
}
