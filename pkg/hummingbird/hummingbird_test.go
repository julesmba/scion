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

package hummingbird_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/hummingbird"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

var testHops = []hummingbird.BaseHop{
	{
		IA:      interfacesTest[0].IA,
		Ingress: 0,
		Egress:  1,
	},
	{
		IA:      13,
		Ingress: 2,
		Egress:  4,
	},
	{
		IA:      interfacesTest[len(interfacesTest)-1].IA,
		Ingress: 5,
		Egress:  0,
	},
}

var testFlyovers = []hummingbird.Flyover{
	{
		BaseHop:   testHops[0],
		ResID:     1234,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  120,
		StartTime: uint32(fixedTime.Unix()) - 10,
	},
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
		ResID:     365,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
		Bw:        20,
		Duration:  150,
		StartTime: uint32(fixedTime.Unix()) - 80,
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

func TestPrepareHbirdPath(t *testing.T) {
	now := time.Now()

	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	hbirdPath, err := getHbirdNoFlyoversSnetPath(now)
	assert.NoError(t, err)

	out, err := hummingbird.ConvertToHbirdPath(scionPath, now)
	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, out)

	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	c, err := hummingbird.NewReservation(scionPath)
	require.NoError(t, err)
	hops := c.GetPathASes()
	assert.Equal(t, testHops, hops)

	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	output, err := c.FinalizePath(scionPath, 0, now)
	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, output)
}

func TestGetPathASes(t *testing.T) {
	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	c, err := hummingbird.NewReservation(scionPath)
	require.NoError(t, err)
	hops := c.GetPathASes()
	assert.Equal(t, testHops, hops)

	hops = c.GetPathASes()

	assert.Equal(t, testHops, hops)
}

func TestApplyReservations(t *testing.T) {
	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	c, err := hummingbird.NewReservation(scionPath)
	require.NoError(t, err)
	hops := c.GetPathASes()
	assert.Equal(t, testHops, hops)

	err = c.ApplyReservations(testFlyovers)
	assert.NoError(t, err)

	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	hbirdPath, err := getHbirdFlyoversSnetPath(fixedTime)
	assert.NoError(t, err)

	output, err := c.FinalizePath(scionPath, 16, fixedTime)
	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, output)
}

func TestCheckReservationExpiry(t *testing.T) {
	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	c, err := hummingbird.NewReservation(scionPath)
	require.NoError(t, err)
	hops := c.GetPathASes()
	assert.Equal(t, testHops, hops)

	assert.NoError(t, err)

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

	err = c.ApplyReservations(input)
	assert.NoError(t, err)

	c.CheckExpiry(5)

	output := c.GetUsedReservations()

	assert.Equal(t, expected, output)

	// Verify last reservation is unused as it is not yet valid
	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	outPath, err := c.FinalizePath(scionPath, 16, tnow)
	assert.NoError(t, err)

	raw := outPath.Dataplane().(snetpath.Hummingbird).Raw

	dec, err := decodeDataplane(raw)
	assert.NoError(t, err)
	assert.True(t, dec.HopFields[0].Flyover)
	assert.True(t, dec.HopFields[1].Flyover)
	assert.False(t, dec.HopFields[2].Flyover)
	assert.False(t, dec.HopFields[3].Flyover)
}

func TestRemoveReservations(t *testing.T) {
	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	c, err := hummingbird.NewReservation(scionPath)
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
	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	outPath, err := c.FinalizePath(scionPath, 16, time.Now())
	assert.NoError(t, err)

	raw := outPath.Dataplane().(snetpath.Hummingbird).Raw

	dec, err := decodeDataplane(raw)
	assert.NoError(t, err)
	assert.False(t, dec.HopFields[0].Flyover)
	assert.True(t, dec.HopFields[1].Flyover)
	assert.False(t, dec.HopFields[2].Flyover)
	assert.True(t, dec.HopFields[3].Flyover)
}
