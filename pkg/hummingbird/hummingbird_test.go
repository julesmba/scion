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

	"github.com/scionproto/scion/pkg/hummingbird"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

var testHops = []hummingbird.Hop{
	{AS: 12, Ingress: 0, Egress: 1},
	{AS: 13, Ingress: 2, Egress: 2},
	{AS: 16, Ingress: 1, Egress: 0},
}

var testReservatons = []hummingbird.Reservation{
	{
		AS:        12,
		ResID:     1234,
		Ingress:   0,
		Egress:    1,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Bw:        16,
		Duration:  120,
		StartTime: uint32(fixedTime.Unix()) - 10,
	},
	{
		AS:        13,
		ResID:     42,
		Ingress:   2,
		Egress:    2,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0},
		Bw:        16,
		Duration:  180,
		StartTime: uint32(fixedTime.Unix()) - 32,
	},
	{
		AS:        16,
		ResID:     365,
		Ingress:   1,
		Egress:    0,
		Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
		Bw:        20,
		Duration:  150,
		StartTime: uint32(fixedTime.Unix()) - 80,
	},
	{
		AS:        16,
		ResID:     21,
		Ingress:   1,
		Egress:    0,
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

	c := hummingbird.HummingbirdClient{}

	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	hops, err := c.PrepareHbirdPath(scionPath)

	assert.NoError(t, err)
	assert.Equal(t, testHops, hops)

	scionPath, err = getScionSnetPath()
	assert.NoError(t, err)

	output, err := c.FinalizePath(scionPath, 0, now)
	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, output)
}

func TestGetPathASes(t *testing.T) {

	c := hummingbird.HummingbirdClient{}

	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	hops, err := c.PrepareHbirdPath(scionPath)

	assert.NoError(t, err)
	assert.Equal(t, testHops, hops)

	hops = c.GetPathASes()

	assert.Equal(t, testHops, hops)
}

func TestApplyReservations(t *testing.T) {
	c := hummingbird.HummingbirdClient{}

	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	_, err = c.PrepareHbirdPath(scionPath)

	assert.NoError(t, err)

	err = c.ApplyReservations(testReservatons)

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
	c := hummingbird.HummingbirdClient{}

	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	_, err = c.PrepareHbirdPath(scionPath)

	assert.NoError(t, err)

	tnow := time.Now()
	now := uint32(tnow.Unix())

	// hop1: first reservation expired, second ok
	// hop2: first reservation expired, second not started, third expired, fourth ok
	// hop3: first not yet valid, second expired
	input := []hummingbird.Reservation{
		{
			AS:        12,
			ResID:     1234,
			Ingress:   0,
			Egress:    1,
			Duration:  70,
			StartTime: now - 80,
		},
		{
			AS:        12,
			ResID:     34,
			Ingress:   0,
			Egress:    1,
			Duration:  560,
			StartTime: now - 10,
		},
		{
			AS:        13,
			ResID:     42,
			Ingress:   2,
			Egress:    2,
			Duration:  80,
			StartTime: now - 100,
		},
		{
			AS:        13,
			ResID:     31,
			Ingress:   2,
			Egress:    2,
			Duration:  389,
			StartTime: now + 50,
		},
		{
			AS:        13,
			ResID:     12,
			Ingress:   2,
			Egress:    2,
			Duration:  64,
			StartTime: now - 60,
		},
		{
			AS:        13,
			ResID:     5,
			Ingress:   2,
			Egress:    2,
			Duration:  180,
			StartTime: now - 30,
		},
		{
			AS:        16,
			ResID:     365,
			Ingress:   1,
			Egress:    0,
			Duration:  150,
			StartTime: now + 60,
		},
		{
			AS:        16,
			ResID:     345,
			Ingress:   1,
			Egress:    0,
			Duration:  150,
			StartTime: now - 345,
		},
	}

	expected := []hummingbird.Reservation{
		{
			AS:        12,
			ResID:     34,
			Ingress:   0,
			Egress:    1,
			Duration:  560,
			StartTime: now - 10,
		},
		{
			AS:        13,
			ResID:     5,
			Ingress:   2,
			Egress:    2,
			Duration:  180,
			StartTime: now - 30,
		},
		{
			AS:        13,
			ResID:     31,
			Ingress:   2,
			Egress:    2,
			Duration:  389,
			StartTime: now + 50,
		},
		{
			AS:        16,
			ResID:     365,
			Ingress:   1,
			Egress:    0,
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
	c := hummingbird.HummingbirdClient{}

	scionPath, err := getScionSnetPath()
	assert.NoError(t, err)

	_, err = c.PrepareHbirdPath(scionPath)

	assert.NoError(t, err)

	err = c.ApplyReservations(testReservatons)
	assert.NoError(t, err)

	remove := []hummingbird.Reservation{
		{
			AS:    12,
			ResID: 1234,
		},
		{
			AS:    13,
			ResID: 53,
		},
		{
			AS:    16,
			ResID: 365,
		},
	}

	expected := []hummingbird.Reservation{
		{
			AS:        13,
			ResID:     42,
			Ingress:   2,
			Egress:    2,
			Ak:        [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0},
			Bw:        16,
			Duration:  180,
			StartTime: uint32(fixedTime.Unix()) - 32,
		},
		{
			AS:        16,
			ResID:     21,
			Ingress:   1,
			Egress:    0,
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
