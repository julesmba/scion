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

	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReservationWithScionPath(t *testing.T) {
	scionPath := getScionSnetPath(t)

	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(scionPath, flyoverSliceToMap(testFlyoversInDB)),
	)
	require.NoError(t, err)
	hbirdPath, err := getHbirdFlyoversSnetPath(t, fixedTime)
	assert.NoError(t, err)
	decoded := r.DeriveDataPlanePath(16, fixedTime)
	raw := path.Hummingbird{
		Raw: make([]byte, decoded.Len()),
	}
	err = decoded.SerializeTo(raw.Raw)
	assert.NoError(t, err)
	scionPath.DataplanePath = raw

	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, scionPath)
}

func TestReservationWithHbirdPath(t *testing.T) {
	// Build a Reservation from an existing decoded hummingbird path and its associated
	// flyover sequence.
	r, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithExistingHbirdPath(
			decodedHbirdTestPathFlyovers,
			// selectUsedFlyovers(t, testFlyoverFieldsReserved, testExpectedFlyovers)),
			testExpectedFlyovers),
	)
	assert.NoError(t, err)

	// Expected:
	expected, err := hummingbird.NewReservation(
		hummingbird.WithNow(fixedTime),
		hummingbird.WithScionPath(getScionSnetPath(t),
			flyoverSliceToMap(testFlyoversInDB),
		),
	)
	require.NoError(t, err)
	require.Equal(t, expected, r)
}

func flyoverSliceToMap(flyovers []hummingbird.Flyover) hummingbird.FlyoverSet {
	m := make(hummingbird.FlyoverSet)
	for _, flyover := range flyovers {
		clone := flyover
		m[clone.BaseHop] = append(m[clone.BaseHop], &clone)
	}
	return m
}
