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

func TestPrepareHbirdPath(t *testing.T) {
	scionPath := getScionSnetPath(t)

	c, err := hummingbird.NewReservation(
		hummingbird.WithPath(scionPath),
		hummingbird.WithFlyovers(flyoverSliceToMap(testFlyovers)),
		hummingbird.WithNow(fixedTime),
	)
	require.NoError(t, err)

	scionPath = getScionSnetPath(t)
	assert.NoError(t, err)

	hbirdPath, err := getHbirdFlyoversSnetPath(fixedTime)
	assert.NoError(t, err)

	// output, err := c.DeriveDataPlanePath(scionPath, 16, fixedTime)
	decoded := c.DeriveDataPlanePath(16, fixedTime)
	raw := path.Hummingbird{
		Raw: make([]byte, decoded.Len()),
	}
	err = decoded.SerializeTo(raw.Raw)
	assert.NoError(t, err)
	scionPath.DataplanePath = raw

	assert.NoError(t, err)
	assert.Equal(t, hbirdPath, scionPath)
}

func flyoverSliceToMap(flyovers []hummingbird.Flyover) hummingbird.FlyoverSet {
	m := make(hummingbird.FlyoverSet)
	for _, flyover := range flyovers {
		clone := flyover
		m[clone.BaseHop] = append(m[clone.BaseHop], &clone)
	}
	return m
}
