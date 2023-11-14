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

package hummingbird

import "github.com/scionproto/scion/pkg/snet/path"

type ReservationJuanDeleteme struct {
	SCIONPath path.Path
	Flyovers  []*FlyoverJuanDeleteme
	Ratio     float64 // flyover/hops ratio
}

// HopCount returns the number of hops in this path, as understood by a hop in a regular SCION path.
func (r ReservationJuanDeleteme) HopCount() int {
	return len(r.SCIONPath.Meta.Interfaces)
}

func (r ReservationJuanDeleteme) FlyoverCount() int {
	return len(r.Flyovers)
}

func (r ReservationJuanDeleteme) LessThan(other *ReservationJuanDeleteme) bool {
	return r.Ratio < other.Ratio
}
