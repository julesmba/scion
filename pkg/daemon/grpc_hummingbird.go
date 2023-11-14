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

package daemon

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
)

func (c grpcConn) StoreFlyovers(
	ctx context.Context,
	flyovers []*hummingbird.FlyoverJuanDeleteme,
) error {

	return nil
}

func (c grpcConn) ListFlyovers(ctx context.Context,
) ([]*hummingbird.FlyoverJuanDeleteme, error) {

	return nil, nil
}

func (c grpcConn) GetReservations(
	ctx context.Context,
	src, dst addr.IA,
) ([]snet.Path, error) {

	return nil, nil
}
