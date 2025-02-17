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

package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	libepic "github.com/scionproto/scion/pkg/experimental/epic"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/spao"
	"github.com/scionproto/scion/private/topology"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
)

const (
	// TODO(karampok). Investigate whether that value should be higher.  In
	// theory, PayloadLen in SCION header is 16 bits long, supporting a maximum
	// payload size of 64KB. At the moment we are limited by Ethernet size
	// usually ~1500B, but 9000B to support jumbo frames.
	bufSize = 9000

	// hopFieldDefaultExpTime is the default validity of the hop field
	// and 63 is equivalent to 6h.
	hopFieldDefaultExpTime = 63

	// e2eAuthHdrLen is the length in bytes of added information when a SCMP packet
	// needs to be authenticated: 16B (e2e.option.Len()) + 16B (CMAC_tag.Len()).
	e2eAuthHdrLen = 32
)

type bfdSession interface {
	Run(ctx context.Context) error
	ReceiveMessage(*layers.BFD)
	IsUp() bool
}

// BatchConn is a connection that supports batch reads and writes.
type BatchConn interface {
	ReadBatch(underlayconn.Messages) (int, error)
	WriteTo([]byte, *net.UDPAddr) (int, error)
	WriteBatch(msgs underlayconn.Messages, flags int) (int, error)
	Close() error
}

// DataPlane contains a SCION Border Router's forwarding logic. It reads packets
// from multiple sockets, performs routing, and sends them to their destinations
// (after updating the path, if that is needed).
//
// XXX(lukedirtwalker): this is still in development and not feature complete.
// Currently, only the following features are supported:
//   - initializing connections; MUST be done prior to calling Run
type DataPlane struct {
	interfaces        map[uint16]BatchConn
	external          map[uint16]BatchConn
	linkTypes         map[uint16]topology.LinkType
	neighborIAs       map[uint16]addr.IA
	internal          BatchConn
	internalIP        netip.Addr
	internalNextHops  map[uint16]*net.UDPAddr
	svc               *services
	macFactory        func() hash.Hash
	bfdSessions       map[uint16]bfdSession
	localIA           addr.IA
	mtx               sync.Mutex
	running           bool
	Metrics           *Metrics
	forwardingMetrics map[uint16]forwardingMetrics

	// The pool that stores all the packet buffers as described in the design document. See
	// https://github.com/scionproto/scion/blob/master/doc/dev/design/BorderRouter.rst
	packetPool chan []byte
}

var (
	alreadySet                    = serrors.New("already set")
	invalidSrcIA                  = serrors.New("invalid source ISD-AS")
	invalidDstIA                  = serrors.New("invalid destination ISD-AS")
	invalidSrcAddrForTransit      = serrors.New("invalid source address for transit pkt")
	cannotRoute                   = serrors.New("cannot route, dropping pkt")
	emptyValue                    = serrors.New("empty value")
	malformedPath                 = serrors.New("malformed path content")
	modifyExisting                = serrors.New("modifying a running dataplane is not allowed")
	noSVCBackend                  = serrors.New("cannot find internal IP for the SVC")
	unsupportedPathType           = serrors.New("unsupported path type")
	unsupportedPathTypeNextHeader = serrors.New("unsupported combination")
	noBFDSessionFound             = serrors.New("no BFD sessions was found")
	noBFDSessionConfigured        = serrors.New("no BFD sessions have been configured")
	errBFDDisabled                = serrors.New("BFD is disabled")
	// zeroBuffer will be used to reset the Authenticator option in the
	// scionPacketProcessor.OptAuth
	zeroBuffer = make([]byte, 16)
)

type drkeyProvider interface {
	GetAuthKey(validTime time.Time, dstIA addr.IA, dstAddr addr.Host) (drkey.Key, error)
}

type scmpError struct {
	TypeCode slayers.SCMPTypeCode
	Cause    error
}

func (e scmpError) Error() string {
	return serrors.New("scmp", "typecode", e.TypeCode, "cause", e.Cause).Error()
}

// SetIA sets the local IA for the dataplane.
func (d *DataPlane) SetIA(ia addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if ia.IsZero() {
		return emptyValue
	}
	if !d.localIA.IsZero() {
		return alreadySet
	}
	d.localIA = ia
	return nil
}

// SetKey sets the key used for MAC verification. The key provided here should
// already be derived as in scrypto.HFMacFactory.
func (d *DataPlane) SetKey(key []byte) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if len(key) == 0 {
		return emptyValue
	}
	if d.macFactory != nil {
		return alreadySet
	}
	// First check for MAC creation errors.
	if _, err := scrypto.InitMac(key); err != nil {
		return err
	}
	d.macFactory = func() hash.Hash {
		mac, _ := scrypto.InitMac(key)
		return mac
	}
	return nil
}

// AddInternalInterface sets the interface the data-plane will use to
// send/receive traffic in the local AS. This can only be called once; future
// calls will return an error. This can only be called on a not yet running
// dataplane.
func (d *DataPlane) AddInternalInterface(conn BatchConn, ip net.IP) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}
	if d.internal != nil {
		return alreadySet
	}
	if d.interfaces == nil {
		d.interfaces = make(map[uint16]BatchConn)
	}
	d.interfaces[0] = conn
	d.internal = conn
	var ok bool
	d.internalIP, ok = netip.AddrFromSlice(ip)
	if !ok {
		return serrors.New("invalid ip", "ip", ip)
	}
	return nil
}

// AddExternalInterface adds the inter AS connection for the given interface ID.
// If a connection for the given ID is already set this method will return an
// error. This can only be called on a not yet running dataplane.
func (d *DataPlane) AddExternalInterface(ifID uint16, conn BatchConn) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}
	if _, exists := d.external[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.external == nil {
		d.external = make(map[uint16]BatchConn)
	}
	if d.interfaces == nil {
		d.interfaces = make(map[uint16]BatchConn)
	}
	d.interfaces[ifID] = conn
	d.external[ifID] = conn
	return nil
}

// AddNeighborIA adds the neighboring IA for a given interface ID. If an IA for
// the given ID is already set, this method will return an error. This can only
// be called on a yet running dataplane.
func (d *DataPlane) AddNeighborIA(ifID uint16, remote addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if remote.IsZero() {
		return emptyValue
	}
	if _, exists := d.neighborIAs[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.neighborIAs == nil {
		d.neighborIAs = make(map[uint16]addr.IA)
	}
	d.neighborIAs[ifID] = remote
	return nil
}

// AddLinkType adds the link type for a given interface ID. If a link type for
// the given ID is already set, this method will return an error. This can only
// be called on a not yet running dataplane.
func (d *DataPlane) AddLinkType(ifID uint16, linkTo topology.LinkType) error {
	if _, exists := d.linkTypes[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.linkTypes == nil {
		d.linkTypes = make(map[uint16]topology.LinkType)
	}
	d.linkTypes[ifID] = linkTo
	return nil
}

// AddExternalInterfaceBFD adds the inter AS connection BFD session.
func (d *DataPlane) AddExternalInterfaceBFD(ifID uint16, conn BatchConn,
	src, dst control.LinkEnd, cfg control.BFD) error {

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{
			"interface":       fmt.Sprint(ifID),
			"isd_as":          d.localIA.String(),
			"neighbor_isd_as": dst.IA.String(),
		}
		m = bfd.Metrics{
			Up:              d.Metrics.InterfaceUp.With(labels),
			StateChanges:    d.Metrics.BFDInterfaceStateChanges.With(labels),
			PacketsSent:     d.Metrics.BFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.BFDPacketsReceived.With(labels),
		}
	}
	s, err := newBFDSend(conn, src.IA, dst.IA, src.Addr, dst.Addr, ifID, d.macFactory())
	if err != nil {
		return err
	}
	return d.addBFDController(ifID, s, cfg, m)
}

// getInterfaceState checks if there is a bfd session for the input interfaceID and
// returns InterfaceUp if the relevant bfdsession state is up, or if there is no BFD
// session. Otherwise, it returns InterfaceDown.
func (d *DataPlane) getInterfaceState(interfaceID uint16) control.InterfaceState {
	bfdSessions := d.bfdSessions
	if bfdSession, ok := bfdSessions[interfaceID]; ok && !bfdSession.IsUp() {
		return control.InterfaceDown
	}
	return control.InterfaceUp
}

func (d *DataPlane) addBFDController(ifID uint16, s *bfdSend, cfg control.BFD,
	metrics bfd.Metrics) error {

	if cfg.Disable {
		return errBFDDisabled
	}
	if d.bfdSessions == nil {
		d.bfdSessions = make(map[uint16]bfdSession)
	}

	// Generate random discriminator. It can't be zero.
	discInt, err := rand.Int(rand.Reader, big.NewInt(0xfffffffe))
	if err != nil {
		return err
	}
	disc := layers.BFDDiscriminator(uint32(discInt.Uint64()) + 1)
	d.bfdSessions[ifID] = &bfd.Session{
		Sender:                s,
		DetectMult:            layers.BFDDetectMultiplier(cfg.DetectMult),
		DesiredMinTxInterval:  cfg.DesiredMinTxInterval,
		RequiredMinRxInterval: cfg.RequiredMinRxInterval,
		LocalDiscriminator:    disc,
		ReceiveQueueSize:      10,
		Metrics:               metrics,
	}
	return nil
}

// AddSvc adds the address for the given service. This can be called multiple
// times for the same service, with the address added to the list of addresses
// that provide the service.
func (d *DataPlane) AddSvc(svc addr.SVC, a *net.UDPAddr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if a == nil {
		return emptyValue
	}
	if d.svc == nil {
		d.svc = newServices()
	}
	d.svc.AddSvc(svc, a)
	if d.Metrics != nil {
		labels := serviceMetricLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(1)
	}
	return nil
}

// DelSvc deletes the address for the given service.
func (d *DataPlane) DelSvc(svc addr.SVC, a *net.UDPAddr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if a == nil {
		return emptyValue
	}
	if d.svc == nil {
		return nil
	}
	d.svc.DelSvc(svc, a)
	if d.Metrics != nil {
		labels := serviceMetricLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(-1)
	}
	return nil
}

// AddNextHop sets the next hop address for the given interface ID. If the
// interface ID already has an address associated this operation fails. This can
// only be called on a not yet running dataplane.
func (d *DataPlane) AddNextHop(ifID uint16, a *net.UDPAddr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if a == nil {
		return emptyValue
	}
	if _, exists := d.internalNextHops[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.internalNextHops == nil {
		d.internalNextHops = make(map[uint16]*net.UDPAddr)
	}
	d.internalNextHops[ifID] = a
	return nil
}

// AddNextHopBFD adds the BFD session for the next hop address.
// If the remote ifID belongs to an existing address, the existing
// BFD session will be re-used.
func (d *DataPlane) AddNextHopBFD(ifID uint16, src, dst *net.UDPAddr, cfg control.BFD,
	sibling string) error {

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}

	if dst == nil {
		return emptyValue
	}

	for k, v := range d.internalNextHops {
		if v.String() == dst.String() {
			if c, ok := d.bfdSessions[k]; ok {
				d.bfdSessions[ifID] = c
				return nil
			}
		}
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{"isd_as": d.localIA.String(), "sibling": sibling}
		m = bfd.Metrics{
			Up:              d.Metrics.SiblingReachable.With(labels),
			StateChanges:    d.Metrics.SiblingBFDStateChanges.With(labels),
			PacketsSent:     d.Metrics.SiblingBFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.SiblingBFDPacketsReceived.With(labels),
		}
	}

	s, err := newBFDSend(d.internal, d.localIA, d.localIA, src, dst, 0, d.macFactory())
	if err != nil {
		return err
	}
	return d.addBFDController(ifID, s, cfg, m)
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

type RunConfig struct {
	NumProcessors         int
	NumSlowPathProcessors int
	BatchSize             int
}

func (d *DataPlane) Run(ctx context.Context, cfg *RunConfig) error {
	d.mtx.Lock()
	d.running = true
	d.initMetrics()

	processorQueueSize := max(
		len(d.interfaces)*cfg.BatchSize/cfg.NumProcessors,
		cfg.BatchSize)

	d.initPacketPool(cfg, processorQueueSize)
	procQs, fwQs := initQueues(cfg, d.interfaces, processorQueueSize)

	for ifID, conn := range d.interfaces {
		go func(ifID uint16, conn BatchConn) {
			defer log.HandlePanic()
			d.runReceiver(ifID, conn, cfg, procQs)
		}(ifID, conn)
		go func(ifID uint16, conn BatchConn) {
			defer log.HandlePanic()
			d.runForwarder(ifID, conn, cfg, fwQs[ifID])
		}(ifID, conn)
	}
	for i := 0; i < cfg.NumProcessors; i++ {
		go func(i int) {
			defer log.HandlePanic()
			d.runProcessor(i, procQs[i], fwQs)
		}(i)
	}

	for k, v := range d.bfdSessions {
		go func(ifID uint16, c bfdSession) {
			defer log.HandlePanic()
			if err := c.Run(ctx); err != nil && err != bfd.AlreadyRunning {
				log.Error("BFD session failed to start", "ifID", ifID, "err", err)
			}
		}(k, v)
	}

	d.mtx.Unlock()
	<-ctx.Done()
	return nil
}

// initializePacketPool calculates the size of the packet pool based on the
// current dataplane settings and allocates all the buffers
func (d *DataPlane) initPacketPool(cfg *RunConfig, processorQueueSize int) {
	poolSize := len(d.interfaces)*cfg.BatchSize +
		cfg.NumProcessors*(processorQueueSize+1) +
		len(d.interfaces)*(2*cfg.BatchSize)

	log.Debug("Initialize packet pool of size", "poolSize", poolSize)
	d.packetPool = make(chan []byte, poolSize)
	for i := 0; i < poolSize; i++ {
		d.packetPool <- make([]byte, bufSize)
	}
}

// initializes the processing routines and forwarders queues
func initQueues(cfg *RunConfig, interfaces map[uint16]BatchConn,
	processorQueueSize int) ([]chan packet, map[uint16]chan packet) {

	procQs := make([]chan packet, cfg.NumProcessors)
	for i := 0; i < cfg.NumProcessors; i++ {
		procQs[i] = make(chan packet, processorQueueSize)
	}
	fwQs := make(map[uint16]chan packet)
	for ifID := range interfaces {
		fwQs[ifID] = make(chan packet, cfg.BatchSize)
	}
	return procQs, fwQs
}

type packet struct {
	// The source address. Will be set by the receiver
	srcAddr *net.UDPAddr
	// The address to where we are forwarding the packet.
	// Will be set by the processing routine
	dstAddr *net.UDPAddr
	// The ingress on which this packet arrived. Will be
	// set by the receiver
	ingress   uint16
	rawPacket []byte
}

func (d *DataPlane) runReceiver(ifID uint16, conn BatchConn, cfg *RunConfig,
	procQs []chan packet) {

	log.Debug("Run receiver for", "interface", ifID)
	randomValue := make([]byte, 16)
	if _, err := rand.Read(randomValue); err != nil {
		panic("Error while generating random value")
	}

	msgs := underlayconn.NewReadMessages(cfg.BatchSize)
	numReusable := 0 // unused buffers from previous loop
	metrics := d.forwardingMetrics[ifID]
	flowIDBuffer := make([]byte, 3)
	hasher := fnv.New32a()

	enqueueForProcessing := func(pkt ipv4.Message) {
		metrics.InputPacketsTotal.Inc()
		metrics.InputBytesTotal.Add(float64(pkt.N))

		srcAddr := pkt.Addr.(*net.UDPAddr)

		procID, err := computeProcID(pkt.Buffers[0],
			cfg.NumProcessors, randomValue, flowIDBuffer, hasher)
		if err != nil {
			log.Debug("Error while computing procID", "err", err)
			d.returnPacketToPool(pkt.Buffers[0])
			metrics.DroppedPacketsInvalid.Inc()
			return
		}
		outPkt := packet{
			rawPacket: pkt.Buffers[0][:pkt.N],
			ingress:   ifID,
			srcAddr:   srcAddr,
		}
		select {
		case procQs[procID] <- outPkt:
		default:
			d.returnPacketToPool(pkt.Buffers[0])
			metrics.DroppedPacketsBusyProcessor.Inc()
		}
	}

	for d.running {
		// collect packets
		for i := 0; i < cfg.BatchSize-numReusable; i++ {
			p := <-d.packetPool
			msgs[i].Buffers[0] = p
		}

		// read batch
		numPkts, err := conn.ReadBatch(msgs)
		numReusable = len(msgs) - numPkts
		if err != nil {
			log.Debug("Error while reading batch", "interfaceID", ifID, "err", err)
			continue
		}
		for _, pkt := range msgs[:numPkts] {
			enqueueForProcessing(pkt)
		}

	}
}

func computeProcID(data []byte, numProcRoutines int, randomValue []byte,
	flowIDBuffer []byte, hasher hash.Hash32) (uint32, error) {

	if len(data) < slayers.CmnHdrLen {
		return 0, serrors.New("Packet is too short")
	}
	dstHostAddrLen := slayers.AddrType(data[9] >> 4 & 0xf).Length()
	srcHostAddrLen := slayers.AddrType(data[9] & 0xf).Length()
	addrHdrLen := 2*addr.IABytes + srcHostAddrLen + dstHostAddrLen
	if len(data) < slayers.CmnHdrLen+addrHdrLen {
		return 0, serrors.New("Packet is too short")
	}
	copy(flowIDBuffer[0:3], data[1:4])
	flowIDBuffer[0] &= 0xF // the left 4 bits don't belong to the flowID

	hasher.Reset()
	hasher.Write(randomValue)
	hasher.Write(flowIDBuffer[:])
	hasher.Write(data[slayers.CmnHdrLen : slayers.CmnHdrLen+addrHdrLen])
	return hasher.Sum32() % uint32(numProcRoutines), nil
}

func (d *DataPlane) returnPacketToPool(pkt []byte) {
	d.packetPool <- pkt[:cap(pkt)]
}

func (d *DataPlane) runProcessor(id int, q <-chan packet,
	fwQs map[uint16]chan packet) {

	log.Debug("Initialize processor with", "id", id)
	processor := newPacketProcessor(d)
	var scmpErr scmpError
	for d.running {
		p, ok := <-q
		if !ok {
			continue
		}
		metrics := d.forwardingMetrics[p.ingress]
		result, err := processor.processPkt(p.rawPacket, p.srcAddr, p.ingress)
		metrics.ProcessedPackets.Inc()
		egress := result.EgressID
		switch {
		case err == nil:
		case errors.As(err, &scmpErr):
			if !scmpErr.TypeCode.InfoMsg() {
				log.Debug("SCMP", "err", scmpErr)
			}
		default:
			log.Debug("Error processing packet", "err", err)
			metrics.DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(p.rawPacket)
			continue
		}
		if result.OutPkt == nil { // e.g. BFD case no message is forwarded
			d.returnPacketToPool(p.rawPacket)
			continue
		}
		fwCh, ok := fwQs[egress]
		if !ok {
			log.Debug("Error determining forwarder. Egress is invalid", "egress", egress)
			metrics.DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(p.rawPacket)
			continue
		}
		p.rawPacket = result.OutPkt
		p.dstAddr = result.OutAddr

		select {
		case fwCh <- p:
		default:
			d.returnPacketToPool(p.rawPacket)
			metrics.DroppedPacketsBusyForwarder.Inc()
		}

	}
}

func (d *DataPlane) runForwarder(ifID uint16, conn BatchConn,
	cfg *RunConfig, c <-chan packet) {

	log.Debug("Initialize forwarder for", "interface", ifID)
	writeMsgs := make(underlayconn.Messages, cfg.BatchSize)
	for i := range writeMsgs {
		writeMsgs[i].Buffers = make([][]byte, 1)
	}
	metrics := d.forwardingMetrics[ifID]

	remaining := 0
	for d.running {
		available := readUpTo(c, cfg.BatchSize-remaining, remaining == 0,
			writeMsgs[remaining:])
		available += remaining
		written, _ := conn.WriteBatch(writeMsgs[:available], 0)
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as
			// 0 packets written
			written = 0
		}
		writtenBytes := 0
		for i := range writeMsgs[:written] {
			writtenBytes += len(writeMsgs[i].Buffers[0])
			d.returnPacketToPool(writeMsgs[i].Buffers[0])
		}
		metrics.OutputPacketsTotal.Add(float64(written))
		metrics.OutputBytesTotal.Add(float64(writtenBytes))

		if written != available {
			metrics.DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(writeMsgs[written].Buffers[0])
			remaining = available - written - 1
			for i := 0; i < remaining; i++ {
				writeMsgs[i].Buffers[0] = writeMsgs[i+written+1].Buffers[0]
				writeMsgs[i].Addr = writeMsgs[i+written+1].Addr
			}
		} else {
			remaining = 0
		}
	}
}

func readUpTo(c <-chan packet, n int, needsBlocking bool, msg []ipv4.Message) int {
	assign := func(p packet, m *ipv4.Message) {
		m.Buffers[0] = p.rawPacket
		m.Addr = nil
		if p.dstAddr != nil {
			m.Addr = p.dstAddr
		}
	}
	i := 0
	if needsBlocking {
		p, ok := <-c
		if !ok {
			return i
		}
		assign(p, &msg[i])
		i++
	}

	for ; i < n; i++ {
		select {
		case p, ok := <-c:
			if !ok {
				return i
			}
			assign(p, &msg[i])
		default:
			return i
		}

	}
	return i
}

// initMetrics initializes the metrics related to packet forwarding. The
// counters are already instantiated for all the relevant interfaces so this
// will not have to be repeated during packet forwarding.
func (d *DataPlane) initMetrics() {
	d.forwardingMetrics = make(map[uint16]forwardingMetrics)
	labels := interfaceToMetricLabels(0, d.localIA, d.neighborIAs)
	d.forwardingMetrics[0] = initForwardingMetrics(d.Metrics, labels)
	for id := range d.external {
		if _, notOwned := d.internalNextHops[id]; notOwned {
			continue
		}
		labels = interfaceToMetricLabels(id, d.localIA, d.neighborIAs)
		d.forwardingMetrics[id] = initForwardingMetrics(d.Metrics, labels)
	}
}

type processResult struct {
	EgressID uint16
	OutAddr  *net.UDPAddr
	OutPkt   []byte
}

func newPacketProcessor(d *DataPlane) *scionPacketProcessor {
	p := &scionPacketProcessor{
		d:      d,
		buffer: gopacket.NewSerializeBuffer(),
		mac:    d.macFactory(),
		macBuffers: macBuffers{
			scionInput: make([]byte, path.MACBufferSize),
			epicInput:  make([]byte, libepic.MACBufferSize),
			drkeyInput: make([]byte, spao.MACBufferSize),
		},
		// TODO(JordiSubira): Replace this with a useful implementation.
		drkeyProvider: &fakeProvider{},
		optAuth:       slayers.PacketAuthOption{EndToEndOption: new(slayers.EndToEndOption)},
		validAuthBuf:  make([]byte, 16),
	}
	p.scionLayer.RecyclePaths()
	return p
}

func (p *scionPacketProcessor) reset() error {
	p.rawPkt = nil
	p.srcAddr = nil
	p.ingressID = 0
	//p.scionLayer // cannot easily be reset
	p.path = nil
	p.hopField = path.HopField{}
	p.infoField = path.InfoField{}
	p.segmentChange = false
	if err := p.buffer.Clear(); err != nil {
		return serrors.WrapStr("Failed to clear buffer", err)
	}
	p.mac.Reset()
	p.cachedMac = nil
	// Reset hbh layer
	p.hbhLayer = slayers.HopByHopExtnSkipper{}
	// Reset e2e layer
	p.e2eLayer = slayers.EndToEndExtnSkipper{}
	return nil
}

func (p *scionPacketProcessor) processPkt(rawPkt []byte,
	srcAddr *net.UDPAddr, ingressID uint16) (processResult, error) {

	if err := p.reset(); err != nil {
		return processResult{}, err
	}
	p.rawPkt = rawPkt
	p.srcAddr = srcAddr
	p.ingressID = ingressID

	// parse SCION header and skip extensions;
	var err error
	p.lastLayer, err = decodeLayers(p.rawPkt, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return processResult{}, err
	}
	pld := p.lastLayer.LayerPayload()

	pathType := p.scionLayer.PathType
	switch pathType {
	case empty.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			return processResult{}, p.processIntraBFD(pld)
		}
		return processResult{}, serrors.WithCtx(unsupportedPathTypeNextHeader,
			"type", pathType, "header", nextHdr(p.lastLayer))
	case onehop.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			ohp, ok := p.scionLayer.Path.(*onehop.Path)
			if !ok {
				return processResult{}, malformedPath
			}
			return processResult{}, p.processInterBFD(ohp, pld)
		}
		return p.processOHP()
	case scion.PathType:
		return p.processSCION()
	case epic.PathType:
		return p.processEPIC()
	default:
		return processResult{}, serrors.WithCtx(unsupportedPathType, "type", pathType)
	}
}

func (p *scionPacketProcessor) processInterBFD(oh *onehop.Path, data []byte) error {
	if len(p.d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}

	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}

	if v, ok := p.d.bfdSessions[p.ingressID]; ok {
		v.ReceiveMessage(bfd)
		return nil
	}

	return noBFDSessionFound
}

func (p *scionPacketProcessor) processIntraBFD(data []byte) error {
	if len(p.d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}

	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}

	ifID := uint16(0)
	for k, v := range p.d.internalNextHops {
		if bytes.Equal(v.IP, p.srcAddr.IP) && v.Port == p.srcAddr.Port {
			ifID = k
			break
		}
	}

	if v, ok := p.d.bfdSessions[ifID]; ok {
		v.ReceiveMessage(bfd)
		return nil
	}

	return noBFDSessionFound
}

func (p *scionPacketProcessor) processSCION() (processResult, error) {

	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, malformedPath
	}
	return p.process()
}

func (p *scionPacketProcessor) processEPIC() (processResult, error) {

	epicPath, ok := p.scionLayer.Path.(*epic.Path)
	if !ok {
		return processResult{}, malformedPath
	}

	p.path = epicPath.ScionPath
	if p.path == nil {
		return processResult{}, malformedPath
	}

	isPenultimate := p.path.IsPenultimateHop()
	isLast := p.path.IsLastHop()

	result, err := p.process()
	if err != nil {
		return result, err
	}

	if isPenultimate || isLast {
		firstInfo, err := p.path.GetInfoField(0)
		if err != nil {
			return processResult{}, err
		}

		timestamp := time.Unix(int64(firstInfo.Timestamp), 0)
		err = libepic.VerifyTimestamp(timestamp, epicPath.PktID.Timestamp, time.Now())
		if err != nil {
			// TODO(mawyss): Send back SCMP packet
			return processResult{}, err
		}

		HVF := epicPath.PHVF
		if isLast {
			HVF = epicPath.LHVF
		}
		err = libepic.VerifyHVF(p.cachedMac, epicPath.PktID,
			&p.scionLayer, firstInfo.Timestamp, HVF, p.macBuffers.epicInput)
		if err != nil {
			// TODO(mawyss): Send back SCMP packet
			return processResult{}, err
		}
	}

	return result, nil
}

// scionPacketProcessor processes packets. It contains pre-allocated per-packet
// mutable state and context information which should be reused.
type scionPacketProcessor struct {
	// d is a reference to the dataplane instance that initiated this processor.
	d *DataPlane
	// ingressID is the interface ID this packet came in, determined from the
	// socket.
	ingressID uint16
	// rawPkt is the raw packet, it is updated during processing to contain the
	// message to send out.
	rawPkt []byte
	// srcAddr is the source address of the packet
	srcAddr *net.UDPAddr
	// buffer is the buffer that can be used to serialize gopacket layers.
	buffer gopacket.SerializeBuffer
	// mac is the hasher for the MAC computation.
	mac hash.Hash

	// scionLayer is the SCION gopacket layer.
	scionLayer slayers.SCION
	hbhLayer   slayers.HopByHopExtnSkipper
	e2eLayer   slayers.EndToEndExtnSkipper
	// last is the last parsed layer, i.e. either &scionLayer, &hbhLayer or &e2eLayer
	lastLayer gopacket.DecodingLayer

	// path is the raw SCION path. Will be set during processing.
	path *scion.Raw
	// hopField is the current hopField field, is updated during processing.
	hopField path.HopField
	// infoField is the current infoField field, is updated during processing.
	infoField path.InfoField
	// segmentChange indicates if the path segment was changed during processing.
	segmentChange bool

	// cachedMac contains the full 16 bytes of the MAC. Will be set during processing.
	// For a hop performing an Xover, it is the MAC corresponding to the down segment.
	cachedMac []byte
	// macBuffers avoid allocating memory during processing.
	macBuffers macBuffers

	// bfdLayer is reusable buffer for parsing BFD messages
	bfdLayer layers.BFD
	// optAuth is a reusable Packet Authenticator Option
	optAuth slayers.PacketAuthOption
	// validAuthBuf is a reusable buffer for the authentication tag
	// to be used in the hasValidAuth() method.
	validAuthBuf []byte

	// DRKey key derivation for SCMP authentication
	drkeyProvider drkeyProvider
}

// macBuffers are preallocated buffers for the in- and outputs of MAC functions.
type macBuffers struct {
	scionInput []byte
	epicInput  []byte
	drkeyInput []byte
}

func (p *scionPacketProcessor) packSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	cause error,
) (processResult, error) {

	// check invoking packet was an SCMP error:
	if p.lastLayer.NextLayerType() == slayers.LayerTypeSCMP {
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(p.lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			return processResult{}, serrors.WrapStr("decoding SCMP layer", err)
		}
		if !scmpLayer.TypeCode.InfoMsg() {
			return processResult{}, serrors.WrapStr("SCMP error for SCMP error pkt -> DROP", cause)
		}
	}

	rawSCMP, err := p.prepareSCMP(typ, code, scmpP, cause)
	if rawSCMP != nil {
		p.rawPkt = p.rawPkt[:len(rawSCMP)]
		copy(p.rawPkt, rawSCMP)
	}

	return processResult{OutPkt: p.rawPkt, EgressID: p.ingressID, OutAddr: p.srcAddr}, err
}

func (p *scionPacketProcessor) parsePath() (processResult, error) {
	var err error
	p.hopField, err = p.path.GetCurrentHopField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, err
	}
	p.infoField, err = p.path.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, err
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) validateHopExpiry() (processResult, error) {
	expiration := util.SecsToTime(p.infoField.Timestamp).
		Add(path.ExpTimeToDuration(p.hopField.ExpTime))
	expired := expiration.Before(time.Now())
	if !expired {
		return processResult{}, nil
	}
	return p.packSCMP(
		slayers.SCMPTypeParameterProblem,
		slayers.SCMPCodePathExpired,
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		serrors.New("expired hop", "cons_dir", p.infoField.ConsDir, "if_id", p.ingressID,
			"curr_inf", p.path.PathMeta.CurrINF, "curr_hf", p.path.PathMeta.CurrHF),
	)
}

func (p *scionPacketProcessor) validateIngressID() (processResult, error) {
	pktIngressID := p.hopField.ConsIngress
	errCode := slayers.SCMPCodeUnknownHopFieldIngress
	if !p.infoField.ConsDir {
		pktIngressID = p.hopField.ConsEgress
		errCode = slayers.SCMPCodeUnknownHopFieldEgress
	}
	if p.ingressID != 0 && p.ingressID != pktIngressID {
		return p.packSCMP(
			slayers.SCMPTypeParameterProblem,
			errCode,
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.New("ingress interface invalid",
				"pkt_ingress", pktIngressID, "router_ingress", p.ingressID),
		)
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) validateSrcDstIA() (processResult, error) {
	srcIsLocal := (p.scionLayer.SrcIA == p.d.localIA)
	dstIsLocal := (p.scionLayer.DstIA == p.d.localIA)
	if p.ingressID == 0 {
		// Outbound
		// Only check SrcIA if first hop, for transit this already checked by ingress router.
		// Note: SCMP error messages triggered by the sibling router may use paths that
		// don't start with the first hop.
		if p.path.IsFirstHop() && !srcIsLocal {
			return p.invalidSrcIA()
		}
		if dstIsLocal {
			return p.invalidDstIA()
		}
	} else {
		// Inbound
		if srcIsLocal {
			return p.invalidSrcIA()
		}
		if p.path.IsLastHop() != dstIsLocal {
			return p.invalidDstIA()
		}
	}
	return processResult{}, nil
}

// invalidSrcIA is a helper to return an SCMP error for an invalid SrcIA.
func (p *scionPacketProcessor) invalidSrcIA() (processResult, error) {
	return p.packSCMP(
		slayers.SCMPTypeParameterProblem,
		slayers.SCMPCodeInvalidSourceAddress,
		&slayers.SCMPParameterProblem{Pointer: uint16(slayers.CmnHdrLen + addr.IABytes)},
		invalidSrcIA,
	)
}

// invalidDstIA is a helper to return an SCMP error for an invalid DstIA.
func (p *scionPacketProcessor) invalidDstIA() (processResult, error) {
	return p.packSCMP(
		slayers.SCMPTypeParameterProblem,
		slayers.SCMPCodeInvalidDestinationAddress,
		&slayers.SCMPParameterProblem{Pointer: uint16(slayers.CmnHdrLen)},
		invalidDstIA,
	)
}

// validateTransitUnderlaySrc checks that the source address of transit packets
// matches the expected sibling router.
// Provided that underlying network infrastructure prevents address spoofing,
// this check prevents malicious end hosts in the local AS from bypassing the
// SrcIA checks by disguising packets as transit traffic.
func (p *scionPacketProcessor) validateTransitUnderlaySrc() (processResult, error) {
	if p.path.IsFirstHop() || p.ingressID != 0 {
		// not a transit packet, nothing to check
		return processResult{}, nil
	}
	pktIngressID := p.ingressInterface()
	expectedSrc, ok := p.d.internalNextHops[pktIngressID]
	if !ok || !expectedSrc.IP.Equal(p.srcAddr.IP) {
		// Drop
		return processResult{}, invalidSrcAddrForTransit
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) validateEgressID() (processResult, error) {
	pktEgressID := p.egressInterface()
	_, ih := p.d.internalNextHops[pktEgressID]
	_, eh := p.d.external[pktEgressID]
	if !ih && !eh {
		errCode := slayers.SCMPCodeUnknownHopFieldEgress
		if !p.infoField.ConsDir {
			errCode = slayers.SCMPCodeUnknownHopFieldIngress
		}
		return p.packSCMP(
			slayers.SCMPTypeParameterProblem,
			errCode,
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			cannotRoute,
		)
	}

	ingress, egress := p.d.linkTypes[p.ingressID], p.d.linkTypes[pktEgressID]
	if !p.segmentChange {
		// Check that the interface pair is valid within a single segment.
		// No check required if the packet is received from an internal interface.
		switch {
		case p.ingressID == 0:
			return processResult{}, nil
		case ingress == topology.Core && egress == topology.Core:
			return processResult{}, nil
		case ingress == topology.Child && egress == topology.Parent:
			return processResult{}, nil
		case ingress == topology.Parent && egress == topology.Child:
			return processResult{}, nil
		default: // malicious
			return p.packSCMP(
				slayers.SCMPTypeParameterProblem,
				slayers.SCMPCodeInvalidPath, // XXX(matzf) new code InvalidHop?
				&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
				serrors.WithCtx(cannotRoute, "ingress_id", p.ingressID, "ingress_type", ingress,
					"egress_id", pktEgressID, "egress_type", egress))
		}
	}
	// Check that the interface pair is valid on a segment switch.
	// Having a segment change received from the internal interface is never valid.
	switch {
	case ingress == topology.Core && egress == topology.Child:
		return processResult{}, nil
	case ingress == topology.Child && egress == topology.Core:
		return processResult{}, nil
	case ingress == topology.Child && egress == topology.Child:
		return processResult{}, nil
	default:
		return p.packSCMP(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidSegmentChange,
			&slayers.SCMPParameterProblem{Pointer: p.currentInfoPointer()},
			serrors.WithCtx(cannotRoute, "ingress_id", p.ingressID, "ingress_type", ingress,
				"egress_id", pktEgressID, "egress_type", egress))
	}
}

func (p *scionPacketProcessor) updateNonConsDirIngressSegID() error {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
	if !p.infoField.ConsDir && p.ingressID != 0 {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			return serrors.WrapStr("update info field", err)
		}
	}
	return nil
}

func (p *scionPacketProcessor) currentInfoPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*int(p.path.PathMeta.CurrINF))
}

func (p *scionPacketProcessor) currentHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*p.path.NumINF + path.HopLen*int(p.path.PathMeta.CurrHF))
}

func (p *scionPacketProcessor) verifyCurrentMAC() (processResult, error) {
	fullMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macBuffers.scionInput)
	if subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], fullMac[:path.MacLen]) == 0 {
		return p.packSCMP(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidHopFieldMAC,
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.New("MAC verification failed", "expected", fmt.Sprintf(
				"%x", fullMac[:path.MacLen]),
				"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]),
				"cons_dir", p.infoField.ConsDir,
				"if_id", p.ingressID, "curr_inf", p.path.PathMeta.CurrINF,
				"curr_hf", p.path.PathMeta.CurrHF, "seg_id", p.infoField.SegID),
		)
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC does not need to recalculate it.
	p.cachedMac = fullMac

	return processResult{}, nil
}

func (p *scionPacketProcessor) resolveInbound() (*net.UDPAddr, processResult, error) {
	a, err := p.d.resolveLocalDst(p.scionLayer)
	switch {
	case errors.Is(err, noSVCBackend):
		r, err := p.packSCMP(
			slayers.SCMPTypeDestinationUnreachable,
			slayers.SCMPCodeNoRoute,
			&slayers.SCMPDestinationUnreachable{}, err)
		return nil, r, err
	default:
		return a, processResult{}, nil
	}
}

func (p *scionPacketProcessor) processEgress() error {
	// we are the egress router and if we go in construction direction we
	// need to update the SegID.
	if p.infoField.ConsDir {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			// TODO parameter problem invalid path
			return serrors.WrapStr("update info field", err)
		}
	}
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return serrors.WrapStr("incrementing path", err)
	}
	return nil
}

func (p *scionPacketProcessor) doXover() (processResult, error) {
	p.segmentChange = true
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, serrors.WrapStr("incrementing path", err)
	}
	var err error
	if p.hopField, err = p.path.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, err
	}
	if p.infoField, err = p.path.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, err
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) ingressInterface() uint16 {
	info := p.infoField
	hop := p.hopField
	if p.path.IsFirstHopAfterXover() {
		var err error
		info, err = p.path.GetInfoField(int(p.path.PathMeta.CurrINF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
		hop, err = p.path.GetHopField(int(p.path.PathMeta.CurrHF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
	}
	if info.ConsDir {
		return hop.ConsIngress
	}
	return hop.ConsEgress
}

func (p *scionPacketProcessor) egressInterface() uint16 {
	if p.infoField.ConsDir {
		return p.hopField.ConsEgress
	}
	return p.hopField.ConsIngress
}

func (p *scionPacketProcessor) validateEgressUp() (processResult, error) {
	egressID := p.egressInterface()
	if v, ok := p.d.bfdSessions[egressID]; ok {
		if !v.IsUp() {
			typ := slayers.SCMPTypeExternalInterfaceDown
			var scmpP gopacket.SerializableLayer = &slayers.SCMPExternalInterfaceDown{
				IA:   p.d.localIA,
				IfID: uint64(egressID),
			}
			if _, external := p.d.external[egressID]; !external {
				typ = slayers.SCMPTypeInternalConnectivityDown
				scmpP = &slayers.SCMPInternalConnectivityDown{
					IA:      p.d.localIA,
					Ingress: uint64(p.ingressID),
					Egress:  uint64(egressID),
				}
			}
			return p.packSCMP(typ, 0, scmpP, serrors.New("bfd session down"))
		}
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) handleIngressRouterAlert() (processResult, error) {
	if p.ingressID == 0 {
		return processResult{}, nil
	}
	alert := p.ingressRouterAlertFlag()
	if !*alert {
		return processResult{}, nil
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	return p.handleSCMPTraceRouteRequest(p.ingressID)
}

func (p *scionPacketProcessor) ingressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.EgressRouterAlert
	}
	return &p.hopField.IngressRouterAlert
}

func (p *scionPacketProcessor) handleEgressRouterAlert() (processResult, error) {
	alert := p.egressRouterAlertFlag()
	if !*alert {
		return processResult{}, nil
	}
	egressID := p.egressInterface()
	if _, ok := p.d.external[egressID]; !ok {
		return processResult{}, nil
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	return p.handleSCMPTraceRouteRequest(egressID)
}

func (p *scionPacketProcessor) egressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.IngressRouterAlert
	}
	return &p.hopField.EgressRouterAlert
}

func (p *scionPacketProcessor) handleSCMPTraceRouteRequest(
	interfaceID uint16) (processResult, error) {

	if p.lastLayer.NextLayerType() != slayers.LayerTypeSCMP {
		log.Debug("Packet with router alert, but not SCMP")
		return processResult{}, nil
	}
	scionPld := p.lastLayer.LayerPayload()
	var scmpH slayers.SCMP
	if err := scmpH.DecodeFromBytes(scionPld, gopacket.NilDecodeFeedback); err != nil {
		log.Debug("Parsing SCMP header of router alert", "err", err)
		return processResult{}, nil
	}
	if scmpH.TypeCode != slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0) {
		log.Debug("Packet with router alert, but not traceroute request",
			"type_code", scmpH.TypeCode)
		return processResult{}, nil
	}
	var scmpP slayers.SCMPTraceroute
	if err := scmpP.DecodeFromBytes(scmpH.Payload, gopacket.NilDecodeFeedback); err != nil {
		log.Debug("Parsing SCMPTraceroute", "err", err)
		return processResult{}, nil
	}
	scmpP = slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         p.d.localIA,
		Interface:  uint64(interfaceID),
	}
	return p.packSCMP(slayers.SCMPTypeTracerouteReply, 0, &scmpP, nil)
}

func (p *scionPacketProcessor) validatePktLen() (processResult, error) {
	if int(p.scionLayer.PayloadLen) == len(p.scionLayer.Payload) {
		return processResult{}, nil
	}
	return p.packSCMP(
		slayers.SCMPTypeParameterProblem,
		slayers.SCMPCodeInvalidPacketSize,
		&slayers.SCMPParameterProblem{Pointer: 0},
		serrors.New("bad packet size",
			"header", p.scionLayer.PayloadLen, "actual", len(p.scionLayer.Payload)),
	)
}

func (p *scionPacketProcessor) process() (processResult, error) {

	if r, err := p.parsePath(); err != nil {
		return r, err
	}
	if r, err := p.validateHopExpiry(); err != nil {
		return r, err
	}
	if r, err := p.validateIngressID(); err != nil {
		return r, err
	}
	if r, err := p.validatePktLen(); err != nil {
		return r, err
	}
	if r, err := p.validateTransitUnderlaySrc(); err != nil {
		return r, err
	}
	if r, err := p.validateSrcDstIA(); err != nil {
		return r, err
	}
	if err := p.updateNonConsDirIngressSegID(); err != nil {
		return processResult{}, err
	}
	if r, err := p.verifyCurrentMAC(); err != nil {
		return r, err
	}
	if r, err := p.handleIngressRouterAlert(); err != nil {
		return r, err
	}
	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA == p.d.localIA {
		a, r, err := p.resolveInbound()
		if err != nil {
			return r, err
		}
		return processResult{OutAddr: a, OutPkt: p.rawPkt}, nil
	}

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.
	if p.path.IsXover() {
		if r, err := p.doXover(); err != nil {
			return r, err
		}
		if r, err := p.validateHopExpiry(); err != nil {
			return r, serrors.WithCtx(err, "info", "after xover")
		}
		// verify the new block
		if r, err := p.verifyCurrentMAC(); err != nil {
			return r, serrors.WithCtx(err, "info", "after xover")
		}
	}
	if r, err := p.validateEgressID(); err != nil {
		return r, err
	}
	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if r, err := p.handleEgressRouterAlert(); err != nil {
		return r, err
	}
	if r, err := p.validateEgressUp(); err != nil {
		return r, err
	}
	egressID := p.egressInterface()
	if _, ok := p.d.external[egressID]; ok {
		if err := p.processEgress(); err != nil {
			return processResult{}, err
		}
		return processResult{EgressID: egressID, OutPkt: p.rawPkt}, nil
	}
	// ASTransit: pkts leaving from another AS BR.
	if a, ok := p.d.internalNextHops[egressID]; ok {
		return processResult{OutAddr: a, OutPkt: p.rawPkt}, nil
	}
	errCode := slayers.SCMPCodeUnknownHopFieldEgress
	if !p.infoField.ConsDir {
		errCode = slayers.SCMPCodeUnknownHopFieldIngress
	}
	return p.packSCMP(
		slayers.SCMPTypeParameterProblem,
		errCode,
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		cannotRoute,
	)
}

func (p *scionPacketProcessor) processOHP() (processResult, error) {
	s := p.scionLayer
	ohp, ok := s.Path.(*onehop.Path)
	if !ok {
		// TODO parameter problem -> invalid path
		return processResult{}, malformedPath
	}
	if !ohp.Info.ConsDir {
		// TODO parameter problem -> invalid path
		return processResult{}, serrors.WrapStr(
			"OneHop path in reverse construction direction is not allowed",
			malformedPath, "srcIA", s.SrcIA, "dstIA", s.DstIA)
	}

	// OHP leaving our IA
	if p.ingressID == 0 {
		if !p.d.localIA.Equal(s.SrcIA) {
			// TODO parameter problem -> invalid path
			return processResult{}, serrors.WrapStr("bad source IA", cannotRoute,
				"type", "ohp", "egress", ohp.FirstHop.ConsEgress,
				"localIA", p.d.localIA, "srcIA", s.SrcIA)
		}
		neighborIA, ok := p.d.neighborIAs[ohp.FirstHop.ConsEgress]
		if !ok {
			// TODO parameter problem invalid interface
			return processResult{}, serrors.WithCtx(cannotRoute,
				"type", "ohp", "egress", ohp.FirstHop.ConsEgress)
		}
		if !neighborIA.Equal(s.DstIA) {
			return processResult{}, serrors.WrapStr("bad destination IA", cannotRoute,
				"type", "ohp", "egress", ohp.FirstHop.ConsEgress,
				"neighborIA", neighborIA, "dstIA", s.DstIA)
		}
		mac := path.MAC(p.mac, ohp.Info, ohp.FirstHop, p.macBuffers.scionInput)
		if subtle.ConstantTimeCompare(ohp.FirstHop.Mac[:], mac[:]) == 0 {
			// TODO parameter problem -> invalid MAC
			return processResult{}, serrors.New("MAC", "expected", fmt.Sprintf("%x", mac),
				"actual", fmt.Sprintf("%x", ohp.FirstHop.Mac), "type", "ohp")
		}
		ohp.Info.UpdateSegID(ohp.FirstHop.Mac)

		if err := updateSCIONLayer(p.rawPkt, s, p.buffer); err != nil {
			return processResult{}, err
		}
		return processResult{EgressID: ohp.FirstHop.ConsEgress, OutPkt: p.rawPkt},
			nil
	}

	// OHP entering our IA
	if !p.d.localIA.Equal(s.DstIA) {
		return processResult{}, serrors.WrapStr("bad destination IA", cannotRoute,
			"type", "ohp", "ingress", p.ingressID,
			"localIA", p.d.localIA, "dstIA", s.DstIA)
	}
	neighborIA := p.d.neighborIAs[p.ingressID]
	if !neighborIA.Equal(s.SrcIA) {
		return processResult{}, serrors.WrapStr("bad source IA", cannotRoute,
			"type", "ohp", "ingress", p.ingressID,
			"neighborIA", neighborIA, "srcIA", s.SrcIA)
	}

	ohp.SecondHop = path.HopField{
		ConsIngress: p.ingressID,
		ExpTime:     ohp.FirstHop.ExpTime,
	}
	// XXX(roosd): Here we leak the buffer into the SCION packet header.
	// This is okay because we do not operate on the buffer or the packet
	// for the rest of processing.
	ohp.SecondHop.Mac = path.MAC(p.mac, ohp.Info, ohp.SecondHop, p.macBuffers.scionInput)

	if err := updateSCIONLayer(p.rawPkt, s, p.buffer); err != nil {
		return processResult{}, err
	}
	a, err := p.d.resolveLocalDst(s)
	if err != nil {
		return processResult{}, err
	}
	return processResult{OutAddr: a, OutPkt: p.rawPkt}, nil
}

func (d *DataPlane) resolveLocalDst(s slayers.SCION) (*net.UDPAddr, error) {
	dst, err := s.DstAddr()
	if err != nil {
		// TODO parameter problem.
		return nil, err
	}
	switch dst.Type() {
	case addr.HostTypeSVC:
		// For map lookup use the Base address, i.e. strip the multi cast
		// information, because we only register base addresses in the map.
		a, ok := d.svc.Any(dst.SVC().Base())
		if !ok {
			return nil, noSVCBackend
		}
		return a, nil
	case addr.HostTypeIP:
		return addEndhostPort(dst.IP().AsSlice()), nil
	default:
		panic("unexpected address type returned from DstAddr")
	}
}

func addEndhostPort(dst net.IP) *net.UDPAddr {
	return &net.UDPAddr{IP: dst, Port: topology.EndhostPort}
}

// TODO(matzf) this function is now only used to update the OneHop-path.
// This should be changed so that the OneHop-path can be updated in-place, like
// the scion.Raw path.
func updateSCIONLayer(rawPkt []byte, s slayers.SCION, buffer gopacket.SerializeBuffer) error {
	if err := buffer.Clear(); err != nil {
		return err
	}
	if err := s.SerializeTo(buffer, gopacket.SerializeOptions{}); err != nil {
		return err
	}
	// TODO(lukedirtwalker): We should add a method to the scion layers
	// which can write into the existing buffer, see also the discussion in
	// https://fsnets.slack.com/archives/C8ADBBG0J/p1592805884250700
	rawContents := buffer.Bytes()
	copy(rawPkt[:len(rawContents)], rawContents)
	return nil
}

type bfdSend struct {
	conn             BatchConn
	srcAddr, dstAddr *net.UDPAddr
	scn              *slayers.SCION
	ohp              *onehop.Path
	mac              hash.Hash
	macBuffer        []byte
	buffer           gopacket.SerializeBuffer
}

// newBFDSend creates and initializes a BFD Sender
func newBFDSend(conn BatchConn, srcIA, dstIA addr.IA, srcAddr, dstAddr *net.UDPAddr,
	ifID uint16, mac hash.Hash) (*bfdSend, error) {

	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4BFD,
		SrcIA:        srcIA,
		DstIA:        dstIA,
	}

	srcAddrIP, ok := netip.AddrFromSlice(srcAddr.IP)
	if !ok {
		return nil, serrors.New("invalid source IP", "ip", srcAddr.IP)
	}
	dstAddrIP, ok := netip.AddrFromSlice(dstAddr.IP)
	if !ok {
		return nil, serrors.New("invalid destination IP", "ip", dstAddr.IP)
	}
	if err := scn.SetSrcAddr(addr.HostIP(srcAddrIP)); err != nil {
		panic(err) // Must work
	}
	if err := scn.SetDstAddr(addr.HostIP(dstAddrIP)); err != nil {
		panic(err) // Must work
	}

	var ohp *onehop.Path
	if ifID == 0 {
		scn.PathType = empty.PathType
		scn.Path = &empty.Path{}
	} else {
		ohp = &onehop.Path{
			Info: path.InfoField{
				ConsDir: true,
				// Timestamp set in Send
			},
			FirstHop: path.HopField{
				ConsEgress: ifID,
				ExpTime:    hopFieldDefaultExpTime,
			},
		}
		scn.PathType = onehop.PathType
		scn.Path = ohp
	}

	return &bfdSend{
		conn:      conn,
		srcAddr:   srcAddr,
		dstAddr:   dstAddr,
		scn:       scn,
		ohp:       ohp,
		mac:       mac,
		macBuffer: make([]byte, path.MACBufferSize),
		buffer:    gopacket.NewSerializeBuffer(),
	}, nil
}

func (b *bfdSend) String() string {
	return b.srcAddr.String()
}

// Send sends out a BFD message.
// Due to the internal state of the MAC computation, this is not goroutine
// safe.
func (b *bfdSend) Send(bfd *layers.BFD) error {
	if b.ohp != nil {
		// Subtract 10 seconds to deal with possible clock drift.
		ohp := b.ohp
		ohp.Info.Timestamp = uint32(time.Now().Unix() - 10)
		ohp.FirstHop.Mac = path.MAC(b.mac, ohp.Info, ohp.FirstHop, b.macBuffer)
	}

	err := gopacket.SerializeLayers(b.buffer, gopacket.SerializeOptions{FixLengths: true},
		b.scn, bfd)
	if err != nil {
		return err
	}
	_, err = b.conn.WriteTo(b.buffer.Bytes(), b.dstAddr)
	return err
}

func (p *scionPacketProcessor) prepareSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	cause error,
) ([]byte, error) {

	// *copy* and reverse path -- the original path should not be modified as this writes directly
	// back to rawPkt (quote).
	var path *scion.Raw
	pathType := p.scionLayer.Path.Type()
	switch pathType {
	case scion.PathType:
		var ok bool
		path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
				"path type", pathType)
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
				"path type", pathType)
		}
		path = epicPath.ScionPath
	default:
		return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
			"path type", pathType)
	}
	decPath, err := path.ToDecoded()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "decoding raw path")
	}
	revPathTmp, err := decPath.Reverse()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "reversing path for SCMP")
	}
	revPath := revPathTmp.(*scion.Decoded)

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() {
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "reverting cross over for SCMP")
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	_, external := p.d.external[p.ingressID]
	if external {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.Mac)
		}
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "incrementing path for SCMP")
		}
	}

	// create new SCION header for reply.
	var scionL slayers.SCION
	scionL.FlowID = p.scionLayer.FlowID
	scionL.TrafficClass = p.scionLayer.TrafficClass
	scionL.PathType = revPath.Type()
	scionL.Path = revPath
	scionL.DstIA = p.scionLayer.SrcIA
	scionL.SrcIA = p.d.localIA
	srcA, err := p.scionLayer.SrcAddr()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "extracting src addr")
	}
	if err := scionL.SetDstAddr(srcA); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting dest addr")
	}
	if err := scionL.SetSrcAddr(addr.HostIP(p.d.internalIP)); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting src addr")
	}
	scionL.NextHdr = slayers.L4SCMP

	typeCode := slayers.CreateSCMPTypeCode(typ, code)
	scmpH := slayers.SCMP{TypeCode: typeCode}
	scmpH.SetNetworkLayerForChecksum(&scionL)

	// Error messages must be authenticated.
	// Traceroute are OPTIONALLY authenticated ONLY IF the request
	// was authenticated.
	// TODO(JordiSubira): Reuse the key computed in p.hasValidAuth
	// if SCMPTypeTracerouteReply to create the response.
	needsAuth := cause != nil ||
		(scmpH.TypeCode.Type() == slayers.SCMPTypeTracerouteReply &&
			p.hasValidAuth())

	var quote []byte
	if cause != nil {
		// add quote for errors.
		hdrLen := slayers.CmnHdrLen + scionL.AddrHdrLen() + scionL.Path.Len()
		if needsAuth {
			hdrLen += e2eAuthHdrLen
		}
		switch scmpH.TypeCode.Type() {
		case slayers.SCMPTypeExternalInterfaceDown:
			hdrLen += 20
		case slayers.SCMPTypeInternalConnectivityDown:
			hdrLen += 28
		default:
			hdrLen += 8
		}
		quote = p.rawPkt
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if len(quote) > maxQuoteLen {
			quote = quote[:maxQuoteLen]
		}
	}

	if err := p.buffer.Clear(); err != nil {
		return nil, err
	}
	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	// First write the SCMP message only without the SCION header(s) to get a buffer that we
	// can (re-)use as input in the MAC computation.
	// XXX(matzf) could we use iovec gather to avoid copying quote?
	err = gopacket.SerializeLayers(p.buffer, sopts, &scmpH, scmpP, gopacket.Payload(quote))
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCMP message")
	}

	if needsAuth {
		var e2e slayers.EndToEndExtn
		scionL.NextHdr = slayers.End2EndClass

		now := time.Now()
		// srcA == scionL.DstAddr
		key, err := p.drkeyProvider.GetAuthKey(now, scionL.DstIA, srcA)
		if err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "retrieving DRKey")
		}
		if err := p.resetSPAOMetadata(now); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "resetting SPAO header")
		}

		e2e.Options = []*slayers.EndToEndOption{p.optAuth.EndToEndOption}
		e2e.NextHdr = slayers.L4SCMP
		_, err = spao.ComputeAuthCMAC(
			spao.MACInput{
				Key:        key[:],
				Header:     p.optAuth,
				ScionLayer: &scionL,
				PldType:    slayers.L4SCMP,
				Pld:        p.buffer.Bytes(),
			},
			p.macBuffers.drkeyInput,
			p.optAuth.Authenticator(),
		)
		if err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "computing CMAC")
		}
		if err := e2e.SerializeTo(p.buffer, sopts); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCION E2E headers")
		}
	} else {
		scionL.NextHdr = slayers.L4SCMP
	}
	if err := scionL.SerializeTo(p.buffer, sopts); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCION header")
	}

	return p.buffer.Bytes(), scmpError{TypeCode: scmpH.TypeCode, Cause: cause}
}

func (p *scionPacketProcessor) resetSPAOMetadata(now time.Time) error {
	// For creating SCMP responses we use sender side.
	dir := slayers.PacketAuthSenderSide
	// TODO(JordiSubira): We assume the later epoch at the moment.
	// If the authentication stems from an authenticated request, we want to use
	// the same key as the one used by the request sender.
	epoch := slayers.PacketAuthLater
	drkeyType := slayers.PacketAuthASHost

	spi, err := slayers.MakePacketAuthSPIDRKey(uint16(drkey.SCMP), drkeyType, dir, epoch)
	if err != nil {
		return err
	}

	firstInfo, err := p.path.GetInfoField(0)
	if err != nil {
		return err
	}

	timestamp, err := spao.RelativeTimestamp(firstInfo.Timestamp, now)
	if err != nil {
		return err
	}

	// XXX(JordiSubira): Assume that send rate is low so that combination
	// with timestamp is always unique
	sn := uint32(0)
	return p.optAuth.Reset(slayers.PacketAuthOptionParams{
		SPI:            spi,
		Algorithm:      slayers.PacketAuthCMAC,
		Timestamp:      timestamp,
		SequenceNumber: sn,
		Auth:           zeroBuffer,
	})
}

func (p *scionPacketProcessor) hasValidAuth() bool {
	// Check if e2eLayer was parsed for this packet
	if !p.lastLayer.CanDecode().Contains(slayers.LayerTypeEndToEndExtn) {
		return false
	}
	// Parse incoming authField
	e2eLayer := &slayers.EndToEndExtn{}
	if err := e2eLayer.DecodeFromBytes(
		p.e2eLayer.Contents,
		gopacket.NilDecodeFeedback,
	); err != nil {
		return false
	}
	e2eOption, err := e2eLayer.FindOption(slayers.OptTypeAuthenticator)
	if err != nil {
		return false
	}
	authOption, err := slayers.ParsePacketAuthOption(e2eOption)
	if err != nil {
		return false
	}
	// Computing authField
	firstInfo, err := p.path.GetInfoField(0)
	if err != nil {
		return false
	}
	then := spao.Time(firstInfo.Timestamp, authOption.Timestamp())
	srcAddr, err := p.scionLayer.SrcAddr()
	if err != nil {
		return false
	}
	// the sender should have used the receiver side key, i.e., K_{localIA-remoteIA:remoteHost}
	// where remoteIA == p.scionLayer.SrcIA and remoteHost == srcAddr
	// (for the incoming packet).
	key, err := p.drkeyProvider.GetAuthKey(then, p.scionLayer.SrcIA, srcAddr)
	if err != nil {
		return false
	}
	_, err = spao.ComputeAuthCMAC(
		spao.MACInput{
			Key:        key[:],
			Header:     authOption,
			ScionLayer: &p.scionLayer,
			PldType:    slayers.L4SCMP,
			Pld:        p.lastLayer.LayerPayload(),
		},
		p.macBuffers.drkeyInput,
		p.validAuthBuf,
	)
	if err != nil {
		return false
	}

	// compare incoming authField with computed authentication tag
	return subtle.ConstantTimeCompare(authOption.Authenticator(), p.validAuthBuf) != 0
}

// decodeLayers implements roughly the functionality of
// gopacket.DecodingLayerParser, but customized to our use case with a "base"
// layer and additional, optional layers in the given order.
// Returns the last decoded layer.
func decodeLayers(data []byte, base gopacket.DecodingLayer,
	opts ...gopacket.DecodingLayer) (gopacket.DecodingLayer, error) {

	if err := base.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	last := base
	for _, opt := range opts {
		if opt.CanDecode().Contains(last.NextLayerType()) {
			data := last.LayerPayload()
			if err := opt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				return nil, err
			}
			last = opt
		}
	}
	return last, nil
}

func nextHdr(layer gopacket.DecodingLayer) slayers.L4ProtocolType {
	switch v := layer.(type) {
	case *slayers.SCION:
		return v.NextHdr
	case *slayers.EndToEndExtnSkipper:
		return v.NextHdr
	case *slayers.HopByHopExtnSkipper:
		return v.NextHdr
	default:
		return slayers.L4None
	}
}

// forwardingMetrics contains the subset of Metrics relevant for forwarding,
// instantiated with some interface-specific labels.
type forwardingMetrics struct {
	InputBytesTotal             prometheus.Counter
	OutputBytesTotal            prometheus.Counter
	InputPacketsTotal           prometheus.Counter
	OutputPacketsTotal          prometheus.Counter
	DroppedPacketsInvalid       prometheus.Counter
	DroppedPacketsBusyProcessor prometheus.Counter
	DroppedPacketsBusyForwarder prometheus.Counter
	ProcessedPackets            prometheus.Counter
}

func initForwardingMetrics(metrics *Metrics, labels prometheus.Labels) forwardingMetrics {
	c := forwardingMetrics{
		InputBytesTotal:    metrics.InputBytesTotal.With(labels),
		InputPacketsTotal:  metrics.InputPacketsTotal.With(labels),
		OutputBytesTotal:   metrics.OutputBytesTotal.With(labels),
		OutputPacketsTotal: metrics.OutputPacketsTotal.With(labels),
		ProcessedPackets:   metrics.ProcessedPackets.With(labels),
	}
	labels["reason"] = "invalid"
	c.DroppedPacketsInvalid = metrics.DroppedPacketsTotal.With(labels)
	labels["reason"] = "busy_processor"
	c.DroppedPacketsBusyProcessor = metrics.DroppedPacketsTotal.With(labels)
	labels["reason"] = "busy_forwarder"
	c.DroppedPacketsBusyForwarder = metrics.DroppedPacketsTotal.With(labels)

	c.InputBytesTotal.Add(0)
	c.InputPacketsTotal.Add(0)
	c.OutputBytesTotal.Add(0)
	c.OutputPacketsTotal.Add(0)
	c.DroppedPacketsInvalid.Add(0)
	c.DroppedPacketsBusyProcessor.Add(0)
	c.DroppedPacketsBusyForwarder.Add(0)
	c.ProcessedPackets.Add(0)
	return c
}

func interfaceToMetricLabels(id uint16, localIA addr.IA,
	neighbors map[uint16]addr.IA) prometheus.Labels {

	if id == 0 {
		return prometheus.Labels{
			"isd_as":          localIA.String(),
			"interface":       "internal",
			"neighbor_isd_as": localIA.String(),
		}
	}
	return prometheus.Labels{
		"isd_as":          localIA.String(),
		"interface":       strconv.FormatUint(uint64(id), 10),
		"neighbor_isd_as": neighbors[id].String(),
	}
}

func serviceMetricLabels(localIA addr.IA, svc addr.SVC) prometheus.Labels {
	return prometheus.Labels{
		"isd_as":  localIA.String(),
		"service": svc.BaseString(),
	}
}

type fakeProvider struct{}

func (p *fakeProvider) GetAuthKey(
	_ time.Time,
	_ addr.IA,
	_ addr.Host,
) (drkey.Key, error) {
	return drkey.Key{}, nil
}
