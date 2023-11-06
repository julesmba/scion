package router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/spao"
)

// SetSecretValue sets the secret value for the PRF function used to compute the Hummingbird Auth Key
func (d *DataPlane) SetSecretValue(key []byte) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if len(key) == 0 {
		return emptyValue
	}
	if d.prfFactory != nil {
		return alreadySet
	}
	// First check for cipher creation errors
	if _, err := aes.NewCipher(key); err != nil {
		return err
	}
	d.prfFactory = func() cipher.Block {
		prf, _ := aes.NewCipher(key)
		return prf
	}
	return nil
}

func (p *scionPacketProcessor) parseHbirdPath() (processResult, error) {
	var err error
	p.flyoverField, err = p.hbirdPath.GetCurrentHopField()
	if err != nil {
		return processResult{}, err
	}
	p.hopField = p.flyoverField.HopField
	p.infoField, err = p.hbirdPath.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, err
	}
	if p.flyoverField.Flyover {
		p.hasPriority = true
	}

	return processResult{}, nil
}

func (p *scionPacketProcessor) validateReservationExpiry() (processResult, error) {
	startTime := util.SecsToTime(p.hbirdPath.PathMeta.BaseTS - uint32(p.flyoverField.ResStartTime))
	endTime := startTime.Add(time.Duration(p.flyoverField.Duration) * time.Second)
	now := time.Now()
	if startTime.Before(now) && now.Before(endTime) {
		return processResult{}, nil
	}
	log.Debug("SCMP: Reservation is not valid at current time", "reservation start", startTime,
		"reservation end", endTime, "now", now)
	slowPathRequest := slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     slayers.SCMPCodeReservationExpired,
		pointer:  p.currentHopPointer(),
		cause:    reservationExpired,
	}
	return processResult{SlowPathRequest: slowPathRequest}, slowPathRequired
}

func (p *scionPacketProcessor) currentHbirdInfoPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		hummingbird.MetaLen + path.InfoLen*int(p.hbirdPath.PathMeta.CurrINF))
}

func (p *scionPacketProcessor) currentHbirdHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		hummingbird.MetaLen + path.InfoLen*p.hbirdPath.NumINF + hummingbird.LineLen*int(p.hbirdPath.PathMeta.CurrHF))
}

func (p *scionPacketProcessor) verifyCurrentHbirdMAC() (processResult, error) {
	var flyoverMac []byte
	var verified int

	// Compute flyovermac
	if p.flyoverField.Flyover {
		ingress := p.hopField.ConsIngress
		egress := p.hopField.ConsEgress
		// Reservations are not bidirectional, reservation ingress and egress are always real ingress and egress
		if !p.infoField.ConsDir {
			ingress, egress = egress, ingress
		}
		// On crossovers, A Reservation goes from the ingress of the incoming hop to the egress of the outgoing one
		var err error
		if p.hbirdPath.IsXover() {
			egress, err = p.hbirdPath.GetNextEgress()
			if err != nil {
				return processResult{}, err
			}
		} else if p.hbirdPath.IsFirstHopAfterXover() {
			ingress, err = p.hbirdPath.GetPreviousIngress()
			if err != nil {
				return processResult{}, err
			}
		}

		ak := hummingbird.DeriveAuthKey(p.prf, p.flyoverField.ResID, p.flyoverField.Bw, ingress, egress,
			p.hbirdPath.PathMeta.BaseTS-uint32(p.flyoverField.ResStartTime), p.flyoverField.Duration,
			p.macInputBuffer[path.MACBufferSize+hummingbird.FlyoverMacBufferSize:])
		flyoverMac = hummingbird.FullFlyoverMac(ak, p.scionLayer.DstIA, p.scionLayer.PayloadLen, p.flyoverField.ResStartTime,
			p.hbirdPath.PathMeta.HighResTS, p.macInputBuffer[path.MACBufferSize:], p.hbirdXkbuffer)
	}
	// Perform updateHbirdNonConsDirIngressSegID
	// This needs de-aggregated MAC but needs to be done before scionMac is computed
	// Therefore, we check this here instead of before MAC computation like in standard SCiON
	if p.flyoverField.Flyover {
		// de-aggregate first two bytes of mac
		p.hopField.Mac[0] ^= flyoverMac[0]
		p.hopField.Mac[1] ^= flyoverMac[1]
		err := p.updateHbirdNonConsDirIngressSegID()
		// restore correct state of MAC field, even if error
		p.hopField.Mac[0] ^= flyoverMac[0]
		p.hopField.Mac[1] ^= flyoverMac[1]
		if err != nil {
			return processResult{}, err
		}
	} else {
		if err := p.updateHbirdNonConsDirIngressSegID(); err != nil {
			return processResult{}, err
		}
	}
	// Compute scionMac
	scionMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macInputBuffer[:path.MACBufferSize])
	// Aggregate MACS and verify if necessary
	if p.flyoverField.Flyover {
		binary.BigEndian.PutUint32(flyoverMac[0:4], binary.BigEndian.Uint32(scionMac[0:4])^binary.BigEndian.Uint32(flyoverMac[0:4]))
		binary.BigEndian.PutUint16(flyoverMac[4:6], binary.BigEndian.Uint16(scionMac[4:6])^binary.BigEndian.Uint16(flyoverMac[4:6]))

		verified = subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], flyoverMac[:path.MacLen])
		if verified == 0 {
			log.Debug("SCMP: Aggregate MAC verification failed", "expected", fmt.Sprintf("%x", flyoverMac[:path.MacLen]),
				"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]), "cons_dir", p.infoField.ConsDir,
				"scionMac", fmt.Sprintf("%x", scionMac[:path.MacLen]),
				"if_id", p.ingressID, "curr_inf", p.hbirdPath.PathMeta.CurrINF,
				"curr_hf", p.hbirdPath.PathMeta.CurrHF, "seg_id", p.infoField.SegID, "packet length", p.scionLayer.PayloadLen,
				"dest", p.scionLayer.DstIA, "startTime", p.flyoverField.ResStartTime, "highResTS", p.hbirdPath.PathMeta.HighResTS,
				"ResID", p.flyoverField.ResID, "Bw", p.flyoverField.Bw, "in", p.hopField.ConsIngress,
				"Eg", p.hopField.ConsEgress, "start ak", p.hbirdPath.PathMeta.BaseTS-uint32(p.flyoverField.ResStartTime),
				"Duration", p.flyoverField.Duration)
		}
	} else {
		verified = subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], scionMac[:path.MacLen])
		if verified == 0 {
			log.Debug("SCMP: MAC verification failed", "expected", fmt.Sprintf(
				"%x", scionMac[:path.MacLen]),
				"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]),
				"cons_dir", p.infoField.ConsDir,
				"if_id", p.ingressID, "curr_inf", p.hbirdPath.PathMeta.CurrINF,
				"curr_hf", p.hbirdPath.PathMeta.CurrHF, "seg_id", p.infoField.SegID)
		}
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC and hummingbird mac de-aggregation do not need to recalculate it.
	p.cachedMac = scionMac
	if verified == 0 {
		slowPathRequest := slowPathRequest{
			scmpType: slayers.SCMPTypeParameterProblem,
			code:     slayers.SCMPCodeInvalidHopFieldMAC,
			pointer:  p.currentHopPointer(),
			cause:    macVerificationFailed,
		}
		return processResult{SlowPathRequest: slowPathRequest}, slowPathRequired
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) validateHbirdSrcDstIA() (processResult, error) {
	srcIsLocal := (p.scionLayer.SrcIA == p.d.localIA)
	dstIsLocal := (p.scionLayer.DstIA == p.d.localIA)
	if p.ingressID == 0 {
		// Outbound
		// Only check SrcIA if first hop, for transit this already checked by ingress router.
		// Note: SCMP error messages triggered by the sibling router may use paths that
		// don't start with the first hop.
		if p.hbirdPath.IsFirstHop() && !srcIsLocal {
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
		if p.hbirdPath.IsLastHop() != dstIsLocal {
			return p.invalidDstIA()
		}
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) ingressInterfaceHbird() uint16 {
	info := p.infoField
	hop := p.flyoverField
	if !p.peering && p.hbirdPath.IsFirstHopAfterXover() {
		var err error
		info, err = p.hbirdPath.GetInfoField(int(p.hbirdPath.PathMeta.CurrINF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
		// Previous hop should always be a non-flyover field, as flyover is transferred to second hop on xover
		hop, err = p.hbirdPath.GetHopField(int(p.hbirdPath.PathMeta.CurrHF) - 3)
		if err != nil { // cannot be out of range
			panic(err)
		}
	}
	if info.ConsDir {
		return hop.HopField.ConsIngress
	}
	return hop.HopField.ConsEgress
}

// validateTransitUnderlaySrc checks that the source address of transit packets
// matches the expected sibling router.
// Provided that underlying network infrastructure prevents address spoofing,
// this check prevents malicious end hosts in the local AS from bypassing the
// SrcIA checks by disguising packets as transit traffic.
func (p *scionPacketProcessor) validateHbirdTransitUnderlaySrc() (processResult, error) {
	if p.hbirdPath.IsFirstHop() || p.ingressID != 0 {
		// not a transit packet, nothing to check
		return processResult{}, nil
	}
	pktIngressID := p.ingressInterfaceHbird()
	expectedSrc, ok := p.d.internalNextHops[pktIngressID]
	if !ok || !expectedSrc.IP.Equal(p.srcAddr.IP) {
		// Drop
		return processResult{}, invalidSrcAddrForTransit
	}
	return processResult{}, nil
}

// Verifies the PathMetaHeader timestamp is recent
// Current implementation works with a nanosecond granularity HighResTS
func (p *scionPacketProcessor) validatePathMetaTimestamp() {
	timestamp := util.SecsToTime(p.hbirdPath.PathMeta.BaseTS).Add(time.Duration(p.hbirdPath.PathMeta.HighResTS>>22) * time.Millisecond)
	// TODO: make a configurable value instead of using a flat 1.5 seconds
	if time.Until(timestamp).Abs() > time.Duration(1)*time.Second {
		// Hummingbird specification explicitely says to forward best-effort is timestamp too old
		p.hasPriority = false
	}
}

func (p *scionPacketProcessor) handleHbirdIngressRouterAlert() (processResult, error) {
	if p.ingressID == 0 {
		return processResult{}, nil
	}
	alert := p.ingressRouterAlertFlag()
	if !*alert {
		return processResult{}, nil
	}
	*alert = false
	if err := p.hbirdPath.SetHopField(p.flyoverField, int(p.hbirdPath.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	slowPathRequest := slowPathRequest{
		typ:         slowPathRouterAlert,
		interfaceId: p.ingressID,
	}
	return processResult{SlowPathRequest: slowPathRequest}, slowPathRequired
}

func (p *scionPacketProcessor) handleHbirdEgressRouterAlert() (processResult, error) {
	alert := p.egressRouterAlertFlag()
	if !*alert {
		return processResult{}, nil
	}
	egressID := p.egressInterface()
	if _, ok := p.d.external[egressID]; !ok {
		return processResult{}, nil
	}
	*alert = false
	if err := p.hbirdPath.SetHopField(p.flyoverField, int(p.hbirdPath.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	slowPathRequest := slowPathRequest{
		typ:         slowPathRouterAlert,
		interfaceId: egressID,
	}
	return processResult{SlowPathRequest: slowPathRequest}, slowPathRequired
}

func (p *scionPacketProcessor) updateHbirdNonConsDirIngressSegID() error {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
	if !p.infoField.ConsDir && p.ingressID != 0 {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.hbirdPath.SetInfoField(p.infoField, int(p.hbirdPath.PathMeta.CurrINF)); err != nil {
			return serrors.WrapStr("update info field", err)
		}
	}
	return nil
}

func (p *scionPacketProcessor) deAggregateMac() (processResult, error) {
	if !p.flyoverField.Flyover {
		return processResult{}, nil
	}
	copy(p.hopField.Mac[:], p.cachedMac[:path.MacLen])
	if err := p.hbirdPath.ReplaceCurrentMac(p.cachedMac); err != nil {
		//TODO: what SCMP packet should be returned here? Is that even necessary?
		log.Debug("Failed to replace MAC after de-aggregation", "error", err.Error())
		return processResult{}, serrors.Join(err, serrors.New("Mac replacement failed"))
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) doFlyoverXover() error {
	// Move flyoverhopfield to next hop for benefit of egress router
	if err := p.hbirdPath.DoFlyoverXover(); err != nil {
		return err
	}

	// Buffer flyover part of current mac by xoring it with cached scionMac
	binary.BigEndian.PutUint32(p.macInputBuffer[6:10], binary.BigEndian.Uint32(p.flyoverField.HopField.Mac[0:4])^binary.BigEndian.Uint32(p.cachedMac[0:4]))
	p.macInputBuffer[10] = p.flyoverField.HopField.Mac[4] ^ p.cachedMac[4]
	p.macInputBuffer[11] = p.flyoverField.HopField.Mac[5] ^ p.cachedMac[5]
	// deaggregate current mac
	copy(p.hopField.Mac[:], p.cachedMac[0:6])
	p.hbirdPath.ReplaceCurrentMac(p.cachedMac)
	// Aggregate Mac of second hop
	mac, err := p.hbirdPath.GetMac(int(p.hbirdPath.PathMeta.CurrHF) + 3)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(mac[0:4], binary.BigEndian.Uint32(mac[0:4])^binary.BigEndian.Uint32(p.macInputBuffer[6:10]))
	mac[4] ^= p.macInputBuffer[10]
	mac[5] ^= p.macInputBuffer[11]
	return nil
}

func (p *scionPacketProcessor) reverseFlyoverXover() error {
	if err := p.hbirdPath.ReverseFlyoverXover(); err != nil {
		return err
	}
	// No MAC aggregation/de-aggregation, as these are already performed
	p.flyoverField.Flyover = false
	return nil
}

func (p *scionPacketProcessor) doHbirdXover() (processResult, error) {
	p.effectiveXover = true

	if p.flyoverField.Flyover {
		if err := p.doFlyoverXover(); err != nil {
			return processResult{}, err
		}
	}
	if err := p.hbirdPath.IncPath(3); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, serrors.WrapStr("incrementing path", err)
	}

	var err error
	if p.flyoverField, err = p.hbirdPath.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, err
	}
	if p.infoField, err = p.hbirdPath.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, err
	}
	p.hopField = p.flyoverField.HopField
	//TODO: modify method once we have definite design for flyover Xover
	return processResult{}, nil
}

func (p *scionPacketProcessor) processHbirdEgress() error {
	// we are the egress router and if we go in construction direction we
	// need to update the SegID.
	if p.infoField.ConsDir {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.hbirdPath.SetInfoField(p.infoField, int(p.hbirdPath.PathMeta.CurrINF)); err != nil {
			// TODO parameter problem invalid path
			return serrors.WrapStr("update info field", err)
		}
	}

	n := 3
	if p.flyoverField.Flyover {
		n = 5
	}
	if err := p.hbirdPath.IncPath(n); err != nil {
		// TODO parameter problem invalid path
		return serrors.WrapStr("incrementing path", err)
	}
	return nil
}

func (p *scionPacketProcessor) processHBIRD() (processResult, error) {
	var ok bool
	p.hbirdPath, ok = p.scionLayer.Path.(*hummingbird.Raw)
	log.Debug("raw path", "path", fmt.Sprintf("%x", p.hbirdPath.Raw))
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, malformedPath
	}
	if r, err := p.parseHbirdPath(); err != nil {
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
	if r, err := p.validateHbirdTransitUnderlaySrc(); err != nil {
		return r, err
	}
	if r, err := p.validateHbirdSrcDstIA(); err != nil {
		return r, err
	}
	if p.flyoverField.Flyover {
		if r, err := p.validateReservationExpiry(); err != nil {
			return r, err
		}
	}
	// if err := p.updateHbirdNonConsDirIngressSegID(); err != nil {
	// 	return processResult{}, err
	// }
	if r, err := p.verifyCurrentHbirdMAC(); err != nil {
		return r, err
	}
	if p.hasPriority && p.flyoverField.Flyover {
		// TODO: current implementation (which is in line with design) allows for an attack surface where packets with outdated TSs bypass bw check but claim priority to next router
		p.validatePathMetaTimestamp()
	}
	if r, err := p.handleHbirdIngressRouterAlert(); err != nil {
		return r, err
	}
	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA == p.d.localIA {

		if r, err := p.deAggregateMac(); err != nil {
			return r, err
		}
		a, r, err := p.resolveInbound()
		if err != nil {
			return r, err
		}
		return processResult{OutAddr: a, OutPkt: p.rawPkt}, nil
	}

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.
	if p.hbirdPath.IsXover() {
		if r, err := p.doHbirdXover(); err != nil {
			return r, err
		}
		if r, err := p.validateHopExpiry(); err != nil {
			return r, serrors.WithCtx(err, "info", "after xover")
		}
		// verify the new block
		if p.flyoverField.Flyover {
			// TODO: can possibly skip this once we modify flyover at Xover implementation. Will need to aggregate new MAC though
			if r, err := p.verifyCurrentHbirdMAC(); err != nil {
				return r, err
			}
		} else {
			if r, err := p.verifyCurrentMAC(); err != nil {
				return r, err
			}
		}
		if p.flyoverField.Flyover {
			//TODO: can skip repeating those if/once moving previous flyover at Xover is confirmed
			if r, err := p.validateReservationExpiry(); err != nil {
				return r, serrors.WithCtx(err, "info", "after xover")
			}
			if p.hasPriority {
				p.validatePathMetaTimestamp()
			}
		}
	}
	if r, err := p.validateEgressID(); err != nil {
		return r, err
	}
	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if r, err := p.handleHbirdEgressRouterAlert(); err != nil {
		return r, err
	}
	if r, err := p.validateEgressUp(); err != nil {
		return r, err
	}

	egressID := p.egressInterface()
	if _, ok := p.d.external[egressID]; ok {
		if r, err := p.deAggregateMac(); err != nil {
			return r, err
		}
		if p.flyoverField.Flyover && p.hbirdPath.IsFirstHopAfterXover() {
			if err := p.reverseFlyoverXover(); err != nil {
				return processResult{}, err
			}
		}
		if err := p.processHbirdEgress(); err != nil {
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
	log.Debug("SCMP: cannot route")
	slowPathRequest := slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     errCode,
		pointer:  p.currentHopPointer(),
		cause:    cannotRoute,
	}
	return processResult{SlowPathRequest: slowPathRequest}, slowPathRequired
}

// Functions for SCMP packets preparation

func determinePeerHbird(pathMeta hummingbird.MetaHdr, inf path.InfoField) (bool, error) {
	if !inf.Peer {
		return false, nil
	}

	if pathMeta.SegLen[0] == 0 {
		return false, errPeeringEmptySeg0
	}
	if pathMeta.SegLen[1] == 0 {
		return false, errPeeringEmptySeg1

	}
	if pathMeta.SegLen[2] != 0 {
		return false, errPeeringNonemptySeg2
	}

	// The peer hop fields are the last hop field on the first path
	// segment (at SegLen[0] - 1) and the first hop field of the second
	// path segment (at SegLen[0]). The below check applies only
	// because we already know this is a well-formed peering path.
	currHF := pathMeta.CurrHF
	segLen := pathMeta.SegLen[0]
	return currHF == segLen-3 || currHF == segLen, nil
}

func (p *slowPathPacketProcessor) prepareHbirdSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	cause error,
) ([]byte, error) {

	path, ok := p.scionLayer.Path.(*hummingbird.Raw)
	if !ok {
		return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
			"path type", hummingbird.PathType)
	}
	decPath, err := path.ToDecoded()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "decoding raw path")
	}
	revPathTmp, err := decPath.Reverse()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "reversing path for SCMP")
	}
	revPath := revPathTmp.(*hummingbird.Decoded)

	peering, err := determinePeerHbird(revPath.PathMeta, revPath.InfoFields[revPath.PathMeta.CurrINF])
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "peering cannot be determined")
	}

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() && !peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if err := revPath.IncPath(3); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "reverting cross over for SCMP")
		}
	}

	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	_, external := p.d.external[p.ingressID]
	if external {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir && !peering {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.HopField.Mac)
		}
		if err := revPath.IncPath(3); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "incrementing path for SCMP")
		}
	} //TODO else, make sure MAC is deaggregated?

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

	needsAuth := false
	if p.d.ExperimentalSCMPAuthentication {
		// Error messages must be authenticated.
		// Traceroute are OPTIONALLY authenticated ONLY IF the request
		// was authenticated.
		// TODO(JordiSubira): Reuse the key computed in p.hasValidAuth
		// if SCMPTypeTracerouteReply to create the response.
		needsAuth = cause != nil ||
			(scmpH.TypeCode.Type() == slayers.SCMPTypeTracerouteReply &&
				p.hasValidAuth(time.Now()))
	}

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
		key, err := p.drkeyProvider.GetASHostKey(now, scionL.DstIA, srcA)
		if err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "retrieving DRKey")
		}
		if err := p.resetSPAOMetadata(key, now); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "resetting SPAO header")
		}

		e2e.Options = []*slayers.EndToEndOption{p.optAuth.EndToEndOption}
		e2e.NextHdr = slayers.L4SCMP
		_, err = spao.ComputeAuthCMAC(
			spao.MACInput{
				Key:        key.Key[:],
				Header:     p.optAuth,
				ScionLayer: &scionL,
				PldType:    slayers.L4SCMP,
				Pld:        p.buffer.Bytes(),
			},
			p.macInputBuffer,
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

	log.Debug("scmp", "typecode", scmpH.TypeCode, "cause", cause)
	return p.buffer.Bytes(), nil
}
