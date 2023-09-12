package router

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
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
	return p.packSCMP(slayers.SCMPTypeParameterProblem,
		slayers.SCMPCodeReservationExpired,
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		serrors.New("reservation not valid now", "reservation start", startTime, "reservation end", endTime, "now", now),
	)
}

func (p *scionPacketProcessor) verifyCurrentHbirdMAC() (processResult, error) {
	scionMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macBuffers.scionInput)

	var verified bool
	if p.flyoverField.Flyover {
		ak := hummingbird.DeriveAuthKey(p.prf, p.flyoverField.ResID, p.flyoverField.Bw, p.hopField.ConsIngress, p.hopField.ConsEgress,
			p.hbirdPath.PathMeta.BaseTS-uint32(p.flyoverField.ResStartTime), p.flyoverField.Duration, p.macBuffers.hbirdAuthInput)
		flyoverMac := hummingbird.FullFlyoverMac(ak, p.scionLayer.DstIA, p.scionLayer.PayloadLen, p.flyoverField.ResStartTime,
			p.hbirdPath.PathMeta.HighResTS, p.macBuffers.hbirdMacInput, p.macBuffers.hbirdXkbuffer)
		// Xor to Aggregate MACs
		binary.BigEndian.PutUint64(flyoverMac[0:8], binary.BigEndian.Uint64(scionMac[0:8])^binary.BigEndian.Uint64(flyoverMac[0:8]))
		binary.BigEndian.PutUint32(flyoverMac[8:12], binary.BigEndian.Uint32(scionMac[8:12])^binary.BigEndian.Uint32(flyoverMac[8:12]))

		verified = CompareMac(p.hopField.Mac[:path.MacLen], flyoverMac[:path.MacLen])
	} else {
		verified = CompareMac(p.hopField.Mac[:path.MacLen], scionMac[:path.MacLen])
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC and hummingbird mac de-aggregation do not need to recalculate it.
	p.cachedMac = scionMac
	if !verified {
		return p.packSCMP(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidHopFieldMAC,
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.New("MAC verification failed", "expected", fmt.Sprintf(
				"%x", scionMac[:path.MacLen]),
				"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]),
				"aggregate with flyover", p.flyoverField.Flyover,
				"cons_dir", p.infoField.ConsDir,
				"if_id", p.ingressID, "curr_inf", p.path.PathMeta.CurrINF,
				"curr_hf", p.path.PathMeta.CurrHF, "seg_id", p.infoField.SegID),
		)
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
	pktIngressID := p.ingressInterface()
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
	if err := p.hbirdPath.SetHopField(p.flyoverField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	return p.handleSCMPTraceRouteRequest(p.ingressID)
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
	if err := p.hbirdPath.SetHopField(p.flyoverField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	return p.handleSCMPTraceRouteRequest(egressID)
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
		return p.packSCMP(
			slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodeInvalidHopFieldMAC,
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.Join(err, serrors.New("Mac replacement failed")),
		)
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) doHbirdXover() (processResult, error) {
	p.segmentChange = true
	n := 3
	if p.flyoverField.Flyover {
		n = 5
	}
	if err := p.hbirdPath.IncPath(n); err != nil {
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
	if err := p.updateHbirdNonConsDirIngressSegID(); err != nil {
		return processResult{}, err
	}
	if p.flyoverField.Flyover {
		if r, err := p.verifyCurrentHbirdMAC(); err != nil {
			return r, err
		}
	} else {
		if r, err := p.verifyCurrentMAC(); err != nil {
			return r, err
		}
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
	return p.packSCMP(
		slayers.SCMPTypeParameterProblem,
		errCode,
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		cannotRoute,
	)
}
