package lua

import (
	"encoding/binary"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const luaConntrackMaxEntries = 10000
const (
	luaConntrackTimeoutSyn = 60 * time.Second
	luaConntrackTimeoutEst = 300 * time.Second
	luaConntrackTimeoutFin = 60 * time.Second
	luaConntrackTimeoutUDP = 60 * time.Second

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

type luaConnState uint8

const (
	luaConnStateSyn luaConnState = iota
	luaConnStateEstablished
	luaConnStateFin
)

type luaConnTrack struct {
	forwardKey string
	reverseKey string

	proto uint8
	state luaConnState

	start time.Time
	last  time.Time

	incomingTTL  uint8
	l7proto      string
	hostname     string
	hostnameIsIP bool

	luaState     *lua.LTable
	luaInCutoff  bool
	luaOutCutoff bool

	posClient luaConnPos
	posServer luaConnPos

	instanceCutoffs map[string]luaCutoffState
}

type luaCutoffState struct {
	in  bool
	out bool
}

type luaConnPos struct {
	pcounter  uint64
	pdcounter uint64
	pbcounter uint64
	ip6Flow   uint32

	tcp *luaConnTCPPos
}

type luaConnTCPPos struct {
	seq0Set bool
	seq0    uint32
	seqLast uint32
	pos     uint32
	uppos   uint32
	upprev  uint32

	winSize     uint16
	mss         uint16
	winSizeCalc uint32
	scale       uint8
	rseqOver2G  bool
}

type luaConnFlow struct {
	family     uint8
	proto      uint8
	src        []byte
	dst        []byte
	sport      uint16
	dport      uint16
	payloadLen int
	ttl        uint8
	ip6Flow    uint32
	tcp        *luaConnFlowTCP
}

type luaConnFlowTCP struct {
	seq   uint32
	ack   uint32
	flags uint8
	win   uint16
	scale uint8
	mss   uint16
}

func (r *Runtime) luaConntrackFeed(L *lua.LState) int {
	argc := L.GetTop()
	if argc < 1 || argc > 3 {
		L.RaiseError("conntrack_feed expect from %d to %d arguments, got %d", 1, 3, argc)
		return 0
	}

	var (
		dis *lua.LTable
	)

	switch v := L.Get(1).(type) {
	case *lua.LTable:
		var opts *lua.LTable
		if argc >= 2 {
			if x := L.Get(2); x != lua.LNil {
				t, ok := x.(*lua.LTable)
				if !ok {
					L.RaiseError("invalid reconstruct options")
					return 0
				}
				opts = t
			}
		}
		raw, recErr := reconstructPacketFromLua(v, opts)
		if recErr != nil {
			L.RaiseError("invalid dissect data")
			return 0
		}
		disLV, decErr := dissectPacketToLua(L, raw, true)
		if decErr != nil || disLV == lua.LNil {
			L.Push(lua.LNil)
			L.Push(lua.LNil)
			return 2
		}
		dis, _ = disLV.(*lua.LTable)
	case lua.LString:
		raw := []byte(string(v))
		disLV, decErr := dissectPacketToLua(L, raw, true)
		if decErr != nil || disLV == lua.LNil {
			L.Push(lua.LNil)
			L.Push(lua.LNil)
			return 2
		}
		dis, _ = disLV.(*lua.LTable)
	default:
		L.RaiseError("invalid packet data type")
		return 0
	}

	if dis == nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}

	track, outgoing, ok := r.feedConntrackFromDissectLocked(dis)
	if !ok || track == nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}

	r.currentTrack = track
	r.currentOutgoing = outgoing
	r.currentInstance = ""

	L.Push(r.luaTrackTable(track, outgoing))
	L.Push(lua.LBool(outgoing))
	return 2
}

func (r *Runtime) luaInstanceCutoff(L *lua.LState) int {
	argc := L.GetTop()
	if argc < 1 || argc > 2 {
		L.RaiseError("instance_cutoff expect from %d to %d arguments, got %d", 1, 2, argc)
		return 0
	}
	if L.Get(1) == lua.LNil {
		return 0
	}
	if r.currentTrack == nil || r.currentInstance == "" {
		return 0
	}
	in, out := luaCutoffDirections(L, 2)
	r.currentTrack.setInstanceCutoff(r.currentInstance, in, out)
	return 0
}

func (r *Runtime) luaLuaCutoff(L *lua.LState) int {
	argc := L.GetTop()
	if argc < 1 || argc > 2 {
		L.RaiseError("lua_cutoff expect from %d to %d arguments, got %d", 1, 2, argc)
		return 0
	}
	if L.Get(1) == lua.LNil {
		return 0
	}
	if r.currentTrack == nil {
		return 0
	}
	in, out := luaCutoffDirections(L, 2)
	if in {
		r.currentTrack.luaInCutoff = true
	}
	if out {
		r.currentTrack.luaOutCutoff = true
	}
	return 0
}

func luaCutoffDirections(L *lua.LState, idx int) (in bool, out bool) {
	if idx <= L.GetTop() && L.Get(idx) != lua.LNil {
		b, ok := L.Get(idx).(lua.LBool)
		if !ok {
			L.RaiseError("cutoff direction must be boolean")
			return false, false
		}
		out = bool(b)
		in = !out
		return in, out
	}
	return true, true
}

func (r *Runtime) feedConntrackFromDissectLocked(dis *lua.LTable) (*luaConnTrack, bool, bool) {
	flow, ok := luaConnFlowFromDissect(dis)
	if !ok {
		return nil, false, false
	}
	now := time.Now()
	forward, reverse, ok := luaConntrackKeys(flow)
	if !ok {
		return nil, false, false
	}

	ct := r.conntrack[forward]
	outgoing := true
	if ct == nil {
		ct = r.conntrack[reverse]
		if ct != nil {
			outgoing = false
		}
	}
	if ct == nil {
		createReverse := false
		switch flow.proto {
		case ipProtoUDP:
		case ipProtoTCP:
			if flow.tcp == nil {
				return nil, false, false
			}
			switch {
			case tcpSynSegment(flow.tcp.flags):
				createReverse = false
			case tcpSynAckSegment(flow.tcp.flags):
				createReverse = true
			default:
				return nil, false, false
			}
		default:
			return nil, false, false
		}

		fwdKey := forward
		revKey := reverse
		outgoing = true
		if createReverse {
			fwdKey = reverse
			revKey = forward
			outgoing = false
		}

		ct = &luaConnTrack{
			forwardKey:      fwdKey,
			reverseKey:      revKey,
			proto:           flow.proto,
			state:           luaConnStateSyn,
			start:           now,
			last:            now,
			l7proto:         "unknown",
			luaState:        r.L.NewTable(),
			instanceCutoffs: make(map[string]luaCutoffState),
		}
		r.conntrack[fwdKey] = ct
		r.conntrack[revKey] = ct
	}

	if ct.luaState == nil {
		ct.luaState = r.L.NewTable()
	}
	ct.feed(r.L, flow, outgoing, now)
	r.conntrackPurgeLocked(now)
	return ct, outgoing, true
}

func (r *Runtime) conntrackPurgeLocked(now time.Time) {
	seen := make(map[*luaConnTrack]struct{}, len(r.conntrack))
	for _, ct := range r.conntrack {
		if ct == nil {
			continue
		}
		if _, ok := seen[ct]; ok {
			continue
		}
		seen[ct] = struct{}{}
		if now.Sub(ct.last) > ct.timeout() {
			delete(r.conntrack, ct.forwardKey)
			delete(r.conntrack, ct.reverseKey)
		}
	}
	if len(r.conntrack) <= luaConntrackMaxEntries*2 {
		return
	}
	// Жёсткий лимит: если треков слишком много — удаляем самые старые.
	for len(r.conntrack) > luaConntrackMaxEntries*2 {
		var oldest *luaConnTrack
		for _, ct := range r.conntrack {
			if ct == nil {
				continue
			}
			if oldest == nil || ct.last.Before(oldest.last) {
				oldest = ct
			}
		}
		if oldest == nil {
			break
		}
		delete(r.conntrack, oldest.forwardKey)
		delete(r.conntrack, oldest.reverseKey)
	}
}

func (ct *luaConnTrack) feed(L *lua.LState, flow luaConnFlow, outgoing bool, now time.Time) {
	ct.last = now
	if ct.start.IsZero() {
		ct.start = now
	}
	if ct.proto == 0 {
		ct.proto = flow.proto
	}
	var pos *luaConnPos
	if outgoing {
		pos = &ct.posClient
	} else {
		pos = &ct.posServer
	}
	pos.pcounter++
	if flow.payloadLen > 0 {
		pos.pdcounter++
	}
	pos.pbcounter += uint64(flow.payloadLen)
	if flow.family == IPv6 && flow.ip6Flow != 0 {
		pos.ip6Flow = flow.ip6Flow
	}
	if !outgoing && ct.incomingTTL == 0 && flow.ttl != 0 {
		ct.incomingTTL = flow.ttl
	}

	if flow.proto != ipProtoTCP || flow.tcp == nil {
		return
	}

	switch {
	case tcpSynSegment(flow.tcp.flags):
		if ct.state != luaConnStateSyn {
			ct.reinit(L, now)
		}
		ct.ensureTCP(true).seq0 = flow.tcp.seq
	case tcpSynAckSegment(flow.tcp.flags):
		seq0 := flow.tcp.ack - 1
		if ct.state != luaConnStateSyn && ct.ensureTCP(true).seq0 != seq0 {
			ct.reinit(L, now)
		}
		client := ct.ensureTCP(true)
		if client.seq0 == 0 {
			client.seq0 = seq0
		}
		ct.ensureTCP(false).seq0 = flow.tcp.seq
	case flow.tcp.flags&(tcpFlagFIN|tcpFlagRST) != 0:
		ct.state = luaConnStateFin
	default:
		if ct.state == luaConnStateSyn {
			ct.state = luaConnStateEstablished
			if outgoing && ct.ensureTCP(false).seq0 == 0 {
				ct.ensureTCP(false).seq0 = flow.tcp.ack - 1
			}
		}
	}

	ct.applyTCP(flow, outgoing)
}

func (ct *luaConnTrack) applyTCP(flow luaConnFlow, outgoing bool) {
	var directPos *luaConnPos
	if outgoing {
		directPos = &ct.posClient
	} else {
		directPos = &ct.posServer
	}
	if flow.family == IPv6 {
		directPos.ip6Flow = flow.ip6Flow
	}

	direct := ct.ensureTCP(outgoing)
	reverse := ct.ensureTCP(!outgoing)

	direct.winSizeCalc = uint32(flow.tcp.win)
	direct.winSize = flow.tcp.win
	if ct.state == luaConnStateSyn {
		direct.scale = flow.tcp.scale
		if flow.tcp.mss != 0 {
			direct.mss = flow.tcp.mss
		}
	} else {
		direct.winSizeCalc <<= direct.scale
	}

	direct.seqLast = flow.tcp.seq
	direct.pos = flow.tcp.seq + uint32(flow.payloadLen)
	reverse.pos = flow.tcp.ack
	reverse.seqLast = flow.tcp.ack

	if ct.state == luaConnStateSyn {
		direct.upprev = direct.pos
		direct.uppos = direct.pos
	} else if flow.payloadLen > 0 {
		direct.upprev = direct.uppos
		if seqGE(direct.pos, direct.uppos) {
			direct.uppos = direct.pos
		}
	}

	if !direct.rseqOver2G && ((direct.seqLast-direct.seq0)&0x80000000) != 0 {
		direct.rseqOver2G = true
	}
	if !reverse.rseqOver2G && ((reverse.seqLast-reverse.seq0)&0x80000000) != 0 {
		reverse.rseqOver2G = true
	}
}

func (ct *luaConnTrack) ensureTCP(client bool) *luaConnTCPPos {
	var pos *luaConnPos
	if client {
		pos = &ct.posClient
	} else {
		pos = &ct.posServer
	}
	if pos.tcp == nil {
		pos.tcp = &luaConnTCPPos{}
	}
	if !pos.tcp.seq0Set {
		pos.tcp.seq0Set = true
	}
	return pos.tcp
}

func (ct *luaConnTrack) reinit(L *lua.LState, now time.Time) {
	ct.state = luaConnStateSyn
	ct.posClient = luaConnPos{}
	ct.posServer = luaConnPos{}
	ct.start = now
	ct.last = now
	ct.incomingTTL = 0
	ct.luaInCutoff = false
	ct.luaOutCutoff = false
	ct.l7proto = "unknown"
	ct.hostname = ""
	ct.hostnameIsIP = false
	ct.instanceCutoffs = make(map[string]luaCutoffState)
	if L != nil {
		ct.luaState = L.NewTable()
	} else {
		ct.luaState = nil
	}
}

func seqGE(a, b uint32) bool {
	return int32(a-b) >= 0
}

func (ct *luaConnTrack) timeout() time.Duration {
	if ct == nil {
		return luaConntrackTimeoutEst
	}
	switch ct.proto {
	case ipProtoUDP:
		return luaConntrackTimeoutUDP
	case ipProtoTCP:
		switch ct.state {
		case luaConnStateSyn:
			return luaConntrackTimeoutSyn
		case luaConnStateFin:
			return luaConntrackTimeoutFin
		default:
			return luaConntrackTimeoutEst
		}
	default:
		return luaConntrackTimeoutEst
	}
}

func tcpSynSegment(flags uint8) bool {
	return (flags&tcpFlagSYN) != 0 && (flags&tcpFlagACK) == 0
}

func tcpSynAckSegment(flags uint8) bool {
	return (flags&tcpFlagSYN) != 0 && (flags&tcpFlagACK) != 0
}

func (ct *luaConnTrack) setInstanceCutoff(instance string, in, out bool) {
	if instance == "" {
		return
	}
	state := ct.instanceCutoffs[instance]
	if in {
		state.in = true
	}
	if out {
		state.out = true
	}
	ct.instanceCutoffs[instance] = state
}

func (ct *luaConnTrack) instanceCutoff(instance string, outgoing bool) bool {
	state, ok := ct.instanceCutoffs[instance]
	if !ok {
		return false
	}
	if outgoing {
		return state.out
	}
	return state.in
}

func luaConnFlowFromDissect(dis *lua.LTable) (luaConnFlow, bool) {
	if dis == nil {
		return luaConnFlow{}, false
	}

	var flow luaConnFlow
	ip4, _ := dis.RawGetString("ip").(*lua.LTable)
	ip6, _ := dis.RawGetString("ip6").(*lua.LTable)
	switch {
	case ip4 != nil:
		flow.family = IPv4
		flow.src = luaTableBytes(ip4, "ip_src")
		flow.dst = luaTableBytes(ip4, "ip_dst")
		flow.ttl = uint8(luaTableUint(ip4, "ip_ttl", 0))
		flow.proto = uint8(luaTableUint(ip4, "ip_p", 0))
	case ip6 != nil:
		flow.family = IPv6
		flow.src = luaTableBytes(ip6, "ip6_src")
		flow.dst = luaTableBytes(ip6, "ip6_dst")
		flow.ttl = uint8(luaTableUint(ip6, "ip6_hlim", 0))
		flow.ip6Flow = uint32(luaTableUint(ip6, "ip6_flow", 0))
		flow.proto = uint8(luaTableUint(ip6, "ip6_nxt", 0))
	default:
		return luaConnFlow{}, false
	}
	if len(flow.src) == 0 || len(flow.dst) == 0 {
		return luaConnFlow{}, false
	}
	if payload, ok := dis.RawGetString("payload").(lua.LString); ok {
		flow.payloadLen = len(payload)
	}

	if tcp, _ := dis.RawGetString("tcp").(*lua.LTable); tcp != nil {
		flow.proto = ipProtoTCP
		flow.sport = uint16(luaTableUint(tcp, "th_sport", 0))
		flow.dport = uint16(luaTableUint(tcp, "th_dport", 0))
		tcpInfo := &luaConnFlowTCP{
			seq:   uint32(luaTableUint(tcp, "th_seq", 0)),
			ack:   uint32(luaTableUint(tcp, "th_ack", 0)),
			flags: uint8(luaTableUint(tcp, "th_flags", 0)),
			win:   uint16(luaTableUint(tcp, "th_win", 0)),
		}
		parseTCPTrackOptions(tcp, tcpInfo)
		flow.tcp = tcpInfo
		return flow, true
	}
	if udp, _ := dis.RawGetString("udp").(*lua.LTable); udp != nil {
		flow.proto = ipProtoUDP
		flow.sport = uint16(luaTableUint(udp, "uh_sport", 0))
		flow.dport = uint16(luaTableUint(udp, "uh_dport", 0))
		return flow, true
	}
	return luaConnFlow{}, false
}

func parseTCPTrackOptions(tcp *lua.LTable, out *luaConnFlowTCP) {
	if tcp == nil || out == nil {
		return
	}
	opts, _ := tcp.RawGetString("options").(*lua.LTable)
	if opts == nil {
		return
	}
	for i := 1; ; i++ {
		v := opts.RawGetInt(i)
		if v == lua.LNil {
			break
		}
		item, ok := v.(*lua.LTable)
		if !ok {
			continue
		}
		kind := uint8(luaTableUint(item, "kind", 0))
		data := luaTableBytes(item, "data")
		switch kind {
		case 2:
			if len(data) >= 2 {
				out.mss = binary.BigEndian.Uint16(data[:2])
			}
		case 3:
			if len(data) >= 1 {
				out.scale = data[0]
			}
		}
	}
}

func luaConntrackKeys(flow luaConnFlow) (string, string, bool) {
	var addrLen int
	switch flow.family {
	case IPv4:
		addrLen = 4
	case IPv6:
		addrLen = 16
	default:
		return "", "", false
	}
	if len(flow.src) < addrLen || len(flow.dst) < addrLen {
		return "", "", false
	}

	fwd := make([]byte, 0, 2+addrLen*2+4)
	fwd = append(fwd, flow.family, flow.proto)
	fwd = append(fwd, flow.src[:addrLen]...)
	fwd = append(fwd, flow.dst[:addrLen]...)
	fwd = append(fwd, byte(flow.sport>>8), byte(flow.sport))
	fwd = append(fwd, byte(flow.dport>>8), byte(flow.dport))

	rev := make([]byte, 0, len(fwd))
	rev = append(rev, flow.family, flow.proto)
	rev = append(rev, flow.dst[:addrLen]...)
	rev = append(rev, flow.src[:addrLen]...)
	rev = append(rev, byte(flow.dport>>8), byte(flow.dport))
	rev = append(rev, byte(flow.sport>>8), byte(flow.sport))

	return string(fwd), string(rev), true
}

func (r *Runtime) luaTrackTable(ct *luaConnTrack, outgoing bool) *lua.LTable {
	if r == nil || r.L == nil || ct == nil {
		return nil
	}
	t := r.L.NewTable()
	if ct.incomingTTL != 0 {
		t.RawSetString("incoming_ttl", lua.LNumber(ct.incomingTTL))
	}
	t.RawSetString("l7proto", lua.LString(ct.l7proto))
	if ct.hostname != "" {
		t.RawSetString("hostname", lua.LString(ct.hostname))
		t.RawSetString("hostname_is_ip", lua.LBool(ct.hostnameIsIP))
	}
	if ct.luaState != nil {
		t.RawSetString("lua_state", ct.luaState)
	} else {
		t.RawSetString("lua_state", r.L.NewTable())
	}
	t.RawSetString("lua_in_cutoff", lua.LBool(ct.luaInCutoff))
	t.RawSetString("lua_out_cutoff", lua.LBool(ct.luaOutCutoff))
	t.RawSetString("t_start", lua.LNumber(float64(ct.start.UnixNano())/1e9))

	pos := r.L.NewTable()
	dt := ct.last.Sub(ct.start).Seconds()
	if dt < 0 {
		dt = 0
	}
	pos.RawSetString("dt", lua.LNumber(dt))

	client := r.luaTrackPosTable(&ct.posClient)
	server := r.luaTrackPosTable(&ct.posServer)
	pos.RawSetString("client", client)
	pos.RawSetString("server", server)
	if outgoing {
		pos.RawSetString("direct", client)
		pos.RawSetString("reverse", server)
	} else {
		pos.RawSetString("direct", server)
		pos.RawSetString("reverse", client)
	}
	t.RawSetString("pos", pos)

	return t
}

func (r *Runtime) luaTrackPosTable(pos *luaConnPos) *lua.LTable {
	t := r.L.NewTable()
	if pos == nil {
		return t
	}
	t.RawSetString("pcounter", lua.LNumber(pos.pcounter))
	t.RawSetString("pdcounter", lua.LNumber(pos.pdcounter))
	t.RawSetString("pbcounter", lua.LNumber(pos.pbcounter))
	if pos.ip6Flow != 0 {
		t.RawSetString("ip6_flow", lua.LNumber(pos.ip6Flow))
	}
	if pos.tcp != nil && pos.tcp.seq0Set {
		tcp := r.L.NewTable()
		seq0 := pos.tcp.seq0
		tcp.RawSetString("seq0", lua.LNumber(seq0))
		tcp.RawSetString("seq", lua.LNumber(pos.tcp.seqLast))
		tcp.RawSetString("rseq", lua.LNumber(pos.tcp.seqLast-seq0))
		tcp.RawSetString("rseq_over_2G", lua.LBool(pos.tcp.rseqOver2G))
		tcp.RawSetString("pos", lua.LNumber(pos.tcp.pos-seq0))
		tcp.RawSetString("uppos", lua.LNumber(pos.tcp.uppos-seq0))
		tcp.RawSetString("uppos_prev", lua.LNumber(pos.tcp.upprev-seq0))
		tcp.RawSetString("winsize", lua.LNumber(pos.tcp.winSize))
		tcp.RawSetString("winsize_calc", lua.LNumber(pos.tcp.winSizeCalc))
		tcp.RawSetString("scale", lua.LNumber(pos.tcp.scale))
		tcp.RawSetString("mss", lua.LNumber(pos.tcp.mss))
		t.RawSetString("tcp", tcp)
	}
	return t
}
