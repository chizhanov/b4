package lua

import (
	"bytes"
	"net"

	"github.com/daniellavrushin/b4/sni"
	lua "github.com/yuin/gopher-lua"
)

func (r *Runtime) buildDesyncContextLocked(req *PacketRequest) *lua.LTable {
	disTbl := r.buildDissectTableLocked(req)
	desync := r.L.NewTable()
	track, outgoing, ok := r.feedConntrackFromDissectLocked(disTbl)
	if ok {
		r.currentTrack = track
		r.currentOutgoing = outgoing
		desync.RawSetString("track", r.luaTrackTable(track, outgoing))
	} else {
		r.currentTrack = nil
		desync.RawSetString("track", lua.LNil)
	}
	desync.RawSetString("dis", disTbl)
	desync.RawSetString("l7payload", lua.LString(detectL7Payload(req)))
	desync.RawSetString("l7proto", lua.LString("unknown"))
	desync.RawSetString("profile_n", lua.LNumber(r.currentProfileN))
	if r.currentProfile != "" {
		desync.RawSetString("profile_name", lua.LString(r.currentProfile))
	}
	if r.currentCookie != "" {
		desync.RawSetString("cookie", lua.LString(r.currentCookie))
	}
	desync.RawSetString("outgoing", lua.LBool(r.currentOutgoing))
	desync.RawSetString("ifin", luaOptionalString(r.L, req.IfIn))
	desync.RawSetString("ifout", luaOptionalString(r.L, req.IfOut))
	if req.FWMark != 0 {
		desync.RawSetString("fwmark", lua.LNumber(req.FWMark))
	} else {
		desync.RawSetString("fwmark", lua.LNumber(r.defaultFWMark))
	}
	desync.RawSetString("target", buildTargetTable(r.L, req, disTbl))

	desync.RawSetString("replay", lua.LBool(req.Replay))
	if req.ReplayPieceCnt > 0 {
		desync.RawSetString("replay_piece", lua.LNumber(req.ReplayPiece))
		desync.RawSetString("replay_piece_count", lua.LNumber(req.ReplayPieceCnt))
		desync.RawSetString("replay_piece_last", lua.LBool(req.ReplayPieceLast))
	}

	desync.RawSetString("reasm_offset", lua.LNumber(req.ReasmOffset))
	if len(req.ReasmData) > 0 {
		desync.RawSetString("reasm_data", lua.LString(string(req.ReasmData)))
	} else {
		desync.RawSetString("reasm_data", lua.LNil)
	}
	if len(req.DecryptData) > 0 {
		desync.RawSetString("decrypt_data", lua.LString(string(req.DecryptData)))
	} else {
		desync.RawSetString("decrypt_data", lua.LNil)
	}

	if ip, _ := disTbl.RawGetString("ip").(*lua.LTable); ip != nil {
		if id := ip.RawGetString("ip_id"); id != lua.LNil {
			desync.RawSetString("ip_id", id)
		}
	}
	desync.RawSetString("tcp_mss", lua.LNumber(luaTrackMSS(track, outgoing)))
	desync.RawSetString("arg", r.L.NewTable())
	desync.RawSetString("set_name", lua.LString(req.SetName))
	return desync
}

func luaOptionalString(L *lua.LState, s string) lua.LValue {
	if s == "" {
		return lua.LNil
	}
	return lua.LString(s)
}

func buildTargetTable(L *lua.LState, req *PacketRequest, dis *lua.LTable) *lua.LTable {
	target := L.NewTable()
	if req == nil {
		return target
	}
	if req.DstPort != 0 {
		target.RawSetString("port", lua.LNumber(req.DstPort))
	}

	if req.Family == IPv4 {
		ip := net.ParseIP(req.DstIP).To4()
		if len(ip) == 4 {
			target.RawSetString("ip", lua.LString(string(ip)))
			return target
		}
	}
	if req.Family == IPv6 {
		ip := net.ParseIP(req.DstIP).To16()
		if len(ip) == 16 {
			target.RawSetString("ip6", lua.LString(string(ip)))
			return target
		}
	}

	if dis != nil {
		if target.RawGetString("port") == lua.LNil {
			if tcp, _ := dis.RawGetString("tcp").(*lua.LTable); tcp != nil {
				if p := luaTableUint(tcp, "th_dport", 0); p != 0 {
					target.RawSetString("port", lua.LNumber(p))
				}
			} else if udp, _ := dis.RawGetString("udp").(*lua.LTable); udp != nil {
				if p := luaTableUint(udp, "uh_dport", 0); p != 0 {
					target.RawSetString("port", lua.LNumber(p))
				}
			}
		}
		if ip, _ := dis.RawGetString("ip").(*lua.LTable); ip != nil {
			if dst := luaTableBytes(ip, "ip_dst"); len(dst) == 4 {
				target.RawSetString("ip", lua.LString(string(dst)))
			}
		}
		if ip6, _ := dis.RawGetString("ip6").(*lua.LTable); ip6 != nil {
			if dst := luaTableBytes(ip6, "ip6_dst"); len(dst) == 16 {
				target.RawSetString("ip6", lua.LString(string(dst)))
			}
		}
	}
	return target
}

func luaTrackMSS(track *luaConnTrack, outgoing bool) uint16 {
	const defaultMSS = 1220
	if track == nil {
		return defaultMSS
	}
	var direct, reverse *luaConnPos
	if outgoing {
		direct = &track.posClient
		reverse = &track.posServer
	} else {
		direct = &track.posServer
		reverse = &track.posClient
	}
	if direct == nil || reverse == nil || direct.tcp == nil || reverse.tcp == nil || direct.tcp.mss == 0 || reverse.tcp.mss == 0 {
		return defaultMSS
	}
	if reverse.tcp.mss > direct.tcp.mss {
		return direct.tcp.mss
	}
	return reverse.tcp.mss
}

func (r *Runtime) buildDissectTableLocked(req *PacketRequest) *lua.LTable {
	if r == nil || r.L == nil || req == nil {
		return nil
	}

	disLV, err := dissectPacketToLua(r.L, req.RawPacket, true)
	if err != nil || disLV == lua.LNil {
		disTbl := r.L.NewTable()
		disTbl.RawSetString("payload", lua.LString(string(req.Payload)))
		return disTbl
	}

	disTbl, _ := disLV.(*lua.LTable)
	if disTbl == nil {
		disTbl = r.L.NewTable()
		disTbl.RawSetString("payload", lua.LString(string(req.Payload)))
	}
	return disTbl
}

func detectL7Payload(req *PacketRequest) string {
	payload := req.Payload
	if len(payload) == 0 {
		return "empty"
	}

	switch req.Proto {
	case ipProtoTCP:
		if isHTTPRequest(payload) {
			return "http_req"
		}
		if isHTTPReply(payload) {
			return "http_reply"
		}
		if len(payload) >= 6 && payload[0] == 0x16 && payload[5] == 0x01 {
			return "tls_client_hello"
		}
		if host, _, _ := sni.ParseTLSClientHelloSNI(payload); host != "" {
			return "tls_client_hello"
		}
		return "unknown"
	case ipProtoUDP:
		switch len(payload) {
		case 148:
			return "wireguard_initiation"
		case 92:
			return "wireguard_response"
		case 64:
			return "wireguard_cookie"
		}
		if bytes.HasPrefix(payload, []byte("d1:")) {
			return "dht"
		}
		return "unknown"
	default:
		return "unknown"
	}
}

func isHTTPRequest(payload []byte) bool {
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
		[]byte("DELETE "), []byte("OPTIONS "), []byte("CONNECT "), []byte("TRACE "), []byte("PATCH "),
	}
	for _, m := range methods {
		if bytes.HasPrefix(payload, m) {
			return true
		}
	}
	return false
}

func isHTTPReply(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("HTTP/1.")) || bytes.HasPrefix(payload, []byte("HTTP/2"))
}
