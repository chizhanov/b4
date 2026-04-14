package lua

import (
	"encoding/binary"
	"errors"
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

func dissectPacketToLua(L *lua.LState, raw []byte, partialOK bool) (lua.LValue, error) {
	if len(raw) == 0 {
		return lua.LNil, errors.New("empty packet")
	}

	ver := raw[0] >> 4
	switch ver {
	case IPv4:
		return dissectIPv4ToLua(L, raw, partialOK)
	case IPv6:
		return dissectIPv6ToLua(L, raw, partialOK)
	default:
		return lua.LNil, fmt.Errorf("unsupported ip version: %d", ver)
	}
}

func dissectIPv4ToLua(L *lua.LState, raw []byte, partialOK bool) (lua.LValue, error) {
	if len(raw) < IPv4HeaderMinLen {
		if partialOK {
			return lua.LNil, nil
		}
		return lua.LNil, errors.New("short ipv4 header")
	}

	ihl := int(raw[0]&0x0f) * 4
	if ihl < IPv4HeaderMinLen || len(raw) < ihl {
		if partialOK {
			return lua.LNil, nil
		}
		return lua.LNil, errors.New("invalid ipv4 ihl")
	}

	pkt := L.NewTable()
	ip := L.NewTable()
	pkt.RawSetString("ip", ip)

	ip.RawSetString("ip_tos", lua.LNumber(raw[1]))
	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	ip.RawSetString("ip_len", lua.LNumber(totalLen))
	ip.RawSetString("ip_id", lua.LNumber(binary.BigEndian.Uint16(raw[4:6])))
	ip.RawSetString("ip_off", lua.LNumber(binary.BigEndian.Uint16(raw[6:8])))
	ip.RawSetString("ip_ttl", lua.LNumber(raw[8]))
	ip.RawSetString("ip_p", lua.LNumber(raw[9]))
	ip.RawSetString("ip_sum", lua.LNumber(binary.BigEndian.Uint16(raw[10:12])))
	ip.RawSetString("ip_src", lua.LString(string(raw[12:16])))
	ip.RawSetString("ip_dst", lua.LString(string(raw[16:20])))
	if ihl > IPv4HeaderMinLen {
		ip.RawSetString("options", lua.LString(string(raw[20:ihl])))
	} else {
		ip.RawSetString("options", lua.LString(""))
	}

	if totalLen >= ihl {
		if !partialOK && len(raw) < totalLen {
			return lua.LNil, errors.New("truncated ipv4 payload")
		}
		if totalLen <= len(raw) {
			raw = raw[:totalLen]
		}
	}

	proto := raw[9]
	payloadStart := ihl
	ipOff := binary.BigEndian.Uint16(raw[6:8])
	isFragment := (ipOff&0x1fff) != 0 || (ipOff&0x2000) != 0

	if !isFragment {
		switch proto {
		case ipProtoTCP:
			if t, p, ok := dissectTCPToLua(L, raw[ihl:], partialOK); ok {
				pkt.RawSetString("tcp", t)
				payloadStart = ihl + p
			}
		case ipProtoUDP:
			if u, p, ok := dissectUDPToLua(L, raw[ihl:], partialOK); ok {
				pkt.RawSetString("udp", u)
				payloadStart = ihl + p
			}
		case ipProtoICMP:
			if ic, p, ok := dissectICMPToLua(L, raw[ihl:], partialOK); ok {
				pkt.RawSetString("icmp", ic)
				payloadStart = ihl + p
			}
		}
	}

	if payloadStart < 0 || payloadStart > len(raw) {
		payloadStart = len(raw)
	}
	pkt.RawSetString("payload", lua.LString(string(raw[payloadStart:])))

	return pkt, nil
}

func dissectIPv6ToLua(L *lua.LState, raw []byte, partialOK bool) (lua.LValue, error) {
	if len(raw) < IPv6HeaderLen {
		if partialOK {
			return lua.LNil, nil
		}
		return lua.LNil, errors.New("short ipv6 header")
	}

	pkt := L.NewTable()
	ip6 := L.NewTable()
	pkt.RawSetString("ip6", ip6)

	flow := binary.BigEndian.Uint32(raw[0:4])
	plen := binary.BigEndian.Uint16(raw[4:6])
	next := raw[6]
	hlim := raw[7]

	ip6.RawSetString("ip6_flow", lua.LNumber(flow))
	ip6.RawSetString("ip6_plen", lua.LNumber(plen))
	ip6.RawSetString("ip6_nxt", lua.LNumber(next))
	ip6.RawSetString("ip6_hlim", lua.LNumber(hlim))
	ip6.RawSetString("ip6_src", lua.LString(string(raw[8:24])))
	ip6.RawSetString("ip6_dst", lua.LString(string(raw[24:40])))

	totalLen := IPv6HeaderLen + int(plen)
	if !partialOK && len(raw) < totalLen {
		return lua.LNil, errors.New("truncated ipv6 payload")
	}
	if totalLen <= len(raw) {
		raw = raw[:totalLen]
	}

	offset := IPv6HeaderLen
	cur := next
	exthdr := L.NewTable()
	exthdrIdx := 1

	for {
		if !isIPv6ExtHeader(cur) {
			break
		}
		if offset+2 > len(raw) {
			if !partialOK {
				return lua.LNil, errors.New("truncated ipv6 extension header")
			}
			break
		}
		nextHdr := raw[offset]
		hdrLen := 0
		switch cur {
		case ipProtoFragment:
			hdrLen = 8
		case ipProtoAH:
			hdrLen = (int(raw[offset+1]) + 2) * 4
		default:
			hdrLen = (int(raw[offset+1]) + 1) * 8
		}
		if hdrLen < 2 || offset+hdrLen > len(raw) {
			if !partialOK {
				return lua.LNil, errors.New("invalid ipv6 extension header length")
			}
			break
		}

		item := L.NewTable()
		item.RawSetString("type", lua.LNumber(cur))
		item.RawSetString("next", lua.LNumber(nextHdr))
		item.RawSetString("data", lua.LString(string(raw[offset+2:offset+hdrLen])))
		exthdr.RawSetInt(exthdrIdx, item)
		exthdrIdx++

		offset += hdrLen
		cur = nextHdr
	}

	if exthdrIdx > 1 {
		ip6.RawSetString("exthdr", exthdr)
	}

	payloadStart := offset
	switch cur {
	case ipProtoTCP:
		if t, p, ok := dissectTCPToLua(L, raw[offset:], partialOK); ok {
			pkt.RawSetString("tcp", t)
			payloadStart = offset + p
		}
	case ipProtoUDP:
		if u, p, ok := dissectUDPToLua(L, raw[offset:], partialOK); ok {
			pkt.RawSetString("udp", u)
			payloadStart = offset + p
		}
	case ipProtoICMPv6:
		if ic, p, ok := dissectICMPToLua(L, raw[offset:], partialOK); ok {
			pkt.RawSetString("icmp", ic)
			payloadStart = offset + p
		}
	}

	if payloadStart < 0 || payloadStart > len(raw) {
		payloadStart = len(raw)
	}
	pkt.RawSetString("payload", lua.LString(string(raw[payloadStart:])))
	return pkt, nil
}

func dissectTCPToLua(L *lua.LState, raw []byte, partialOK bool) (*lua.LTable, int, bool) {
	if len(raw) < TCPHeaderMinLen {
		return nil, 0, false
	}
	hdrLen := int((raw[12]>>4)&0x0f) * 4
	if hdrLen < TCPHeaderMinLen || hdrLen > len(raw) {
		if partialOK {
			return nil, 0, false
		}
		return nil, 0, false
	}

	t := L.NewTable()
	t.RawSetString("th_sport", lua.LNumber(binary.BigEndian.Uint16(raw[0:2])))
	t.RawSetString("th_dport", lua.LNumber(binary.BigEndian.Uint16(raw[2:4])))
	t.RawSetString("th_seq", lua.LNumber(binary.BigEndian.Uint32(raw[4:8])))
	t.RawSetString("th_ack", lua.LNumber(binary.BigEndian.Uint32(raw[8:12])))
	t.RawSetString("th_x2", lua.LNumber(raw[12]&0x0f))
	t.RawSetString("th_flags", lua.LNumber(raw[13]))
	t.RawSetString("th_win", lua.LNumber(binary.BigEndian.Uint16(raw[14:16])))
	t.RawSetString("th_sum", lua.LNumber(binary.BigEndian.Uint16(raw[16:18])))
	t.RawSetString("th_urp", lua.LNumber(binary.BigEndian.Uint16(raw[18:20])))

	t.RawSetString("options", tcpOptionsToLua(L, raw[20:hdrLen]))
	return t, hdrLen, true
}

func dissectUDPToLua(L *lua.LState, raw []byte, partialOK bool) (*lua.LTable, int, bool) {
	if len(raw) < UDPHeaderLen {
		return nil, 0, false
	}
	u := L.NewTable()
	u.RawSetString("uh_sport", lua.LNumber(binary.BigEndian.Uint16(raw[0:2])))
	u.RawSetString("uh_dport", lua.LNumber(binary.BigEndian.Uint16(raw[2:4])))
	u.RawSetString("uh_ulen", lua.LNumber(binary.BigEndian.Uint16(raw[4:6])))
	u.RawSetString("uh_sum", lua.LNumber(binary.BigEndian.Uint16(raw[6:8])))
	return u, UDPHeaderLen, true
}

func dissectICMPToLua(L *lua.LState, raw []byte, partialOK bool) (*lua.LTable, int, bool) {
	if len(raw) < 8 {
		return nil, 0, false
	}
	ic := L.NewTable()
	ic.RawSetString("icmp_type", lua.LNumber(raw[0]))
	ic.RawSetString("icmp_code", lua.LNumber(raw[1]))
	ic.RawSetString("icmp_cksum", lua.LNumber(binary.BigEndian.Uint16(raw[2:4])))
	ic.RawSetString("icmp_data", lua.LNumber(binary.BigEndian.Uint32(raw[4:8])))
	return ic, 8, true
}

func tcpOptionsToLua(L *lua.LState, raw []byte) *lua.LTable {
	t := L.NewTable()
	idx := 1
	for i := 0; i < len(raw); {
		kind := raw[i]
		item := L.NewTable()
		item.RawSetString("kind", lua.LNumber(kind))
		i++
		if kind == 0 || kind == 1 {
			t.RawSetInt(idx, item)
			idx++
			if kind == 0 {
				for i < len(raw) {
					if raw[i] != 0 {
						break
					}
					n := L.NewTable()
					n.RawSetString("kind", lua.LNumber(0))
					t.RawSetInt(idx, n)
					idx++
					i++
				}
			}
			continue
		}
		if i >= len(raw) {
			break
		}
		optLen := int(raw[i])
		i++
		if optLen < 2 || i+optLen-2 > len(raw) {
			break
		}
		if optLen > 2 {
			item.RawSetString("data", lua.LString(string(raw[i:i+optLen-2])))
		}
		t.RawSetInt(idx, item)
		idx++
		i += optLen - 2
	}
	return t
}

func isIPv6ExtHeader(proto uint8) bool {
	switch proto {
	case ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts:
		return true
	default:
		return false
	}
}
