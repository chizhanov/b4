package lua

import (
	"encoding/binary"
	"errors"

	"github.com/daniellavrushin/b4/sock"
	lua "github.com/yuin/gopher-lua"
)

func reconstructPacketFromLua(dis *lua.LTable, opts *lua.LTable) ([]byte, error) {
	if dis == nil {
		return nil, errors.New("nil dissect")
	}

	payload := luaTableBytes(dis, "payload")

	ip4tbl, _ := dis.RawGetString("ip").(*lua.LTable)
	ip6tbl, _ := dis.RawGetString("ip6").(*lua.LTable)
	tcptbl, _ := dis.RawGetString("tcp").(*lua.LTable)
	udptbl, _ := dis.RawGetString("udp").(*lua.LTable)
	icmptbl, _ := dis.RawGetString("icmp").(*lua.LTable)

	if ip4tbl == nil && ip6tbl == nil {
		out := make([]byte, len(payload))
		copy(out, payload)
		return out, nil
	}

	var (
		l4Proto uint8
		l4Bytes []byte
		err     error
	)

	switch {
	case tcptbl != nil:
		l4Proto = ipProtoTCP
		l4Bytes, err = buildTCPBytes(tcptbl, payload)
	case udptbl != nil:
		l4Proto = ipProtoUDP
		l4Bytes, err = buildUDPBytes(udptbl, payload)
	case icmptbl != nil:
		if ip6tbl != nil {
			l4Proto = ipProtoICMPv6
		} else {
			l4Proto = ipProtoICMP
		}
		l4Bytes, err = buildICMPBytes(icmptbl, payload)
	default:
		l4Bytes = payload
	}
	if err != nil {
		return nil, err
	}

	if ip4tbl != nil {
		return reconstructIPv4FromLua(ip4tbl, l4Bytes, l4Proto)
	}
	return reconstructIPv6FromLua(ip6tbl, l4Bytes, l4Proto, opts)
}

func reconstructIPv4FromLua(ip *lua.LTable, l4 []byte, l4Proto uint8) ([]byte, error) {
	options := luaTableBytes(ip, "options")
	options = padBytes(options, 4)
	ihl := IPv4HeaderMinLen + len(options)

	proto := l4Proto
	if proto == 0 {
		proto = uint8(luaTableUint(ip, "ip_p", 0))
	}
	if proto == 0 {
		proto = ipProtoNone
	}

	packet := make([]byte, ihl+len(l4))
	packet[0] = 0x40 | byte(ihl/4)
	packet[1] = byte(luaTableUint(ip, "ip_tos", 0))
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], uint16(luaTableUint(ip, "ip_id", 0)))
	binary.BigEndian.PutUint16(packet[6:8], uint16(luaTableUint(ip, "ip_off", 0)))
	packet[8] = byte(luaTableUint(ip, "ip_ttl", 64))
	packet[9] = proto
	copy(packet[12:16], fixedLen(luaTableBytes(ip, "ip_src"), 4))
	copy(packet[16:20], fixedLen(luaTableBytes(ip, "ip_dst"), 4))
	copy(packet[20:ihl], options)
	copy(packet[ihl:], l4)

	sock.FixIPv4L4Checksum(packet, ihl, proto)

	return packet, nil
}

func reconstructIPv6FromLua(ip6 *lua.LTable, l4 []byte, l4Proto uint8, opts *lua.LTable) ([]byte, error) {
	preserveNext := luaOptBool(opts, "ip6_preserve_next", false)
	ip6LastProto := uint8(luaOptUint(opts, "ip6_last_proto", uint64(l4Proto)))
	if ip6LastProto == 0 {
		ip6LastProto = uint8(luaTableUint(ip6, "ip6_nxt", ipProtoNone))
	}

	exthdrTbl, _ := ip6.RawGetString("exthdr").(*lua.LTable)
	type exthdrBytes struct {
		typ  uint8
		next uint8
		raw  []byte
	}
	segments := make([]exthdrBytes, 0)
	if exthdrTbl != nil {
		for i := 1; ; i++ {
			v := exthdrTbl.RawGetInt(i)
			if v == lua.LNil {
				break
			}
			item, ok := v.(*lua.LTable)
			if !ok {
				continue
			}
			typeLV := item.RawGetString("type")
			if typeLV == lua.LNil {
				continue
			}
			typ := uint8(luaTableUint(item, "type", 0))
			segments = append(segments, exthdrBytes{typ: typ, raw: luaTableBytes(item, "data")})
		}
	}

	baseNext := ip6LastProto
	if len(segments) > 0 {
		if preserveNext {
			baseNext = uint8(luaTableUint(ip6, "ip6_nxt", uint64(segments[0].typ)))
		} else {
			baseNext = segments[0].typ
		}
	}

	for i := range segments {
		if preserveNext {
			item, _ := exthdrTbl.RawGetInt(i + 1).(*lua.LTable)
			if item != nil {
				segments[i].next = uint8(luaTableUint(item, "next", uint64(ip6LastProto)))
			} else {
				segments[i].next = ip6LastProto
			}
		} else if i+1 < len(segments) {
			segments[i].next = segments[i+1].typ
		} else {
			segments[i].next = ip6LastProto
		}
	}

	exthdrRaw := make([]byte, 0)
	for _, seg := range segments {
		h, err := buildIPv6ExtHeader(seg.typ, seg.next, seg.raw)
		if err != nil {
			return nil, err
		}
		exthdrRaw = append(exthdrRaw, h...)
	}

	packet := make([]byte, IPv6HeaderLen+len(exthdrRaw)+len(l4))
	flow := uint32(luaTableUint(ip6, "ip6_flow", 0x60000000))
	binary.BigEndian.PutUint32(packet[0:4], flow)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(exthdrRaw)+len(l4)))
	packet[6] = baseNext
	packet[7] = byte(luaTableUint(ip6, "ip6_hlim", 64))
	copy(packet[8:24], fixedLen(luaTableBytes(ip6, "ip6_src"), 16))
	copy(packet[24:40], fixedLen(luaTableBytes(ip6, "ip6_dst"), 16))
	copy(packet[40:40+len(exthdrRaw)], exthdrRaw)
	copy(packet[40+len(exthdrRaw):], l4)

	finalProto := ip6LastProto
	if l4Proto != 0 {
		finalProto = l4Proto
	}
	l4Off := IPv6HeaderLen + len(exthdrRaw)
	sock.FixIPv6L4Checksum(packet, l4Off, finalProto)

	return packet, nil
}

func buildTCPBytes(tcp *lua.LTable, payload []byte) ([]byte, error) {
	options := encodeTCPOptions(tcp)
	options = padWithNOP(options)
	hdrLen := TCPHeaderMinLen + len(options)

	out := make([]byte, hdrLen+len(payload))
	binary.BigEndian.PutUint16(out[0:2], uint16(luaTableUint(tcp, "th_sport", 0)))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(tcp, "th_dport", 0)))
	binary.BigEndian.PutUint32(out[4:8], uint32(luaTableUint(tcp, "th_seq", 0)))
	binary.BigEndian.PutUint32(out[8:12], uint32(luaTableUint(tcp, "th_ack", 0)))
	x2 := byte(luaTableUint(tcp, "th_x2", 0)) & 0x0f
	out[12] = byte((hdrLen/4)<<4) | x2
	out[13] = byte(luaTableUint(tcp, "th_flags", 0))
	binary.BigEndian.PutUint16(out[14:16], uint16(luaTableUint(tcp, "th_win", 0)))
	binary.BigEndian.PutUint16(out[16:18], uint16(luaTableUint(tcp, "th_sum", 0)))
	binary.BigEndian.PutUint16(out[18:20], uint16(luaTableUint(tcp, "th_urp", 0)))
	copy(out[20:hdrLen], options)
	copy(out[hdrLen:], payload)
	return out, nil
}

func buildUDPBytes(udp *lua.LTable, payload []byte) ([]byte, error) {
	ulen := luaTableUint(udp, "uh_ulen", uint64(UDPHeaderLen+len(payload)))
	if ulen < UDPHeaderLen {
		ulen = UDPHeaderLen
	}
	out := make([]byte, UDPHeaderLen+len(payload))
	binary.BigEndian.PutUint16(out[0:2], uint16(luaTableUint(udp, "uh_sport", 0)))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(udp, "uh_dport", 0)))
	binary.BigEndian.PutUint16(out[4:6], uint16(ulen))
	binary.BigEndian.PutUint16(out[6:8], uint16(luaTableUint(udp, "uh_sum", 0)))
	copy(out[8:], payload)
	return out, nil
}

func buildICMPBytes(icmp *lua.LTable, payload []byte) ([]byte, error) {
	out := make([]byte, 8+len(payload))
	out[0] = byte(luaTableUint(icmp, "icmp_type", 0))
	out[1] = byte(luaTableUint(icmp, "icmp_code", 0))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(icmp, "icmp_cksum", 0)))
	binary.BigEndian.PutUint32(out[4:8], uint32(luaTableUint(icmp, "icmp_data", 0)))
	copy(out[8:], payload)
	return out, nil
}

func buildIPv6ExtHeader(typ, next uint8, data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, errors.New("invalid ipv6 exthdr data size")
	}
	if typ == ipProtoAH {
		if len(data) >= 1024 || ((len(data)+2)&3) != 0 {
			return nil, errors.New("invalid ipv6 ah exthdr data size")
		}
		total := 2 + len(data)
		b := make([]byte, total)
		b[0] = next
		b[1] = byte(total/4 - 2)
		copy(b[2:], data)
		return b, nil
	}
	if len(data) >= 2048 || ((len(data)+2)&7) != 0 {
		return nil, errors.New("invalid ipv6 exthdr data size")
	}
	total := 2 + len(data)
	b := make([]byte, total)
	b[0] = next
	b[1] = byte(total/8 - 1)
	copy(b[2:], data)
	return b, nil
}

func encodeTCPOptions(tcp *lua.LTable) []byte {
	optsTbl, _ := tcp.RawGetString("options").(*lua.LTable)
	if optsTbl == nil {
		return nil
	}
	out := make([]byte, 0)
	for i := 1; ; i++ {
		v := optsTbl.RawGetInt(i)
		if v == lua.LNil {
			break
		}
		item, ok := v.(*lua.LTable)
		if !ok {
			continue
		}
		kind := uint8(luaTableUint(item, "kind", 0))
		switch kind {
		case 0, 1:
			out = append(out, kind)
		default:
			data := luaTableBytes(item, "data")
			if len(data) > 253 {
				data = data[:253]
			}
			out = append(out, kind, uint8(len(data)+2))
			out = append(out, data...)
		}
	}
	return out
}

func padWithNOP(options []byte) []byte {
	if len(options)%4 == 0 {
		return options
	}
	pad := 4 - (len(options) % 4)
	for i := 0; i < pad; i++ {
		options = append(options, 1)
	}
	return options
}

func padBytes(b []byte, align int) []byte {
	if align <= 1 || len(b)%align == 0 {
		return b
	}
	pad := align - (len(b) % align)
	out := make([]byte, len(b)+pad)
	copy(out, b)
	return out
}

func fixedLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func luaTableBytes(t *lua.LTable, key string) []byte {
	if t == nil {
		return nil
	}
	v := t.RawGetString(key)
	s, ok := v.(lua.LString)
	if !ok {
		return nil
	}
	b := []byte(string(s))
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
