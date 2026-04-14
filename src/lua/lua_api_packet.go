package lua

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
	lua "github.com/yuin/gopher-lua"
)

func (r *Runtime) luaReconstructIPHdr(L *lua.LState) int {
	ip := L.CheckTable(1)
	raw, err := reconstructIPv4HeaderFromTable(ip)
	if err != nil {
		L.RaiseError("invalid data for iphdr")
		return 0
	}
	L.Push(lua.LString(string(raw)))
	return 1
}

func (r *Runtime) luaReconstructTCPHdr(L *lua.LState) int {
	tcp := L.CheckTable(1)
	raw, err := reconstructTCPHeaderFromTable(tcp)
	if err != nil {
		L.RaiseError("invalid data for tcphdr")
		return 0
	}
	L.Push(lua.LString(string(raw)))
	return 1
}

func (r *Runtime) luaReconstructUDPHdr(L *lua.LState) int {
	udp := L.CheckTable(1)
	raw, err := reconstructUDPHeaderFromTable(udp)
	if err != nil {
		L.RaiseError("invalid data for udphdr")
		return 0
	}
	L.Push(lua.LString(string(raw)))
	return 1
}

func (r *Runtime) luaReconstructICMPHdr(L *lua.LState) int {
	icmp := L.CheckTable(1)
	raw, err := reconstructICMPHeaderFromTable(icmp)
	if err != nil {
		L.RaiseError("invalid data for icmphdr")
		return 0
	}
	L.Push(lua.LString(string(raw)))
	return 1
}

func (r *Runtime) luaReconstructIP6Hdr(L *lua.LState) int {
	ip6 := L.CheckTable(1)
	var opts *lua.LTable
	if v := L.Get(2); v != lua.LNil {
		t, ok := v.(*lua.LTable)
		if !ok {
			L.RaiseError("invalid reconstruct options")
			return 0
		}
		opts = t
	}

	raw, err := reconstructIPv6HeaderFromTable(ip6, opts)
	if err != nil {
		L.RaiseError("invalid data for ip6hdr")
		return 0
	}
	L.Push(lua.LString(string(raw)))
	return 1
}

func (r *Runtime) luaDissectTCPHdr(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	t, _, ok := dissectTCPToLua(L, raw, false)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(t)
	return 1
}

func (r *Runtime) luaDissectUDPHdr(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	u, _, ok := dissectUDPToLua(L, raw, false)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(u)
	return 1
}

func (r *Runtime) luaDissectICMPHdr(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	ic, _, ok := dissectICMPToLua(L, raw, false)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(ic)
	return 1
}

func (r *Runtime) luaDissectIPHdr(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	if len(raw) < IPv4HeaderMinLen || (raw[0]>>4) != IPv4 {
		L.Push(lua.LNil)
		return 1
	}
	v, err := dissectIPv4ToLua(L, raw, false)
	if err != nil || v == lua.LNil {
		L.Push(lua.LNil)
		return 1
	}
	pkt, ok := v.(*lua.LTable)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(pkt.RawGetString("ip"))
	return 1
}

func (r *Runtime) luaDissectIP6Hdr(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	if len(raw) < IPv6HeaderLen || (raw[0]>>4) != IPv6 {
		L.Push(lua.LNil)
		return 1
	}
	v, err := dissectIPv6ToLua(L, raw, false)
	if err != nil || v == lua.LNil {
		L.Push(lua.LNil)
		return 1
	}
	pkt, ok := v.(*lua.LTable)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(pkt.RawGetString("ip6"))
	return 1
}

func (r *Runtime) luaCsumIP4Fix(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	ihl, ok := parseIPv4HeaderLen(raw)
	if !ok || len(raw) > 60 {
		L.RaiseError("invalid ip header")
		return 0
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	out[10], out[11] = 0, 0
	cs := checksum16(out[:ihl])
	binary.BigEndian.PutUint16(out[10:12], cs)
	L.Push(lua.LString(string(out)))
	return 1
}

func (r *Runtime) luaCsumTCPFix(L *lua.LState) int {
	ipRaw := []byte(L.CheckString(1))
	tcpRaw := []byte(L.CheckString(2))
	payload := []byte(L.CheckString(3))
	if len(payload) > 0xFFFF {
		L.RaiseError("invalid payload length")
		return 0
	}
	if !isValidTCPHeader(tcpRaw) {
		L.RaiseError("invalid tcp header")
		return 0
	}
	family, src, dst, err := parseIPForChecksum(ipRaw)
	if err != nil {
		L.RaiseError("invalid ip header")
		return 0
	}

	seg := make([]byte, len(tcpRaw)+len(payload))
	copy(seg, tcpRaw)
	copy(seg[len(tcpRaw):], payload)
	seg[16], seg[17] = 0, 0

	sum := uint32(0)
	switch family {
	case IPv4:
		sum = checksumAcc(sum, buildPseudoIPv4(src, dst, uint16(len(seg)), ipProtoTCP))
	case IPv6:
		sum = checksumAcc(sum, buildPseudoIPv6(src, dst, uint32(len(seg)), ipProtoTCP))
	}
	sum = checksumAcc(sum, seg)
	binary.BigEndian.PutUint16(seg[16:18], checksumFold(sum))

	L.Push(lua.LString(string(seg[:len(tcpRaw)])))
	return 1
}

func (r *Runtime) luaCsumUDPFix(L *lua.LState) int {
	ipRaw := []byte(L.CheckString(1))
	udpRaw := []byte(L.CheckString(2))
	payload := []byte(L.CheckString(3))
	if len(payload) > 0xFFFF {
		L.RaiseError("invalid payload length")
		return 0
	}
	if len(udpRaw) < UDPHeaderLen {
		L.RaiseError("invalid udp header")
		return 0
	}
	family, src, dst, err := parseIPForChecksum(ipRaw)
	if err != nil {
		L.RaiseError("invalid ip header")
		return 0
	}

	seg := make([]byte, len(udpRaw)+len(payload))
	copy(seg, udpRaw)
	copy(seg[len(udpRaw):], payload)
	seg[6], seg[7] = 0, 0

	sum := uint32(0)
	switch family {
	case IPv4:
		sum = checksumAcc(sum, buildPseudoIPv4(src, dst, uint16(len(seg)), ipProtoUDP))
	case IPv6:
		sum = checksumAcc(sum, buildPseudoIPv6(src, dst, uint32(len(seg)), ipProtoUDP))
	}
	sum = checksumAcc(sum, seg)
	cs := checksumFold(sum)
	if cs == 0 {
		cs = 0xFFFF
	}
	binary.BigEndian.PutUint16(seg[6:8], cs)

	L.Push(lua.LString(string(seg[:len(udpRaw)])))
	return 1
}

func (r *Runtime) luaCsumICMPFix(L *lua.LState) int {
	ipRaw := []byte(L.CheckString(1))
	icmpRaw := []byte(L.CheckString(2))
	payload := []byte(L.CheckString(3))
	if len(payload) > 0xFFFF {
		L.RaiseError("invalid payload length")
		return 0
	}
	if len(icmpRaw) < 8 {
		L.RaiseError("invalid icmp header")
		return 0
	}
	family, src, dst, err := parseIPForChecksum(ipRaw)
	if err != nil {
		L.RaiseError("invalid ip header")
		return 0
	}

	seg := make([]byte, len(icmpRaw)+len(payload))
	copy(seg, icmpRaw)
	copy(seg[len(icmpRaw):], payload)
	seg[2], seg[3] = 0, 0

	sum := uint32(0)
	if family == IPv6 {
		sum = checksumAcc(sum, buildPseudoIPv6(src, dst, uint32(len(seg)), ipProtoICMPv6))
	}
	sum = checksumAcc(sum, seg)
	binary.BigEndian.PutUint16(seg[2:4], checksumFold(sum))

	L.Push(lua.LString(string(seg[:len(icmpRaw)])))
	return 1
}

func (r *Runtime) luaRawsend(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	if _, _, err := packetDestination(raw); err != nil {
		L.RaiseError("bad ip4/ip6 header")
		return 0
	}
	opts := r.luaRawsendParseOptions(L, 2)
	ok := r.luaSendRawPacket(raw, opts)
	L.Push(lua.LBool(ok))
	return 1
}

func (r *Runtime) luaRawsendDissect(L *lua.LState) int {
	dis := L.CheckTable(1)
	var reconstructOpts *lua.LTable
	if L.GetTop() >= 3 {
		if v := L.Get(3); v != lua.LNil {
			t, ok := v.(*lua.LTable)
			if !ok {
				L.RaiseError("invalid reconstruct options")
				return 0
			}
			reconstructOpts = t
		}
	}
	raw, err := reconstructPacketFromLua(dis, reconstructOpts)
	if err != nil {
		L.RaiseError("invalid dissect data")
		return 0
	}
	if _, _, err := packetDestination(raw); err != nil {
		L.RaiseError("bad ip4/ip6 header")
		return 0
	}
	opts := r.luaRawsendParseOptions(L, 2)
	L.Push(lua.LBool(r.luaSendRawPacket(raw, opts)))
	return 1
}

type luaRawsendOptions struct {
	repeats int
	fwmark  uint32
	ifout   string
}

func (r *Runtime) luaRawsendParseOptions(L *lua.LState, idx int) luaRawsendOptions {
	opts := luaRawsendOptions{
		repeats: 1,
		fwmark:  r.defaultFWMark,
	}
	if idx > L.GetTop() || L.Get(idx) == lua.LNil {
		return opts
	}

	t, ok := L.Get(idx).(*lua.LTable)
	if !ok {
		L.RaiseError("rawsend: options must be a table")
		return opts
	}

	if lv := t.RawGetString("repeats"); lv != lua.LNil {
		repeats := int(luaLValueToInt64(lv))
		if repeats < 0 {
			L.RaiseError("rawsend: negative repeats")
			return opts
		}
		if repeats > 0 {
			opts.repeats = repeats
		}
	}

	if lv := t.RawGetString("fwmark"); lv != lua.LNil {
		opts.fwmark = uint32(luaLValueToInt64(lv)) | r.defaultFWMark
	}

	if lv := t.RawGetString("ifout"); lv != lua.LNil {
		if s, ok := lv.(lua.LString); ok {
			opts.ifout = string(s)
		}
	}

	return opts
}

func (r *Runtime) luaSendRawPacket(raw []byte, opts luaRawsendOptions) bool {
	if len(raw) == 0 {
		return false
	}
	family, dst, err := packetDestination(raw)
	if err != nil {
		return false
	}

	sender, err := r.rawSenderForOptions(opts)
	if err != nil {
		log.Tracef("lua rawsend sender init failed: %v", err)
		return false
	}

	for i := 0; i < opts.repeats; i++ {
		switch family {
		case IPv4:
			if err := sender.SendIPv4(raw, dst); err != nil {
				log.Tracef("lua rawsend ipv4 failed: %v", err)
				return false
			}
		case IPv6:
			if err := sender.SendIPv6(raw, dst); err != nil {
				log.Tracef("lua rawsend ipv6 failed: %v", err)
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (r *Runtime) rawSenderForOptions(opts luaRawsendOptions) (*sock.Sender, error) {
	key := fmt.Sprintf("%d|%s", opts.fwmark, opts.ifout)
	if s := r.senderCache[key]; s != nil {
		return s, nil
	}
	s, err := sock.NewSenderWithMarkAndInterface(int(opts.fwmark), opts.ifout)
	if err != nil {
		return nil, err
	}
	r.senderCache[key] = s
	return s, nil
}

func packetDestination(raw []byte) (uint8, net.IP, error) {
	if len(raw) < 1 {
		return 0, nil, errors.New("empty packet")
	}
	ver := raw[0] >> 4
	switch ver {
	case IPv4:
		if len(raw) < IPv4HeaderMinLen {
			return 0, nil, errors.New("short ipv4 packet")
		}
		ihl := int(raw[0]&0x0F) * 4
		if ihl < IPv4HeaderMinLen || len(raw) < ihl {
			return 0, nil, errors.New("invalid ipv4 header")
		}
		dst := append(net.IP(nil), raw[16:20]...)
		return IPv4, dst, nil
	case IPv6:
		if len(raw) < IPv6HeaderLen {
			return 0, nil, errors.New("short ipv6 packet")
		}
		dst := append(net.IP(nil), raw[24:40]...)
		return IPv6, dst, nil
	default:
		return 0, nil, errors.New("unsupported ip version")
	}
}

func (r *Runtime) luaGetSourceIP(L *lua.LState) int {
	target := []byte(L.CheckString(1))
	src, err := getSourceIPBestEffort(target)
	if err != nil || len(src) == 0 {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(string(src)))
	return 1
}

func (r *Runtime) luaGetIfaddrs(L *lua.LState) int {
	out := L.NewTable()

	ifs, err := net.Interfaces()
	if err != nil {
		populateIfaddrsFallback(L, out)
		L.Push(out)
		return 1
	}

	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		addrTbl := L.NewTable()
		addrIdx := 1
		for _, a := range addrs {
			ip, mask := addrIPAndMask(a)
			if ip == nil {
				continue
			}

			v4 := ip.To4()
			if v4 != nil {
				entry := L.NewTable()
				entry.RawSetString("addr", lua.LString(string(v4)))
				if len(mask) == 4 {
					entry.RawSetString("netmask", lua.LString(string(mask)))
					bcast := make([]byte, 4)
					for i := 0; i < 4; i++ {
						bcast[i] = v4[i] | ^mask[i]
					}
					entry.RawSetString("broadcast", lua.LString(string(bcast)))
				}
				addrTbl.RawSetInt(addrIdx, entry)
				addrIdx++
				continue
			}

			v6 := ip.To16()
			if v6 == nil {
				continue
			}
			entry := L.NewTable()
			entry.RawSetString("addr", lua.LString(string(v6)))
			if len(mask) == 16 {
				entry.RawSetString("netmask", lua.LString(string(mask)))
			}
			addrTbl.RawSetInt(addrIdx, entry)
			addrIdx++
		}

		if addrIdx == 1 {
			continue
		}

		ifTbl := L.NewTable()
		ifTbl.RawSetString("index", lua.LNumber(iface.Index))
		ifTbl.RawSetString("flags", lua.LNumber(uint64(iface.Flags)))
		ifTbl.RawSetString("mtu", lua.LNumber(iface.MTU))
		ifTbl.RawSetString("addr", addrTbl)
		out.RawSetString(iface.Name, ifTbl)
	}

	if out.Len() == 0 {
		populateIfaddrsFallback(L, out)
	}

	L.Push(out)
	return 1
}

func populateIfaddrsFallback(L *lua.LState, out *lua.LTable) {
	if out == nil {
		return
	}
	if out.Len() != 0 {
		return
	}

	addrTbl := L.NewTable()

	v4 := L.NewTable()
	v4.RawSetString("addr", lua.LString(string([]byte{127, 0, 0, 1})))
	v4.RawSetString("netmask", lua.LString(string([]byte{255, 0, 0, 0})))
	v4.RawSetString("broadcast", lua.LString(string([]byte{127, 255, 255, 255})))
	addrTbl.RawSetInt(1, v4)

	v6 := L.NewTable()
	v6.RawSetString("addr", lua.LString(string([]byte{
		0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	})))
	v6.RawSetString("netmask", lua.LString(string([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})))
	addrTbl.RawSetInt(2, v6)

	ifTbl := L.NewTable()
	ifTbl.RawSetString("index", lua.LNumber(1))
	ifTbl.RawSetString("flags", lua.LNumber(0))
	ifTbl.RawSetString("mtu", lua.LNumber(65536))
	ifTbl.RawSetString("addr", addrTbl)
	out.RawSetString("lo", ifTbl)
}

func reconstructIPv4HeaderFromTable(ip *lua.LTable) ([]byte, error) {
	if ip == nil {
		return nil, errors.New("nil ip table")
	}
	if _, ok := ip.RawGetString("ip_ttl").(lua.LNumber); !ok {
		return nil, errors.New("ip_ttl is required")
	}
	if _, ok := ip.RawGetString("ip_p").(lua.LNumber); !ok {
		return nil, errors.New("ip_p is required")
	}

	src, ok := ip.RawGetString("ip_src").(lua.LString)
	if !ok || len(src) != 4 {
		return nil, errors.New("ip_src is required")
	}
	dst, ok := ip.RawGetString("ip_dst").(lua.LString)
	if !ok || len(dst) != 4 {
		return nil, errors.New("ip_dst is required")
	}

	options := []byte(nil)
	if v := ip.RawGetString("options"); v != lua.LNil {
		if s, ok := v.(lua.LString); ok {
			options = []byte(string(s))
		}
	}
	if len(options) > 40 {
		return nil, errors.New("options too large")
	}
	options = padBytes(options, 4)
	ihl := IPv4HeaderMinLen + len(options)
	if ihl > 60 {
		return nil, errors.New("invalid ihl")
	}

	out := make([]byte, ihl)
	out[0] = 0x40 | byte(ihl/4)
	out[1] = byte(luaTableUint(ip, "ip_tos", 0))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(ip, "ip_len", 0)))
	binary.BigEndian.PutUint16(out[4:6], uint16(luaTableUint(ip, "ip_id", 0)))
	binary.BigEndian.PutUint16(out[6:8], uint16(luaTableUint(ip, "ip_off", 0)))
	out[8] = byte(luaTableUint(ip, "ip_ttl", 0))
	out[9] = byte(luaTableUint(ip, "ip_p", 0))
	copy(out[12:16], []byte(string(src)))
	copy(out[16:20], []byte(string(dst)))
	copy(out[20:], options)
	sock.FixIPv4Checksum(out)
	return out, nil
}

func reconstructTCPHeaderFromTable(tcp *lua.LTable) ([]byte, error) {
	if tcp == nil {
		return nil, errors.New("nil tcp table")
	}
	required := []string{"th_sport", "th_dport", "th_seq", "th_ack", "th_flags", "th_win"}
	for _, k := range required {
		if _, ok := tcp.RawGetString(k).(lua.LNumber); !ok {
			return nil, fmt.Errorf("%s is required", k)
		}
	}

	options := encodeTCPOptions(tcp)
	options = padWithNOP(options)
	if len(options) > 40 {
		return nil, errors.New("tcp options too large")
	}
	hdrLen := TCPHeaderMinLen + len(options)
	out := make([]byte, hdrLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(luaTableUint(tcp, "th_sport", 0)))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(tcp, "th_dport", 0)))
	binary.BigEndian.PutUint32(out[4:8], uint32(luaTableUint(tcp, "th_seq", 0)))
	binary.BigEndian.PutUint32(out[8:12], uint32(luaTableUint(tcp, "th_ack", 0)))
	x2 := byte(luaTableUint(tcp, "th_x2", 0)) & 0x0F
	out[12] = byte((hdrLen/4)<<4) | x2
	out[13] = byte(luaTableUint(tcp, "th_flags", 0))
	binary.BigEndian.PutUint16(out[14:16], uint16(luaTableUint(tcp, "th_win", 0)))
	binary.BigEndian.PutUint16(out[16:18], uint16(luaTableUint(tcp, "th_sum", 0)))
	binary.BigEndian.PutUint16(out[18:20], uint16(luaTableUint(tcp, "th_urp", 0)))
	copy(out[20:], options)
	return out, nil
}

func reconstructUDPHeaderFromTable(udp *lua.LTable) ([]byte, error) {
	if udp == nil {
		return nil, errors.New("nil udp table")
	}
	if _, ok := udp.RawGetString("uh_sport").(lua.LNumber); !ok {
		return nil, errors.New("uh_sport is required")
	}
	if _, ok := udp.RawGetString("uh_dport").(lua.LNumber); !ok {
		return nil, errors.New("uh_dport is required")
	}
	out := make([]byte, UDPHeaderLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(luaTableUint(udp, "uh_sport", 0)))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(udp, "uh_dport", 0)))
	binary.BigEndian.PutUint16(out[4:6], uint16(luaTableUint(udp, "uh_ulen", 0)))
	binary.BigEndian.PutUint16(out[6:8], uint16(luaTableUint(udp, "uh_sum", 0)))
	return out, nil
}

func reconstructICMPHeaderFromTable(icmp *lua.LTable) ([]byte, error) {
	if icmp == nil {
		return nil, errors.New("nil icmp table")
	}
	if _, ok := icmp.RawGetString("icmp_type").(lua.LNumber); !ok {
		return nil, errors.New("icmp_type is required")
	}
	if _, ok := icmp.RawGetString("icmp_code").(lua.LNumber); !ok {
		return nil, errors.New("icmp_code is required")
	}
	out := make([]byte, 8)
	out[0] = byte(luaTableUint(icmp, "icmp_type", 0))
	out[1] = byte(luaTableUint(icmp, "icmp_code", 0))
	binary.BigEndian.PutUint16(out[2:4], uint16(luaTableUint(icmp, "icmp_cksum", 0)))
	binary.BigEndian.PutUint32(out[4:8], uint32(luaTableUint(icmp, "icmp_data", 0)))
	return out, nil
}

func reconstructIPv6HeaderFromTable(ip6 *lua.LTable, opts *lua.LTable) ([]byte, error) {
	if ip6 == nil {
		return nil, errors.New("nil ip6 table")
	}

	src, ok := ip6.RawGetString("ip6_src").(lua.LString)
	if !ok || len(src) != 16 {
		return nil, errors.New("ip6_src is required")
	}
	dst, ok := ip6.RawGetString("ip6_dst").(lua.LString)
	if !ok || len(dst) != 16 {
		return nil, errors.New("ip6_dst is required")
	}

	flow := uint32(0x60000000)
	if v, ok := ip6.RawGetString("ip6_flow").(lua.LNumber); ok {
		flow = uint32(v)
	}
	nxt := uint8(luaTableUint(ip6, "ip6_nxt", 0))
	hlim := uint8(luaTableUint(ip6, "ip6_hlim", 0))

	preserveNext := luaOptBool(opts, "ip6_preserve_next", false)
	lastProto := uint8(luaOptUint(opts, "ip6_last_proto", uint64(ipProtoNone)))

	headers := make([][]byte, 0)
	exthdrTbl, _ := ip6.RawGetString("exthdr").(*lua.LTable)
	if exthdrTbl != nil {
		for i := 1; ; i++ {
			v := exthdrTbl.RawGetInt(i)
			if v == lua.LNil {
				break
			}
			item, ok := v.(*lua.LTable)
			if !ok {
				return nil, errors.New("invalid exthdr item")
			}
			typeLV := item.RawGetString("type")
			typeNum, ok := typeLV.(lua.LNumber)
			if !ok {
				return nil, errors.New("invalid exthdr type")
			}
			typ := uint8(typeNum)

			next := uint8(ipProtoNone)
			if n, ok := item.RawGetString("next").(lua.LNumber); ok {
				next = uint8(n)
			}

			dataLV := item.RawGetString("data")
			dataStr, ok := dataLV.(lua.LString)
			if !ok {
				return nil, errors.New("invalid exthdr data")
			}
			data := []byte(string(dataStr))
			if len(data) < 6 {
				return nil, errors.New("invalid exthdr data size")
			}

			var hdr []byte
			if typ == ipProtoAH {
				if len(data) >= 1024 || ((len(data)+2)&3) != 0 {
					return nil, errors.New("invalid ah exthdr size")
				}
				hdr = make([]byte, len(data)+2)
				copy(hdr[2:], data)
				hdr[1] = byte((len(hdr) / 4) - 2)
			} else {
				if len(data) >= 2048 || ((len(data)+2)&7) != 0 {
					return nil, errors.New("invalid exthdr size")
				}
				hdr = make([]byte, len(data)+2)
				copy(hdr[2:], data)
				hdr[1] = byte((len(hdr) / 8) - 1)
			}
			hdr[0] = next
			headers = append(headers, hdr)

			if !preserveNext {
				if len(headers) == 1 {
					nxt = typ
				} else {
					headers[len(headers)-2][0] = typ
				}
			}
		}
	}

	if !preserveNext {
		if len(headers) == 0 {
			nxt = lastProto
		} else {
			headers[len(headers)-1][0] = lastProto
		}
	}

	payloadLenSet := false
	var payloadLen uint16
	if v := ip6.RawGetString("ip6_plen"); v != lua.LNil {
		switch x := v.(type) {
		case lua.LNumber:
			payloadLen = uint16(x)
			payloadLenSet = true
		case lua.LString:
			n, ok := parseLuaInteger(string(x))
			if !ok || n < 0 {
				return nil, errors.New("invalid ip6_plen")
			}
			payloadLen = uint16(n)
			payloadLenSet = true
		default:
			return nil, errors.New("invalid ip6_plen type")
		}
	}

	extLen := 0
	for _, h := range headers {
		extLen += len(h)
	}

	out := make([]byte, IPv6HeaderLen+extLen)
	binary.BigEndian.PutUint32(out[0:4], flow)
	if payloadLenSet {
		binary.BigEndian.PutUint16(out[4:6], payloadLen)
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(extLen))
	}
	out[6] = nxt
	out[7] = hlim
	copy(out[8:24], []byte(string(src)))
	copy(out[24:40], []byte(string(dst)))

	off := IPv6HeaderLen
	for _, h := range headers {
		copy(out[off:], h)
		off += len(h)
	}
	return out, nil
}

func parseIPv4HeaderLen(raw []byte) (int, bool) {
	if len(raw) < IPv4HeaderMinLen || (raw[0]>>4) != IPv4 {
		return 0, false
	}
	ihl := int(raw[0]&0x0F) * 4
	if ihl < IPv4HeaderMinLen || ihl > len(raw) {
		return 0, false
	}
	return ihl, true
}

func isValidTCPHeader(raw []byte) bool {
	if len(raw) < TCPHeaderMinLen {
		return false
	}
	hdrLen := int((raw[12]>>4)&0x0F) * 4
	if hdrLen < TCPHeaderMinLen || hdrLen > len(raw) {
		return false
	}
	return true
}

func parseIPForChecksum(ipRaw []byte) (int, []byte, []byte, error) {
	if len(ipRaw) < 1 {
		return 0, nil, nil, errors.New("empty ip")
	}
	ver := ipRaw[0] >> 4
	switch ver {
	case IPv4:
		_, ok := parseIPv4HeaderLen(ipRaw)
		if !ok {
			return 0, nil, nil, errors.New("invalid ipv4")
		}
		return IPv4, ipRaw[12:16], ipRaw[16:20], nil
	case IPv6:
		if len(ipRaw) < IPv6HeaderLen {
			return 0, nil, nil, errors.New("invalid ipv6")
		}
		return IPv6, ipRaw[8:24], ipRaw[24:40], nil
	default:
		return 0, nil, nil, errors.New("unsupported ip version")
	}
}

func buildPseudoIPv4(src, dst []byte, l4Len uint16, proto uint8) []byte {
	p := make([]byte, 12)
	copy(p[0:4], src)
	copy(p[4:8], dst)
	p[8] = 0
	p[9] = proto
	binary.BigEndian.PutUint16(p[10:12], l4Len)
	return p
}

func buildPseudoIPv6(src, dst []byte, l4Len uint32, proto uint8) []byte {
	p := make([]byte, 40)
	copy(p[0:16], src)
	copy(p[16:32], dst)
	binary.BigEndian.PutUint32(p[32:36], l4Len)
	p[39] = proto
	return p
}

func checksum16(b []byte) uint16 {
	return checksumFold(checksumAcc(0, b))
}

func checksumAcc(sum uint32, b []byte) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func addrIPAndMask(addr net.Addr) (net.IP, net.IPMask) {
	switch a := addr.(type) {
	case *net.IPNet:
		if v4 := a.IP.To4(); v4 != nil {
			if len(a.Mask) >= 4 {
				return append(net.IP(nil), v4...), append(net.IPMask(nil), a.Mask[len(a.Mask)-4:]...)
			}
			return append(net.IP(nil), v4...), nil
		}
		if v6 := a.IP.To16(); v6 != nil {
			if len(a.Mask) >= 16 {
				return append(net.IP(nil), v6...), append(net.IPMask(nil), a.Mask[len(a.Mask)-16:]...)
			}
			return append(net.IP(nil), v6...), nil
		}
	case *net.IPAddr:
		if v4 := a.IP.To4(); v4 != nil {
			return append(net.IP(nil), v4...), nil
		}
		if v6 := a.IP.To16(); v6 != nil {
			return append(net.IP(nil), v6...), nil
		}
	}
	return nil, nil
}

func getSourceIPBestEffort(target []byte) ([]byte, error) {
	src, err := getSourceIPByDial(target)
	if err == nil && len(src) > 0 {
		return src, nil
	}
	fallback := pickLocalIPByFamily(len(target))
	if len(fallback) > 0 {
		return fallback, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("source ip not found")
}

func getSourceIPByDial(target []byte) ([]byte, error) {
	switch len(target) {
	case 4:
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(target), Port: 9})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		la, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok || la == nil {
			return nil, errors.New("no local addr")
		}
		ip := la.IP.To4()
		if ip == nil {
			return nil, errors.New("no ipv4 local addr")
		}
		return []byte(ip), nil
	case 16:
		conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IP(target), Port: 9})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		la, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok || la == nil {
			return nil, errors.New("no local addr")
		}
		ip := la.IP.To16()
		if ip == nil {
			return nil, errors.New("no ipv6 local addr")
		}
		return []byte(ip), nil
	default:
		return nil, fmt.Errorf("invalid IP length %d", len(target))
	}
}

func pickLocalIPByFamily(targetLen int) []byte {
	ifs, err := net.Interfaces()
	if err != nil {
		return loopbackByFamily(targetLen)
	}
	var fallback []byte
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _ := addrIPAndMask(a)
			if ip == nil {
				continue
			}
			var raw []byte
			switch targetLen {
			case 4:
				v4 := ip.To4()
				if v4 == nil {
					continue
				}
				raw = v4
			case 16:
				v6 := ip.To16()
				if v6 == nil {
					continue
				}
				raw = v6
			default:
				return nil
			}

			if !ip.IsLoopback() {
				return []byte(raw)
			}
			if fallback == nil {
				fallback = []byte(raw)
			}
		}
	}
	if fallback != nil {
		return fallback
	}
	return loopbackByFamily(targetLen)
}

func loopbackByFamily(targetLen int) []byte {
	switch targetLen {
	case 4:
		return []byte{127, 0, 0, 1}
	case 16:
		return []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}
	default:
		return nil
	}
}
