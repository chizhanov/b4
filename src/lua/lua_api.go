package lua

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/log"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/unix"
)

const luaCompatVersion = 5
const luaU48Mask = uint64(0xFFFFFFFFFFFF)

func (r *Runtime) registerRuntimeAPI(L *lua.LState) {
	setConst := func(name string, value uint64) {
		L.SetGlobal(name, lua.LNumber(value))
	}

	setConst("NFQWS2_COMPAT_VER", luaCompatVersion)
	setConst("VERDICT_PASS", uint64(VerdictPass))
	setConst("VERDICT_MODIFY", uint64(VerdictModify))
	setConst("VERDICT_DROP", uint64(VerdictDrop))
	setConst("VERDICT_MASK", uint64(VerdictMask))
	setConst("VERDICT_PRESERVE_NEXT", uint64(VerdictPreserveNext))

	setConst("IP_BASE_LEN", IPv4HeaderMinLen)
	setConst("IP6_BASE_LEN", IPv6HeaderLen)
	setConst("TCP_BASE_LEN", TCPHeaderMinLen)
	setConst("UDP_BASE_LEN", UDPHeaderLen)
	setConst("ICMP_BASE_LEN", 8)

	setConst("IPPROTO_NONE", ipProtoNone)
	setConst("IPPROTO_ICMP", ipProtoICMP)
	setConst("IPPROTO_IPIP", ipProtoIPIP)
	setConst("IPPROTO_TCP", ipProtoTCP)
	setConst("IPPROTO_UDP", ipProtoUDP)
	setConst("IPPROTO_IPV6", ipProtoIPv6)
	setConst("IPPROTO_ROUTING", ipProtoRouting)
	setConst("IPPROTO_FRAGMENT", ipProtoFragment)
	setConst("IPPROTO_AH", ipProtoAH)
	setConst("IPPROTO_ICMPV6", ipProtoICMPv6)
	setConst("IPPROTO_HOPOPTS", ipProtoHopByHop)
	setConst("IPPROTO_DSTOPTS", ipProtoDestOpts)

	setConst("TH_FIN", 0x01)
	setConst("TH_SYN", 0x02)
	setConst("TH_RST", 0x04)
	setConst("TH_PUSH", 0x08)
	setConst("TH_ACK", 0x10)
	setConst("TH_URG", 0x20)
	setConst("TH_ECE", 0x40)
	setConst("TH_CWR", 0x80)

	setConst("TCP_KIND_END", 0)
	setConst("TCP_KIND_NOOP", 1)
	setConst("TCP_KIND_MSS", 2)
	setConst("TCP_KIND_SCALE", 3)
	setConst("TCP_KIND_SACK_PERMITTED", 4)
	setConst("TCP_KIND_SACK", 5)
	setConst("TCP_KIND_TS", 8)
	setConst("TCP_KIND_MD5", 19)

	setConst("IP_MF", 0x2000)
	setConst("IP6F_MORE_FRAG", 0x0001)
	setConst("DEFAULT_MSS", 1220)

	setConst("ICMP_ECHOREPLY", 0)
	setConst("ICMP_DEST_UNREACH", 3)
	setConst("ICMP_UNREACH_PORT", 3)
	setConst("ICMP_ECHO", 8)
	setConst("ICMP6_ECHO_REQUEST", 128)
	setConst("ICMP6_ECHO_REPLY", 129)

	registerDefaultBlobs(L)

	L.SetGlobal("DLOG", L.NewFunction(r.luaDLOG))
	L.SetGlobal("DLOG_ERR", L.NewFunction(r.luaDLOGErr))
	L.SetGlobal("DLOG_CONDUP", L.NewFunction(r.luaDLOGCondup))
	L.SetGlobal("DLOG_WARN", L.NewFunction(r.luaDLOGWarn))
	L.SetGlobal("DLOG_INFO", L.NewFunction(r.luaDLOGInfo))

	L.SetGlobal("getpid", L.NewFunction(luaGetpid))
	L.SetGlobal("gettid", L.NewFunction(luaGettid))
	L.SetGlobal("clock_gettime", L.NewFunction(luaClockGettime))
	L.SetGlobal("clock_getfloattime", L.NewFunction(luaClockGetfloattime))
	L.SetGlobal("localtime", L.NewFunction(luaLocaltime))
	L.SetGlobal("gmtime", L.NewFunction(luaGmtime))
	L.SetGlobal("timelocal", L.NewFunction(luaTimelocal))
	L.SetGlobal("timegm", L.NewFunction(luaTimegm))

	L.SetGlobal("bitand", L.NewFunction(luaBitAnd))
	L.SetGlobal("bitor", L.NewFunction(luaBitOr))
	L.SetGlobal("bitxor", L.NewFunction(luaBitXor))
	L.SetGlobal("bitnot", L.NewFunction(luaBitNot))
	L.SetGlobal("bitnot8", L.NewFunction(luaBitNot8))
	L.SetGlobal("bitnot16", L.NewFunction(luaBitNot16))
	L.SetGlobal("bitnot24", L.NewFunction(luaBitNot24))
	L.SetGlobal("bitnot32", L.NewFunction(luaBitNot32))
	L.SetGlobal("bitnot48", L.NewFunction(luaBitNot48))
	L.SetGlobal("bitlshift", L.NewFunction(luaBitLShift))
	L.SetGlobal("bitrshift", L.NewFunction(luaBitRShift))
	L.SetGlobal("bitget", L.NewFunction(luaBitGet))
	L.SetGlobal("bitset", L.NewFunction(luaBitSet))

	L.SetGlobal("band", L.NewFunction(luaBand))
	L.SetGlobal("bor", L.NewFunction(luaBor))
	L.SetGlobal("bxor", L.NewFunction(luaBxor))
	L.SetGlobal("bnot", L.NewFunction(luaBnot))

	L.SetGlobal("u8", L.NewFunction(luaU8))
	L.SetGlobal("u16", L.NewFunction(luaU16))
	L.SetGlobal("u24", L.NewFunction(luaU24))
	L.SetGlobal("u32", L.NewFunction(luaU32))
	L.SetGlobal("u48", L.NewFunction(luaU48))
	L.SetGlobal("bu8", L.NewFunction(luaBU8))
	L.SetGlobal("bu16", L.NewFunction(luaBU16))
	L.SetGlobal("bu24", L.NewFunction(luaBU24))
	L.SetGlobal("bu32", L.NewFunction(luaBU32))
	L.SetGlobal("bu48", L.NewFunction(luaBU48))

	L.SetGlobal("u8add", L.NewFunction(luaU8Add))
	L.SetGlobal("u16add", L.NewFunction(luaU16Add))
	L.SetGlobal("u24add", L.NewFunction(luaU24Add))
	L.SetGlobal("u32add", L.NewFunction(luaU32Add))
	L.SetGlobal("u48add", L.NewFunction(luaU48Add))
	L.SetGlobal("divint", L.NewFunction(luaDivInt))

	L.SetGlobal("swap16", L.NewFunction(luaSwap16))
	L.SetGlobal("swap24", L.NewFunction(luaSwap24))
	L.SetGlobal("swap32", L.NewFunction(luaSwap32))
	L.SetGlobal("swap48", L.NewFunction(luaSwap48))

	L.SetGlobal("parse_hex", L.NewFunction(luaParseHex))
	L.SetGlobal("brandom", L.NewFunction(luaBrandom))
	L.SetGlobal("brandom_az", L.NewFunction(luaBrandomAZ))
	L.SetGlobal("brandom_az09", L.NewFunction(luaBrandomAZ09))
	L.SetGlobal("bcryptorandom", L.NewFunction(luaBCryptoRandom))
	L.SetGlobal("gzip_init", L.NewFunction(luaGzipInit))
	L.SetGlobal("gzip_deflate", L.NewFunction(luaGzipDeflate))
	L.SetGlobal("gzip_end", L.NewFunction(luaGzipEnd))
	L.SetGlobal("gunzip_init", L.NewFunction(luaGunzipInit))
	L.SetGlobal("gunzip_inflate", L.NewFunction(luaGunzipInflate))
	L.SetGlobal("gunzip_end", L.NewFunction(luaGunzipEnd))

	L.SetGlobal("raw_packet", L.NewFunction(r.luaRawPacket))
	L.SetGlobal("reconstruct_tcphdr", L.NewFunction(r.luaReconstructTCPHdr))
	L.SetGlobal("reconstruct_udphdr", L.NewFunction(r.luaReconstructUDPHdr))
	L.SetGlobal("reconstruct_icmphdr", L.NewFunction(r.luaReconstructICMPHdr))
	L.SetGlobal("reconstruct_ip6hdr", L.NewFunction(r.luaReconstructIP6Hdr))
	L.SetGlobal("reconstruct_iphdr", L.NewFunction(r.luaReconstructIPHdr))
	L.SetGlobal("dissect", L.NewFunction(r.luaDissect))
	L.SetGlobal("dissect_tcphdr", L.NewFunction(r.luaDissectTCPHdr))
	L.SetGlobal("dissect_udphdr", L.NewFunction(r.luaDissectUDPHdr))
	L.SetGlobal("dissect_icmphdr", L.NewFunction(r.luaDissectICMPHdr))
	L.SetGlobal("dissect_ip6hdr", L.NewFunction(r.luaDissectIP6Hdr))
	L.SetGlobal("dissect_iphdr", L.NewFunction(r.luaDissectIPHdr))
	L.SetGlobal("reconstruct_dissect", L.NewFunction(r.luaReconstructDissect))
	L.SetGlobal("csum_ip4_fix", L.NewFunction(r.luaCsumIP4Fix))
	L.SetGlobal("csum_tcp_fix", L.NewFunction(r.luaCsumTCPFix))
	L.SetGlobal("csum_udp_fix", L.NewFunction(r.luaCsumUDPFix))
	L.SetGlobal("csum_icmp_fix", L.NewFunction(r.luaCsumICMPFix))

	L.SetGlobal("resolve_pos", L.NewFunction(r.luaResolvePos))
	L.SetGlobal("resolve_multi_pos", L.NewFunction(r.luaResolveMultiPos))
	L.SetGlobal("resolve_range", L.NewFunction(r.luaResolveRange))

	L.SetGlobal("execution_plan", L.NewFunction(r.luaExecutionPlan))
	L.SetGlobal("execution_plan_cancel", L.NewFunction(r.luaExecutionPlanCancel))
	L.SetGlobal("instance_cutoff", L.NewFunction(r.luaInstanceCutoff))
	L.SetGlobal("lua_cutoff", L.NewFunction(r.luaLuaCutoff))
	L.SetGlobal("conntrack_feed", L.NewFunction(r.luaConntrackFeed))

	L.SetGlobal("rawsend", L.NewFunction(r.luaRawsend))
	L.SetGlobal("rawsend_dissect", L.NewFunction(r.luaRawsendDissect))
	L.SetGlobal("get_source_ip", L.NewFunction(r.luaGetSourceIP))
	L.SetGlobal("get_ifaddrs", L.NewFunction(r.luaGetIfaddrs))

	L.SetGlobal("pton", L.NewFunction(luaPton))
	L.SetGlobal("ntop", L.NewFunction(luaNtop))
	L.SetGlobal("uname", L.NewFunction(luaUname))
	L.SetGlobal("stat", L.NewFunction(luaStat))

	L.SetGlobal("hkdf", L.NewFunction(luaHKDF))
	L.SetGlobal("hash", L.NewFunction(luaHash))
	L.SetGlobal("aes", L.NewFunction(luaAES))
	L.SetGlobal("aes_ctr", L.NewFunction(luaAESCTR))
	L.SetGlobal("aes_gcm", L.NewFunction(luaAESGCM))
	L.SetGlobal("tls_mod", L.NewFunction(luaTLSMod))

	L.SetGlobal("timer_set", L.NewFunction(r.luaTimerSet))
	L.SetGlobal("timer_del", L.NewFunction(r.luaTimerDel))
}

func (r *Runtime) luaDLOG(L *lua.LState) int {
	log.Tracef("[lua] %s", luaToStringAny(L.Get(1)))
	return 0
}

func (r *Runtime) luaDLOGErr(L *lua.LState) int {
	_ = log.Errorf("[lua] %s", luaToStringAny(L.Get(1)))
	return 0
}

func (r *Runtime) luaDLOGCondup(L *lua.LState) int {
	log.Infof("[lua] %s", luaToStringAny(L.Get(1)))
	return 0
}

func (r *Runtime) luaDLOGWarn(L *lua.LState) int {
	log.Warnf("[lua] %s", luaToStringAny(L.Get(1)))
	return 0
}

func (r *Runtime) luaDLOGInfo(L *lua.LState) int {
	log.Infof("[lua] %s", luaToStringAny(L.Get(1)))
	return 0
}

func (r *Runtime) luaRawPacket(L *lua.LState) int {
	if r.currentReq == nil {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(string(r.currentReq.RawPacket)))
	return 1
}

func (r *Runtime) luaDissect(L *lua.LState) int {
	raw := []byte(L.CheckString(1))
	partial := L.OptBool(2, false)
	v, err := dissectPacketToLua(L, raw, partial)
	if err != nil || v == lua.LNil {
		out := L.NewTable()
		out.RawSetString("payload", lua.LString(string(raw)))
		L.Push(out)
		return 1
	}
	L.Push(v)
	return 1
}

func (r *Runtime) luaReconstructDissect(L *lua.LState) int {
	dis := L.CheckTable(1)
	var opts *lua.LTable
	if v := L.Get(2); v != lua.LNil {
		if t, ok := v.(*lua.LTable); ok {
			opts = t
		}
	}

	raw, err := reconstructPacketFromLua(dis, opts)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(string(raw)))
	return 1
}

func (r *Runtime) luaExecutionPlan(L *lua.LState) int {
	start := 0
	if r.currentPlanIdx >= 0 {
		start = r.currentPlanIdx + 1
	}
	setName := ""
	if r.currentReq != nil {
		setName = strings.TrimSpace(r.currentReq.SetName)
	}
	plan := r.L.NewTable()
	idx := 1
	for i := start; i < len(r.cfg.ExecutionPlan); i++ {
		raw := r.cfg.ExecutionPlan[i]
		if setName != "" && strings.TrimSpace(raw.SetName) != "" && strings.TrimSpace(raw.SetName) != setName {
			continue
		}
		inst := r.buildPlanInstanceTable(i, raw, r.currentOutgoing)
		plan.RawSetInt(idx, inst)
		idx++
	}
	L.Push(plan)
	return 1
}

func (r *Runtime) luaExecutionPlanCancel(L *lua.LState) int {
	r.cancelRemaining = true
	return 0
}

func (r *Runtime) luaUnsupportedNoop(name string) lua.LGFunction {
	return func(L *lua.LState) int {
		r.warnUnsupported(name)
		return 0
	}
}

func (r *Runtime) luaUnsupportedNil(name string) lua.LGFunction {
	return func(L *lua.LState) int {
		r.warnUnsupported(name)
		L.Push(lua.LNil)
		return 1
	}
}

func (r *Runtime) luaUnsupportedFalse(name string) lua.LGFunction {
	return func(L *lua.LState) int {
		r.warnUnsupported(name)
		L.Push(lua.LBool(false))
		return 1
	}
}

func (r *Runtime) warnUnsupported(name string) {
	if _, ok := r.unsupportedWarn[name]; ok {
		return
	}
	r.unsupportedWarn[name] = struct{}{}
	log.Warnf("Lua API '%s' is not implemented in current MVP runtime", name)
}

func (r *Runtime) luaResolvePos(L *lua.LState) int {
	data := []byte(L.CheckString(1))
	l7 := L.CheckString(2)
	expr := L.CheckString(3)
	zeroBased := L.OptBool(4, false)

	pos, ok := resolveMarkerExpr(data, l7, expr)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	if !zeroBased {
		pos++
	}
	L.Push(lua.LNumber(pos))
	return 1
}

func (r *Runtime) luaResolveMultiPos(L *lua.LState) int {
	data := []byte(L.CheckString(1))
	l7 := L.CheckString(2)
	exprList := L.CheckString(3)
	zeroBased := L.OptBool(4, false)

	parts := strings.Split(exprList, ",")
	out := L.NewTable()
	idx := 1
	positions := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pos, ok := resolveMarkerExpr(data, l7, p)
		if !ok {
			continue
		}
		positions = append(positions, pos)
	}
	if len(positions) == 0 {
		L.Push(lua.LNil)
		return 1
	}
	sort.Ints(positions)
	uniq := positions[:1]
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[i-1] {
			uniq = append(uniq, positions[i])
		}
	}
	for _, pos := range uniq {
		if !zeroBased {
			pos++
		}
		out.RawSetInt(idx, lua.LNumber(pos))
		idx++
	}
	L.Push(out)
	return 1
}

func (r *Runtime) luaResolveRange(L *lua.LState) int {
	data := []byte(L.CheckString(1))
	l7 := L.CheckString(2)
	expr := L.CheckString(3)
	strict := L.OptBool(4, false)
	zeroBased := L.OptBool(5, false)

	parts := strings.Split(expr, ",")
	if len(parts) < 2 {
		L.Push(lua.LNil)
		return 1
	}
	p1, ok1 := resolveMarkerExpr(data, l7, strings.TrimSpace(parts[0]))
	p2, ok2 := resolveMarkerExpr(data, l7, strings.TrimSpace(parts[1]))
	if (!ok1 && !ok2) || (strict && (!ok1 || !ok2)) {
		L.Push(lua.LNil)
		return 1
	}
	if !ok1 {
		p1 = 0
	}
	if !ok2 {
		p2 = len(data) - 1
	}
	if p1 > p2 {
		L.Push(lua.LNil)
		return 1
	}
	if !zeroBased {
		p1++
		p2++
	}
	out := L.NewTable()
	out.RawSetInt(1, lua.LNumber(p1))
	out.RawSetInt(2, lua.LNumber(p2))
	L.Push(out)
	return 1
}

func luaGetpid(L *lua.LState) int {
	L.Push(lua.LNumber(os.Getpid()))
	return 1
}

func luaGettid(L *lua.LState) int {
	L.Push(lua.LNumber(unix.Gettid()))
	return 1
}

func luaClockGettime(L *lua.LState) int {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}
	L.Push(lua.LNumber(ts.Sec))
	L.Push(lua.LNumber(ts.Nsec))
	return 2
}

func luaClockGetfloattime(L *lua.LState) int {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts); err != nil {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LNumber(float64(ts.Sec) + float64(ts.Nsec)/1e9))
	return 1
}

func luaLocaltime(L *lua.LState) int {
	sec := luaArgInt64(L, 1)
	L.Push(luaTimeTable(L, time.Unix(sec, 0).In(time.Local), sec))
	return 1
}

func luaGmtime(L *lua.LState) int {
	sec := luaArgInt64(L, 1)
	L.Push(luaTimeTable(L, time.Unix(sec, 0).UTC(), sec))
	return 1
}

func luaTimelocal(L *lua.LState) int {
	t := L.CheckTable(1)
	tt, isdst, ok := luaTableToTime(t, time.Local)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	tt = applyIsDSTHint(tt, isdst)
	L.Push(lua.LNumber(tt.Unix()))
	return 1
}

func luaTimegm(L *lua.LState) int {
	t := L.CheckTable(1)
	tt, _, ok := luaTableToTime(t, time.UTC)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LNumber(tt.Unix()))
	return 1
}

func luaTimeTable(L *lua.LState, t time.Time, unix int64) *lua.LTable {
	out := L.NewTable()
	out.RawSetString("sec", lua.LNumber(t.Second()))
	out.RawSetString("min", lua.LNumber(t.Minute()))
	out.RawSetString("hour", lua.LNumber(t.Hour()))
	out.RawSetString("mday", lua.LNumber(t.Day()))
	out.RawSetString("mon", lua.LNumber(int(t.Month())-1))
	out.RawSetString("year", lua.LNumber(t.Year()))
	out.RawSetString("wday", lua.LNumber(int(t.Weekday())))
	out.RawSetString("yday", lua.LNumber(t.YearDay()-1))
	if t.IsDST() {
		out.RawSetString("isdst", lua.LNumber(1))
	} else {
		out.RawSetString("isdst", lua.LNumber(0))
	}
	zone, _ := t.Zone()
	out.RawSetString("zone", lua.LString(zone))
	out.RawSetString("str", lua.LString(t.Format("02.01.2006 15:04:05")))
	out.RawSetString("unix", lua.LNumber(unix))
	return out
}

func luaTableToTime(t *lua.LTable, loc *time.Location) (time.Time, int, bool) {
	sec, ok := luaFieldInt(t, "sec")
	if !ok {
		return time.Time{}, 0, false
	}
	min, ok := luaFieldInt(t, "min")
	if !ok {
		return time.Time{}, 0, false
	}
	hour, ok := luaFieldInt(t, "hour")
	if !ok {
		return time.Time{}, 0, false
	}
	mday, ok := luaFieldInt(t, "mday")
	if !ok {
		return time.Time{}, 0, false
	}
	mon, ok := luaFieldInt(t, "mon")
	if !ok {
		return time.Time{}, 0, false
	}
	year, ok := luaFieldInt(t, "year")
	if !ok {
		return time.Time{}, 0, false
	}
	isdst, ok := luaFieldInt(t, "isdst")
	if !ok {
		return time.Time{}, 0, false
	}
	return time.Date(year, time.Month(mon+1), mday, hour, min, sec, 0, loc), isdst, true
}

func luaFieldInt(t *lua.LTable, key string) (int, bool) {
	v := t.RawGetString(key)
	switch x := v.(type) {
	case lua.LNumber:
		return int(x), true
	case lua.LString:
		n, ok := parseLuaInteger(string(x))
		if !ok {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func applyIsDSTHint(t time.Time, isdst int) time.Time {
	// Lua tm.isdst semantics: -1 means unknown, 0 standard time, >0 daylight time.
	if isdst < 0 {
		return t
	}
	if isdst == 0 && t.IsDST() {
		for i := 0; i < 3 && t.IsDST(); i++ {
			t = t.Add(-time.Hour)
		}
		return t
	}
	if isdst > 0 && !t.IsDST() {
		for i := 0; i < 3 && !t.IsDST(); i++ {
			t = t.Add(time.Hour)
		}
	}
	return t
}

func luaBitAnd(L *lua.LState) int {
	if L.GetTop() < 2 {
		L.RaiseError("bitand: invalid arg count")
		return 0
	}
	v := luaU48Mask
	for i := 1; i <= L.GetTop(); i++ {
		v &= luaCheckU48Arg(L, i)
	}
	L.Push(lua.LNumber(v))
	return 1
}

func luaBitOr(L *lua.LState) int {
	if L.GetTop() < 1 {
		L.RaiseError("bitor: invalid arg count")
		return 0
	}
	v := uint64(0)
	for i := 1; i <= L.GetTop(); i++ {
		v |= luaCheckU48Arg(L, i)
	}
	L.Push(lua.LNumber(v))
	return 1
}

func luaBitXor(L *lua.LState) int {
	if L.GetTop() < 1 {
		L.RaiseError("bitxor: invalid arg count")
		return 0
	}
	v := uint64(0)
	for i := 1; i <= L.GetTop(); i++ {
		v ^= luaCheckU48Arg(L, i)
	}
	L.Push(lua.LNumber(v))
	return 1
}

func luaBitNot(L *lua.LState) int {
	return luaBitNotX(L, luaU48Mask)
}

func luaBitNot8(L *lua.LState) int {
	return luaBitNotX(L, 0xFF)
}

func luaBitNot16(L *lua.LState) int {
	return luaBitNotX(L, 0xFFFF)
}

func luaBitNot24(L *lua.LState) int {
	return luaBitNotX(L, 0xFFFFFF)
}

func luaBitNot32(L *lua.LState) int {
	return luaBitNotX(L, 0xFFFFFFFF)
}

func luaBitNot48(L *lua.LState) int {
	return luaBitNotX(L, luaU48Mask)
}

func luaBitNotX(L *lua.LState, max uint64) int {
	i := luaArgInt64(L, 1)
	if i > int64(max) || i < -int64(max) {
		L.RaiseError("out of range")
		return 0
	}
	v := uint64(i)
	L.Push(lua.LNumber((^v) & max))
	return 1
}

func luaBitLShift(L *lua.LState) int {
	v := luaCheckU48Arg(L, 1)
	s := luaCheckBitShiftArg(L, 2)
	L.Push(lua.LNumber((v << s) & luaU48Mask))
	return 1
}

func luaBitRShift(L *lua.LState) int {
	v := luaCheckU48Arg(L, 1)
	s := luaCheckBitShiftArg(L, 2)
	L.Push(lua.LNumber(v >> s))
	return 1
}

func luaBitGet(L *lua.LState) int {
	v := luaCheckU48Arg(L, 1)
	from, to := luaCheckBitRangeArgs(L, 2, 3)
	mask := uint64(1)<<(to-from+1) - 1
	L.Push(lua.LNumber((v >> from) & mask))
	return 1
}

func luaBitSet(L *lua.LState) int {
	v := luaCheckU48Arg(L, 1)
	from, to := luaCheckBitRangeArgs(L, 2, 3)
	set := luaCheckU48Arg(L, 4)
	mask := uint64(1)<<(to-from+1) - 1
	res := (v & ^(mask << from)) | ((set & mask) << from)
	L.Push(lua.LNumber(res & luaU48Mask))
	return 1
}

func luaBand(L *lua.LState) int {
	return luaBinaryBitOp(L, func(a, b byte) byte { return a & b }, func(a, b uint32) uint32 { return a & b })
}
func luaBor(L *lua.LState) int {
	return luaBinaryBitOp(L, func(a, b byte) byte { return a | b }, func(a, b uint32) uint32 { return a | b })
}
func luaBxor(L *lua.LState) int {
	return luaBinaryBitOp(L, func(a, b byte) byte { return a ^ b }, func(a, b uint32) uint32 { return a ^ b })
}

func luaBnot(L *lua.LState) int {
	if s, ok := L.Get(1).(lua.LString); ok {
		b := []byte(string(s))
		for i := range b {
			b[i] = ^b[i]
		}
		L.Push(lua.LString(string(b)))
		return 1
	}
	L.Push(lua.LNumber(^uint32(luaArgUint64(L, 1))))
	return 1
}

func luaBinaryBitOp(L *lua.LState, bop func(a, b byte) byte, nop func(a, b uint32) uint32) int {
	if s1, ok1 := L.Get(1).(lua.LString); ok1 {
		s2, ok2 := L.Get(2).(lua.LString)
		if !ok2 {
			L.Push(lua.LNil)
			return 1
		}
		b1 := []byte(string(s1))
		b2 := []byte(string(s2))
		if len(b1) != len(b2) {
			L.RaiseError("string lengths must be the same")
			return 0
		}
		out := make([]byte, len(b1))
		for i := range b1 {
			out[i] = bop(b1[i], b2[i])
		}
		L.Push(lua.LString(string(out)))
		return 1
	}
	v1 := uint32(luaCheckU48Arg(L, 1))
	v2 := uint32(luaCheckU48Arg(L, 2))
	L.Push(lua.LNumber(uint64(nop(v1, v2)) & luaU48Mask))
	return 1
}

func luaCheckU48Arg(L *lua.LState, idx int) uint64 {
	v := luaArgInt64(L, idx)
	if v > int64(luaU48Mask) || v < -int64(luaU48Mask) {
		L.RaiseError("out of range")
		return 0
	}
	return uint64(v) & luaU48Mask
}

func luaCheckBitShiftArg(L *lua.LState, idx int) uint {
	s := luaArgInt64(L, idx)
	if s < 0 || s > 48 {
		L.RaiseError("out of range")
		return 0
	}
	return uint(s)
}

func luaCheckBitRangeArgs(L *lua.LState, fromIdx, toIdx int) (uint, uint) {
	from := luaArgInt64(L, fromIdx)
	to := luaArgInt64(L, toIdx)
	if from < 0 || to < 0 || from > to || from > 47 || to > 47 {
		L.RaiseError("bit range invalid")
		return 0, 0
	}
	return uint(from), uint(to)
}

func luaU8(L *lua.LState) int  { return luaReadUintN(L, 1) }
func luaU16(L *lua.LState) int { return luaReadUintN(L, 2) }
func luaU24(L *lua.LState) int { return luaReadUintN(L, 3) }
func luaU32(L *lua.LState) int { return luaReadUintN(L, 4) }
func luaU48(L *lua.LState) int { return luaReadUintN(L, 6) }

func luaReadUintN(L *lua.LState, n int) int {
	v := L.Get(1)
	if num, ok := v.(lua.LNumber); ok {
		mask := uint64(1)<<(8*uint(n)) - 1
		L.Push(lua.LNumber(uint64(num) & mask))
		return 1
	}
	s, ok := v.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	buf := []byte(string(s))
	off := int(luaArgUint64Default(L, 2, 1)) - 1
	if off < 0 || off+n > len(buf) {
		L.Push(lua.LNil)
		return 1
	}
	var out uint64
	for i := 0; i < n; i++ {
		out = (out << 8) | uint64(buf[off+i])
	}
	L.Push(lua.LNumber(out))
	return 1
}

func luaBU8(L *lua.LState) int  { return luaPackUintN(L, 1) }
func luaBU16(L *lua.LState) int { return luaPackUintN(L, 2) }
func luaBU24(L *lua.LState) int { return luaPackUintN(L, 3) }
func luaBU32(L *lua.LState) int { return luaPackUintN(L, 4) }
func luaBU48(L *lua.LState) int { return luaPackUintN(L, 6) }

func luaPackUintN(L *lua.LState, n int) int {
	v := luaArgUint64(L, 1)
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = byte(v & 0xff)
		v >>= 8
	}
	L.Push(lua.LString(string(out)))
	return 1
}

func luaU8Add(L *lua.LState) int  { return luaAddMod(L, 0xff) }
func luaU16Add(L *lua.LState) int { return luaAddMod(L, 0xffff) }
func luaU24Add(L *lua.LState) int { return luaAddMod(L, 0xffffff) }
func luaU32Add(L *lua.LState) int { return luaAddMod(L, 0xffffffff) }
func luaU48Add(L *lua.LState) int { return luaAddMod(L, luaU48Mask) }

func luaAddMod(L *lua.LState, mask uint64) int {
	if L.GetTop() < 1 {
		L.RaiseError("invalid arg count")
		return 0
	}
	var sum uint64
	for i := 1; i <= L.GetTop(); i++ {
		v := luaArgInt64(L, i)
		if v > int64(mask) || v < -int64(mask) {
			L.RaiseError("out of range")
			return 0
		}
		sum += uint64(v)
	}
	L.Push(lua.LNumber(sum & mask))
	return 1
}

func luaSwap16(L *lua.LState) int {
	v := luaArgInt64(L, 1)
	if v > 0xffff || v < -0xffff {
		L.RaiseError("out of range")
		return 0
	}
	u := uint16(v)
	out := (u << 8) | (u >> 8)
	L.Push(lua.LNumber(out))
	return 1
}

func luaSwap24(L *lua.LState) int {
	v := luaArgInt64(L, 1)
	if v > 0xffffff || v < -0xffffff {
		L.RaiseError("out of range")
		return 0
	}
	u := uint32(v) & 0xffffff
	out := ((u & 0x0000ff) << 16) | (u & 0x00ff00) | ((u & 0xff0000) >> 16)
	L.Push(lua.LNumber(out))
	return 1
}

func luaSwap32(L *lua.LState) int {
	v := luaArgInt64(L, 1)
	if v > 0xffffffff || v < -0xffffffff {
		L.RaiseError("out of range")
		return 0
	}
	u := uint32(v)
	out := ((u & 0x000000ff) << 24) |
		((u & 0x0000ff00) << 8) |
		((u & 0x00ff0000) >> 8) |
		((u & 0xff000000) >> 24)
	L.Push(lua.LNumber(out))
	return 1
}

func luaSwap48(L *lua.LState) int {
	v := luaArgInt64(L, 1)
	if v > int64(luaU48Mask) || v < -int64(luaU48Mask) {
		L.RaiseError("out of range")
		return 0
	}
	u := uint64(v) & luaU48Mask
	out := ((u & 0x0000000000ff) << 40) |
		((u & 0x00000000ff00) << 24) |
		((u & 0x000000ff0000) << 8) |
		((u & 0x0000ff000000) >> 8) |
		((u & 0x00ff00000000) >> 24) |
		((u & 0xff0000000000) >> 40)
	L.Push(lua.LNumber(out))
	return 1
}

func luaDivInt(L *lua.LState) int {
	a := float64(luaArgNumber(L, 1))
	b := float64(luaArgNumber(L, 2))
	if b == 0 {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LNumber(math.Floor(a / b)))
	return 1
}

func luaParseHex(L *lua.LState) int {
	s := L.CheckString(1)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			buf = append(buf, c)
		}
	}
	if len(buf)%2 == 1 {
		buf = append([]byte{'0'}, buf...)
	}
	decoded := make([]byte, hex.DecodedLen(len(buf)))
	n, err := hex.Decode(decoded, buf)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(string(decoded[:n])))
	return 1
}

func luaBrandom(L *lua.LState) int { return luaRandomFromAlphabet(L, nil) }
func luaBrandomAZ(L *lua.LState) int {
	return luaRandomFromAlphabet(L, []byte("abcdefghijklmnopqrstuvwxyz"))
}
func luaBrandomAZ09(L *lua.LState) int {
	return luaRandomFromAlphabet(L, []byte("abcdefghijklmnopqrstuvwxyz0123456789"))
}
func luaBCryptoRandom(L *lua.LState) int { return luaRandomFromAlphabet(L, nil) }

type luaGzipStream struct {
	buf    bytes.Buffer
	w      *gzip.Writer
	closed bool
}

type luaGunzipStream struct {
	in          bytes.Buffer
	decodedSize int
}

func luaGzipInit(L *lua.LState) int {
	level := 9
	if L.GetTop() >= 2 && L.Get(2) != lua.LNil {
		level = int(luaArgInt64(L, 2))
	}

	s := &luaGzipStream{}
	w, err := gzip.NewWriterLevel(&s.buf, level)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	s.w = w

	ud := L.NewUserData()
	ud.Value = s
	L.Push(ud)
	return 1
}

func luaGzipDeflate(L *lua.LState) int {
	ud := L.CheckUserData(1)
	s, ok := ud.Value.(*luaGzipStream)
	if !ok || s == nil || s.w == nil {
		L.Push(lua.LNil)
		return 1
	}

	start := s.buf.Len()
	if L.GetTop() >= 2 && L.Get(2) != lua.LNil {
		if s.closed {
			L.Push(lua.LNil)
			return 1
		}
		if _, err := s.w.Write([]byte(L.CheckString(2))); err != nil {
			L.Push(lua.LNil)
			return 1
		}
	} else if !s.closed {
		if err := s.w.Close(); err != nil {
			L.Push(lua.LNil)
			return 1
		}
		s.closed = true
	}

	L.Push(lua.LString(string(s.buf.Bytes()[start:])))
	return 1
}

func luaGzipEnd(L *lua.LState) int {
	ud := L.CheckUserData(1)
	s, ok := ud.Value.(*luaGzipStream)
	if !ok || s == nil || s.w == nil {
		return 0
	}
	if !s.closed {
		_ = s.w.Close()
		s.closed = true
	}
	return 0
}

func luaGunzipInit(L *lua.LState) int {
	ud := L.NewUserData()
	ud.Value = &luaGunzipStream{}
	L.Push(ud)
	return 1
}

func luaGunzipInflate(L *lua.LState) int {
	ud := L.CheckUserData(1)
	s, ok := ud.Value.(*luaGunzipStream)
	if !ok || s == nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}
	in := []byte(L.CheckString(2))
	if len(in) > 0 {
		_, _ = s.in.Write(in)
	}

	decoded, err := gunzipAll(s.in.Bytes())
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			L.Push(lua.LString(""))
			L.Push(lua.LBool(false))
			return 2
		}
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}
	if s.decodedSize > len(decoded) {
		s.decodedSize = 0
	}
	out := decoded[s.decodedSize:]
	s.decodedSize = len(decoded)
	L.Push(lua.LString(string(out)))
	L.Push(lua.LBool(true))
	return 2
}

func luaGunzipEnd(L *lua.LState) int {
	_ = L.CheckUserData(1)
	return 0
}

func gunzipAll(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func luaRandomFromAlphabet(L *lua.LState, alphabet []byte) int {
	n := int(luaArgUint64(L, 1))
	if n < 0 {
		n = 0
	}
	out := make([]byte, n)
	if len(alphabet) == 0 {
		if _, err := crand.Read(out); err != nil {
			for i := range out {
				out[i] = byte(mrand.Intn(256))
			}
		}
	} else {
		raw := make([]byte, n)
		if _, err := crand.Read(raw); err != nil {
			for i := range raw {
				raw[i] = byte(mrand.Intn(256))
			}
		}
		for i := range out {
			out[i] = alphabet[int(raw[i])%len(alphabet)]
		}
	}
	L.Push(lua.LString(string(out)))
	return 1
}

func luaPton(L *lua.LState) int {
	s := L.CheckString(1)
	ip := net.ParseIP(s)
	if ip == nil {
		L.Push(lua.LNil)
		return 1
	}
	if v4 := ip.To4(); v4 != nil {
		L.Push(lua.LString(string(v4)))
		return 1
	}
	if v6 := ip.To16(); v6 != nil {
		L.Push(lua.LString(string(v6)))
		return 1
	}
	L.Push(lua.LNil)
	return 1
}

func luaNtop(L *lua.LState) int {
	s := []byte(L.CheckString(1))
	if len(s) != 4 && len(s) != 16 {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(net.IP(s).String()))
	return 1
}

func luaUname(L *lua.LState) int {
	t := L.NewTable()
	t.RawSetString("sysname", lua.LString(runtime.GOOS))
	t.RawSetString("nodename", lua.LString(""))
	t.RawSetString("release", lua.LString(""))
	t.RawSetString("version", lua.LString(""))
	t.RawSetString("machine", lua.LString(runtime.GOARCH))
	L.Push(t)
	return 1
}

func luaHKDF(L *lua.LState) int {
	hName := strings.ToLower(L.CheckString(1))
	salt := []byte(L.CheckString(2))
	ikm := []byte(L.CheckString(3))
	info := []byte("")
	if v := L.Get(4); v != lua.LNil {
		info = []byte(luaToStringAny(v))
	}
	outLen := int(luaArgUint64(L, 5))
	if outLen < 0 {
		outLen = 0
	}
	var h func() hash.Hash
	switch hName {
	case "sha256":
		h = sha256.New
	case "sha224":
		h = sha256.New224
	default:
		L.Push(lua.LNil)
		return 1
	}
	r := hkdf.New(h, ikm, salt, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(string(out)))
	return 1
}

func luaAESCTR(L *lua.LState) int {
	key := []byte(L.CheckString(1))
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		L.RaiseError("aes_ctr: wrong key length %d. should be 16,24,32.", len(key))
		return 0
	}
	iv := []byte(L.CheckString(2))
	if len(iv) != aes.BlockSize {
		L.RaiseError("aes_ctr: wrong iv length %d. should be 16.", len(iv))
		return 0
	}
	data := []byte(L.CheckString(3))
	block, err := aes.NewCipher(key)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	out := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out, data)
	L.Push(lua.LString(string(out)))
	return 1
}

func luaHash(L *lua.LState) int {
	hName := strings.ToLower(L.CheckString(1))
	data := []byte(L.CheckString(2))

	var sum []byte
	switch hName {
	case "sha256":
		s := sha256.Sum256(data)
		sum = s[:]
	case "sha224":
		s := sha256.Sum224(data)
		sum = s[:]
	default:
		L.Push(lua.LNil)
		return 1
	}

	L.Push(lua.LString(string(sum)))
	return 1
}

func luaAES(L *lua.LState) int {
	encrypt := L.OptBool(1, true)
	key := []byte(L.CheckString(2))
	data := []byte(L.CheckString(3))
	if len(data) != aes.BlockSize {
		L.RaiseError("aes: wrong data length %d. should be 16.", len(data))
		return 0
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		L.RaiseError("aes: wrong key length %d. should be 16,24,32.", len(key))
		return 0
	}

	out := make([]byte, len(data))
	if encrypt {
		block.Encrypt(out, data)
	} else {
		block.Decrypt(out, data)
	}
	L.Push(lua.LString(string(out)))
	return 1
}

func luaAESGCM(L *lua.LState) int {
	encrypt := L.OptBool(1, true)
	key := []byte(L.CheckString(2))
	iv := []byte(L.CheckString(3))
	data := []byte(L.CheckString(4))
	var aad []byte
	if v := L.Get(5); v != lua.LNil {
		aad = []byte(luaToStringAny(v))
	}

	if len(iv) != 12 {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		return 2
	}

	if encrypt {
		sealed := gcm.Seal(nil, iv, data, aad)
		ct := sealed[:len(data)]
		tag := sealed[len(data):]
		L.Push(lua.LString(string(ct)))
		L.Push(lua.LString(string(tag)))
		return 2
	}

	pt := gcmDecryptNoVerify(block, iv, data)
	sealed := gcm.Seal(nil, iv, pt, aad)
	tag := sealed[len(pt):]
	L.Push(lua.LString(string(pt)))
	L.Push(lua.LString(string(tag)))
	return 2
}

func gcmDecryptNoVerify(block cipher.Block, iv, ct []byte) []byte {
	counter := make([]byte, 16)
	copy(counter, iv)
	binary.BigEndian.PutUint32(counter[12:16], 2)
	stream := cipher.NewCTR(block, counter)
	pt := make([]byte, len(ct))
	stream.XORKeyStream(pt, ct)
	return pt
}
