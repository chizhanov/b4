package lua

import (
	crand "crypto/rand"
	"encoding/binary"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

const (
	tlsModRnd uint32 = 1 << iota
	tlsModRndSNI
	tlsModSNI
	tlsModDupSID
	tlsModPadEncap
)

type tlsModSpec struct {
	mask uint32
	sni  string
}

type tlsHelloMeta struct {
	recLenOff int
	hsLenOff  int

	sidLen int
	sidOff int

	extLenOff int
	extStart  int
	extEnd    int
}

func luaTLSMod(L *lua.LState) int {
	if L.GetTop() < 2 || L.GetTop() > 3 {
		L.RaiseError("tls_mod expect from 2 to 3 arguments")
		return 0
	}

	fakeTLS := []byte(L.CheckString(1))
	modList := L.CheckString(2)
	var payload []byte
	if L.GetTop() >= 3 && L.Get(3) != lua.LNil {
		payload = []byte(L.CheckString(3))
	}

	spec, ok := parseTLSModList(modList)
	if !ok {
		L.RaiseError("invalid tls mod list : '%s'", modList)
		return 0
	}
	if spec.mask == 0 {
		L.Push(lua.LString(string(fakeTLS)))
		return 1
	}

	// zapret2 добавляет запас под возможный рост SNI и pad-расширения.
	work := make([]byte, len(fakeTLS), len(fakeTLS)+maxInt(4, len(spec.sni))+8)
	copy(work, fakeTLS)

	out, ok := applyTLSMod(work, payload, spec)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(string(out)))
	return 1
}

func parseTLSModList(modList string) (tlsModSpec, bool) {
	spec := tlsModSpec{}
	for _, raw := range strings.Split(modList, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		key := token
		val := ""
		if i := strings.IndexByte(token, '='); i >= 0 {
			key = token[:i]
			val = token[i+1:]
		}
		switch key {
		case "rnd":
			spec.mask |= tlsModRnd
		case "rndsni":
			spec.mask |= tlsModRndSNI
		case "dupsid":
			spec.mask |= tlsModDupSID
		case "padencap":
			spec.mask |= tlsModPadEncap
		case "sni":
			if val == "" {
				return tlsModSpec{}, false
			}
			spec.mask |= tlsModSNI
			spec.sni = val
		case "none":
		default:
			return tlsModSpec{}, false
		}
	}
	return spec, true
}

func applyTLSMod(fakeTLS []byte, payload []byte, spec tlsModSpec) ([]byte, bool) {
	meta, ok := parseTLSHelloMeta(fakeTLS)
	if !ok {
		return nil, false
	}

	if spec.mask&(tlsModSNI|tlsModRndSNI) != 0 {
		sniHdr, sniListLenOff, sniHostLenOff, hostOff, hostLen, ok := tlsFindSNI(fakeTLS, meta)
		if !ok {
			return nil, false
		}
		if spec.mask&tlsModSNI != 0 {
			repl := []byte(spec.sni)
			var replOK bool
			fakeTLS, replOK = replaceRange(fakeTLS, hostOff, hostOff+hostLen, repl, cap(fakeTLS))
			if !replOK {
				return nil, false
			}
			delta := len(repl) - hostLen
			if !tlsAddLen16(fakeTLS, meta.recLenOff, delta) ||
				!tlsAddLen24(fakeTLS, meta.hsLenOff, delta) ||
				!tlsAddLen16(fakeTLS, meta.extLenOff, delta) ||
				!tlsAddLen16(fakeTLS, sniHdr+2, delta) ||
				!tlsAddLen16(fakeTLS, sniListLenOff, delta) ||
				!tlsAddLen16(fakeTLS, sniHostLenOff, delta) {
				return nil, false
			}

			meta, ok = parseTLSHelloMeta(fakeTLS)
			if !ok {
				return nil, false
			}
			_, _, _, hostOff, hostLen, ok = tlsFindSNI(fakeTLS, meta)
			if !ok {
				return nil, false
			}
		}
		if spec.mask&tlsModRndSNI != 0 {
			if hostLen == 0 {
				return nil, false
			}
			fillRandomSNI(fakeTLS[hostOff : hostOff+hostLen])
		}
	}

	if spec.mask&tlsModRnd != 0 {
		if len(fakeTLS) < meta.sidOff+meta.sidLen || len(fakeTLS) < 43 {
			return nil, false
		}
		fillRandomBytes(fakeTLS[11 : 11+32])
		if meta.sidLen > 0 {
			fillRandomBytes(fakeTLS[meta.sidOff : meta.sidOff+meta.sidLen])
		}
	}

	if len(payload) > 0 && spec.mask&tlsModDupSID != 0 {
		if len(payload) >= 44 {
			psidLen := int(payload[43])
			if psidLen == meta.sidLen && len(payload) >= 44+psidLen && len(fakeTLS) >= 44+meta.sidLen {
				copy(fakeTLS[44:44+meta.sidLen], payload[44:44+psidLen])
			}
		}
	}

	if len(payload) > 0 && spec.mask&tlsModPadEncap != 0 {
		var padLenOff int
		padHdr, _, padLen, found := tlsFindExt(fakeTLS, meta, 21)
		if found {
			if padHdr+4+padLen != len(fakeTLS) {
				return nil, false
			}
			padLenOff = padHdr + 2
		} else {
			if len(fakeTLS)+4 > cap(fakeTLS) {
				return nil, false
			}
			fakeTLS = append(fakeTLS, 0x00, 0x15, 0x00, 0x00)
			if !tlsAddLen16(fakeTLS, meta.recLenOff, 4) ||
				!tlsAddLen24(fakeTLS, meta.hsLenOff, 4) ||
				!tlsAddLen16(fakeTLS, meta.extLenOff, 4) {
				return nil, false
			}
			padLenOff = len(fakeTLS) - 2
			meta, ok = parseTLSHelloMeta(fakeTLS)
			if !ok {
				return nil, false
			}
		}

		recLen := int(binary.BigEndian.Uint16(fakeTLS[meta.recLenOff : meta.recLenOff+2]))
		hsLen := int(readU24(fakeTLS[meta.hsLenOff : meta.hsLenOff+3]))
		extLen := int(binary.BigEndian.Uint16(fakeTLS[meta.extLenOff : meta.extLenOff+2]))
		padLenNow := int(binary.BigEndian.Uint16(fakeTLS[padLenOff : padLenOff+2]))
		add := len(payload)
		if recLen+add <= 0xFFFF && hsLen+add <= 0xFFFFFF && extLen+add <= 0xFFFF && padLenNow+add <= 0xFFFF {
			binary.BigEndian.PutUint16(fakeTLS[meta.recLenOff:meta.recLenOff+2], uint16(recLen+add))
			writeU24(fakeTLS[meta.hsLenOff:meta.hsLenOff+3], uint32(hsLen+add))
			binary.BigEndian.PutUint16(fakeTLS[meta.extLenOff:meta.extLenOff+2], uint16(extLen+add))
			binary.BigEndian.PutUint16(fakeTLS[padLenOff:padLenOff+2], uint16(padLenNow+add))
		}
	}

	return fakeTLS, true
}

func parseTLSHelloMeta(data []byte) (tlsHelloMeta, bool) {
	if len(data) < 44 || data[0] != 0x16 {
		return tlsHelloMeta{}, false
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return tlsHelloMeta{}, false
	}
	if len(data) < 9 || data[5] != 0x01 {
		return tlsHelloMeta{}, false
	}
	hsLen := int(readU24(data[6:9]))
	if hsLen+4 > recLen {
		return tlsHelloMeta{}, false
	}

	sidLen := int(data[43])
	sidOff := 44
	if len(data) < sidOff+sidLen {
		return tlsHelloMeta{}, false
	}

	pos := sidOff + sidLen
	if len(data) < pos+2 {
		return tlsHelloMeta{}, false
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + csLen
	if len(data) < pos+1 {
		return tlsHelloMeta{}, false
	}
	compLen := int(data[pos])
	pos += 1 + compLen
	if len(data) < pos+2 {
		return tlsHelloMeta{}, false
	}
	extLenOff := pos
	extLen := int(binary.BigEndian.Uint16(data[extLenOff : extLenOff+2]))
	extStart := extLenOff + 2
	extEnd := extStart + extLen
	if extEnd > len(data) {
		return tlsHelloMeta{}, false
	}

	return tlsHelloMeta{
		recLenOff: 3,
		hsLenOff:  6,
		sidLen:    sidLen,
		sidOff:    sidOff,
		extLenOff: extLenOff,
		extStart:  extStart,
		extEnd:    extEnd,
	}, true
}

func tlsFindExt(data []byte, meta tlsHelloMeta, extType uint16) (hdrOff int, dataOff int, extLen int, found bool) {
	pos := meta.extStart
	for pos+4 <= meta.extEnd {
		typ := binary.BigEndian.Uint16(data[pos : pos+2])
		ln := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		dataPos := pos + 4
		if dataPos+ln > meta.extEnd {
			return 0, 0, 0, false
		}
		if typ == extType {
			return pos, dataPos, ln, true
		}
		pos = dataPos + ln
	}
	return 0, 0, 0, false
}

// Возвращает: sniExtHeaderOff, sniListLenOff, sniLenFieldOff, hostOff, hostLen.
func tlsFindSNI(data []byte, meta tlsHelloMeta) (int, int, int, int, int, bool) {
	hdrOff, extDataOff, extLen, found := tlsFindExt(data, meta, 0)
	if !found || extLen < 5 {
		return 0, 0, 0, 0, 0, false
	}
	sniListLen := int(binary.BigEndian.Uint16(data[extDataOff : extDataOff+2]))
	if sniListLen+2 > extLen {
		return 0, 0, 0, 0, 0, false
	}
	p := extDataOff + 2
	end := p + sniListLen
	if p+3 > end || data[p] != 0 {
		return 0, 0, 0, 0, 0, false
	}
	sniLenFieldOff := p + 1
	hostLen := int(binary.BigEndian.Uint16(data[sniLenFieldOff : sniLenFieldOff+2]))
	hostOff := p + 3
	if hostOff+hostLen > end {
		return 0, 0, 0, 0, 0, false
	}
	return hdrOff, extDataOff, sniLenFieldOff, hostOff, hostLen, true
}

func tlsAddLen16(data []byte, off int, delta int) bool {
	cur := int(binary.BigEndian.Uint16(data[off : off+2]))
	next := cur + delta
	if next < 0 || next > 0xFFFF {
		return false
	}
	binary.BigEndian.PutUint16(data[off:off+2], uint16(next))
	return true
}

func tlsAddLen24(data []byte, off int, delta int) bool {
	cur := int(readU24(data[off : off+3]))
	next := cur + delta
	if next < 0 || next > 0xFFFFFF {
		return false
	}
	writeU24(data[off:off+3], uint32(next))
	return true
}

func replaceRange(data []byte, start, end int, repl []byte, maxCap int) ([]byte, bool) {
	if start < 0 || end < start || end > len(data) {
		return nil, false
	}
	oldLen := end - start
	delta := len(repl) - oldLen
	newLen := len(data) + delta
	if newLen < 0 || newLen > maxCap {
		return nil, false
	}
	if delta > 0 {
		data = append(data, make([]byte, delta)...)
		copy(data[end+delta:], data[end:len(data)-delta])
	} else if delta < 0 {
		copy(data[start+len(repl):], data[end:])
		data = data[:newLen]
	}
	copy(data[start:start+len(repl)], repl)
	return data, true
}

func fillRandomBytes(dst []byte) {
	if len(dst) == 0 {
		return
	}
	_, _ = crand.Read(dst)
}

func fillRandomSNI(sni []byte) {
	if len(sni) == 0 {
		return
	}
	sni[0] = randAlpha()
	if len(sni) >= 7 {
		for i := 1; i < len(sni)-4; i++ {
			sni[i] = randAlphaNum()
		}
		sni[len(sni)-4] = '.'
		tld := []string{"com", "org", "net", "edu", "gov", "biz"}
		chosen := tld[randIntn(len(tld))]
		copy(sni[len(sni)-3:], chosen)
		return
	}
	for i := 1; i < len(sni); i++ {
		sni[i] = randAlphaNum()
	}
}

func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	var b [1]byte
	_, _ = crand.Read(b[:])
	return int(b[0]) % n
}

func randAlpha() byte {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	return letters[randIntn(len(letters))]
}

func randAlphaNum() byte {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	return letters[randIntn(len(letters))]
}

func readU24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func writeU24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
