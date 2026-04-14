package lua

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strconv"
	"strings"
)

var markerExprRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)([+-]\d+)?$`)

func resolveMarkerExpr(data []byte, l7payload, expr string) (int, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, false
	}

	if n, ok := parseLuaInteger(expr); ok {
		pos := int(n)
		if pos < 0 {
			pos = len(data) + pos
		}
		if pos < 0 || pos >= len(data) {
			return 0, false
		}
		return pos, true
	}

	m := markerExprRe.FindStringSubmatch(expr)
	if len(m) == 0 {
		return 0, false
	}
	baseName := strings.ToLower(m[1])
	basePos, ok := resolveMarkerBase(data, strings.ToLower(l7payload), baseName)
	if !ok {
		return 0, false
	}
	if m[2] != "" {
		delta, err := strconv.Atoi(m[2])
		if err != nil {
			return 0, false
		}
		basePos += delta
	}
	if basePos < 0 || basePos >= len(data) {
		return 0, false
	}
	return basePos, true
}

func resolveMarkerBase(data []byte, l7payload, marker string) (int, bool) {
	hstart, hend, hasHost := findHostRange(data, l7payload)

	switch marker {
	case "method":
		if l7payload == "http_req" {
			return 0, true
		}
		return 0, false
	case "host":
		if hasHost {
			return hstart, true
		}
		return 0, false
	case "endhost":
		if hasHost {
			return hend, true
		}
		return 0, false
	case "sld", "midsld", "endsld":
		if !hasHost {
			return 0, false
		}
		s, mid, e, ok := hostSLDMarkers(data[hstart:hend])
		if !ok {
			return 0, false
		}
		s += hstart
		mid += hstart
		e += hstart
		switch marker {
		case "sld":
			return s, true
		case "midsld":
			return mid, true
		default:
			return e, true
		}
	case "sniext", "extlen":
		ts, te, sniext, extlen, ok := findTLSSNIRange(data)
		if !ok {
			return 0, false
		}
		switch marker {
		case "sniext":
			return sniext, true
		case "extlen":
			return extlen, true
		}
		_ = ts
		_ = te
	}

	return 0, false
}

func findHostRange(data []byte, l7payload string) (start, end int, ok bool) {
	switch l7payload {
	case "http_req", "http_reply":
		return findHTTPHostRange(data)
	case "tls_client_hello":
		hs, he, _, _, ok := findTLSSNIRange(data)
		return hs, he, ok
	default:
		return 0, 0, false
	}
}

func findHTTPHostRange(data []byte) (start, end int, ok bool) {
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		return 0, 0, false
	}
	pos := lineEnd + 1
	for pos < len(data) {
		nlRel := bytes.IndexByte(data[pos:], '\n')
		line := data[pos:]
		adv := len(line)
		if nlRel >= 0 {
			line = data[pos : pos+nlRel]
			adv = nlRel + 1
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon > 0 {
			key := strings.ToLower(strings.TrimSpace(string(line[:colon])))
			if key == "host" {
				vStart := colon + 1
				for vStart < len(line) && (line[vStart] == ' ' || line[vStart] == '\t') {
					vStart++
				}
				vEnd := len(line)
				for vEnd > vStart && (line[vEnd-1] == ' ' || line[vEnd-1] == '\t') {
					vEnd--
				}
				if vStart < vEnd {
					return pos + vStart, pos + vEnd, true
				}
			}
		}
		pos += adv
	}
	return 0, 0, false
}

func hostSLDMarkers(host []byte) (start, mid, end int, ok bool) {
	if len(host) == 0 {
		return 0, 0, 0, false
	}
	dots := make([]int, 0, 4)
	for i, b := range host {
		if b == '.' {
			dots = append(dots, i)
		}
	}
	if len(dots) == 0 {
		return 0, 0, 0, false
	}
	sldStart := 0
	sldEnd := len(host)
	if len(dots) == 1 {
		sldEnd = dots[0]
	} else if len(dots) >= 2 {
		sldStart = dots[len(dots)-2] + 1
		sldEnd = dots[len(dots)-1]
	}
	if sldStart >= sldEnd {
		return 0, 0, 0, false
	}
	sldLen := sldEnd - sldStart
	midPos := sldStart + sldLen/2
	if sldLen == 1 {
		midPos = sldStart + 1
	}
	return sldStart, midPos, sldEnd, true
}

func findTLSSNIRange(data []byte) (hostStart, hostEnd, sniExtPos, extLenPos int, ok bool) {
	if len(data) < 5 || data[0] != 0x16 {
		return 0, 0, 0, 0, false
	}
	off := 5
	if len(data) < off+4 {
		return 0, 0, 0, 0, false
	}
	if data[off] != 0x01 {
		return 0, 0, 0, 0, false
	}
	hsLen := int(data[off+1])<<16 | int(data[off+2])<<8 | int(data[off+3])
	if len(data) < off+4+hsLen {
		return 0, 0, 0, 0, false
	}

	p := off + 4
	if len(data) < p+2+32+1 {
		return 0, 0, 0, 0, false
	}
	p += 2 + 32

	sidLen := int(data[p])
	p++
	if len(data) < p+sidLen+2 {
		return 0, 0, 0, 0, false
	}
	p += sidLen

	csLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if len(data) < p+csLen+1 {
		return 0, 0, 0, 0, false
	}
	p += csLen

	compLen := int(data[p])
	p++
	if len(data) < p+compLen+2 {
		return 0, 0, 0, 0, false
	}
	p += compLen

	extLenPos = p
	extLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if len(data) < p+extLen {
		return 0, 0, 0, 0, false
	}
	end := p + extLen

	for p+4 <= end {
		eType := binary.BigEndian.Uint16(data[p : p+2])
		eLen := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
		eData := p + 4
		eEnd := eData + eLen
		if eEnd > end {
			return 0, 0, 0, 0, false
		}
		if eType == 0 && eLen >= 5 {
			sniExtPos = p
			nameType := data[eData+2]
			nameLen := int(binary.BigEndian.Uint16(data[eData+3 : eData+5]))
			nStart := eData + 5
			nEnd := nStart + nameLen
			if nameType == 0 && nEnd <= eEnd {
				return nStart, nEnd, sniExtPos, extLenPos, true
			}
		}
		p = eEnd
	}

	return 0, 0, 0, 0, false
}
