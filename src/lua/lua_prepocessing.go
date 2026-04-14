package lua

import (
	"strconv"
	"strings"
)

// normalizeLuaSourceCompat makes Lua 5.1-compatible sources with \xHH escapes
// work on GopherLua by rewriting them to \DDD decimal escapes inside quoted strings.
func normalizeLuaSourceCompat(src string) string {
	if !strings.Contains(src, `\x`) {
		return src
	}

	var b strings.Builder
	b.Grow(len(src))
	quoted := byte(0)
	escaped := false

	for i := 0; i < len(src); i++ {
		c := src[i]

		if quoted == 0 {
			b.WriteByte(c)
			if c == '"' || c == '\'' {
				quoted = c
				escaped = false
			}
			continue
		}

		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}

		if c == '\\' {
			if i+3 < len(src) && src[i+1] == 'x' {
				if v, ok := parseHexByte(src[i+2], src[i+3]); ok {
					b.WriteByte('\\')
					dec := strconv.Itoa(int(v))
					if len(dec) == 1 {
						b.WriteByte('0')
						b.WriteByte('0')
					} else if len(dec) == 2 {
						b.WriteByte('0')
					}
					b.WriteString(dec)
					i += 3
					continue
				}
			}
			b.WriteByte(c)
			escaped = true
			continue
		}

		b.WriteByte(c)
		if c == quoted {
			quoted = 0
		}
	}

	return b.String()
}

func parseHexByte(a, b byte) (byte, bool) {
	hi, ok := hexNibble(a)
	if !ok {
		return 0, false
	}
	lo, ok := hexNibble(b)
	if !ok {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
