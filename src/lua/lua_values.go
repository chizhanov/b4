package lua

import (
	"math"
	"strconv"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

func parseLuaInteger(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	} else if s[0] == '+' {
		s = s[1:]
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	if s == "" {
		return 0, false
	}
	u, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		if u > uint64(math.MaxInt64)+1 {
			return 0, false
		}
		if u == uint64(math.MaxInt64)+1 {
			return math.MinInt64, true
		}
		return -int64(u), true
	}
	if u > uint64(math.MaxInt64) {
		return 0, false
	}
	return int64(u), true
}

func luaToVerdict(v lua.LValue) (uint8, bool) {
	switch x := v.(type) {
	case lua.LNumber:
		if x < 0 {
			return 0, false
		}
		return uint8(x), true
	case lua.LString:
		n, ok := parseLuaInteger(string(x))
		if !ok || n < 0 {
			return 0, false
		}
		return uint8(n), true
	default:
		return 0, false
	}
}

func luaToStringAny(v lua.LValue) string {
	switch x := v.(type) {
	case lua.LString:
		return string(x)
	default:
		return v.String()
	}
}

func luaLValueToInt64(v lua.LValue) int64 {
	switch x := v.(type) {
	case lua.LNumber:
		return int64(x)
	case lua.LString:
		if n, ok := parseLuaInteger(string(x)); ok {
			return n
		}
	}
	return 0
}

func luaTableUint(t *lua.LTable, key string, def uint64) uint64 {
	if t == nil {
		return def
	}
	v := t.RawGetString(key)
	switch x := v.(type) {
	case lua.LNumber:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case lua.LString:
		if n, ok := parseLuaInteger(string(x)); ok {
			if n < 0 {
				return 0
			}
			return uint64(n)
		}
	}
	return def
}

func luaOptBool(t *lua.LTable, key string, def bool) bool {
	if t == nil {
		return def
	}
	v := t.RawGetString(key)
	if b, ok := v.(lua.LBool); ok {
		return bool(b)
	}
	return def
}

func luaOptUint(t *lua.LTable, key string, def uint64) uint64 {
	if t == nil {
		return def
	}
	return luaTableUint(t, key, def)
}

func luaArgUint64(L *lua.LState, idx int) uint64 {
	return luaArgUint64Default(L, idx, 0)
}

func luaArgUint64Default(L *lua.LState, idx int, def uint64) uint64 {
	if idx > L.GetTop() {
		return def
	}
	v := L.Get(idx)
	switch x := v.(type) {
	case lua.LNumber:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case lua.LString:
		n, ok := parseLuaInteger(string(x))
		if !ok {
			return def
		}
		if n < 0 {
			return 0
		}
		return uint64(n)
	default:
		return def
	}
}

func luaArgInt64(L *lua.LState, idx int) int64 {
	if idx > L.GetTop() {
		return 0
	}
	v := L.Get(idx)
	switch x := v.(type) {
	case lua.LNumber:
		return int64(x)
	case lua.LString:
		n, ok := parseLuaInteger(string(x))
		if ok {
			return n
		}
	}
	return 0
}

func luaArgNumber(L *lua.LState, idx int) float64 {
	if idx > L.GetTop() {
		return 0
	}
	switch x := L.Get(idx).(type) {
	case lua.LNumber:
		return float64(x)
	case lua.LString:
		f, err := strconv.ParseFloat(strings.TrimSpace(string(x)), 64)
		if err == nil {
			return f
		}
	}
	return 0
}
