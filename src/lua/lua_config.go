package lua

import (
	"errors"
	"fmt"
	"strings"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
)

func defaultLegacyRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Mode:          LuaModeLegacy,
		LuaInit:       []string{},
		ExecutionPlan: []ExecutionInstance{},
	}
}

func newLuaRuntime(path string, runtimeCfg RuntimeConfig, defaultFWMark uint32) *Runtime {
	return &Runtime{
		path:            path,
		cfg:             runtimeCfg,
		defaultFWMark:   defaultFWMark,
		currentPlanIdx:  -1,
		unsupportedWarn: make(map[string]struct{}),
		senderCache:     make(map[string]*sock.Sender),
		conntrack:       make(map[string]*luaConnTrack),
		timers:          make(map[string]*luaTimer),
	}
}

func newLegacyLuaRuntime(path string, defaultFWMark uint32) *Runtime {
	return newLuaRuntime(path, defaultLegacyRuntimeConfig(), defaultFWMark)
}

func runtimeBasePath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.ConfigPath)
}

func runtimeDefaultFWMark(cfg *config.Config) uint32 {
	if cfg == nil {
		return 0
	}
	return uint32(cfg.Queue.Mark)
}

func LoadRuntime(cfg *config.Config) *Runtime {
	defaultFWMark := runtimeDefaultFWMark(cfg)
	path, runtimeCfg, err := loadLuaRuntimeFromB4Config(cfg)
	if err != nil {
		log.Errorf("Lua runtime set config error: %v. Fallback to legacy mode.", err)
		return newLegacyLuaRuntime(path, defaultFWMark)
	}
	return newLuaRuntime(path, runtimeCfg, defaultFWMark)
}

func loadLuaRuntimeFromB4Config(cfg *config.Config) (string, RuntimeConfig, error) {
	path := runtimeBasePath(cfg)
	runtimeCfg := defaultLegacyRuntimeConfig()

	if cfg == nil {
		return path, runtimeCfg, nil
	}

	initSeen := make(map[string]struct{})
	enabledLuaSets := 0
	profileN := 0

	for _, entry := range cfg.System.Lua.Init {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if _, exists := initSeen[trimmed]; exists {
			continue
		}
		initSeen[trimmed] = struct{}{}
		runtimeCfg.LuaInit = append(runtimeCfg.LuaInit, trimmed)
	}

	for _, set := range cfg.Sets {
		if set == nil || !set.Enabled || !set.Lua.Enabled {
			continue
		}
		setName := strings.TrimSpace(set.Name)
		if setName == "" {
			return "", RuntimeConfig{}, errors.New("lua-enabled set must have non-empty name")
		}
		enabledLuaSets++
		profileN++
		funcN := 0

		for i := range set.Lua.ExecutionPlan {
			funcN++
			inst := ExecutionInstance{
				Func:          set.Lua.ExecutionPlan[i].Func,
				Arg:           cloneStringMap(set.Lua.ExecutionPlan[i].Arg),
				PayloadFilter: set.Lua.ExecutionPlan[i].PayloadFilter,
				RangeIn:       convertPacketRangeCfg(set.Lua.ExecutionPlan[i].RangeIn),
				RangeOut:      convertPacketRangeCfg(set.Lua.ExecutionPlan[i].RangeOut),
				SetName:       setName,
				ProfileN:      profileN,
				ProfileName:   setName,
				FuncN:         funcN,
			}
			runtimeCfg.ExecutionPlan = append(runtimeCfg.ExecutionPlan, inst)
		}

		for i, spec := range set.Lua.Desync {
			inst, err := parseDesyncSpec(spec)
			if err != nil {
				return "", RuntimeConfig{}, fmt.Errorf("set %q: lua.desync[%d]: %w", setName, i, err)
			}
			inst.SetName = setName
			inst.ProfileN = profileN
			inst.ProfileName = setName
			funcN++
			inst.FuncN = funcN
			runtimeCfg.ExecutionPlan = append(runtimeCfg.ExecutionPlan, inst)
		}
	}

	if enabledLuaSets == 0 {
		return path, runtimeCfg, nil
	}

	runtimeCfg.Mode = LuaModeLua
	if err := normalizeRuntimeConfig(&runtimeCfg); err != nil {
		return "", RuntimeConfig{}, err
	}
	log.Infof("Lua runtime config loaded from sets: sets=%d, lua_init=%d, execution_plan=%d, config=%s",
		enabledLuaSets, len(runtimeCfg.LuaInit), len(runtimeCfg.ExecutionPlan), path)
	return path, runtimeCfg, nil
}

func normalizeRuntimeConfig(cfg *RuntimeConfig) error {
	if cfg == nil {
		return errors.New("nil runtime config")
	}
	if cfg.Mode == "" {
		cfg.Mode = LuaModeLegacy
	}
	if cfg.LuaInit == nil {
		cfg.LuaInit = []string{}
	}
	if cfg.ExecutionPlan == nil {
		cfg.ExecutionPlan = []ExecutionInstance{}
	}
	if cfg.Mode != LuaModeLegacy && cfg.Mode != LuaModeLua {
		return errors.New("mode must be 'legacy' or 'lua'")
	}

	cleanedInit := make([]string, 0, len(cfg.LuaInit))
	for _, entry := range cfg.LuaInit {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		cleanedInit = append(cleanedInit, trimmed)
	}
	cfg.LuaInit = cleanedInit

	for i := range cfg.ExecutionPlan {
		cfg.ExecutionPlan[i].Func = strings.TrimSpace(cfg.ExecutionPlan[i].Func)
		if cfg.ExecutionPlan[i].Func == "" {
			return errors.New("execution_plan contains empty func")
		}
		cfg.ExecutionPlan[i].SetName = strings.TrimSpace(cfg.ExecutionPlan[i].SetName)
		cfg.ExecutionPlan[i].ProfileName = strings.TrimSpace(cfg.ExecutionPlan[i].ProfileName)
		cfg.ExecutionPlan[i].Cookie = strings.TrimSpace(cfg.ExecutionPlan[i].Cookie)
		if cfg.ExecutionPlan[i].ProfileN <= 0 {
			cfg.ExecutionPlan[i].ProfileN = 1
		}
		if cfg.ExecutionPlan[i].FuncN <= 0 {
			cfg.ExecutionPlan[i].FuncN = i + 1
		}
		if cfg.ExecutionPlan[i].Arg == nil {
			cfg.ExecutionPlan[i].Arg = map[string]string{}
		}
		normalizePacketRange(&cfg.ExecutionPlan[i].RangeIn)
		normalizePacketRange(&cfg.ExecutionPlan[i].RangeOut)
	}
	return nil
}

func defaultPacketRange() PacketRange {
	return PacketRange{
		UpperCutoff: false,
		From: PacketPos{
			Mode: "a",
			Pos:  0,
		},
		To: PacketPos{
			Mode: "a",
			Pos:  0,
		},
	}
}

func parseDesyncSpec(spec string) (ExecutionInstance, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ExecutionInstance{}, fmt.Errorf("empty desync entry")
	}
	parts := strings.Split(spec, ":")
	fn := strings.TrimSpace(parts[0])
	if fn == "" {
		return ExecutionInstance{}, fmt.Errorf("missing function name")
	}

	inst := ExecutionInstance{
		Func:          fn,
		Arg:           map[string]string{},
		PayloadFilter: "",
		RangeIn:       defaultPacketRange(),
		RangeOut:      defaultPacketRange(),
	}
	for _, token := range parts[1:] {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		kv := strings.SplitN(token, "=", 2)
		key := strings.TrimSpace(kv[0])
		if key == "" {
			return ExecutionInstance{}, fmt.Errorf("invalid arg token %q", token)
		}
		val := "1"
		if len(kv) == 2 {
			val = kv[1]
		}
		inst.Arg[key] = val
	}
	return inst, nil
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func convertPacketRangeCfg(r config.LuaPacketRangeConfig) PacketRange {
	return PacketRange{
		UpperCutoff: r.UpperCutoff,
		From: PacketPos{
			Mode: r.From.Mode,
			Pos:  r.From.Pos,
		},
		To: PacketPos{
			Mode: r.To.Mode,
			Pos:  r.To.Pos,
		},
	}
}

func normalizePacketRange(r *PacketRange) {
	if strings.TrimSpace(r.From.Mode) == "" {
		r.From.Mode = "a"
	}
	if strings.TrimSpace(r.To.Mode) == "" {
		r.To.Mode = "a"
	}
}

func (r *Runtime) ReloadFromConfig(cfg *config.Config) error {
	if r == nil {
		return nil
	}

	nextPath, nextCfg, cfgErr := loadLuaRuntimeFromB4Config(cfg)
	if cfgErr != nil {
		return cfgErr
	}
	nextFWMark := runtimeDefaultFWMark(cfg)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return errors.New("lua runtime is closed")
	}
	if r.L != nil {
		r.L.Close()
		r.L = nil
	}
	r.closeSendersLocked()
	r.closeTimersLocked()

	r.path = nextPath
	r.cfg = nextCfg
	r.defaultFWMark = nextFWMark
	r.initErr = nil
	r.currentReq = nil
	r.currentPlanIdx = -1
	r.currentOutgoing = false
	r.currentTrack = nil
	r.currentInstance = ""
	r.currentProfileN = 1
	r.currentProfile = ""
	r.currentCookie = ""
	r.cancelRemaining = false
	r.unsupportedWarn = make(map[string]struct{})
	r.senderCache = make(map[string]*sock.Sender)
	r.conntrack = make(map[string]*luaConnTrack)
	r.timers = make(map[string]*luaTimer)
	r.timerSeq = 0

	log.Infof("Lua runtime reloaded: mode=%s, lua_init=%d, execution_plan=%d",
		r.cfg.Mode, len(r.cfg.LuaInit), len(r.cfg.ExecutionPlan))
	return nil
}
