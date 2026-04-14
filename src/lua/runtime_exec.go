package lua

import (
	"errors"
	"fmt"
	"strings"

	"github.com/daniellavrushin/b4/log"
	"github.com/florianl/go-nfqueue"
	lua "github.com/yuin/gopher-lua"
)

const (
	VerdictPass         uint8 = 0
	VerdictModify       uint8 = 1
	VerdictDrop         uint8 = 2
	VerdictMask         uint8 = 3
	VerdictPreserveNext uint8 = 4
)

func (r *Runtime) Process(req *PacketRequest) (PacketResult, error) {
	if r == nil || !r.Enabled() {
		return PacketResult{Verdict: VerdictPass}, nil
	}
	if req == nil {
		return PacketResult{Verdict: VerdictPass}, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return PacketResult{Verdict: VerdictPass}, errors.New("lua runtime is closed")
	}
	if r.L == nil {
		if err := r.initStateLocked(); err != nil {
			r.initErr = err
			return PacketResult{Verdict: VerdictPass}, err
		}
	}
	if r.initErr != nil {
		return PacketResult{Verdict: VerdictPass}, r.initErr
	}

	r.currentReq = req
	r.currentOutgoing = true
	r.currentTrack = nil
	r.currentInstance = ""
	r.currentProfileN = 1
	r.currentProfile = ""
	r.currentCookie = ""
	r.currentPlanIdx = -1
	r.cancelRemaining = false
	r.resolveCurrentProfile(req.SetName)
	defer func() {
		r.currentReq = nil
		r.currentPlanIdx = -1
		r.currentOutgoing = false
		r.currentTrack = nil
		r.currentInstance = ""
		r.currentProfileN = 1
		r.currentProfile = ""
		r.currentCookie = ""
		r.cancelRemaining = false
	}()

	desync := r.buildDesyncContextLocked(req)
	if r.currentTrack != nil {
		if r.currentOutgoing && r.currentTrack.luaOutCutoff {
			return PacketResult{Verdict: VerdictPass}, nil
		}
		if !r.currentOutgoing && r.currentTrack.luaInCutoff {
			return PacketResult{Verdict: VerdictPass}, nil
		}
	}

	verdict := VerdictPass

	for i := range r.cfg.ExecutionPlan {
		if r.cancelRemaining {
			break
		}
		inst := r.cfg.ExecutionPlan[i]
		if inst.SetName != "" && inst.SetName != req.SetName {
			continue
		}
		r.currentPlanIdx = i
		instTbl := r.buildPlanInstanceTable(i, inst, r.currentOutgoing)
		funcInstance := luaToStringAny(instTbl.RawGetString("func_instance"))
		if r.currentTrack != nil && r.currentTrack.instanceCutoff(funcInstance, r.currentOutgoing) {
			continue
		}
		r.currentInstance = funcInstance
		v, err := r.executeInstanceLocked(desync, verdict, instTbl, inst.Func)
		r.currentInstance = ""
		if err != nil {
			return PacketResult{Verdict: VerdictPass}, err
		}
		verdict = v
	}

	res := PacketResult{Verdict: verdict}
	if (verdict & VerdictMask) == VerdictModify {
		disAfter, _ := desync.RawGetString("dis").(*lua.LTable)
		if disAfter == nil {
			return PacketResult{Verdict: VerdictPass}, errors.New("lua VERDICT_MODIFY without desync.dis")
		}
		rawModified, err := reconstructPacketFromLua(disAfter, nil)
		if err != nil {
			return PacketResult{Verdict: VerdictPass}, fmt.Errorf("reconstruct modified packet: %w", err)
		}
		res.ModifiedPacket = rawModified
	}

	return res, nil
}

func (r *Runtime) executeInstanceLocked(desync *lua.LTable, prev uint8, instTbl *lua.LTable, fnName string) (uint8, error) {
	if r.L == nil {
		return prev, errors.New("lua state is nil")
	}

	if fn, ok := r.L.GetGlobal("plan_instance_execute").(*lua.LFunction); ok {
		if err := r.L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, desync, lua.LNumber(prev), instTbl); err != nil {
			return prev, err
		}
		ret := r.L.Get(-1)
		r.L.Pop(1)
		if v, ok := luaToVerdict(ret); ok {
			return v, nil
		}
		return prev, nil
	}

	// Fallback path without zapret-lib helpers.
	if applyFn, ok := r.L.GetGlobal("apply_execution_plan").(*lua.LFunction); ok {
		if err := r.L.CallByParam(lua.P{Fn: applyFn, NRet: 0, Protect: true}, desync, instTbl); err != nil {
			return prev, err
		}
	} else {
		desync.RawSetString("func", instTbl.RawGetString("func"))
		desync.RawSetString("func_n", instTbl.RawGetString("func_n"))
		desync.RawSetString("func_instance", instTbl.RawGetString("func_instance"))
		desync.RawSetString("arg", instTbl.RawGetString("arg"))
	}

	fnLV := r.L.GetGlobal(fnName)
	fn, ok := fnLV.(*lua.LFunction)
	if !ok {
		return prev, fmt.Errorf("lua function not found: %s", fnName)
	}
	if err := r.L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, lua.LNil, desync); err != nil {
		return prev, err
	}
	ret := r.L.Get(-1)
	r.L.Pop(1)
	v := prev
	if rv, ok := luaToVerdict(ret); ok {
		v = aggregateVerdicts(prev, rv)
	}
	return v, nil
}

func aggregateVerdicts(v1, v2 uint8) uint8 {
	flags := (v1 & VerdictPreserveNext) | (v2 & VerdictPreserveNext)
	a1 := v1 & VerdictMask
	a2 := v2 & VerdictMask

	action := VerdictPass
	switch {
	case a1 == VerdictDrop || a2 == VerdictDrop:
		action = VerdictDrop
	case a1 == VerdictModify || a2 == VerdictModify:
		action = VerdictModify
	default:
		action = VerdictPass
	}
	return action | flags
}

func (r *Runtime) buildPlanInstanceTable(idx int, inst ExecutionInstance, outgoing bool) *lua.LTable {
	L := r.L
	t := L.NewTable()
	profileN := inst.ProfileN
	if profileN <= 0 {
		profileN = 1
	}
	funcN := inst.FuncN
	if funcN <= 0 {
		funcN = idx + 1
	}
	funcInstance := desyncInstanceName(inst.Func, profileN, funcN)

	t.RawSetString("func", lua.LString(inst.Func))
	t.RawSetString("func_n", lua.LNumber(funcN))
	t.RawSetString("func_instance", lua.LString(funcInstance))
	t.RawSetString("profile_n", lua.LNumber(profileN))
	if inst.ProfileName != "" {
		t.RawSetString("profile_name", lua.LString(inst.ProfileName))
	}
	if inst.Cookie != "" {
		t.RawSetString("cookie", lua.LString(inst.Cookie))
	}

	arg := L.NewTable()
	for k, v := range inst.Arg {
		arg.RawSetString(k, lua.LString(v))
	}
	t.RawSetString("arg", arg)

	payloadFilter := strings.TrimSpace(inst.PayloadFilter)
	if payloadFilter == "" {
		payloadFilter = "known"
	}
	t.RawSetString("payload_filter", lua.LString(payloadFilter))

	rangeCfg := inst.RangeIn
	if outgoing {
		rangeCfg = inst.RangeOut
	}
	t.RawSetString("range", luaRangeTable(L, rangeCfg))

	return t
}

func desyncInstanceName(fn string, profileN, funcN int) string {
	return fmt.Sprintf("%s_%d_%d", fn, profileN, funcN)
}

func (r *Runtime) resolveCurrentProfile(setName string) {
	r.currentProfileN = 1
	r.currentProfile = strings.TrimSpace(setName)
	r.currentCookie = ""
	for i := range r.cfg.ExecutionPlan {
		inst := r.cfg.ExecutionPlan[i]
		if strings.TrimSpace(inst.SetName) != strings.TrimSpace(setName) {
			continue
		}
		if inst.ProfileN > 0 {
			r.currentProfileN = inst.ProfileN
		}
		if inst.ProfileName != "" {
			r.currentProfile = inst.ProfileName
		}
		r.currentCookie = inst.Cookie
		return
	}
}

func luaRangeTable(L *lua.LState, rng PacketRange) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("upper_cutoff", lua.LBool(rng.UpperCutoff))
	from := L.NewTable()
	from.RawSetString("mode", lua.LString(defaultPosMode(rng.From.Mode)))
	from.RawSetString("pos", lua.LNumber(rng.From.Pos))
	to := L.NewTable()
	to.RawSetString("mode", lua.LString(defaultPosMode(rng.To.Mode)))
	to.RawSetString("pos", lua.LNumber(rng.To.Pos))
	t.RawSetString("from", from)
	t.RawSetString("to", to)
	return t
}

func defaultPosMode(mode string) string {
	m := strings.TrimSpace(mode)
	if m == "" {
		return "a"
	}
	return m
}

func applyAcceptVerdict(q *nfqueue.Nfqueue, id uint32) int {
	if err := q.SetVerdict(id, nfqueue.NfAccept); err != nil {
		log.Tracef("failed to set accept verdict on Lua packet %d: %v", id, err)
	}
	return 0
}

// HandleNFQueuePacket runs Lua runtime and maps its result to NFQUEUE verdict API.
func (r *Runtime) HandleNFQueuePacket(
	q *nfqueue.Nfqueue,
	id uint32,
	req *PacketRequest,
	originalSize int,
) int {
	if r == nil || !r.Enabled() || req == nil {
		return applyAcceptVerdict(q, id)
	}

	res, err := r.Process(req)
	if err != nil {
		log.Errorf("Lua runtime process error: %v", err)
		return applyAcceptVerdict(q, id)
	}
	return ApplyNFQueueVerdict(q, id, res, originalSize)
}

// ApplyNFQueueVerdict maps Lua packet result to NFQUEUE verdict API.
func ApplyNFQueueVerdict(q *nfqueue.Nfqueue, id uint32, res PacketResult, originalSize int) int {
	action := res.Verdict & VerdictMask

	switch action {
	case VerdictPass:
		return applyAcceptVerdict(q, id)
	case VerdictDrop:
		if err := q.SetVerdict(id, nfqueue.NfDrop); err != nil {
			log.Tracef("failed to set drop verdict on Lua packet %d: %v", id, err)
		}
		return 0
	case VerdictModify:
		if len(res.ModifiedPacket) == 0 {
			log.Warnf("Lua verdict MODIFY without packet payload, fallback to PASS")
			return applyAcceptVerdict(q, id)
		}
		if err := q.SetVerdictModPacket(id, nfqueue.NfAccept, res.ModifiedPacket); err != nil {
			log.Errorf("failed to set modified verdict on Lua packet %d: %v", id, err)
			return applyAcceptVerdict(q, id)
		}
		log.Tracef("Lua modified packet applied: %d => %d bytes", originalSize, len(res.ModifiedPacket))
		return 0
	default:
		log.Warnf("Lua verdict has unsupported action bits: %s. Fallback to PASS", fmt.Sprintf("0x%x", action))
		return applyAcceptVerdict(q, id)
	}
}
