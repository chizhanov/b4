package lua

import (
	"time"

	"github.com/daniellavrushin/b4/log"
	lua "github.com/yuin/gopher-lua"
)

type luaTimer struct {
	id       uint64
	name     string
	funcName string
	period   time.Duration
	oneshot  bool
	data     lua.LValue
	stopCh   chan struct{}
}

func (r *Runtime) closeTimersLocked() {
	for name, t := range r.timers {
		delete(r.timers, name)
		if t != nil {
			close(t.stopCh)
		}
	}
}

func (r *Runtime) removeTimerLocked(name string, expected *luaTimer) bool {
	if r == nil || r.timers == nil {
		return false
	}
	t := r.timers[name]
	if t == nil {
		return false
	}
	if expected != nil && t != expected {
		return false
	}
	delete(r.timers, name)
	close(t.stopCh)
	return true
}

func (r *Runtime) setTimerLocked(name, funcName string, period time.Duration, oneshot bool, data lua.LValue) {
	if old := r.timers[name]; old != nil {
		r.removeTimerLocked(name, old)
	}
	r.timerSeq++
	t := &luaTimer{
		id:       r.timerSeq,
		name:     name,
		funcName: funcName,
		period:   period,
		oneshot:  oneshot,
		data:     data,
		stopCh:   make(chan struct{}),
	}
	r.timers[name] = t
	go r.runTimerLoop(t)
}

func (r *Runtime) runTimerLoop(t *luaTimer) {
	if t == nil {
		return
	}
	if t.oneshot {
		timer := time.NewTimer(t.period)
		defer timer.Stop()
		select {
		case <-timer.C:
			r.fireTimer(t)
		case <-t.stopCh:
		}
		return
	}

	ticker := time.NewTicker(t.period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !r.fireTimer(t) {
				return
			}
		case <-t.stopCh:
			return
		}
	}
}

func (r *Runtime) fireTimer(t *luaTimer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.L == nil {
		return false
	}
	current := r.timers[t.name]
	if current != t {
		return false
	}

	fn, ok := r.L.GetGlobal(t.funcName).(*lua.LFunction)
	if !ok {
		log.Errorf("timer '%s': function '%s' does not exist", t.name, t.funcName)
		r.removeTimerLocked(t.name, t)
		return false
	}

	argData := t.data
	if argData == nil {
		argData = lua.LNil
	}
	if err := r.L.CallByParam(
		lua.P{Fn: fn, NRet: 0, Protect: true},
		lua.LString(t.name),
		argData,
	); err != nil {
		log.Errorf("timer '%s': lua callback error: %v", t.name, err)
		r.removeTimerLocked(t.name, t)
		return false
	}

	current = r.timers[t.name]
	if current != t {
		// Таймер мог быть удалён/заменён из Lua callback.
		return false
	}
	if t.oneshot {
		r.removeTimerLocked(t.name, t)
		return false
	}
	return true
}

func (r *Runtime) luaTimerSet(L *lua.LState) int {
	if L.GetTop() < 3 || L.GetTop() > 5 {
		L.RaiseError("timer_set expect from 3 to 5 arguments")
		return 0
	}

	name := L.CheckString(1)
	funcName := L.CheckString(2)
	periodMS := luaArgInt64(L, 3)
	if periodMS < 10 {
		L.RaiseError("invalid timer period. must be >=10 ms")
		return 0
	}
	if _, ok := L.GetGlobal(funcName).(*lua.LFunction); !ok {
		L.RaiseError("timer function '%s' does not exist", funcName)
		return 0
	}

	oneshot := false
	if L.GetTop() >= 4 && L.Get(4) != lua.LNil {
		oneshot = lua.LVAsBool(L.Get(4))
	}
	data := lua.LValue(lua.LNil)
	if L.GetTop() >= 5 {
		data = L.Get(5)
	}

	r.setTimerLocked(name, funcName, time.Duration(periodMS)*time.Millisecond, oneshot, data)
	return 0
}

func (r *Runtime) luaTimerDel(L *lua.LState) int {
	if L.GetTop() != 1 {
		L.RaiseError("timer_del expect exactly 1 argument")
		return 0
	}
	name := L.CheckString(1)
	L.Push(lua.LBool(r.removeTimerLocked(name, nil)))
	return 1
}
