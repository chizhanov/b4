package lua

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/daniellavrushin/b4/log"
	lua "github.com/yuin/gopher-lua"
)

func (r *Runtime) Enabled() bool {
	return r != nil && r.cfg.Mode == LuaModeLua
}

func (r *Runtime) Mode() string {
	if r == nil {
		return LuaModeLegacy
	}
	return r.cfg.Mode
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.closed = true
	r.closeTimersLocked()
	if r.L != nil {
		r.L.Close()
		r.L = nil
	}
	r.closeSendersLocked()
	return nil
}

func (r *Runtime) closeSendersLocked() {
	for key, sender := range r.senderCache {
		if sender != nil {
			sender.Close()
		}
		delete(r.senderCache, key)
	}
}

func (r *Runtime) initStateLocked() error {
	L := lua.NewState()
	L.OpenLibs()
	r.L = L

	if err := L.DoString(`do
		local _fmt = string.format
		function string.format(fmt, ...)
			fmt = string.gsub(fmt, "%%([%-+ #0-9%.]*)u", "%%%1d")
			return _fmt(fmt, ...)
		end
	end`); err != nil {
		return fmt.Errorf("lua compat init failed: %w", err)
	}

	r.registerRuntimeAPI(L)

	for _, entry := range r.cfg.LuaInit {
		if err := r.evalInitEntryLocked(entry); err != nil {
			r.L.Close()
			r.L = nil
			return err
		}
	}

	log.Infof("Lua runtime initialized with GopherLua: lua_init=%d", len(r.cfg.LuaInit))
	return nil
}

func (r *Runtime) evalInitEntryLocked(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}

	if strings.HasPrefix(entry, "@") {
		path := strings.TrimSpace(strings.TrimPrefix(entry, "@"))
		if path == "" {
			return errors.New("empty @ path in lua_init")
		}
		if !filepath.IsAbs(path) {
			baseDir := filepath.Dir(r.path)
			path = filepath.Join(baseDir, path)
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("lua_init file %s: %w", path, err)
		}
		source := normalizeLuaSourceCompat(string(src))
		fn, err := r.L.Load(strings.NewReader(source), path)
		if err != nil {
			return fmt.Errorf("lua_init file %s: %w", path, err)
		}
		r.L.Push(fn)
		if err := r.L.PCall(0, lua.MultRet, nil); err != nil {
			return fmt.Errorf("lua_init file %s: %w", path, err)
		}
		return nil
	}

	source := normalizeLuaSourceCompat(entry)
	if err := r.L.DoString(source); err != nil {
		return fmt.Errorf("lua_init chunk: %w", err)
	}
	return nil
}
