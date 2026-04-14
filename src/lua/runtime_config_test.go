package lua

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestLoadLuaRuntimeFromB4Config(t *testing.T) {
	cfg := config.NewConfig()
	set := config.NewSetConfig()
	set.Id = "set-1"
	set.Name = "set-1"
	set.Enabled = true
	set.Lua.Enabled = true
	cfg.System.Lua.Init = []string{"@a.lua", "@a.lua", "  ", "@b.lua"}
	set.Lua.ExecutionPlan = []config.LuaExecutionInstanceConfig{
		{Func: "pass", Arg: map[string]string{"x": "1"}},
	}
	set.Lua.Desync = []string{"fake:foo=bar:baz"}
	cfg.Sets = []*config.SetConfig{&set}

	_, runtimeCfg, err := loadLuaRuntimeFromB4Config(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtimeCfg.Mode != LuaModeLua {
		t.Fatalf("expected mode=%s, got %s", LuaModeLua, runtimeCfg.Mode)
	}
	if len(runtimeCfg.LuaInit) != 2 {
		t.Fatalf("expected 2 unique init entries, got %d", len(runtimeCfg.LuaInit))
	}
	if len(runtimeCfg.ExecutionPlan) != 2 {
		t.Fatalf("expected 2 execution instances, got %d", len(runtimeCfg.ExecutionPlan))
	}
	if runtimeCfg.ExecutionPlan[0].SetName != "set-1" || runtimeCfg.ExecutionPlan[1].SetName != "set-1" {
		t.Fatalf("expected set filter to be propagated")
	}
	if runtimeCfg.ExecutionPlan[1].Arg["foo"] != "bar" {
		t.Fatalf("expected parsed arg foo=bar, got %q", runtimeCfg.ExecutionPlan[1].Arg["foo"])
	}
	if runtimeCfg.ExecutionPlan[1].Arg["baz"] != "1" {
		t.Fatalf("expected parsed flag arg baz=1, got %q", runtimeCfg.ExecutionPlan[1].Arg["baz"])
	}
}

func TestLoadLuaRuntimeFromB4ConfigDisabled(t *testing.T) {
	cfg := config.NewConfig()
	set := config.NewSetConfig()
	set.Id = "set-1"
	set.Name = "set-1"
	set.Enabled = true
	set.Lua.Enabled = false
	cfg.Sets = []*config.SetConfig{&set}

	_, runtimeCfg, err := loadLuaRuntimeFromB4Config(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtimeCfg.Mode != LuaModeLegacy {
		t.Fatalf("expected mode=%s, got %s", LuaModeLegacy, runtimeCfg.Mode)
	}
}

func TestParseDesyncSpec(t *testing.T) {
	inst, err := parseDesyncSpec("test:foo=bar:flag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inst.Func != "test" {
		t.Fatalf("expected func test, got %q", inst.Func)
	}
	if inst.Arg["foo"] != "bar" {
		t.Fatalf("expected foo=bar, got %q", inst.Arg["foo"])
	}
	if inst.Arg["flag"] != "1" {
		t.Fatalf("expected flag=1, got %q", inst.Arg["flag"])
	}
	if inst.RangeIn.From.Mode != "a" || inst.RangeOut.To.Mode != "a" {
		t.Fatalf("expected default ranges with mode a")
	}

	if _, err := parseDesyncSpec(":foo=bar"); err == nil {
		t.Fatal("expected error for empty function name")
	}
}
