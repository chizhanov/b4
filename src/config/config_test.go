package config

import "testing"

func TestNewSetConfig_DeepCopy(t *testing.T) {
	set1 := NewSetConfig()
	set2 := NewSetConfig()

	set1.TCP.Win.Values = append(set1.TCP.Win.Values, 999)
	set1.Targets.GeoSiteCategories = append(set1.Targets.GeoSiteCategories, "test")
	set1.Faking.SNIMutation.FakeSNIs = append(set1.Faking.SNIMutation.FakeSNIs, "test.com")
	set1.Lua.Desync = append(set1.Lua.Desync, "pass")
	set1.Lua.ExecutionPlan = append(set1.Lua.ExecutionPlan, LuaExecutionInstanceConfig{Func: "pass"})

	if len(set2.TCP.Win.Values) != 4 {
		t.Error("WinValues leaked between instances")
	}
	if len(set2.Targets.GeoSiteCategories) != 0 {
		t.Error("GeoSiteCategories leaked between instances")
	}
	if len(set2.Faking.SNIMutation.FakeSNIs) != 3 {
		t.Error("FakeSNIs leaked between instances")
	}
	if len(set2.Lua.Desync) != 0 {
		t.Error("Lua.Desync leaked between instances")
	}
	if len(set2.Lua.ExecutionPlan) != 0 {
		t.Error("Lua.ExecutionPlan leaked between instances")
	}

	set1.Fragmentation.StrategyPool = append(set1.Fragmentation.StrategyPool, "combo")
	if len(set2.Fragmentation.StrategyPool) != 0 {
		t.Error("StrategyPool leaked between instances")
	}
}

func TestResolveRange(t *testing.T) {
	if v := ResolveRange(5, 0); v != 5 {
		t.Errorf("ResolveRange(5,0) = %d, want 5", v)
	}
	if v := ResolveRange(5, 5); v != 5 {
		t.Errorf("ResolveRange(5,5) = %d, want 5", v)
	}
	if v := ResolveRange(5, 3); v != 5 {
		t.Errorf("ResolveRange(5,3) = %d, want 5 (max<min)", v)
	}
	for i := 0; i < 100; i++ {
		v := ResolveRange(5, 10)
		if v < 5 || v > 10 {
			t.Fatalf("ResolveRange(5,10) = %d, out of [5,10]", v)
		}
	}
}

func TestNewConfig_DeepCopySystemLuaInit(t *testing.T) {
	cfg1 := NewConfig()
	cfg2 := NewConfig()

	cfg1.System.Lua.Init = append(cfg1.System.Lua.Init, "@/tmp/a.lua")
	if len(cfg2.System.Lua.Init) != 0 {
		t.Error("System.Lua.Init leaked between instances")
	}
}

func TestResolveStrategyPool(t *testing.T) {
	if v := ResolveStrategyPool(nil, "tcp"); v != "tcp" {
		t.Errorf("empty pool should return fallback, got %q", v)
	}
	if v := ResolveStrategyPool([]string{}, "tcp"); v != "tcp" {
		t.Errorf("empty pool should return fallback, got %q", v)
	}
	if v := ResolveStrategyPool([]string{"combo"}, "tcp"); v != "combo" {
		t.Errorf("single-item pool should return that item, got %q", v)
	}
	pool := []string{"combo", "disorder", "tcp"}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		seen[ResolveStrategyPool(pool, "none")] = true
	}
	for _, s := range pool {
		if !seen[s] {
			t.Errorf("strategy %q never picked from pool in 100 tries", s)
		}
	}
}
