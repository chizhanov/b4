package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/lua"
	"github.com/daniellavrushin/b4/sock"
)

func main() {
	workspace := strings.TrimSpace(os.Getenv("GITHUB_WORKSPACE"))
	if workspace == "" {
		cwd, err := os.Getwd()
		if err == nil {
			workspace = filepath.Dir(cwd)
		}
	}
	if workspace == "" {
		fmt.Fprintln(os.Stderr, "cannot resolve workspace path")
		os.Exit(2)
	}

	cfg := config.NewConfig()
	cfg.System.Lua.Init = []string{
		"@" + filepath.Join(workspace, "lua", "zapret-lib.lua"),
		"@" + filepath.Join(workspace, "lua", "zapret-tests.lua"),
	}
	if !canRawsend() {
		cfg.System.Lua.Init = append(cfg.System.Lua.Init, `
test_rawsend = function(...)
	print("* rawsend (skipped: CAP_NET_RAW required)")
end
`)
	}
	cfg.System.Lua.Init = append(cfg.System.Lua.Init, "test_all()")

	set := config.NewSetConfig()
	set.Id = "lua-ci"
	set.Name = "lua-ci"
	set.Enabled = true
	set.Lua.Enabled = true
	set.Lua.Desync = []string{"pass"}
	cfg.Sets = []*config.SetConfig{&set}

	rt := lua.LoadRuntime(&cfg)
	if rt == nil || !rt.Enabled() {
		fmt.Fprintln(os.Stderr, "lua runtime is not enabled")
		os.Exit(3)
	}

	raw := []byte{
		0x45, 0x00, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
		0x01, 0x01, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
		0x1f, 0x90, 0x00, 0x35, 0x00, 0x09, 0x00, 0x00, 0x61,
	}

	if _, err := rt.Process(&lua.PacketRequest{
		Family:    4,
		Proto:     17,
		RawPacket: raw,
		Payload:   []byte{0x61},
		SrcIP:     "1.1.1.1",
		DstIP:     "8.8.8.8",
		SrcPort:   8080,
		DstPort:   53,
		SetName:   "lua-ci",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "lua smoke failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("lua smoke passed")
}

func canRawsend() bool {
	s, err := sock.NewSenderWithMarkAndInterface(0, "")
	if err != nil {
		return false
	}
	s.Close()
	return true
}
