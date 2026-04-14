package lua

import (
	"sync"

	"github.com/daniellavrushin/b4/sock"
	lua "github.com/yuin/gopher-lua"
)

const (
	LuaModeLegacy = "legacy"
	LuaModeLua    = "lua"
)

type RuntimeConfig struct {
	Mode          string              `json:"mode"`
	LuaInit       []string            `json:"lua_init"`
	ExecutionPlan []ExecutionInstance `json:"execution_plan"`
}

type PacketPos struct {
	Mode string `json:"mode"`
	Pos  uint64 `json:"pos"`
}

type PacketRange struct {
	UpperCutoff bool      `json:"upper_cutoff"`
	From        PacketPos `json:"from"`
	To          PacketPos `json:"to"`
}

type ExecutionInstance struct {
	Func          string            `json:"func"`
	Arg           map[string]string `json:"arg"`
	PayloadFilter string            `json:"payload_filter"`
	RangeIn       PacketRange       `json:"range_in"`
	RangeOut      PacketRange       `json:"range_out"`
	SetName       string            `json:"set_name,omitempty"`
	ProfileN      int               `json:"profile_n,omitempty"`
	ProfileName   string            `json:"profile_name,omitempty"`
	Cookie        string            `json:"cookie,omitempty"`
	FuncN         int               `json:"func_n,omitempty"`
}

type PacketRequest struct {
	Family uint8
	Proto  uint8

	RawPacket []byte
	Payload   []byte

	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16

	IfIn   string
	IfOut  string
	FWMark uint32

	Replay          bool
	ReplayPiece     uint32
	ReplayPieceCnt  uint32
	ReplayPieceLast bool

	ReasmOffset uint32
	ReasmData   []byte
	DecryptData []byte

	SetName string
}

type PacketResult struct {
	Verdict        uint8
	ModifiedPacket []byte
}

type Runtime struct {
	path string
	cfg  RuntimeConfig

	defaultFWMark uint32

	mu              sync.Mutex
	L               *lua.LState
	closed          bool
	initErr         error
	currentReq      *PacketRequest
	currentPlanIdx  int
	currentOutgoing bool
	currentTrack    *luaConnTrack
	currentInstance string
	currentProfileN int
	currentProfile  string
	currentCookie   string
	cancelRemaining bool

	unsupportedWarn map[string]struct{}
	senderCache     map[string]*sock.Sender
	conntrack       map[string]*luaConnTrack
	timers          map[string]*luaTimer
	timerSeq        uint64
}
