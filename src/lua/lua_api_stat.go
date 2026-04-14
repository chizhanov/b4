package lua

import (
	"errors"
	"os"
	"syscall"

	lua "github.com/yuin/gopher-lua"
)

func luaStat(L *lua.LState) int {
	path := L.CheckString(1)
	info, err := os.Stat(path)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		L.Push(lua.LNumber(statErrno(err)))
		return 3
	}

	out := L.NewTable()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		out.RawSetString("dev", lua.LNumber(st.Dev))
		out.RawSetString("inode", lua.LNumber(st.Ino))
	}
	out.RawSetString("size", lua.LNumber(info.Size()))
	out.RawSetString("mtime", lua.LNumber(float64(info.ModTime().UnixNano())/1e9))
	out.RawSetString("type", lua.LString(statFileType(info.Mode())))
	L.Push(out)
	return 1
}

func statErrno(err error) int {
	if err == nil {
		return 0
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		var errno syscall.Errno
		if errors.As(pe.Err, &errno) {
			return int(errno)
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return 0
}

func statFileType(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "file"
	case mode.IsDir():
		return "dir"
	case (mode & os.ModeSymlink) != 0:
		return "symlink"
	case (mode & os.ModeSocket) != 0:
		return "socket"
	case (mode & os.ModeDevice) != 0:
		if (mode & os.ModeCharDevice) != 0 {
			return "chardev"
		}
		return "blockdev"
	case (mode & os.ModeNamedPipe) != 0:
		return "fifo"
	default:
		return "unknown"
	}
}
