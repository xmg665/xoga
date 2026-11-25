package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelNone
)

func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG":
		return LevelDebug
	case "info", "INFO", "":
		return LevelInfo
	case "warn", "warning", "WARN", "WARNING":
		return LevelWarn
	case "error", "ERROR":
		return LevelError
	case "none", "off", "NONE":
		return LevelNone
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "NONE"
	}
}

// Logger is a low-allocation leveled logger designed for systemd/journald output.
type Logger struct {
	level atomic.Int32
	mu    sync.Mutex
	out   io.Writer
	buf   []byte
}

var std = New(os.Stdout, LevelInfo)

func New(out io.Writer, level Level) *Logger {
	l := &Logger{
		out: out,
		buf: make([]byte, 0, 512),
	}
	l.level.Store(int32(level))
	return l
}

func SetLevel(level Level) { std.SetLevel(level) }
func Default() *Logger    { return std }

func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

func (l *Logger) Enabled(level Level) bool {
	return int32(level) >= l.level.Load()
}

func (l *Logger) logf(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.buf = l.buf[:0]
	l.buf = now.AppendFormat(l.buf, "2006-01-02 15:04:05 ")
	l.buf = append(l.buf, '[')
	l.buf = append(l.buf, level.String()...)
	l.buf = append(l.buf, ']', ' ')
	l.buf = fmt.Appendf(l.buf, format, args...)
	if len(l.buf) == 0 || l.buf[len(l.buf)-1] != '\n' {
		l.buf = append(l.buf, '\n')
	}
	_, _ = l.out.Write(l.buf)
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

func Debugf(format string, args ...any) { std.Debugf(format, args...) }
func Infof(format string, args ...any)  { std.Infof(format, args...) }
func Warnf(format string, args ...any)  { std.Warnf(format, args...) }
func Errorf(format string, args ...any) { std.Errorf(format, args...) }
