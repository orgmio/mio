package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/orgmio/mio/config"
)

// levelFatal 是导致程序退出的错误，显示为 FATAL。
const levelFatal = slog.LevelError + 4

// timestampFormat 是完整时间戳的格式，例如 +0800 2026-11-15 19:00:37。
const timestampFormat = "-0700 2006-01-02 15:04:05"

// startTime 是相对时间戳（INFO[0012] 方括号里的秒数）的起点。
var startTime = time.Now()

type timestampMode uint8

const (
	timestampRelative timestampMode = iota // INFO[0012] 消息
	timestampFull                          // +0800 2026-11-15 19:00:37 INFO 消息
	timestampNone                          // INFO 消息
)

// logHandler 把 slog 记录写成一行：级别、时间戳、消息。
// 名为 err 的属性接在消息后面写成 ": 错误"，其余属性写成 " 键=值"。
type logHandler struct {
	mu        *sync.Mutex
	out       io.Writer
	level     slog.Level
	color     bool
	timestamp timestampMode
}

func newLogHandler(out io.Writer, level slog.Level, color bool, timestamp timestampMode) *logHandler {
	return &logHandler{mu: new(sync.Mutex), out: out, level: level, color: color, timestamp: timestamp}
}

func (h *logHandler) Enabled(_ context.Context, level slog.Level) bool { return level >= h.level }

func (h *logHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *logHandler) WithGroup(string) slog.Handler { return h }

func (h *logHandler) Handle(_ context.Context, record slog.Record) error {
	name, color := "DEBUG", "37"
	switch {
	case record.Level >= levelFatal:
		name, color = "FATAL", "31"
	case record.Level >= slog.LevelError:
		name, color = "ERROR", "31"
	case record.Level >= slog.LevelWarn:
		name, color = "WARN", "33"
	case record.Level >= slog.LevelInfo:
		name, color = "INFO", "36"
	}
	if h.color {
		name = "\x1b[" + color + "m" + name + "\x1b[0m"
	}

	var line strings.Builder
	switch h.timestamp {
	case timestampFull:
		line.WriteString(record.Time.Format(timestampFormat))
		line.WriteString(" ")
		line.WriteString(name)
		line.WriteString(" ")
	case timestampNone:
		line.WriteString(name)
		line.WriteString(" ")
	default:
		fmt.Fprintf(&line, "%s[%04d] ", name, int(record.Time.Sub(startTime)/time.Second))
	}
	line.WriteString(record.Message)
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "err" {
			line.WriteString(": ")
			line.WriteString(attr.Value.String())
		} else {
			line.WriteString(" ")
			line.WriteString(attr.Key)
			line.WriteString("=")
			line.WriteString(attr.Value.String())
		}
		return true
	})
	line.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, line.String())
	return err
}

// consoleHandler 写到标准错误，时间戳是程序启动以来的秒数。
func consoleHandler(level slog.Level) *logHandler {
	return newLogHandler(os.Stderr, level, !disableColor && term.IsTerminal(int(os.Stderr.Fd())), timestampRelative)
}

// useConsoleLog 是读到配置之前使用的日志。
func useConsoleLog() {
	slog.SetDefault(slog.New(consoleHandler(slog.LevelInfo)))
}

// fatal 把 err 打印到标准错误并以状态码 1 退出，不受配置文件里日志设置的影响。
func fatal(err error) {
	slog.New(consoleHandler(slog.LevelInfo)).Log(context.Background(), levelFatal, err.Error())
	os.Exit(1)
}

// setupLog 按配置文件的 [log] 设置日志，返回的函数用于在退出时关闭日志文件。
//
// timestamp 为 true 时每行带完整时间戳；为 false 时，输出到终端的日志带启动以来的秒数，输出到文件的日志不带时间。
// 颜色只在输出到终端且没有 --disable-color 时使用。
func setupLog(cfg config.Log) (func(), error) {
	if !cfg.Enable {
		slog.SetDefault(slog.New(slog.DiscardHandler))
		return func() {}, nil
	}
	level, err := cfg.SlogLevel()
	if err != nil {
		return nil, err
	}

	if cfg.Output == "" {
		handler := consoleHandler(level)
		if cfg.Timestamp {
			handler.timestamp = timestampFull
		}
		slog.SetDefault(slog.New(handler))
		return func() {}, nil
	}

	file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", cfg.Output, err)
	}
	timestamp := timestampNone
	if cfg.Timestamp {
		timestamp = timestampFull
	}
	slog.SetDefault(slog.New(newLogHandler(file, level, false, timestamp)))
	return func() { file.Close() }, nil
}
