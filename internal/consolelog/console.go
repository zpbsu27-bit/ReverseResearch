package consolelog

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Color uint8

const (
	ColorWhite Color = iota
	ColorDim
	ColorStatus
	ColorGreen
	ColorYellow
	ColorRed
	ColorTunnel
)

// stdout and stderr share the same Windows console and its color attributes.
var outputMu sync.Mutex

func Event(color Color, component, message string) {
	writer := io.Writer(os.Stdout)
	if color == ColorRed || color == ColorYellow || color == ColorTunnel {
		writer = os.Stderr
	}
	write(writer, color, eventLine(color, component, message))
}

func Eventf(color Color, component, format string, args ...any) {
	Event(color, component, fmt.Sprintf(format, args...))
}

func eventLine(color Color, component, message string) string {
	level := "信息"
	switch color {
	case ColorDim:
		level = "状态"
	case ColorStatus:
		level = "进行"
	case ColorGreen:
		level = "完成"
	case ColorYellow:
		level = "警告"
	case ColorRed:
		level = "错误"
	case ColorTunnel:
		level = "连接"
	}
	return fmt.Sprintf("[%s] [%s] %s", level, component, message)
}

func write(writer io.Writer, color Color, value string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	value = strings.TrimRight(value, "\r\n")
	value = strings.Map(func(r rune) rune {
		// External diagnostic lines cannot inject console control sequences or
		// manufacture extra log rows. Normal Unicode text remains readable.
		if r < ' ' || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ' '
		}
		return r
	}, value)
	writeConsole(writer, color, "["+time.Now().Format("2006-01-02 15:04:05.000")+"] "+value)
}

func TunnelWriter() *TunnelLog {
	w := &TunnelLog{lineWriter: &lineWriter{writer: os.Stderr, classify: classifyTunnelLine, component: "TUNNEL"}}
	w.onLine = w.observeLine
	return w
}

// TunnelLog only projects events emitted by the SDK. It does not own polling,
// connection health, or retries, and a previous success is not a live probe.
type TunnelLog struct {
	*lineWriter
	observation TunnelObservation
}

type TunnelObservation struct {
	LastEvent    string
	ObservedAt   time.Time
	PollFailures uint64
	FailureKind  string
}

func (w *TunnelLog) Snapshot() TunnelObservation {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.observation
}

// ObserveReady records the SDK's one-time first successful poll. A delayed
// Ready receiver must not overwrite a subsequent failure or recovery event.
func (w *TunnelLog) ObserveReady() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.observation.LastEvent == "" {
		w.observation.LastEvent = "first_poll_ok"
		w.observation.ObservedAt = time.Now()
	}
}

// observeLine runs under lineWriter.mu after a complete line is received.
func (w *TunnelLog) observeLine(line string) {
	level, message := tunnelLogHeader(line)
	switch {
	case (level == "warn" || level == "warning" || level == "error") &&
		(message == "poll failed; backing off" || message == "poll timed out; backing off"):
		w.observation.LastEvent = "poll_retry"
		w.observation.PollFailures++
		w.observation.FailureKind = "poll_failure"
		switch {
		case message == "poll timed out; backing off" || strings.Contains(line, "poll transport failed (timeout)"):
			w.observation.FailureKind = "timeout"
		case strings.Contains(line, "poll transport failed (network_error)"):
			w.observation.FailureKind = "network_error"
		}
	case level == "info" && message == "poller recovered; polling operational":
		w.observation.LastEvent = "poll_recovered"
		w.observation.FailureKind = ""
	case level == "info" && message == "poller stopped":
		w.observation.LastEvent = "poll_stopped"
	default:
		return
	}
	w.observation.ObservedAt = time.Now()
}

func (s TunnelObservation) Summary() string {
	message := "等待首次轮询结果"
	switch s.LastEvent {
	case "first_poll_ok":
		message = "首次轮询成功"
	case "poll_recovered":
		message = "轮询已恢复"
	case "poll_retry":
		message = "轮询失败，SDK 正在退避重试"
		switch s.FailureKind {
		case "timeout":
			message += "（超时）"
		case "network_error":
			message += "（网络错误）"
		}
	case "poll_stopped":
		message = "轮询已停止"
	}
	if !s.ObservedAt.IsZero() {
		message += " @ " + s.ObservedAt.Format("15:04:05")
	}
	return fmt.Sprintf("隧道最近观测：%s；累计轮询失败 %d", message, s.PollFailures)
}

// Writer adapts newline-delimited diagnostics without changing their producer.
func Writer(component string, color Color) io.Writer {
	return &lineWriter{writer: os.Stderr, classify: func(string) Color { return color }, component: component}
}

const maxTunnelLineBytes = 64 << 10

type lineWriter struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
	writer    io.Writer
	classify  func(string) Color
	component string
	onLine    func(string)
}

func (w *lineWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	originalLength := len(payload)
	for len(payload) > 0 {
		newline := bytes.IndexByte(payload, '\n')
		segment := payload
		complete := false
		if newline >= 0 {
			segment = payload[:newline]
			complete = true
		}

		remaining := maxTunnelLineBytes - w.buffer.Len()
		if remaining > 0 {
			keep := len(segment)
			if keep > remaining {
				keep = remaining
			}
			_, _ = w.buffer.Write(segment[:keep])
			if keep < len(segment) {
				w.truncated = true
			}
		} else if len(segment) > 0 {
			w.truncated = true
		}

		if !complete {
			break
		}
		w.flushLine()
		payload = payload[newline+1:]
	}
	return originalLength, nil
}

func (w *lineWriter) flushLine() {
	line := strings.TrimRight(w.buffer.String(), "\r")
	if w.truncated {
		line += " [line truncated at 65536 bytes]"
	}
	w.buffer.Reset()
	w.truncated = false
	if line != "" {
		if w.onLine != nil {
			w.onLine(line)
		}
		color := w.classify(line)
		if w.component != "" {
			line = eventLine(color, w.component, line)
		}
		write(w.writer, color, line)
	}
}

func classifyTunnelLine(line string) Color {
	level, message := tunnelLogHeader(line)
	// An error attribute describes a cause; the producer's level owns severity.
	// Ignore level-looking text inside the quoted message and later attributes.
	switch level {
	case "error", "fatal":
		return ColorRed
	case "warn", "warning":
		return ColorYellow
	case "debug":
		return ColorDim
	}
	lower := strings.ToLower(message)
	if level == "" {
		lower = strings.ToLower(line)
		if strings.Contains(lower, " error=") {
			return ColorRed
		}
	}
	switch {
	case lower == "poller recovered; polling operational",
		strings.Contains(lower, "tunnel metadata fetched"):
		return ColorGreen
	case strings.Contains(lower, "poller started"),
		strings.Contains(lower, "starting control-plane poller"),
		strings.Contains(lower, "route resolved"),
		strings.Contains(lower, "channels registered"):
		return ColorStatus
	case strings.Contains(lower, "tls trust summary"),
		strings.Contains(lower, "harpoon"),
		strings.Contains(lower, "catalog digest"),
		strings.Contains(lower, "skipping mcp probe"):
		return ColorDim
	default:
		return ColorWhite
	}
}

// The SDK uses slog.TextHandler: time and level precede msg. Reading only this
// header avoids mistaking quoted diagnostics for producer attributes.
func tunnelLogHeader(line string) (level, message string) {
	remaining := strings.TrimSpace(line)
	for remaining != "" {
		if strings.HasPrefix(remaining, "msg=") {
			value := strings.TrimPrefix(remaining, "msg=")
			if strings.HasPrefix(value, "\"") {
				quoted, err := strconv.QuotedPrefix(value)
				if err == nil {
					message, _ = strconv.Unquote(quoted)
				}
			} else {
				message, _, _ = strings.Cut(value, " ")
			}
			return level, message
		}
		field, rest, _ := strings.Cut(remaining, " ")
		if value, ok := strings.CutPrefix(field, "level="); ok {
			level = strings.ToLower(value)
		}
		remaining = strings.TrimSpace(rest)
	}
	return level, message
}
