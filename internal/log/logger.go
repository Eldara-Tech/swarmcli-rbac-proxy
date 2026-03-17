package proxylog

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *ProxyLogger
	raw    *zap.Logger

	noopLogger = &ProxyLogger{zap.NewNop().Sugar()}

	atomicLevel zap.AtomicLevel
)

// ProxyLogger wraps zap's SugaredLogger for convenience.
type ProxyLogger struct {
	*zap.SugaredLogger
}

// With adds structured fields to the logger and returns a new instance.
func (l *ProxyLogger) With(args ...interface{}) *ProxyLogger {
	if l == nil {
		return noopLogger
	}
	return &ProxyLogger{l.SugaredLogger.With(args...)}
}

// L returns the global logger or a no-op fallback if uninitialized.
func L() *ProxyLogger {
	if logger == nil {
		return noopLogger
	}
	return logger
}

// Init initializes the global logger.
//
// mode selects the encoder: "dev" → console, anything else → JSON.
// level selects the minimum log level: "debug", "info", "warn", "error".
// Empty strings use defaults (prod mode, info level — or debug in dev mode).
func Init(mode, level string) {
	if raw != nil {
		_ = raw.Sync()
	}

	mode = parseMode(mode)
	atomicLevel = zap.NewAtomicLevelAt(parseLogLevel(level, mode))

	writer := zapcore.AddSync(os.Stdout)

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	var encoder zapcore.Encoder
	if mode == "dev" {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	core := zapcore.NewCore(encoder, writer, atomicLevel)
	raw = zap.New(core, zap.AddCaller())
	logger = &ProxyLogger{raw.Sugar()}
}

// Sync flushes any buffered log entries.
func Sync() {
	if raw != nil {
		_ = raw.Sync()
	}
}

// InitTestIfTestLogEnv creates a lightweight logger for tests that logs to
// stdout if the TEST_LOG env is set; otherwise sets a noop logger.
func InitTestIfTestLogEnv() {
	if os.Getenv("TEST_LOG") == "" {
		logger = noopLogger
		return
	}

	cfg := zap.NewDevelopmentConfig()
	cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	cfg.OutputPaths = []string{"stdout"}
	raw, _ = cfg.Build(zap.AddCaller())
	logger = &ProxyLogger{raw.Sugar()}
}

// SetLevel allows changing the log level at runtime.
func SetLevel(level zapcore.Level) {
	if atomicLevel != (zap.AtomicLevel{}) {
		atomicLevel.SetLevel(level)
	}
}

// parseMode normalizes a mode string to "dev" or "prod".
func parseMode(s string) string {
	switch strings.ToLower(s) {
	case "dev", "development":
		return "dev"
	default:
		return "prod"
	}
}

// parseLogLevel converts a level string to a zapcore.Level.
// Falls back to debug in dev mode and info in prod mode.
func parseLogLevel(level, mode string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zap.DebugLevel
	case "info":
		return zap.InfoLevel
	case "warn", "warning":
		return zap.WarnLevel
	case "error":
		return zap.ErrorLevel
	default:
		if mode == "dev" {
			return zap.DebugLevel
		}
		return zap.InfoLevel
	}
}
