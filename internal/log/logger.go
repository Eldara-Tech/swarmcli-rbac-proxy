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
// It reads PROXY_ENV to select the encoder:
//   - PROXY_ENV=dev → human-readable console output on stdout
//   - PROXY_ENV=prod (default) → JSON output on stdout
//
// Log level is controlled via PROXY_LOG_LEVEL (debug, info, warn, error).
// Defaults to debug in dev mode and info in prod mode.
func Init() {
	if raw != nil {
		_ = raw.Sync()
	}

	mode := detectMode()
	atomicLevel = zap.NewAtomicLevelAt(detectLogLevel())

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

// detectMode determines dev or prod mode from PROXY_ENV.
func detectMode() string {
	env := strings.ToLower(os.Getenv("PROXY_ENV"))
	switch env {
	case "dev", "development":
		return "dev"
	default:
		return "prod"
	}
}

// detectLogLevel picks the initial log level from PROXY_LOG_LEVEL.
func detectLogLevel() zapcore.Level {
	switch strings.ToLower(os.Getenv("PROXY_LOG_LEVEL")) {
	case "debug":
		return zap.DebugLevel
	case "warn", "warning":
		return zap.WarnLevel
	case "error":
		return zap.ErrorLevel
	default:
		if detectMode() == "dev" {
			return zap.DebugLevel
		}
		return zap.InfoLevel
	}
}
