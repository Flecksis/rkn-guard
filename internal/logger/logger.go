package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger wraps zerolog.Logger
type Logger struct {
	zerolog.Logger
}

// New creates a new console logger with pretty output
func New() *Logger {
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}

	logger := zerolog.New(output).
		With().
		Timestamp().
		Logger()

	return &Logger{logger}
}

// NewWithLevel creates a logger with specific level
func NewWithLevel(level string) *Logger {
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}

	logLevel := parseLevel(level)

	logger := zerolog.New(output).
		Level(logLevel).
		With().
		Timestamp().
		Logger()

	return &Logger{logger}
}

// parseLevel converts string to zerolog level
func parseLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	default:
		return zerolog.InfoLevel
	}
}

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	log.Logger = logger.Logger
}

// Global returns the global logger
func Global() *Logger {
	return &Logger{log.Logger}
}
