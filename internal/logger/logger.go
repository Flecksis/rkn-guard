package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger дополняет zerolog.Logger настройками проекта.
type Logger struct {
	zerolog.Logger
}

// New создаёт журнал с читаемым выводом в консоль.
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

// NewWithLevel создаёт журнал с указанным уровнем сообщений.
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

// parseLevel преобразует название уровня в значение zerolog.
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

// SetGlobalLogger задаёт общий журнал приложения.
func SetGlobalLogger(logger *Logger) {
	log.Logger = logger.Logger
}

// Global возвращает общий журнал приложения.
func Global() *Logger {
	return &Logger{log.Logger}
}
