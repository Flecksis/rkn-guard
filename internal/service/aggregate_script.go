package service

import (
	_ "embed"
	"strings"
)

// AggregateLogsScriptTemplate используется таймером и интерактивным просмотром.
//
//go:embed aggregate_logs.py
var aggregateLogsScript string

var AggregateLogsScriptTemplate = strings.ReplaceAll(aggregateLogsScript, "\r\n", "\n")
