package service

import _ "embed"

// AggregateLogsScriptTemplate используется таймером и интерактивным просмотром.
//
//go:embed aggregate_logs.py
var AggregateLogsScriptTemplate string
