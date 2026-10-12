package service

import _ "embed"

// AggregateLogsScriptTemplate is shared by the timer and the interactive view.
//
//go:embed aggregate_logs.py
var AggregateLogsScriptTemplate string
