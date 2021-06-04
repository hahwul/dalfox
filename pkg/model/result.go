package model

import (
	"time"
)

// PoC is PoC struct for Result
type PoC struct {
	Type   string
	Method string
	Data   string
}

// Result is struct for library and cli application
type Result struct {
	Logs      []string
	PoCs      []PoC
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
}
