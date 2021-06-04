package model

import (
	"time"
)

// PoC is PoC struct for Result
type PoC struct {
	Type string
	Data string
}

// Result is struct for library and cli application
type Result struct {
	Logs      []string
	PoCs      []PoC
	Duration  int64
	StartTime time.Time
	EndTime   time.Time
}

// IsFound is check for result
func (c *Result) IsFound() bool {
	if len(c.PoCs) > 0 {
		return true
	}
	return false
}
