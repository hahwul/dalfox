package lib

import (
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// Options is dalfox options for lib
type Options = model.Options

// Target is target object
type Target struct {
	URL     string
	Method  string
	Options Options
}

// Result is struct for library and cli application
type Result struct {
	Logs      []string
	PoCs      []model.PoC
	Params    []model.ParamResult
	Duration  time.Duration
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
