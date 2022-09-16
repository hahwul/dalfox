package model

import (
	"time"
)

// PoC is PoC struct for Result
type PoC struct {
	Type       string `json:"type"`
	InjectType string `json:"inject_type"`
	PoCType    string `json:"poc_type"`
	Method     string `json:"method"`
	Data       string `json:"data"`
	Param      string `json:"param"`
	Payload    string `json:"payload"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
}

// Result is struct for library and cli application
type Result struct {
	Logs      []string      `json:"logs"`
	PoCs      []PoC         `json:"pocs"`
	Params    []ParamResult `json:"params"`
	Duration  time.Duration `json:"duration"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
}

type ParamResult struct {
	Name           string
	Type           string
	Reflected      bool
	ReflectedPoint string
	ReflectedCode  string
	Chars          []string
}
