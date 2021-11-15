package lib

import (
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// Options is dalfox options for lib
type Options struct {
	UniqParam        []string `json:"param"`
	Cookie           string   `json:"cookie"`
	Header           []string `json:"header"`
	BlindURL         string   `json:"blind"`
	CustomAlertValue string   `json:"custom-alert-value"`
	CustomAlertType  string   `json:"custom-alert-type"`
	Data             string   `json:"data"`
	UserAgent        string   `json:"user-agent"`
	ProxyAddress     string   `json:"proxy"`
	Grep             string   `json:"grep"`
	IgnoreReturn     string   `json:"ignore-return"`
	Trigger          string   `json:"trigger"`
	TriggerMethod    string   `json:"request-method"`
	Timeout          int      `json:"timeout"`
	Concurrence      int      `json:"worker"`
	Delay            int      `json:"delay"`
	OnlyDiscovery    bool     `json:"only-discovery"`
	FollowRedirect   bool     `json:"follow-redirects"`
	Mining           bool     `json:"mining-dict"`
	FindingDOM       bool     `json:"mining-dom"`
	NoBAV            bool     `json:"no-bav"`
	NoGrep           bool     `json:"skip-grepping"`
	RemotePayloads   string
	RemoteWordlists  string
}

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
