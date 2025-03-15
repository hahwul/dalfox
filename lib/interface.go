package lib

import (
	"time"

	"github.com/hahwul/dalfox/v2/internal/har"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// Options is dalfox options for lib
type Options struct {
	UniqParam         []string `json:"param"`
	Cookie            string   `json:"cookie"`
	Header            []string `json:"header"`
	BlindURL          string   `json:"blind"`
	CustomPayloadFile string   `json:"custom-payload-file"`
	CustomAlertValue  string   `json:"custom-alert-value"`
	CustomAlertType   string   `json:"custom-alert-type"`
	Data              string   `json:"data"`
	UserAgent         string   `json:"user-agent"`
	OutputFile        string   `json:"output"`
	FoundAction       string   `json:"found-action"`
	FoundActionShell  string   `json:"found-action-shell"`
	ProxyAddress      string   `json:"proxy"`
	Grep              string   `json:"grep"`
	IgnoreReturn      string   `json:"ignore-return"`
	IgnoreParams      []string `json:"ignore-params"`
	Trigger           string   `json:"trigger"`
	TriggerMethod     string   `json:"request-method"`
	Sequence          int      `json:"sequence"`
	Timeout           int      `json:"timeout"`
	Concurrence       int      `json:"worker"`
	Delay             int      `json:"delay"`
	OnlyDiscovery     bool     `json:"only-discovery"`
	OnlyCustomPayload bool     `json:"only-custom-payload"`
	FollowRedirect    bool     `json:"follow-redirects"`
	Mining            bool     `json:"mining-dict"`
	FindingDOM        bool     `json:"mining-dom"`
	NoBAV             bool     `json:"no-bav"`
	NoGrep            bool     `json:"skip-grepping"`
	UseHeadless       bool     `json:"use-headless"`
	UseDeepDXSS       bool     `json:"use-deepdxss"`
	RemotePayloads    string
	RemoteWordlists   string
	PoCType           string      `json:"poc-type"`
	WAFEvasion        bool        `json:"waf-evasion"`
	HarWriter         *har.Writer `json:"har-file-path"`
	OutputRequest     bool        `json:"output-request,omitempty"`
	OutputResponse    bool        `json:"output-response,omitempty"`
	UseBAV            bool        `json:"use-bav,omitempty"`
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
