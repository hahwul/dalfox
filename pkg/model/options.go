package model

import (
	"net/http"
	"sync"
	t "time"

	"github.com/hahwul/dalfox/v2/internal/har"

	s "github.com/briandowns/spinner"
	a "github.com/logrusorgru/aurora"
)

// ConfigOptions contains user-configurable options through CLI flags or config file
type Options struct {
	// Target Related
	UniqParam    []string `json:"param,omitempty"`
	IgnoreParams []string `json:"ignore-params,omitempty"`
	Method       string   `json:"method,omitempty"`
	IgnoreReturn string   `json:"ignore-return,omitempty"`

	// HTTP Options
	Cookie        string   `json:"cookie,omitempty"`
	Header        []string `json:"header,omitempty"`
	Data          string   `json:"data,omitempty"`
	UserAgent     string   `json:"user-agent,omitempty"`
	ProxyAddress  string   `json:"proxy,omitempty"`
	CookieFromRaw string   `json:"cookie-from-raw,omitempty"`

	// Feature Options
	BlindURL                  string `json:"blind,omitempty"`
	CustomPayloadFile         string `json:"custom-payload-file,omitempty"`
	CustomBlindXSSPayloadFile string `json:"custom-blind-xss-payload-file,omitempty"`
	CustomAlertValue          string `json:"custom-alert-value,omitempty"`
	CustomAlertType           string `json:"custom-alert-type,omitempty"`
	OnlyDiscovery             bool   `json:"only-discovery,omitempty"`
	OnlyCustomPayload         bool   `json:"only-custom-payload,omitempty"`
	Mining                    bool   `json:"mining-dict,omitempty"`
	FindingDOM                bool   `json:"mining-dom,omitempty"`
	MiningWordlist            string `json:"mining-dict-word,omitempty"`
	RemotePayloads            string `json:"remote-payloads,omitempty"`
	RemoteWordlists           string `json:"remote-wordlists,omitempty"`
	UseHeadless               bool   `json:"use-headless,omitempty"`
	UseDeepDXSS               bool   `json:"use-deepdxss,omitempty"`
	OnlyPoC                   string `json:"only-poc,omitempty"`
	FollowRedirect            bool   `json:"follow-redirects,omitempty"`
	WAFName                   string `json:"waf-name,omitempty"`
	WAFEvasion                bool
	UseBAV                    bool `json:"use-bav,omitempty"`
	NoBAV                     bool `json:"no-bav,omitempty"`
	NoGrep                    bool `json:"skip-grepping,omitempty"`
	SkipDiscovery             bool `json:"skip-discovery,omitempty"`
	ForceHeadlessVerification bool `json:"force-headless-verification,omitempty"`
	DetailedAnalysis          bool `json:"detailed-analysis,omitempty"` // Enable detailed parameter analysis (Issue #695)
	FastScan                  bool `json:"fast-scan,omitempty"`         // Enable fast scanning mode for URL lists (Issue #764)
	MagicCharTest             bool `json:"magic-char-test,omitempty"`   // Enable magic character testing
	ContextAware              bool `json:"context-aware,omitempty"`     // Enable context-aware payload selection

	// Performance Options
	Timeout     int `json:"timeout,omitempty"`
	Concurrence int `json:"worker,omitempty"`
	MaxCPU      int `json:"maxcpu,omitempty"`
	Delay       int `json:"delay,omitempty"`

	// Server Mode Options
	ServerHost     string   `json:"server-host,omitempty"`
	ServerPort     int      `json:"server-port,omitempty"`
	APIKey         string   `json:"api-key,omitempty"`
	ServerType     string   `json:"server-type,omitempty"`
	AllowedOrigins []string `json:"allowed-origins,omitempty"`
	JSONP          bool     `json:"jsonp,omitempty"`

	// Output Options
	Silence          bool   `json:"silence,omitempty"`
	NoColor          bool   `json:"no-color,omitempty"`
	NoSpinner        bool   `json:"no-spinner,omitempty"`
	Grep             string `json:"grep,omitempty"`
	ConfigFile       string `json:"config,omitempty"`
	OutputFile       string `json:"output,omitempty"`
	Format           string `json:"format,omitempty"`
	PoCType          string `json:"poc-type,omitempty"`
	FoundAction      string `json:"found-action,omitempty"`
	FoundActionShell string `json:"found-action-shell,omitempty"`
	OutputAll        bool   `json:"output-all,omitempty"`
	OutputRequest    bool   `json:"output-request,omitempty"`
	OutputResponse   bool   `json:"output-response,omitempty"`
	Debug            bool   `json:"debug,omitempty"`
	HarFilePath      string `json:"har-file-path,omitempty"`
	ReportFormat     string
	ReportBool       bool

	// Advanced Options
	TriggerMethod string `json:"trigger-method,omitempty"`
	Trigger       string `json:"trigger,omitempty"`
	LimitResult   int    `json:"limit-result,omitempty"`
	Sequence      int    `json:"sequence,omitempty"`
	IsAPI         bool   `json:"is-api,omitempty"`
	IsLibrary     bool   `json:"is-library,omitempty"`
	Mass          bool   `json:"mass,omitempty"`
	MulticastMode bool   `json:"multicast-mode,omitempty"`

	// Runtime Options
	AllURLS         int
	NowURL          int
	Scan            map[string]Scan
	ScanResult      Result
	SpinnerObject   *s.Spinner
	AuroraObject    a.Aurora
	StartTime       t.Time
	HarWriter       *har.Writer
	PathReflection  map[int]string
	WAF             bool
	Mutex           *sync.Mutex
	CustomTransport http.RoundTripper
}

// MassJob is list for mass
type MassJob struct {
	Name string
	URLs []string
}

// Scan is struct of scan
type Scan struct {
	URL     string
	ScanID  string
	Logs    []string
	Results []PoC
}

// Issue is struct of issue
type Issue struct {
	Type  string `json:"type"`
	Param string `json:"param"`
	PoC   PoC    `json:"poc"`
}
