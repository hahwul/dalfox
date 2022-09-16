package model

import (
	"sync"
	t "time"

	s "github.com/briandowns/spinner"
	a "github.com/logrusorgru/aurora"
)

// Options is struct of options
type Options struct {
	UniqParam         []string `json:"param"`
	Cookie            string   `json:"cookie"`
	Header            []string `json:"header"`
	ConfigFile        string   `json:"config"`
	BlindURL          string   `json:"blind"`
	CustomPayloadFile string   `json:"custom-payload-file"`
	CustomAlertValue  string   `json:"custom-alert-value"`
	CustomAlertType   string   `json:"custom-alert-type"`
	Data              string   `json:"data"`
	UserAgent         string   `json:"user-agent"`
	OutputFile        string   `json:"output"`
	Format            string   `json:"format"`
	FoundAction       string   `json:"found-action"`
	FoundActionShell  string   `json:"found-action-shell"`
	ProxyAddress      string   `json:"proxy"`
	Grep              string   `json:"grep"`
	IgnoreReturn      string   `json:"ignore-return"`
	IgnoreParams      []string `json:"ignore-params"`
	Trigger           string   `json:"trigger"`
	Timeout           int      `json:"timeout"`
	Concurrence       int      `json:"worker"`
	Delay             int      `json:"delay"`
	AllURLS           int
	NowURL            int
	Sequence          int  `json:"sequence"`
	OnlyDiscovery     bool `json:"only-discovery"`
	OnlyCustomPayload bool `json:"only-custom-payload"`
	Silence           bool `json:"silence"`
	IsAPI             bool
	IsLibrary         bool
	Mass              bool `json:"mass"`
	MulticastMode     bool
	Scan              map[string]Scan
	FollowRedirect    bool   `json:"follow-redirects"`
	Mining            bool   `json:"mining-dict"`
	FindingDOM        bool   `json:"mining-dom"`
	MiningWordlist    string `json:"mining-dict-word"`
	NoColor           bool   `json:"no-color"`
	Method            string `json:"method"`
	TriggerMethod     string `json:"trigger-method"`
	NoSpinner         bool   `json:"no-spinner"`
	NoBAV             bool   `json:"no-bav"`
	ServerHost        string
	ServerPort        int
	NoGrep            bool `json:"skip-grepping"`
	Debug             bool `json:"debug"`
	CookieFromRaw     string
	ScanResult        Result
	SpinnerObject     *s.Spinner
	AuroraObject      a.Aurora
	StartTime         t.Time
	PathReflection    map[int]string
	RemotePayloads    string
	RemoteWordlists   string
	UseHeadless       bool   `json:"use-headless"`
	UseDeepDXSS       bool   `json:"use-deepdxss"`
	OnlyPoC           string `json:"only-poc"`
	OutputAll         bool   `json:"output-all"`
	WAF               bool
	WAFEvasion        bool
	PoCType           string `json:"poc-type"`
	Mutex             *sync.Mutex
	ReportFormat      string
	ReportBool        bool
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
