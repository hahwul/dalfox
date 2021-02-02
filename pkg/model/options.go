package model

// Options is struct of options
type Options struct {
	UniqParam         string `json:"param"`
	Cookie            string `json:"cookie"`
	Header            string `json:"header"`
	ConfigFile        string `json:"config"`
	BlindURL          string `json:"blind"`
	CustomPayloadFile string `json:""`
	CustomAlertValue  string `json:"custom-alert-value"`
	CustomAlertType   string `json:"custom-alert-type"`
	Data              string `json:"data"`
	UserAgent         string `json:"user-agent"`
	OutputFile        string `json:"output"`
	Format            string `json:"format"`
	FoundAction       string `json:"found-action"`
	ProxyAddress      string `json:"proxy"`
	Grep              string `json:"grep"`
	IgnoreReturn      string `json:"ignore-return"`
	Trigger           string `json:"trigger"`
	Timeout           int `json:"timeout"`
	Concurrence       int `json:"worker"`
	Delay             int `json:"delay"`
	AllURLS           int 
	NowURL            int
	Sequence          int `json:"sequence"`
	OnlyDiscovery     bool `json:"only-discovery"`
	OnlyCustomPayload bool `json:"only-custom-payload"`
	Silence           bool `json:"silence"`
	IsAPI             bool 
	Mass              bool `json:"mass"`
	Scan              map[string]Scan
	FollowRedirect    bool `json:"follow-redirects"`
	Mining            bool `json:"mining-dict"`
	FindingDOM        bool `json:"mining-dom"`
	MiningWordlist    string `json:"mining-dict-word"`
	NoColor           bool `json:"no-color"`
	Method            string `json:"method"`
	NoSpinner         bool `json:"no-spinner"`
	NoBAV             bool `json:"no-bav"`
	ServerHost        string
	ServerPort        int
	NoGrep            bool `json:"skip-grepping"`
	Debug		  bool `json:"debug"`
}

// Scan is struct of scan
type Scan struct {
	URL     string
	ScanID  string
	Logs    []string
	Results []Issue
}

// Issue is struct of issue
type Issue struct {
	Type  string `json:"type"`
	Param string `json:"param"`
	PoC   string `json:"poc"`
}
