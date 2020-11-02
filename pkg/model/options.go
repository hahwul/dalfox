package model

// Options is struct of options
type Options struct {
	UniqParam         string
	Cookie            string
	Header            string
	ConfigFile        string
	BlindURL          string
	CustomPayloadFile string
	Data              string
	UserAgent         string
	OutputFile        string
	Format            string
	FoundAction       string
	ProxyAddress      string
	Grep              string
	IgnoreReturn      string
	Trigger           string
	Timeout           int
	Concurrence       int
	Delay             int
	AllURLS           int
	NowURL            int
	Sequence          int
	OnlyDiscovery     bool
	OnlyCustomPayload bool
	Silence           bool
	IsAPI             bool
	Mass              bool
	Scan              map[string]Scan
	FollowRedirect    bool
	Mining            bool
	FindingDOM        bool
	MiningWordlist    string
	NoColor           bool
	Method            string
	NoSpinner         bool
	NoBAV             bool
	ServerHost        string
	ServerPort        int
	NoGrep            bool
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
