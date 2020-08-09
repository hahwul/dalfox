package model

type Options struct {
	UniqParam string
	Cookie string
	Header string
	ConfigFile string
	BlindURL string
	CustomPayloadFile string
	Data string
	UserAgent string
	OutputFile string
	Format string
	FoundAction string
	ProxyAddress string
	Grep string
	IgnoreReturn string
	Trigger string
	Timeout int
	Concurrence int
	Delay int
	AllURLS int
	NowURL int
	Sequence int
	OnlyDiscovery bool
	Silence bool
	IsAPI bool
	Mass bool
	Scan map[string]Scan
	FollowRedirect bool
}

type Scan struct {
	URL string
	ScanID string
	Logs []string
	Results []Issue
}

type Issue struct {
	Type string `json:"type"`
	Param string `json:"param"`
	PoC string `json:"poc"`	
}
