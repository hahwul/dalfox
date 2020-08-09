package main

type Options struct {
	UniqParam string
	Cookie string
	Header string
	ConfigFile string
	BlindURL string
	CustomPayloadFile string
	Data string
	UserAgent string
	Format string
	FoundAction string
	ProxyAddress string
	Grep string
	IgnoreReturn string
	Timeout int
	Concurrence int
	Delay int
	OnlyDiscovery bool
	Silence bool
	IsAPI bool
	Logs []interface{}
	Results []interface{}
}
