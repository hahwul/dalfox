package lib

//scanning.Scan(args[0], options, "Single")
import (
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/logrusorgru/aurora"
)

// Initialize is init for model.Options
func Initialize(target Target, options Options) model.Options {
	au := aurora.NewAurora(false)
	stime := time.Now()
	newOptions := model.Options{
		IsLibrary:         true,
		Header:            "",
		Cookie:            "",
		UniqParam:         "",
		BlindURL:          "",
		CustomPayloadFile: "",
		CustomAlertValue:  "1",
		CustomAlertType:   "none",
		Data:              "",
		UserAgent:         "",
		OutputFile:        "",
		Format:            "plain",
		FoundAction:       "",
		FoundActionShell:  "bash",
		ProxyAddress:      "",
		Grep:              "",
		IgnoreReturn:      "",
		Timeout:           10,
		Concurrence:       100,
		Delay:             0,
		OnlyDiscovery:     false,
		OnlyCustomPayload: false,
		Silence:           true,
		FollowRedirect:    false,
		Scan:              make(map[string]model.Scan),
		Mining:            true,
		MiningWordlist:    "",
		FindingDOM:        true,
		NoColor:           true,
		Method:            "GET",
		NoSpinner:         true,
		NoBAV:             false,
		NoGrep:            false,
		Debug:             false,
		CookieFromRaw:     "",
		AuroraObject:      au,
		StartTime:         stime,
		MulticastMode:     false,
		RemotePayloads:    "",
		RemoteWordlists:   "",
		OnlyPoC:           "",
		OutputAll:         false,
	}
	if options.UniqParam != "" {
		newOptions.UniqParam = options.UniqParam
	}
	if options.Cookie != "" {
		newOptions.Cookie = options.Cookie
	}
	if options.Header != "" {
		newOptions.Header = options.Header
	}
	if options.BlindURL != "" {
		newOptions.BlindURL = options.BlindURL
	}
	if options.CustomAlertValue != "" {
		newOptions.CustomAlertValue = options.CustomAlertValue
	}
	if options.CustomAlertType != "" {
		newOptions.CustomAlertType = options.CustomAlertType
	}
	if options.Data != "" {
		newOptions.Data = options.Data
	}
	if options.UserAgent != "" {
		newOptions.UserAgent = options.UserAgent
	}
	if options.ProxyAddress != "" {
		newOptions.ProxyAddress = options.ProxyAddress
	}
	if options.Grep != "" {
		newOptions.Grep = options.Grep
	}
	if options.IgnoreReturn != "" {
		newOptions.IgnoreReturn = options.IgnoreReturn
	}
	if options.Trigger != "" {
		newOptions.Trigger = options.Trigger
	}
	if options.Timeout != 0 {
		newOptions.Timeout = options.Timeout
	}
	if options.Concurrence != 0 {
		newOptions.Concurrence = options.Concurrence
	}
	if options.Delay != 0 {
		newOptions.Delay = options.Delay
	}
	if options.OnlyDiscovery != false {
		newOptions.OnlyDiscovery = options.OnlyDiscovery
	}
	if options.FollowRedirect != false {
		newOptions.FollowRedirect = options.FollowRedirect
	}
	if options.Mining != false {
		newOptions.Mining = options.Mining
	}
	if options.FindingDOM != false {
		newOptions.FindingDOM = options.FindingDOM
	}
	if options.NoBAV != false {
		newOptions.NoBAV = options.NoBAV
	}
	if options.NoGrep != false {
		newOptions.NoGrep = options.NoGrep
	}
	if options.RemotePayloads != "" {
		newOptions.RemotePayloads = options.RemotePayloads
	}
	if options.RemoteWordlists != "" {
		newOptions.RemoteWordlists = options.RemoteWordlists
	}
	return newOptions
}

// NewScan is dalfox single scan in lib
func NewScan(target Target) (Result, error) {
	newOptions := Initialize(target, target.Options)
	modelResult, err := scanning.Scan(target.URL, newOptions, "Single")
	result := Result{
		Logs:      modelResult.Logs,
		PoCs:      modelResult.PoCs,
		Duration:  modelResult.Duration,
		StartTime: modelResult.StartTime,
		EndTime:   modelResult.EndTime,
	}
	return result, err
}
