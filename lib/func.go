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
	// Set default values for new options
	au := aurora.NewAurora(false)
	stime := time.Now()

	// Initialize with default values
	newOptions := model.Options{
		IsLibrary:                 true,
		Header:                    []string{},
		Cookie:                    "",
		UniqParam:                 []string{},
		BlindURL:                  "",
		CustomPayloadFile:         "",
		CustomAlertValue:          "1",
		CustomAlertType:           "none",
		Data:                      "",
		UserAgent:                 "",
		OutputFile:                "",
		Format:                    "plain",
		FoundAction:               "",
		FoundActionShell:          "bash",
		ProxyAddress:              "",
		Grep:                      "",
		IgnoreReturn:              "",
		IgnoreParams:              []string{},
		Timeout:                   10,
		TriggerMethod:             "GET",
		Concurrence:               100,
		Delay:                     0,
		OnlyDiscovery:             false,
		OnlyCustomPayload:         false,
		Silence:                   true,
		FollowRedirect:            false,
		Scan:                      make(map[string]model.Scan),
		Mining:                    true,
		MiningWordlist:            "",
		FindingDOM:                true,
		NoColor:                   true,
		Method:                    "GET",
		NoSpinner:                 true,
		NoBAV:                     false,
		NoGrep:                    false,
		Debug:                     false,
		CookieFromRaw:             "",
		AuroraObject:              au,
		StartTime:                 stime,
		MulticastMode:             false,
		RemotePayloads:            "",
		RemoteWordlists:           "",
		OnlyPoC:                   "",
		OutputAll:                 false,
		PoCType:                   "",
		Sequence:                  -1,
		UseHeadless:               true,
		UseDeepDXSS:               false,
		WAFEvasion:                false,
		OutputRequest:             false,
		OutputResponse:            false,
		UseBAV:                    false,
		MaxCPU:                    1,
		ServerHost:                "",
		ServerPort:                0,
		ConfigFile:                "",
		ReportFormat:              "plain",
		ReportBool:                false,
		Trigger:                   "",
		LimitResult:               0,
		IsAPI:                     false,
		Mass:                      false,
		WAFName:                   "",
		SkipDiscovery:             false,
		ForceHeadlessVerification: false,
		HarFilePath:               "",
	}

	// Override method from target if provided
	if target.Method != "" {
		newOptions.Method = target.Method
	}

	// Override with provided options

	// --- String options (only if not empty) ---
	stringOptions := map[string]struct {
		value  *string
		source string
	}{
		"Cookie":            {&newOptions.Cookie, options.Cookie},
		"BlindURL":          {&newOptions.BlindURL, options.BlindURL},
		"CustomAlertValue":  {&newOptions.CustomAlertValue, options.CustomAlertValue},
		"CustomAlertType":   {&newOptions.CustomAlertType, options.CustomAlertType},
		"Data":              {&newOptions.Data, options.Data},
		"UserAgent":         {&newOptions.UserAgent, options.UserAgent},
		"OutputFile":        {&newOptions.OutputFile, options.OutputFile},
		"ProxyAddress":      {&newOptions.ProxyAddress, options.ProxyAddress},
		"Grep":              {&newOptions.Grep, options.Grep},
		"IgnoreReturn":      {&newOptions.IgnoreReturn, options.IgnoreReturn},
		"Trigger":           {&newOptions.Trigger, options.Trigger},
		"TriggerMethod":     {&newOptions.TriggerMethod, options.TriggerMethod},
		"RemotePayloads":    {&newOptions.RemotePayloads, options.RemotePayloads},
		"RemoteWordlists":   {&newOptions.RemoteWordlists, options.RemoteWordlists},
		"PoCType":           {&newOptions.PoCType, options.PoCType},
		"CustomPayloadFile": {&newOptions.CustomPayloadFile, options.CustomPayloadFile},
		"FoundAction":       {&newOptions.FoundAction, options.FoundAction},
		"FoundActionShell":  {&newOptions.FoundActionShell, options.FoundActionShell},
		"OnlyPoC":           {&newOptions.OnlyPoC, options.OnlyPoC},
		"WAFName":           {&newOptions.WAFName, options.WAFName},
		"MiningWordlist":    {&newOptions.MiningWordlist, options.MiningWordlist},
		"CookieFromRaw":     {&newOptions.CookieFromRaw, options.CookieFromRaw},
		"HarFilePath":       {&newOptions.HarFilePath, options.HarFilePath},
	}

	for _, opt := range stringOptions {
		if opt.source != "" {
			*opt.value = opt.source
		}
	}

	// --- Integer options (only if not default) ---
	if options.Timeout != 0 {
		newOptions.Timeout = options.Timeout
	}
	if options.Concurrence != 0 {
		newOptions.Concurrence = options.Concurrence
	}
	if options.Delay != 0 {
		newOptions.Delay = options.Delay
	}
	if options.Sequence != -1 {
		newOptions.Sequence = options.Sequence
	}
	if options.LimitResult != 0 {
		newOptions.LimitResult = options.LimitResult
	}
	if options.MaxCPU != 0 {
		newOptions.MaxCPU = options.MaxCPU
	}
	if options.ServerPort != 0 {
		newOptions.ServerPort = options.ServerPort
	}

	// --- Boolean options (only if true) ---
	boolOptions := map[string]struct {
		target *bool
		source bool
	}{
		"OnlyDiscovery":             {&newOptions.OnlyDiscovery, options.OnlyDiscovery},
		"OnlyCustomPayload":         {&newOptions.OnlyCustomPayload, options.OnlyCustomPayload},
		"FollowRedirect":            {&newOptions.FollowRedirect, options.FollowRedirect},
		"WAFEvasion":                {&newOptions.WAFEvasion, options.WAFEvasion},
		"UseBAV":                    {&newOptions.UseBAV, options.UseBAV},
		"UseDeepDXSS":               {&newOptions.UseDeepDXSS, options.UseDeepDXSS},
		"OutputAll":                 {&newOptions.OutputAll, options.OutputAll},
		"OutputRequest":             {&newOptions.OutputRequest, options.OutputRequest},
		"OutputResponse":            {&newOptions.OutputResponse, options.OutputResponse},
		"IsAPI":                     {&newOptions.IsAPI, options.IsAPI},
		"Mass":                      {&newOptions.Mass, options.Mass},
		"SkipDiscovery":             {&newOptions.SkipDiscovery, options.SkipDiscovery},
		"ForceHeadlessVerification": {&newOptions.ForceHeadlessVerification, options.ForceHeadlessVerification},
		"NoBAV":                     {&newOptions.NoBAV, options.NoBAV},
		"NoGrep":                    {&newOptions.NoGrep, options.NoGrep},
		"Debug":                     {&newOptions.Debug, options.Debug},
		"MulticastMode":             {&newOptions.MulticastMode, options.MulticastMode},
		"ReportBool":                {&newOptions.ReportBool, options.ReportBool},
	}

	for _, opt := range boolOptions {
		if opt.source {
			*opt.target = true
		}
	}

	// --- Boolean options (special cases - when false is meaningful) ---
	if options.UseHeadless == false {
		newOptions.UseHeadless = false
	}
	if options.Mining == false {
		newOptions.Mining = false
	}
	if options.FindingDOM == false {
		newOptions.FindingDOM = false
	}

	// --- Slice options ---
	if len(options.UniqParam) > 0 {
		newOptions.UniqParam = append(newOptions.UniqParam, options.UniqParam...)
	}
	if len(options.Header) > 0 {
		newOptions.Header = append(newOptions.Header, options.Header...)
	}
	if len(options.IgnoreParams) > 0 {
		newOptions.IgnoreParams = append(newOptions.IgnoreParams, options.IgnoreParams...)
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
		Params:    modelResult.Params,
		Duration:  modelResult.Duration,
		StartTime: modelResult.StartTime,
		EndTime:   modelResult.EndTime,
	}
	return result, err
}
