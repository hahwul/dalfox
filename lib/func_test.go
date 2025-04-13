package lib_test

import (
	"testing"
	"time"

	dalfox "github.com/hahwul/dalfox/v2/lib"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestInitialize(t *testing.T) {
	opt := dalfox.Options{
		Cookie:            "ABCD=1234",
		UniqParam:         []string{"q"},
		BlindURL:          "your-callback-url",
		CustomAlertValue:  "1",
		CustomAlertType:   "none",
		Header:            []string{"Cookie: 1234", "ABCD: 1234"},
		Data:              "b=123",
		UserAgent:         "Test-UA",
		ProxyAddress:      "http://127.0.0.1",
		Grep:              "Test",
		IgnoreReturn:      "301",
		IgnoreParams:      []string{"qqq"},
		OnlyDiscovery:     true,
		FollowRedirect:    true,
		Trigger:           "https://google.com",
		TriggerMethod:     "GET",
		Timeout:           5,
		Mining:            true,
		FindingDOM:        true,
		Concurrence:       10,
		Delay:             2,
		NoBAV:             true,
		NoGrep:            true,
		RemotePayloads:    "portswigger",
		RemoteWordlists:   "burp",
		PoCType:           "curl",
		UseBAV:            false,
		CustomPayloadFile: "payloads.txt",
		OutputFile:        "output.txt",
		FoundAction:       "notify",
		FoundActionShell:  "bash",
		OnlyCustomPayload: true,
		UseHeadless:       false,
		UseDeepDXSS:       true,
		WAFEvasion:        true,
		Sequence:          1,
	}
	target := dalfox.Target{
		URL:     "https://www.hahwul.com",
		Method:  "GET",
		Options: opt,
	}

	newOptions := dalfox.Initialize(target, opt)
	assert.NotEqual(t, newOptions.Cookie, "", "they should not be equal")
	assert.NotEqual(t, newOptions.UniqParam, []string{}, "they should not be equal")
	assert.NotEqual(t, newOptions.BlindURL, "", "they should not be equal")
	assert.NotEqual(t, newOptions.CustomAlertValue, "", "they should not be equal")
	assert.NotEqual(t, newOptions.CustomAlertType, "", "they should not be equal")
	assert.NotEqual(t, newOptions.Data, "", "they should not be equal")
	assert.NotEqual(t, newOptions.UserAgent, "", "they should not be equal")
	assert.NotEqual(t, newOptions.ProxyAddress, "", "they should not be equal")
	assert.NotEqual(t, newOptions.Grep, "", "they should not be equal")
	assert.NotEqual(t, newOptions.IgnoreReturn, "", "they should not be equal")
	assert.NotEqual(t, newOptions.IgnoreParams, []string{}, "they should not be equal")
	assert.NotEqual(t, newOptions.Trigger, "", "they should not be equal")
	assert.NotEqual(t, newOptions.Timeout, 10, "they should not be equal")
	assert.NotEqual(t, newOptions.Concurrence, 100, "they should not be equal")
	assert.NotEqual(t, newOptions.Delay, 0, "they should not be equal")
	assert.NotEqual(t, newOptions.NoBAV, false, "they should not be equal")
	assert.NotEqual(t, newOptions.NoGrep, false, "they should not be equal")
	assert.NotEqual(t, newOptions.RemotePayloads, "", "they should not be equal")
	assert.NotEqual(t, newOptions.RemoteWordlists, "", "they should not be equal")
	assert.NotEqual(t, newOptions.OnlyDiscovery, false, "they should not be equal")
	assert.NotEqual(t, newOptions.FollowRedirect, false, "they should not be equal")
	assert.NotEqual(t, newOptions.Mining, false, "they should not be equal")
	assert.NotEqual(t, newOptions.FindingDOM, false, "they should not be equal")
	assert.Equal(t, newOptions.Method, "GET", "Method should be GET")
	assert.Equal(t, newOptions.Format, "plain", "Format should be plain")
	assert.Equal(t, newOptions.FoundActionShell, "bash", "FoundActionShell should be bash")
	assert.Equal(t, newOptions.Timeout, 5, "Timeout should be 5")
	assert.Equal(t, newOptions.Concurrence, 10, "Concurrence should be 10")
	assert.Equal(t, newOptions.Delay, 2, "Delay should be 2")
	assert.Equal(t, newOptions.NoBAV, true, "NoBAV should be true")
	assert.Equal(t, newOptions.NoGrep, true, "NoGrep should be true")
	assert.Equal(t, newOptions.RemotePayloads, "portswigger", "RemotePayloads should be portswigger")
	assert.Equal(t, newOptions.RemoteWordlists, "burp", "RemoteWordlists should be burp")
	assert.Equal(t, newOptions.PoCType, "curl", "PoCType should be curl")
	assert.Equal(t, newOptions.UseBAV, false, "UseBAV should be false")
	assert.Equal(t, newOptions.CustomPayloadFile, "payloads.txt", "CustomPayloadFile should be payloads.txt")
	assert.Equal(t, newOptions.OutputFile, "output.txt", "OutputFile should be output.txt")
	assert.Equal(t, newOptions.FoundAction, "notify", "FoundAction should be notify")
	assert.Equal(t, newOptions.OnlyCustomPayload, true, "OnlyCustomPayload should be true")
	assert.Equal(t, newOptions.UseHeadless, false, "UseHeadless should be false")
	assert.Equal(t, newOptions.UseDeepDXSS, true, "UseDeepDXSS should be true")
	assert.Equal(t, newOptions.WAFEvasion, true, "WAFEvasion should be true")
	assert.Equal(t, newOptions.Sequence, 1, "Sequence should be 1")
	assert.Equal(t, newOptions.UseBAV, false, "UseBAV should be true")
}

func TestNewScan(t *testing.T) {
	opt := dalfox.Options{}
	target := dalfox.Target{
		URL:     "https://www.hahwul.com",
		Method:  "GET",
		Options: opt,
	}

	result, err := dalfox.NewScan(target)
	assert.NoError(t, err, "Error should be nil")
	assert.NotNil(t, result, "Result should not be nil")
	assert.NotZero(t, result.Duration, "Duration should not be zero")
	assert.NotZero(t, result.StartTime, "StartTime should not be zero")
	assert.NotZero(t, result.EndTime, "EndTime should not be zero")
}

func TestResultIsFound(t *testing.T) {
	// Test case 1: No PoCs found
	emptyResult := dalfox.Result{
		Logs:      []string{"test log"},
		PoCs:      []model.PoC{},
		Params:    []model.ParamResult{},
		Duration:  1 * time.Second,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	assert.False(t, emptyResult.IsFound(), "IsFound should return false when no PoCs exist")

	// Test case 2: PoCs found
	resultWithPoCs := dalfox.Result{
		Logs: []string{"test log"},
		PoCs: []model.PoC{
			{
				Type:  "XSS",
				Data:  "<script>alert(1)</script>",
				Param: "q",
			},
		},
		Params:    []model.ParamResult{},
		Duration:  1 * time.Second,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	assert.True(t, resultWithPoCs.IsFound(), "IsFound should return true when PoCs exist")
}
