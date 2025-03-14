package lib_test

import (
	"testing"

	dalfox "github.com/hahwul/dalfox/v2/lib"
	"github.com/stretchr/testify/assert"
)

func TestInitialize(t *testing.T) {
	opt := dalfox.Options{
		Cookie:           "ABCD=1234",
		UniqParam:        []string{"q"},
		BlindURL:         "your-callback-url",
		CustomAlertValue: "1",
		CustomAlertType:  "none",
		Header:           []string{"Cookie: 1234", "ABCD: 1234"},
		Data:             "b=123",
		UserAgent:        "Test-UA",
		ProxyAddress:     "http://127.0.0.1",
		Grep:             "Test",
		IgnoreReturn:     "301",
		IgnoreParams:     []string{"qqq"},
		OnlyDiscovery:    true,
		FollowRedirect:   true,
		Trigger:          "https://google.com",
		Timeout:          5,
		Mining:           true,
		FindingDOM:       true,
		Concurrence:      10,
		Delay:            2,
		NoBAV:            true,
		NoGrep:           true,
		RemotePayloads:   "portswigger",
		RemoteWordlists:  "burp",
		PoCType:          "curl",
		UseBAV:           false,
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
	assert.Equal(t, newOptions.Method, "GET", "they should be equal")
	assert.Equal(t, newOptions.Format, "plain", "they should be equal")
	assert.Equal(t, newOptions.FoundActionShell, "bash", "they should be equal")
	assert.Equal(t, newOptions.Timeout, 5, "they should be equal")
	assert.Equal(t, newOptions.Concurrence, 10, "they should be equal")
	assert.Equal(t, newOptions.Delay, 2, "they should be equal")
	assert.Equal(t, newOptions.NoBAV, true, "they should be equal")
	assert.Equal(t, newOptions.NoGrep, true, "they should be equal")
	assert.Equal(t, newOptions.RemotePayloads, "portswigger", "they should be equal")
	assert.Equal(t, newOptions.RemoteWordlists, "burp", "they should be equal")
	assert.Equal(t, newOptions.PoCType, "curl", "they should be equal")
	assert.Equal(t, newOptions.UseBAV, false, "they should be equal")
}
