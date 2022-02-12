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
		BlindURL:         "hahwul.xss.ht",
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
	}
	target := dalfox.Target{
		URL:     "https://www.hahwul.com",
		Method:  "GET",
		Options: opt,
	}

	newOptions := dalfox.Initialize(target, opt)
	assert.NotEqual(t, newOptions.Cookie, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.UniqParam, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.BlindURL, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.CustomAlertValue, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.CustomAlertType, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.Data, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.UserAgent, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.ProxyAddress, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.Grep, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.IgnoreReturn, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.IgnoreParams, []string{""}, "they should not bee equal")
	assert.NotEqual(t, newOptions.Trigger, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.Timeout, 10, "they should not bee equal")
	assert.NotEqual(t, newOptions.Concurrence, 100, "they should not bee equal")
	assert.NotEqual(t, newOptions.Delay, 0, "they should not bee equal")
	assert.NotEqual(t, newOptions.NoBAV, false, "they should not bee equal")
	assert.NotEqual(t, newOptions.NoGrep, false, "they should not bee equal")
	assert.NotEqual(t, newOptions.RemotePayloads, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.RemoteWordlists, "", "they should not bee equal")
	assert.NotEqual(t, newOptions.OnlyDiscovery, false, "they should not bee equal")
	assert.NotEqual(t, newOptions.FollowRedirect, false, "they should not bee equal")
	assert.NotEqual(t, newOptions.Mining, false, "they should not bee equal")
	assert.NotEqual(t, newOptions.FindingDOM, false, "they should not bee equal")
}
