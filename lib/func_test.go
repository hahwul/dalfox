package lib_test

import (
	"testing"
	"github.com/stretchr/testify/assert"
	dalfox "github.com/hahwul/dalfox/v2/lib"
)

func TestInitialize(t *testing.T) {
	opt := dalfox.Options{
		Cookie: "ABCD=1234",
		UniqParam: "q",
		Header: "Authorization: abcd",
		BlindURL: "hahwul.xss.ht",
		CustomAlertValue: "1",
		CustomAlertType: "none",
		Data: "b=123",
		UserAgent: "Test-UA",
		ProxyAddress: "http://127.0.0.1",
		Grep: "Test",
		IgnoreReturn: "301",
		Trigger: "https://google.com",
		Timeout: 5,
		Concurrence: 10,
		Delay: 2,
		NoBAV: true,
		NoGrep: true,
		RemotePayloads: "portswigger",
		RemoteWordlists: "burp",
	}
	target := dalfox.Target{
		URL:     "https://www.hahwul.com",
		Method:  "GET",
		Options: opt,
	}

	newOptions := dalfox.Initialize(target, opt)
	assert.NotEqual(t,newOptions.Cookie,"","they should not bee equal")
	assert.NotEqual(t,newOptions.UniqParam,"","they should not bee equal")
	assert.NotEqual(t,newOptions.Header,"","they should not bee equal")
	assert.NotEqual(t,newOptions.BlindURL,"","they should not bee equal")
	assert.NotEqual(t,newOptions.CustomAlertValue,"","they should not bee equal")
	assert.NotEqual(t,newOptions.CustomAlertType,"","they should not bee equal")
	assert.NotEqual(t,newOptions.Data,"","they should not bee equal")
	assert.NotEqual(t,newOptions.UserAgent,"","they should not bee equal")
	assert.NotEqual(t,newOptions.ProxyAddress,"","they should not bee equal")
	assert.NotEqual(t,newOptions.Grep,"","they should not bee equal")
	assert.NotEqual(t,newOptions.IgnoreReturn,"","they should not bee equal")
	assert.NotEqual(t,newOptions.Trigger,"","they should not bee equal")
	assert.NotEqual(t,newOptions.Timeout,10,"they should not bee equal")
	assert.NotEqual(t,newOptions.Concurrence,100,"they should not bee equal")
	assert.NotEqual(t,newOptions.Delay,0,"they should not bee equal")
	assert.NotEqual(t,newOptions.NoBAV,false,"they should not bee equal")
	assert.NotEqual(t,newOptions.NoGrep,false,"they should not bee equal")
	assert.NotEqual(t,newOptions.RemotePayloads,"","they should not bee equal")
	assert.NotEqual(t,newOptions.RemoteWordlists,"","they should not bee equal")
	assert.NotEqual(t,newOptions.OnlyDiscovery,true,"they should not bee equal")
	assert.NotEqual(t,newOptions.FollowRedirect,true,"they should not bee equal")
	assert.NotEqual(t,newOptions.Mining,false,"they should not bee equal")
	assert.NotEqual(t,newOptions.FindingDOM,false,"they should not bee equal")
}


func TestNewScan(t *testing.T) {
	opt := dalfox.Options{
		Cookie:     "ABCD=1234",
	}
	t.Log(opt)
	result, err := dalfox.NewScan(dalfox.Target{
		URL:     "https://xss-game.appspot.com/level1/frame",
		Method:  "GET",
		Options: opt,
	})
	t.Log(result)
	if err != nil {
		t.Errorf("DalFox NewScan Error")
	}
}

