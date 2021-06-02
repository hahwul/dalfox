package lib_test

import (
	"testing"

	dalfox "github.com/hahwul/dalfox/v2/lib"
)

func TestInitialize(t *testing.T) {
	opt := dalfox.Options{
		Cookie: "ABCD=1234",
	}
	target := dalfox.Target{
		URL:     "https://www.hahwul.com",
		Method:  "GET",
		Options: opt,
	}
	/*
		dalfox.NewScan(dalfox.Target{
			URL:     "https://www.hahwul.com",
			Method:  "GET",
			Options: opt,
		})
	*/
	newOptions := dalfox.Initialize(target, opt)
	if newOptions.Cookie == "" {
		t.Errorf("dalfox options initialize error")
	}
}
