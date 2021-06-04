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

	newOptions := dalfox.Initialize(target, opt)
	if newOptions.Cookie == "" {
		t.Errorf("DalFox Options Initialize error")
	}
}

/*
func TestNewScan(t *testing.T) {
	opt := dalfox.Options{
		Cookie:     "ABCD=1234",
		NoBAV:      true,
		Mining:     false,
		FindingDOM: false,
		UniqParam:  "abababab",
	}

	result, _ := dalfox.NewScan(dalfox.Target{
		URL:     "https://dalfox.hahwul.com?abababab=1",
		Method:  "GET",
		Options: opt,
	})
	if len(result.Logs) == 0 {
		t.Errorf("DalFox NewScan Error")
	}
}
*/
