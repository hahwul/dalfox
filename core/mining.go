package core

import (
	"net/url"
)

func QuickMining(target string, options_string map[string]string) map[string][]string {
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		return params
	}
	_ = u
	return params
}
func DeepMining(target string, options_string map[string]string) map[string][]string {
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		return params
	}
	_ = u
	return params

}
