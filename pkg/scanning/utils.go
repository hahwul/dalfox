package scanning

import (
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 //not found.
}

func duplicatedResult(result []model.PoC, rst model.PoC) bool {
	for _, v := range result {
		if v.Type == rst.Type {
			return true
		}
	}
	return false
}

func containsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	t := strings.Split(item, "(")
	i := t[0]
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[i]
	return ok
}

func checkPType(str string) bool {
	if strings.Contains(str, "toBlind") {
		return false
	}
	if strings.Contains(str, "toGrepping") {
		return false
	}
	return true
}
