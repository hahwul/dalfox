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
	return -1 // not found
}

func duplicatedResult(result []model.PoC, rst model.PoC) bool {
	types := make(map[string]struct{}, len(result))
	for _, v := range result {
		types[v.Type] = struct{}{}
	}
	_, exists := types[rst.Type]
	return exists
}

func containsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	i := strings.Split(item, "(")[0]
	_, ok := set[i]
	return ok
}

func checkPType(str string) bool {
	return !strings.Contains(str, "toBlind") && !strings.Contains(str, "toGrepping")
}
