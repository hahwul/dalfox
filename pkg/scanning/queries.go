package scanning

import (
	"net/http"
)

// Queries is struct of queries
type Queries struct {
	request  *http.Request
	metadata map[string]string
}

func checkVStatus(vStatus map[string]bool) bool {
	for k, v := range vStatus {
		if k == "pleasedonthaveanamelikethis_plz_plz" || !v {
			return false
		}
	}
	return true
}
