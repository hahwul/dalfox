package scanning

import (
	"net/http"
)

// Queries is struct of queries
type Queries struct {
	request  *http.Request
	metadata map[string]string
}
