package scanning

import (
	"net/http"
)

type Queries struct {
	request  *http.Request
	metadata map[string]string
}
