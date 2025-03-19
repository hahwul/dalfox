package printing

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// LogPoC logs the PoC details and adds request/response data if configured.
func LogPoC(poc *model.PoC, resbody string, req *http.Request, options model.Options, show bool, level string, message string) {
	DalLog(level, message, options)
	DalLog("CODE", poc.Evidence, options)
	if options.OutputRequest {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			poc.RawHTTPRequest = string(reqDump)
			DalLog("CODE", "\n"+string(reqDump), options)
		}
	}
	if options.OutputResponse {
		poc.RawHTTPResponse = resbody
		DalLog("CODE", string(resbody), options)
	}
	if show {
		if options.Format == "json" {
			pocj, _ := json.Marshal(poc)
			DalLog("PRINT", string(pocj)+",", options)
		} else {
			pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
			DalLog("PRINT", pocs, options)
		}
	}
}

// MakePoC is making poc codes
func MakePoC(poc string, req *http.Request, options model.Options) string {
	if options.PoCType == "http-request" {
		requestDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			return "HTTP RAW REQUEST\n" + string(requestDump)
		}
	}

	if req.Body != nil {
		body, err := req.GetBody()
		if err == nil {
			reqBody, err := io.ReadAll(body)
			if err == nil {
				if string(reqBody) != "" {
					switch options.PoCType {
					case "curl":
						return "curl -i -k -X " + req.Method + " " + poc + " -d \"" + string(reqBody) + "\""
					case "httpie":
						return "http " + req.Method + " " + poc + " \"" + string(reqBody) + "\" --verify=false -f"
					default:
						return poc + " -d " + string(reqBody)
					}
				}
			}
		}
	} else {
		switch options.PoCType {
		case "curl":
			return "curl -i -k " + poc
		case "httpie":
			return "http " + poc + " --verify=false"
		default:
			return poc
		}
	}
	return poc
}
