package scanning

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// StaticAnalysis is found information on original req/res
func StaticAnalysis(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string) {
	policy := make(map[string]string)
	pathReflection := make(map[int]string)
	req := optimization.GenerateNewRequest(target, "", options)
	_, resp, _, _, err := SendReq(req, "", options)
	if err != nil {
		return policy, pathReflection
	}

	extractPolicyHeaders(resp.Header, policy)

	paths := strings.Split(target, "/")

	// case of https://domain/ + @
	for idx := range paths {
		if idx > 2 {
			id := idx - 3
			tempPath := strings.Split(target, "/")
			tempPath[idx] = "dalfoxpathtest"
			tempURL := strings.Join(tempPath, "/")
			checkPathReflection(tempURL, id, options, rl, pathReflection)
		}
	}

	// case of https://domain
	if len(paths) == 3 {
		tempURL := target + "/dalfoxpathtest"
		checkPathReflection(tempURL, 0, options, rl, pathReflection)
	}

	return policy, pathReflection
}

func extractPolicyHeaders(header http.Header, policy map[string]string) {
	if contentType := header.Get("Content-Type"); contentType != "" {
		policy["Content-Type"] = contentType
	}
	if csp := header.Get("Content-Security-Policy"); csp != "" {
		policy["Content-Security-Policy"] = csp
		if result := checkCSP(csp); result != "" {
			policy["BypassCSP"] = result
		}
	}
	if xFrameOptions := header.Get("X-Frame-Options"); xFrameOptions != "" {
		policy["X-Frame-Options"] = xFrameOptions
	}
	if hsts := header.Get("Strict-Transport-Security"); hsts != "" {
		policy["Strict-Transport-Security"] = hsts
	}
	if acao := header.Get("Access-Control-Allow-Origin"); acao != "" {
		policy["Access-Control-Allow-Origin"] = acao
	}
}

func checkPathReflection(tempURL string, id int, options model.Options, rl *rateLimiter, pathReflection map[int]string) {
	req := optimization.GenerateNewRequest(tempURL, "", options)
	rl.Block(req.Host)
	resbody, _, _, vrs, err := SendReq(req, "dalfoxpathtest", options)
	if err != nil {
		return
	}
	if vrs {
		pointer := optimization.Abstraction(resbody, "dalfoxpathtest")
		smap := "Injected: "
		tempSmap := make(map[string]int)

		for _, v := range pointer {
			tempSmap[v]++
		}
		for k, v := range tempSmap {
			smap += "/" + k + "(" + strconv.Itoa(v) + ")"
		}
		pathReflection[id] = smap
	}
}
