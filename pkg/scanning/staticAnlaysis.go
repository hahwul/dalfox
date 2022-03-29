package scanning

import (
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
)

// StaticAnalysis is found information on original req/res
func StaticAnalysis(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string) {
	policy := make(map[string]string)
	pathReflection := make(map[int]string)
	req := optimization.GenerateNewRequest(target, "", options)
	resbody, resp, _, _, err := SendReq(req, "", options)
	if err != nil {
		return policy, pathReflection
	}
	_ = resbody
	if resp.Header["Content-Type"] != nil {
		policy["Content-Type"] = resp.Header["Content-Type"][0]
	}
	if resp.Header["Content-Security-Policy"] != nil {
		policy["Content-Security-Policy"] = resp.Header["Content-Security-Policy"][0]
		result := checkCSP(policy["Content-Security-Policy"])
		if result != "" {
			policy["BypassCSP"] = result
		}
	}
	if resp.Header["X-Frame-Options"] != nil {
		policy["X-Frame-Options"] = resp.Header["X-Frame-Options"][0]
	}
	if resp.Header["Strict-Transport-Security"] != nil {
		policy["Strict-Transport-Security"] = resp.Header["Strict-Transport-Security"][0]
	}
	if resp.Header["Access-Control-Allow-Origin"] != nil {
		policy["Access-Control-Allow-Origin"] = resp.Header["Access-Control-Allow-Origin"][0]
	}
	paths := strings.Split(target, "/")

	// case of https://domain/ + @
	for idx := range paths {
		if idx > 2 {
			id := idx - 3
			_ = id
			//var tempPath []string
			//copy(tempPath, paths)
			tempPath := strings.Split(target, "/")
			tempPath[idx] = "dalfoxpathtest"

			tempURL := strings.Join(tempPath, "/")
			req := optimization.GenerateNewRequest(tempURL, "", options)
			rl.Block(req.Host)
			resbody, _, _, vrs, err := SendReq(req, "dalfoxpathtest", options)
			if err != nil {
				return policy, pathReflection
			}
			if vrs {
				pointer := optimization.Abstraction(resbody, "dalfoxpathtest")
				smap := "Injected: "
				tempSmap := make(map[string]int)

				for _, v := range pointer {
					if tempSmap[v] == 0 {
						tempSmap[v] = 1
					} else {
						tempSmap[v] = tempSmap[v] + 1
					}
				}
				for k, v := range tempSmap {
					smap = smap + "/" + k + "(" + strconv.Itoa(v) + ")"
				}
				pathReflection[id] = smap
			}
		}
	}

	// case of https://domain
	if len(paths) == 3 {

		tempURL := target + "/dalfoxpathtest"
		req := optimization.GenerateNewRequest(tempURL, "", options)
		rl.Block(req.Host)
		resbody, _, _, vrs, err := SendReq(req, "dalfoxpathtest", options)
		if err != nil {
			return policy, pathReflection
		}
		if vrs {
			pointer := optimization.Abstraction(resbody, "dalfoxpathtest")
			smap := "Injected: "
			tempSmap := make(map[string]int)

			for _, v := range pointer {
				if tempSmap[v] == 0 {
					tempSmap[v] = 1
				} else {
					tempSmap[v] = tempSmap[v] + 1
				}
			}
			for k, v := range tempSmap {
				smap = smap + "/" + k + "(" + strconv.Itoa(v) + ")"
			}
			pathReflection[0] = smap
		}
	}
	return policy, pathReflection
}
