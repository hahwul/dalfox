package scanning

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
)

// SSTIAnalysis is basic check for SSTI
func SSTIAnalysis(target string, options model.Options, rl *rateLimiter) {
	// Build-in Grepping payload :: SSTI
	// {444*6664}
	// 2958816
	bpu, _ := url.Parse(target)
	bpd := bpu.Query()
	var wg sync.WaitGroup
	concurrency := options.Concurrence
	reqs := make(chan *http.Request)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for req := range reqs {
				rl.Block(req.Host)
				SendReq(req, "toGrepping", options)
			}
			wg.Done()
		}()
	}

	for bpk := range bpd {
		if optimization.CheckInspectionParam(options, bpk) {
			for _, ssti := range getSSTIPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, ssti, "toGrepping", "ToAppend", "Nan", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()
}

//CRLFAnalysis is basic check for CRLF Injection
func CRLFAnalysis(target string, options model.Options, rl *rateLimiter) {
	bpu, _ := url.Parse(target)
	bpd := bpu.Query()
	var wg sync.WaitGroup
	concurrency := options.Concurrence
	reqs := make(chan *http.Request)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for req := range reqs {
				rl.Block(req.Host)
				SendReq(req, "toGrepping", options)
			}
			wg.Done()
		}()
	}

	for bpk := range bpd {
		if optimization.CheckInspectionParam(options, bpk) {
			for _, crlfpayload := range getCRLFPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, crlfpayload, "toGrepping", "ToAppend", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()

}

//ESIIAnalysis is basic check for CRLF Injection
func ESIIAnalysis(target string, options model.Options, rl *rateLimiter) {
	bpu, _ := url.Parse(target)
	bpd := bpu.Query()
	var wg sync.WaitGroup
	concurrency := options.Concurrence
	reqs := make(chan *http.Request)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for req := range reqs {
				rl.Block(req.Host)
				SendReq(req, "toGrepping", options)
			}
			wg.Done()
		}()
	}

	for bpk := range bpd {
		if optimization.CheckInspectionParam(options, bpk) {
			for _, crlfpayload := range getESIIPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, crlfpayload, "toGrepping", "ToAppend", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()

}

//SqliAnalysis is basic check for SQL Injection
func SqliAnalysis(target string, options model.Options, rl *rateLimiter) {
	// sqli payload

	bpu, _ := url.Parse(target)
	bpd := bpu.Query()
	var wg sync.WaitGroup
	concurrency := options.Concurrence
	reqs := make(chan *http.Request)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for req := range reqs {
				rl.Block(req.Host)
				SendReq(req, "toGrepping", options)
			}
			wg.Done()
		}()
	}

	for bpk := range bpd {
		if optimization.CheckInspectionParam(options, bpk) {
			for _, sqlipayload := range getSQLIPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, sqlipayload, "toGrepping", "ToAppend", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()

}

//OpenRedirectorAnalysis is basic check for open redirectors
func OpenRedirectorAnalysis(target string, options model.Options, rl *rateLimiter) {

	// openredirect payload
	bpu, _ := url.Parse(target)
	bpd := bpu.Query()
	var wg sync.WaitGroup
	concurrency := options.Concurrence
	reqs := make(chan *http.Request)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for req := range reqs {
				rl.Block(req.Host)
				SendReq(req, "toOpenRedirecting", options)
			}
			wg.Done()
		}()
	}

	for bpk := range bpd {
		if optimization.CheckInspectionParam(options, bpk) {
			for _, openRedirectPayload := range getOpenRedirectPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, openRedirectPayload, "toOpenRedirecting", "toReplace", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()
}
