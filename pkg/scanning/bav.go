package scanning

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// RunBAVAnalysis runs the BAV analysis.
func RunBAVAnalysis(target string, options model.Options, rl *rateLimiter, bav *string) {
	var bavWaitGroup sync.WaitGroup
	bavTask := 5
	bavWaitGroup.Add(bavTask)
	go func() {
		defer bavWaitGroup.Done()
		ESIIAnalysis(target, options, rl)
	}()
	go func() {
		defer bavWaitGroup.Done()
		SqliAnalysis(target, options, rl)
	}()
	go func() {
		defer bavWaitGroup.Done()
		SSTIAnalysis(target, options, rl)
	}()
	go func() {
		defer bavWaitGroup.Done()
		CRLFAnalysis(target, options, rl)
	}()
	go func() {
		defer bavWaitGroup.Done()
		OpenRedirectorAnalysis(target, options, rl)
	}()

	bavWaitGroup.Wait()
	*bav = " > BAV(o)"
printing.DalLog("SYSTEM", "["+*bav+"] BAV analysis completed", options)
}

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
			for _, ssti := range payload.GetSSTIPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, ssti, "toGrepping", "ToAppend", "Nan", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()
}

// CRLFAnalysis is basic check for CRLF Injection
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
			for _, crlfpayload := range payload.GetCRLFPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, crlfpayload, "toGrepping", "ToAppend", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()

}

// ESIIAnalysis is basic check for CRLF Injection
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
			for _, crlfpayload := range payload.GetESIIPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, crlfpayload, "toGrepping", "ToAppend", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()

}

// SqliAnalysis is basic check for SQL Injection
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
			for _, sqlipayload := range payload.GetSQLIPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, sqlipayload, "toGrepping", "ToAppend", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()

}

// OpenRedirectorAnalysis is basic check for open redirectors
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
			for _, openRedirectPayload := range payload.GetOpenRedirectPayload() {
				turl, _ := optimization.MakeRequestQuery(target, bpk, openRedirectPayload, "toOpenRedirecting", "toReplace", "NaN", options)
				reqs <- turl
			}
		}
	}
	close(reqs)
	wg.Wait()
}
