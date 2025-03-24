package scanning

import (
	"strconv"
	"sync"
	"time"

	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// performDiscovery handles the discovery phase including static, parameter, and BAV analysis.
func performDiscovery(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string, map[string]model.ParamResult) {
	policy := make(map[string]string)
	pathReflection := make(map[int]string)
	params := make(map[string]model.ParamResult)

	var wait sync.WaitGroup
	task := 3
	sa := "SA: ✓ "
	pa := "PA: ✓ "
	bav := "BAV: ✓ "
	if !options.UseBAV {
		task = 2
		bav = ""
	}

	wait.Add(task)
	printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis to complete", options)

	go func() {
		defer wait.Done()
		policy, pathReflection = StaticAnalysis(target, options, rl)
		sa = options.AuroraObject.Green(sa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis to complete", options)
	}()
	go func() {
		defer wait.Done()
		params = ParameterAnalysis(target, options, rl)
		pa = options.AuroraObject.Green(pa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis to complete", options)
	}()
	if options.UseBAV {
		go func() {
			defer wait.Done()
			RunBAVAnalysis(target, options, rl, &bav)
		}()
	}

	if options.NowURL != 0 && !options.Silence {
		s.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks] Scanning.."
	}
	if !(options.Silence || options.NoSpinner) {
		time.Sleep(1 * time.Second)
		s.Start()
	}
	wait.Wait()
	if !(options.Silence || options.NoSpinner) {
		s.Stop()
	}

	return policy, pathReflection, params
}
