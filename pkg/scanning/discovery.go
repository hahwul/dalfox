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

	// sa/pa/bav are progress labels the analysis goroutines update and print
	// concurrently; guard them so the status line is not a data race.
	var statusMu sync.Mutex
	markDone := func(update func()) string {
		statusMu.Lock()
		defer statusMu.Unlock()
		update()
		return "[" + sa + pa + bav + "] Waiting for analysis to complete"
	}

	go func() {
		defer wait.Done()
		policy, pathReflection = StaticAnalysis(target, options, rl)
		line := markDone(func() { sa = options.AuroraObject.Green(sa).String() })
		printing.DalLog("SYSTEM", line, options)
	}()
	go func() {
		defer wait.Done()
		params = ParameterAnalysis(target, options, rl)
		line := markDone(func() { pa = options.AuroraObject.Green(pa).String() })
		printing.DalLog("SYSTEM", line, options)
	}()
	if options.UseBAV {
		go func() {
			defer wait.Done()
			label := "BAV: ✓ "
			RunBAVAnalysis(target, options, rl, &label)
			markDone(func() { bav = label })
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
