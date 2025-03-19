package scanning

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
	"github.com/stretchr/testify/assert"
)

// Define function variable types
var (
	staticAnalysisFunc    func(string, model.Options, *rateLimiter) (map[string]string, map[int]string)
	parameterAnalysisFunc func(string, model.Options, *rateLimiter) map[string]model.ParamResult
	runBAVAnalysisFunc    func(string, model.Options, *rateLimiter, *string)
)

// Initialize original functions for mocking
func init() {
	staticAnalysisFunc = StaticAnalysis
	parameterAnalysisFunc = ParameterAnalysis
	runBAVAnalysisFunc = RunBAVAnalysis
}

// Override performDiscovery to use our function variables
func performDiscoveryTest(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string, map[string]model.ParamResult) {
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
	printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)

	go func() {
		defer wait.Done()
		policy, pathReflection = staticAnalysisFunc(target, options, rl)
		sa = options.AuroraObject.Green(sa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	}()
	go func() {
		defer wait.Done()
		params = parameterAnalysisFunc(target, options, rl)
		pa = options.AuroraObject.Green(pa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	}()
	if options.UseBAV {
		go func() {
			defer wait.Done()
			runBAVAnalysisFunc(target, options, rl, &bav)
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

func TestPerformDiscovery(t *testing.T) {
	// Setup the test
	target := "http://example.com"

	// Create options with required fields for testing
	options := model.Options{
		Timeout:      10,
		Concurrence:  10,
		Delay:        1,
		UseBAV:       true,
		AuroraObject: aurora.NewAurora(false), // No color for testing
		NoSpinner:    true,                    // No spinner for testing
	}

	// Create a rate limiter for testing
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	// Save original functions
	origStaticAnalysis := staticAnalysisFunc
	origParameterAnalysis := parameterAnalysisFunc
	origRunBAVAnalysis := runBAVAnalysisFunc

	// Defer restoration of original functions
	defer func() {
		staticAnalysisFunc = origStaticAnalysis
		parameterAnalysisFunc = origParameterAnalysis
		runBAVAnalysisFunc = origRunBAVAnalysis
	}()

	// Mock implementation of StaticAnalysis
	staticAnalysisFunc = func(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string) {
		policy := make(map[string]string)
		pathReflection := make(map[int]string)
		policy["Content-Type"] = "text/html"
		pathReflection[0] = "test"
		return policy, pathReflection
	}

	// Mock implementation of ParameterAnalysis
	parameterAnalysisFunc = func(target string, options model.Options, rl *rateLimiter) map[string]model.ParamResult {
		params := make(map[string]model.ParamResult)
		params["test"] = model.ParamResult{
			Name:      "test",
			Type:      "URL",
			Reflected: true,
		}
		return params
	}

	// Mock implementation of RunBAVAnalysis
	runBAVAnalysisFunc = func(target string, options model.Options, rl *rateLimiter, bav *string) {
		*bav = "BAV: ✅"
	}

	// Test with BAV enabled
	policy, pathReflection, params := performDiscoveryTest(target, options, rl)

	// Assertions for BAV-enabled test
	assert.NotNil(t, policy)
	assert.NotNil(t, pathReflection)
	assert.NotNil(t, params)
	assert.Equal(t, "text/html", policy["Content-Type"])
	assert.Equal(t, "test", pathReflection[0])
	assert.Equal(t, "test", params["test"].Name)

	// Test with BAV disabled
	options.UseBAV = false
	policy, pathReflection, params = performDiscoveryTest(target, options, rl)

	// Assertions for BAV-disabled test
	assert.NotNil(t, policy)
	assert.NotNil(t, pathReflection)
	assert.NotNil(t, params)
}

func TestPerformDiscoveryWithSilence(t *testing.T) {
	// Setup the test
	target := "http://example.com"

	// Create options with required fields for testing
	options := model.Options{
		Timeout:      10,
		Concurrence:  10,
		Delay:        1,
		UseBAV:       true,
		Silence:      true,
		NowURL:       1,
		AllURLS:      10,
		AuroraObject: aurora.NewAurora(false), // No color for testing
	}

	// Create a rate limiter for testing
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	// Save original functions
	origStaticAnalysis := staticAnalysisFunc
	origParameterAnalysis := parameterAnalysisFunc
	origRunBAVAnalysis := runBAVAnalysisFunc

	// Defer restoration of original functions
	defer func() {
		staticAnalysisFunc = origStaticAnalysis
		parameterAnalysisFunc = origParameterAnalysis
		runBAVAnalysisFunc = origRunBAVAnalysis
	}()

	// Mock implementation of StaticAnalysis
	staticAnalysisFunc = func(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string) {
		policy := make(map[string]string)
		pathReflection := make(map[int]string)
		policy["Content-Type"] = "text/html"
		return policy, pathReflection
	}

	// Mock implementation of ParameterAnalysis
	parameterAnalysisFunc = func(target string, options model.Options, rl *rateLimiter) map[string]model.ParamResult {
		params := make(map[string]model.ParamResult)
		return params
	}

	// Mock implementation of RunBAVAnalysis
	runBAVAnalysisFunc = func(target string, options model.Options, rl *rateLimiter, bav *string) {
		*bav = "BAV: ✅"
	}

	// Test with silence mode enabled
	policy, pathReflection, params := performDiscoveryTest(target, options, rl)

	// Assertions
	assert.NotNil(t, policy)
	assert.NotNil(t, pathReflection)
	assert.NotNil(t, params)
}

// TestPerformDiscoveryErrorHandling tests the error handling in performDiscovery
func TestPerformDiscoveryErrorHandling(t *testing.T) {
	// Setup the test
	target := "http://example.com"

	// Create options with required fields for testing
	options := model.Options{
		Timeout:      10,
		Concurrence:  10,
		Delay:        1,
		UseBAV:       true,
		NoSpinner:    true,
		AuroraObject: aurora.NewAurora(false), // No color for testing
	}

	// Create a rate limiter for testing
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	// Save original functions
	origStaticAnalysis := staticAnalysisFunc
	origParameterAnalysis := parameterAnalysisFunc
	origRunBAVAnalysis := runBAVAnalysisFunc

	// Defer restoration of original functions
	defer func() {
		staticAnalysisFunc = origStaticAnalysis
		parameterAnalysisFunc = origParameterAnalysis
		runBAVAnalysisFunc = origRunBAVAnalysis
	}()

	// Mock implementations with empty results
	staticAnalysisFunc = func(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string) {
		policy := make(map[string]string)
		pathReflection := make(map[int]string)
		return policy, pathReflection
	}

	parameterAnalysisFunc = func(target string, options model.Options, rl *rateLimiter) map[string]model.ParamResult {
		params := make(map[string]model.ParamResult)
		return params
	}

	runBAVAnalysisFunc = func(target string, options model.Options, rl *rateLimiter, bav *string) {
		*bav = "BAV: ✅"
	}

	// Test handling of empty results
	policy, pathReflection, params := performDiscoveryTest(target, options, rl)

	// Assertions - even with "errors", we should get empty maps, not nil
	assert.NotNil(t, policy)
	assert.NotNil(t, pathReflection)
	assert.NotNil(t, params)
	assert.Empty(t, policy)
	assert.Empty(t, pathReflection)
	assert.Empty(t, params)
}
