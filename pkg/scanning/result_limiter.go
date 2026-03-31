package scanning

import (
	"strings"
	"sync"
)

const (
	limitResultTypeAll = "all"
	limitResultTypeV   = "v"
	limitResultTypeR   = "r"
)

// resultLimiter coordinates global early-stop behavior for findings.
type resultLimiter struct {
	limit int
	mu    sync.Mutex
	count int
	stop  bool
}

func newResultLimiter(limit int) *resultLimiter {
	return &resultLimiter{limit: limit}
}

func (rl *resultLimiter) shouldStop() bool {
	if rl.limit <= 0 {
		return false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.stop
}

// allowAndCount records one finding if under limit.
func (rl *resultLimiter) allowAndCount() bool {
	if rl.limit <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.count < rl.limit {
		rl.count++
		if rl.count >= rl.limit {
			rl.stop = true
		}
		return true
	}
	rl.stop = true
	return false
}

func normalizeLimitResultType(limitResultType string) string {
	switch strings.ToLower(strings.TrimSpace(limitResultType)) {
	case limitResultTypeV:
		return limitResultTypeV
	case limitResultTypeR:
		return limitResultTypeR
	case limitResultTypeAll:
		return limitResultTypeAll
	default:
		return limitResultTypeAll
	}
}

func shouldCountResultByType(resultType, limitResultType string) bool {
	normalized := normalizeLimitResultType(limitResultType)
	switch normalized {
	case limitResultTypeV:
		return strings.EqualFold(resultType, "V")
	case limitResultTypeR:
		return strings.EqualFold(resultType, "R")
	default:
		return true
	}
}
