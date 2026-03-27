package scanning

import (
	"sync"
	"testing"
)

func TestResultLimiter_Unlimited(t *testing.T) {
	rl := newResultLimiter(0)
	for i := 0; i < 10; i++ {
		if !rl.allowAndCount() {
			t.Fatalf("expected unlimited limiter to allow result at iteration %d", i)
		}
	}
	if rl.shouldStop() {
		t.Fatal("expected unlimited limiter to never stop")
	}
}

func TestResultLimiter_LimitOne(t *testing.T) {
	rl := newResultLimiter(1)
	if !rl.allowAndCount() {
		t.Fatal("expected first finding to be accepted")
	}
	if !rl.shouldStop() {
		t.Fatal("expected limiter to request stop after first finding")
	}
	if rl.allowAndCount() {
		t.Fatal("expected second finding to be rejected")
	}
}

func TestResultLimiter_Concurrent(t *testing.T) {
	rl := newResultLimiter(5)
	var wg sync.WaitGroup
	accepted := 0
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.allowAndCount() {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 5 {
		t.Fatalf("expected exactly 5 accepted findings, got %d", accepted)
	}
	if !rl.shouldStop() {
		t.Fatal("expected limiter to stop after reaching limit")
	}
}

func TestNormalizeLimitResultType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "default all", input: "", want: "all"},
		{name: "explicit all", input: "all", want: "all"},
		{name: "uppercase v", input: "V", want: "v"},
		{name: "trimmed r", input: " r ", want: "r"},
		{name: "invalid fallback", input: "verified", want: "all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeLimitResultType(tt.input); got != tt.want {
				t.Fatalf("normalizeLimitResultType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShouldCountResultByType(t *testing.T) {
	tests := []struct {
		name            string
		resultType      string
		limitResultType string
		want            bool
	}{
		{name: "all accepts v", resultType: "V", limitResultType: "all", want: true},
		{name: "all accepts r", resultType: "R", limitResultType: "all", want: true},
		{name: "v accepts only v", resultType: "V", limitResultType: "v", want: true},
		{name: "v rejects r", resultType: "R", limitResultType: "v", want: false},
		{name: "r accepts only r", resultType: "R", limitResultType: "r", want: true},
		{name: "r rejects v", resultType: "V", limitResultType: "r", want: false},
		{name: "invalid type falls back all", resultType: "R", limitResultType: "unknown", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldCountResultByType(tt.resultType, tt.limitResultType); got != tt.want {
				t.Fatalf("shouldCountResultByType() = %v, want %v", got, tt.want)
			}
		})
	}
}
