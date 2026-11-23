package model

import "sync"

// scanStoreMu guards every Options.Scan map. Scans write their result from
// a background goroutine while REST handlers read and delete entries, and a
// concurrent map read and write is a fatal error in Go, not a recoverable
// panic. All access to an Options.Scan map goes through these helpers.
var scanStoreMu sync.RWMutex

// StoreScan records a scan result.
func StoreScan(m map[string]Scan, sid string, s Scan) {
	if m == nil {
		return
	}
	scanStoreMu.Lock()
	defer scanStoreMu.Unlock()
	m[sid] = s
}

// LoadScan returns a recorded scan.
func LoadScan(m map[string]Scan, sid string) (Scan, bool) {
	scanStoreMu.RLock()
	defer scanStoreMu.RUnlock()
	s, ok := m[sid]
	return s, ok
}

// DeleteScan removes one recorded scan.
func DeleteScan(m map[string]Scan, sid string) {
	scanStoreMu.Lock()
	defer scanStoreMu.Unlock()
	delete(m, sid)
}

// ClearScans removes every recorded scan. It empties the map in place:
// running scans hold the same map and keep writing to it.
func ClearScans(m map[string]Scan) {
	scanStoreMu.Lock()
	defer scanStoreMu.Unlock()
	for k := range m {
		delete(m, k)
	}
}
