package printing

import (
	"strconv"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"golang.org/x/term"
)

// ScanSummary prints the summary of the scan.
func ScanSummary(scanResult model.Result, options model.Options) {
	if term.IsTerminal(0) {
		width, _, err := term.GetSize(0)
		if err == nil {
			var dash string
			for i := 0; i < width-5; i++ {
				dash = dash + "-"
			}
			DalLog("SYSTEM-M", dash, options)
		}
	}
	DalLog("SYSTEM-M", "[duration: "+scanResult.Duration.String()+"][issues: "+strconv.Itoa(len(scanResult.PoCs))+"] Finish Scan!", options)
}
