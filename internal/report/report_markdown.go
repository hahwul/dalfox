package report

import (
	"fmt"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// GenerateMarkdownReport creates a report in Markdown format
func GenerateMarkdownReport(scanResult model.Result, options model.Options) string {
	var report strings.Builder

	report.WriteString("## Information\n")
	report.WriteString(fmt.Sprintf("- Start: %s\n", scanResult.StartTime.String()))
	report.WriteString(fmt.Sprintf("- End: %s\n", scanResult.EndTime.String()))
	report.WriteString(fmt.Sprintf("- Duration: %s\n\n", scanResult.Duration.String()))

	report.WriteString("## Parameter Analysis\n")
	report.WriteString("| Param | Type | Reflected | R-Point | R-Code | Chars |\n")
	report.WriteString("|---|---|---|---|---|---|\n")
	for _, v := range scanResult.Params {
		chars := strings.Join(v.Chars, " ")
		reflected := "false"
		if v.Reflected {
			reflected = "true"
		}
		report.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n", v.Name, v.Type, reflected, v.ReflectedPoint, v.ReflectedCode, chars))
	}
	report.WriteString("\n")

	report.WriteString("## XSS PoCs\n")
	if len(scanResult.PoCs) > 0 {
		report.WriteString("| # | Type | Severity | Method | Param | Inject-Type | CWE |\n")
		report.WriteString("|---|---|---|---|---|---|---|\n")
		for i, v := range scanResult.PoCs {
			report.WriteString(fmt.Sprintf("| #%d | %s | %s | %s | %s | %s | %s |\n", i, v.Type, v.Severity, v.Method, v.Param, v.InjectType, v.CWE))
		}
		report.WriteString("\n")
		for i, v := range scanResult.PoCs {
			report.WriteString(fmt.Sprintf("### PoC #%d\n", i))
			report.WriteString(fmt.Sprintf("```\n%s\n```\n\n", v.Data))
		}
	} else {
		report.WriteString("No XSS vulnerabilities found.\n\n")
	}

	return report.String()
}
