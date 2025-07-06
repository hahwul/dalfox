package report

import (
	"fmt"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// GenerateMarkdownReport creates a report in Markdown format
func GenerateMarkdownReport(scanResult model.Result, options model.Options) string {
	var report strings.Builder
	sanitize := func(s string) string {
		return strings.NewReplacer(
			"|", `\|`,
			"<", "&lt;",
			">", "&gt;",
		).Replace(s)
	}

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
		report.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n", sanitize(v.Name), sanitize(v.Type), reflected, sanitize(v.ReflectedPoint), sanitize(v.ReflectedCode), sanitize(chars)))
	}
	report.WriteString("\n")

	report.WriteString("## XSS PoCs\n")
	if len(scanResult.PoCs) > 0 {
		report.WriteString("| # | Type | Severity | Method | Param | Inject-Type | CWE |\n")
		report.WriteString("|---|---|---|---|---|---|---|\n")
		for i, v := range scanResult.PoCs {
			idx := i + 1
			report.WriteString(fmt.Sprintf("| [PoC%d](#PoC%d) | %s | %s | %s | %s | %s | %s |\n", idx, idx, v.Type, v.Severity, v.Method, v.Param, v.InjectType, v.CWE))
		}
		report.WriteString("\n")
		for i, v := range scanResult.PoCs {
			idx := i + 1
			report.WriteString(fmt.Sprintf("### PoC%d\n", idx))
			report.WriteString(fmt.Sprintf("```\n%s\n```\n\n", v.Data))
		}
	} else {
		report.WriteString("No XSS vulnerabilities found.\n\n")
	}

	return report.String()
}
