package report

import (
	"strings"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
)

func TestGenerateMarkdownReport(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true), // Or false, depending on whether you want color in tests
	}
	scanResult := model.Result{
		StartTime: time.Date(2023, 10, 26, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2023, 10, 26, 11, 0, 0, 0, time.UTC),
		Duration:  1 * time.Hour,
		Params: []model.ParamResult{
			{
				Name:           "param1",
				Type:           "query",
				Reflected:      true,
				ReflectedPoint: "body",
				ReflectedCode:  "param1_reflected",
				Chars:          []string{"'", "\""},
			},
			{
				Name:           "param2",
				Type:           "header",
				Reflected:      false,
				ReflectedPoint: "",
				ReflectedCode:  "",
				Chars:          []string{},
			},
		},
		PoCs: []model.PoC{
			{
				Type:       "XSS",
				Severity:   "High",
				Method:     "GET",
				Param:      "param1",
				InjectType: "inHTML",
				CWE:        "CWE-79",
				Data:       "<script>alert(1)</script>",
			},
		},
	}

	expectedReport := `## Information
- Start: 2023-10-26 10:00:00 +0000 UTC
- End: 2023-10-26 11:00:00 +0000 UTC
- Duration: 1h0m0s

## Parameter Analysis
| Param | Type | Reflected | R-Point | R-Code | Chars |
|---|---|---|---|---|---|
| param1 | query | true | body | param1_reflected | ' " |
| param2 | header | false |  |  |  |

## XSS PoCs
| # | Type | Severity | Method | Param | Inject-Type | CWE |
|---|---|---|---|---|---|---|
| [PoC1](#PoC1) | XSS | High | GET | param1 | inHTML | CWE-79 |

### PoC1
` + "```\n<script>alert(1)</script>\n```" + `

` // Adding the code block directly as it contains backticks

	report := GenerateMarkdownReport(scanResult, options)

	if report != expectedReport {
		t.Errorf("GenerateMarkdownReport() output did not match expected.\nGot:\n%s\n\nWant:\n%s", report, expectedReport)
	}
}

func TestGenerateMarkdownReport_NoPoCs(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	scanResult := model.Result{
		StartTime: time.Date(2023, 10, 26, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2023, 10, 26, 11, 0, 0, 0, time.UTC),
		Duration:  1 * time.Hour,
		Params: []model.ParamResult{
			{
				Name:           "param1",
				Type:           "query",
				Reflected:      true,
				ReflectedPoint: "body",
				ReflectedCode:  "param1_reflected",
				Chars:          []string{"'", "\""},
			},
		},
		PoCs: []model.PoC{}, // No PoCs
	}

	expectedReport := `## Information
- Start: 2023-10-26 10:00:00 +0000 UTC
- End: 2023-10-26 11:00:00 +0000 UTC
- Duration: 1h0m0s

## Parameter Analysis
| Param | Type | Reflected | R-Point | R-Code | Chars |
|---|---|---|---|---|---|
| param1 | query | true | body | param1_reflected | ' " |

## XSS PoCs
No XSS vulnerabilities found.

`

	report := GenerateMarkdownReport(scanResult, options)

	if report != expectedReport {
		t.Errorf("GenerateMarkdownReport() with no PoCs output did not match expected.\nGot:\n%s\n\nWant:\n%s", report, expectedReport)
	}
}

func TestGenerateMarkdownReport_NoParams(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	scanResult := model.Result{
		StartTime: time.Date(2023, 10, 26, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2023, 10, 26, 11, 0, 0, 0, time.UTC),
		Duration:  1 * time.Hour,
		Params:    []model.ParamResult{}, // No Params
		PoCs: []model.PoC{
			{
				Type:       "XSS",
				Severity:   "High",
				Method:     "GET",
				Param:      "param1",
				InjectType: "inHTML",
				CWE:        "CWE-79",
				Data:       "<script>alert(1)</script>",
			},
		},
	}

	expectedReport := `## Information
- Start: 2023-10-26 10:00:00 +0000 UTC
- End: 2023-10-26 11:00:00 +0000 UTC
- Duration: 1h0m0s

## Parameter Analysis
| Param | Type | Reflected | R-Point | R-Code | Chars |
|---|---|---|---|---|---|

## XSS PoCs
| # | Type | Severity | Method | Param | Inject-Type | CWE |
|---|---|---|---|---|---|---|
| [PoC1](#PoC1) | XSS | High | GET | param1 | inHTML | CWE-79 |

### PoC1
` + "```\n<script>alert(1)</script>\n```" + `

`
	report := GenerateMarkdownReport(scanResult, options)

	if report != expectedReport {
		t.Errorf("GenerateMarkdownReport() with no Params output did not match expected.\nGot:\n%s\n\nWant:\n%s", report, expectedReport)
	}
}

func TestGenerateMarkdownReport_EmptyResult(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	scanResult := model.Result{
		StartTime: time.Date(2023, 10, 26, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2023, 10, 26, 11, 0, 0, 0, time.UTC),
		Duration:  1 * time.Hour,
		Params:    []model.ParamResult{}, // No Params
		PoCs:      []model.PoC{},         // No PoCs
	}

	expectedReport := `## Information
- Start: 2023-10-26 10:00:00 +0000 UTC
- End: 2023-10-26 11:00:00 +0000 UTC
- Duration: 1h0m0s

## Parameter Analysis
| Param | Type | Reflected | R-Point | R-Code | Chars |
|---|---|---|---|---|---|

## XSS PoCs
No XSS vulnerabilities found.

`
	report := GenerateMarkdownReport(scanResult, options)

	if report != expectedReport {
		t.Errorf("GenerateMarkdownReport() with empty result output did not match expected.\nGot:\n%s\n\nWant:\n%s", report, expectedReport)
	}
}

func TestGenerateMarkdownReport_MultiplePoCs(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	scanResult := model.Result{
		StartTime: time.Date(2023, 10, 26, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2023, 10, 26, 11, 0, 0, 0, time.UTC),
		Duration:  1 * time.Hour,
		Params: []model.ParamResult{
			{
				Name:           "param1",
				Type:           "query",
				Reflected:      true,
				ReflectedPoint: "body",
				ReflectedCode:  "param1_reflected",
				Chars:          []string{"'", "\""},
			},
		},
		PoCs: []model.PoC{
			{
				Type:       "XSS",
				Severity:   "High",
				Method:     "GET",
				Param:      "param1",
				InjectType: "inHTML",
				CWE:        "CWE-79",
				Data:       "<script>alert(1)</script>",
			},
			{
				Type:       "Reflected XSS",
				Severity:   "Medium",
				Method:     "POST",
				Param:      "q",
				InjectType: "inJs",
				CWE:        "CWE-79",
				Data:       "';alert(2);'",
			},
		},
	}

	report := GenerateMarkdownReport(scanResult, options)

	if !strings.Contains(report, "### PoC1") {
		t.Errorf("Report does not contain PoC1")
	}
	if !strings.Contains(report, "<script>alert(1)</script>") {
		t.Errorf("Report does not contain data for PoC1")
	}
	if !strings.Contains(report, "### PoC2") {
		t.Errorf("Report does not contain PoC2")
	}
	if !strings.Contains(report, "';alert(2);'") {
		t.Errorf("Report does not contain data for PoC2")
	}
}
