package report

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
)

func TestGenerateReport(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	scanResult := model.Result{
		StartTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Hour),
		Duration:  1 * time.Hour,
		Params: []model.ParamResult{
			{
				Name:           "param1",
				Type:           "type1",
				Reflected:      true,
				ReflectedPoint: "point1",
				ReflectedCode:  "code1",
				Chars:          []string{"char1", "char2"},
			},
		},
		PoCs: []model.PoC{
			{
				Type:       "type1",
				Severity:   "high",
				Method:     "GET",
				Param:      "param1",
				InjectType: "type1",
				CWE:        "cwe1",
				Data:       "data1",
			},
		},
	}

	// Redirect stdout to capture output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call the function
	GenerateReport(scanResult, options)

	// Capture the output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stdout = old

	// Check the output
	got := buf.String()
	if len(got) < 1 {
		t.Errorf("GenerateReport() = %v, want %v", got, nil)
	}
}

func Test_renderTable(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	params := []model.ParamResult{
		{
			Name:           "param1",
			Type:           "type1",
			Reflected:      true,
			ReflectedPoint: "point1",
			ReflectedCode:  "code1",
			Chars:          []string{"char1", "char2"},
		},
	}

	// Redirect stdout to capture output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call the function
	renderTable(params, options)

	// Capture the output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stdout = old

	// Check the output
	got := buf.String()

	if len(got) < 1 {
		t.Errorf("renderTable() = %v, want %v", got, nil)
	}
}

func Test_renderPoCTable(t *testing.T) {
	options := model.Options{
		AuroraObject: aurora.NewAurora(true),
	}
	pocs := []model.PoC{
		{
			Type:       "type1",
			Severity:   "high",
			Method:     "GET",
			Param:      "param1",
			InjectType: "type1",
			CWE:        "cwe1",
			Data:       "data1",
		},
	}

	// Redirect stdout to capture output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call the function
	renderPoCTable(pocs, options)

	// Capture the output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stdout = old

	// Check the output
	got := buf.String()

	if len(got) < 1 {
		t.Errorf("renderPoCTable() = %v, want %v", got, nil)
	}
}
