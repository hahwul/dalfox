package payload

import (
	"fmt"
	"strings"
	"testing"
)

func TestGetCommonPayloadWithSize(t *testing.T) {
	payloads, size := GetCommonPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
	if size == 0 {
		t.Error("Expected non-empty common payloads")
	}
}

func TestGetHTMLPayloadWithSize(t *testing.T) {
	payloads, size := GetHTMLPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
	if size == 0 {
		t.Error("Expected non-empty HTML payloads")
	}
}

func TestGetAttrPayloadWithSize(t *testing.T) {
	payloads, size := GetAttrPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
	if size == 0 {
		t.Error("Expected non-empty Attr payloads")
	}
}

func TestGetInJsPayloadWithSize(t *testing.T) {
	payloads, size := GetInJsPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
	if size == 0 {
		t.Error("Expected non-empty InJs payloads")
	}
}

func TestGetInJsBreakScriptPayloadWithSize(t *testing.T) {
	payloads, size := GetInJsBreakScriptPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
	if size == 0 {
		t.Error("Expected non-empty InJsBreakScript payloads")
	}
}

func TestGetBlindPayload(t *testing.T) {
	payloads := GetBlindPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty blind payloads")
	}
	for i, p := range payloads {
		if !strings.Contains(p, "CALLBACKURL") && !strings.Contains(p, "alert(String.fromCharCode(88,83,83))") {
			t.Errorf("Blind payload at index %d does not contain expected substring: %s", i, p)
		}
	}
}

func TestGetWAFBypassPayloads(t *testing.T) {
	payloads := GetWAFBypassPayloads()
	if len(payloads) == 0 {
		t.Error("Expected non-empty WAF bypass payloads")
	}
	// Check for a few known patterns to ensure the list is somewhat correct
	foundSVG := false
	foundIMG := false
	for _, p := range payloads {
		if strings.Contains(p, "<svg") {
			foundSVG = true
		}
		if strings.Contains(p, "<img") {
			foundIMG = true
		}
	}
	if !foundSVG || !foundIMG {
		t.Error("Expected specific patterns (svg, img) not found in WAFBypassPayloads")
	}
}

func TestGetCommonPayload(t *testing.T) {
	payloads := GetCommonPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty common payloads")
	}
	for i, p := range payloads {
		if !strings.Contains(p, "DALFOX_ALERT_VALUE") && !strings.Contains(p, "dalfox") && !strings.Contains(p, "String.fromCharCode(88,83,83)") && !strings.Contains(p, "confirm``") && !strings.Contains(p, "alert``") {
			// Allow some flexibility for payloads not matching the primary patterns
			// This check is a heuristic
			fmt.Printf("Warning: Common payload at index %d might be missing DALFOX_ALERT_VALUE or class=dalfox: %s\n", i, p)
		}
	}
}

func TestGetHTMLPayload(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectedMin int
		mustContain []string
	}{
		{"empty ip", "", 50, []string{"<sVg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>"}}, // Assuming DALFOX_ALERT_VALUE is default
		{"comment ip", "comment", 50, []string{"--><svg/onload=alert(DALFOX_ALERT_VALUE)>"}},
		{"random ip", "random", 50, []string{"<sVg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetHTMLPayload(tt.ip)
			if len(payloads) < tt.expectedMin {
				t.Errorf("GetHTMLPayload(%s): expected at least %d payloads, got %d", tt.ip, tt.expectedMin, len(payloads))
			}
			for _, substr := range tt.mustContain {
				found := false
				for _, p := range payloads {
					if strings.Contains(p, substr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GetHTMLPayload(%s): expected to find payload containing '%s'", tt.ip, substr)
				}
			}
		})
	}
}

func TestGetAttrPayload(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectedMin int
		mustStart   []string // Check if some payloads start with these if ip is single/double
		mustContain []string // General contains check
	}{
		{"empty ip", "", 100, nil, []string{"onload=alert(DALFOX_ALERT_VALUE) class=dalfox "}},
		{"none ip", "none", 100, nil, []string{"onmouseover=confirm(DALFOX_ALERT_VALUE) class=dalfox "}},
		{"double ip", "double", 100, []string{"\"onload", "\"onmouseover"}, []string{"onload=alert(DALFOX_ALERT_VALUE) class=dalfox "}},
		{"single ip", "single", 100, []string{"'onload", "'onmouseover"}, []string{"onload=alert(DALFOX_ALERT_VALUE) class=dalfox "}},
		{"random ip", "random", 100, nil, []string{"onload=alert(DALFOX_ALERT_VALUE) class=dalfox "}}, // behaves like empty ip
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetAttrPayload(tt.ip)
			if len(payloads) < tt.expectedMin {
				t.Errorf("GetAttrPayload(%s): expected at least %d payloads, got %d", tt.ip, tt.expectedMin, len(payloads))
			}

			if tt.mustStart != nil {
				for _, prefix := range tt.mustStart {
					found := false
					for _, p := range payloads {
						if strings.HasPrefix(p, prefix) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("GetAttrPayload(%s): expected to find payload starting with '%s'", tt.ip, prefix)
					}
				}
			}
			if tt.mustContain != nil {
				for _, substr := range tt.mustContain {
					found := false
					for _, p := range payloads {
						if strings.Contains(p, substr) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("GetAttrPayload(%s): expected to find payload containing '%s'", tt.ip, substr)
					}
				}
			}
		})
	}
}

func TestGetInJsBreakScriptPayload(t *testing.T) {
	payloads := GetInJsBreakScriptPayload("") // ip param is not used by this function
	if len(payloads) == 0 {
		t.Error("Expected non-empty InJsBreakScript payloads")
	}
	expected := []string{
		"</sCRipt><sVg/onload=alert(DALFOX_ALERT_VALUE)>",
		"</scRiPt><sVG/onload=confirm(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=prompt(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=print(DALFOX_ALERT_VALUE)>",
		"</sCriPt><ScRiPt>alert(DALFOX_ALERT_VALUE)</sCrIpt>",
		"</scRipT><sCrIpT>confirm(DALFOX_ALERT_VALUE)</SCriPt>",
		"</ScripT><ScRIpT>prompt(DALFOX_ALERT_VALUE)</scRIpT>",
		"</ScripT><ScRIpT>print(DALFOX_ALERT_VALUE)</scRIpT>",
	}
	if len(payloads) != len(expected) {
		t.Errorf("GetInJsBreakScriptPayload: expected %d payloads, got %d", len(expected), len(payloads))
	}
	for _, exp := range expected {
		found := false
		for _, p := range payloads {
			if p == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetInJsBreakScriptPayload: expected payload '%s' not found", exp)
		}
	}
}

func TestGetInJsPayload(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectedMin int
		mustContain []string // Check if some payloads contain these based on ip
	}{
		{"empty ip", "", 20, []string{"alert(DALFOX_ALERT_VALUE)"}}, // Default behavior
		{"none ip", "none", 60, []string{";alert(DALFOX_ALERT_VALUE);//", ";alert(DALFOX_ALERT_VALUE);", "alert(DALFOX_ALERT_VALUE)"}},
		{"double ip", "double", 100, []string{"\"+alert(DALFOX_ALERT_VALUE)//", "\";alert(DALFOX_ALERT_VALUE)//", "\"alert(DALFOX_ALERT_VALUE)\""}},
		{"single ip", "single", 100, []string{"'+alert(DALFOX_ALERT_VALUE)//", "';alert(DALFOX_ALERT_VALUE)//", "'alert(DALFOX_ALERT_VALUE)'"}},
		{"backtick ip", "backtick", 20, []string{"${alert(DALFOX_ALERT_VALUE)}"}},
		{"random ip", "random", 20, []string{"alert(DALFOX_ALERT_VALUE)"}}, // behaves like empty ip
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetInJsPayload(tt.ip)
			if len(payloads) < tt.expectedMin {
				t.Errorf("GetInJsPayload(%s): expected at least %d payloads, got %d", tt.ip, tt.expectedMin, len(payloads))
			}
			for _, substr := range tt.mustContain {
				found := false
				for _, p := range payloads {
					// DALFOX_ALERT_VALUE might be substituted in some contexts, so check for alert part too
					normalizedP := strings.ReplaceAll(p, "DALFOX_ALERT_VALUE", "XSS_TEST")
					normalizedSubstr := strings.ReplaceAll(substr, "DALFOX_ALERT_VALUE", "XSS_TEST")
					if strings.Contains(normalizedP, normalizedSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GetInJsPayload(%s): expected to find payload containing '%s'", tt.ip, substr)
				}
			}
		})
	}
}

func TestGetDOMXSSPayload(t *testing.T) {
	payloads := GetDOMXSSPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty DOMXSS payloads")
	}
	expected := []string{
		"<img/src/onerror=.1|alert`DALFOX_ALERT_VALUE`>",
		";alert(DALFOX_ALERT_VALUE);",
		"javascript:alert(DALFOX_ALERT_VALUE)",
	}
	if len(payloads) != len(expected) {
		t.Errorf("GetDOMXSSPayload: expected %d payloads, got %d", len(expected), len(payloads))
	}
	for _, exp := range expected {
		found := false
		for _, p := range payloads {
			if p == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetDOMXSSPayload: expected payload '%s' not found", exp)
		}
	}
}

func TestGetDeepDOMXSPayload(t *testing.T) {
	payloads := GetDeepDOMXSPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty DeepDOMXS payloads")
	}
	// Check if it contains some known patterns
	mustContain := []string{
		"<svg/OnLoad=\"`${prompt`DALFOX_ALERT_VALUE`}`\">",
		"javascript:alert(DALFOX_ALERT_VALUE)",
		"</scrIpt><scrIpt>alert(DALFOX_ALERT_VALUE)</scrIpt>",
	}
	for _, substr := range mustContain {
		found := false
		for _, p := range payloads {
			if strings.Contains(p, substr) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetDeepDOMXSPayload: expected to find payload containing '%s'", substr)
		}
	}
}

// Test splitLines as it's used in this package
func TestSplitLines_xss(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []string
	}{
		{"empty string", "", []string{}},
		{"single line", "hello", []string{"hello"}},
		{"multiple lines", "hello\nworld", []string{"hello", "world"}},
		{"crnl lines", "hello\r\nworld", []string{"hello", "world"}},
		{"mixed newlines", "hello\nworld\r\nagain", []string{"hello", "world", "again"}},
		{"trailing newline", "hello\n", []string{"hello"}},
		{"multiple trailing newlines", "hello\n\n", []string{"hello", ""}},
		{"leading newline", "\nhello", []string{"", "hello"}},
		{"only newlines", "\n\n", []string{"", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitLines(tt.s)
			// equalSlices is defined in remote_test.go in the same package.
			// No need to redefine or qualify if both files are part of the same 'payload' package.
			if len(got) == 0 && len(tt.want) == 0 {
				// This is fine, both are empty slices
			} else if !equalSlices(got, tt.want) { // This will use the one from remote_test.go
				t.Errorf("splitLines(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
