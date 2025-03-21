package payload

import (
	"testing"
)

func TestGetCommonPayloadWithSize(t *testing.T) {
	payloads, size := GetCommonPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
}

func TestGetHTMLPayloadWithSize(t *testing.T) {
	payloads, size := GetHTMLPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
}

func TestGetAttrPayloadWithSize(t *testing.T) {
	payloads, size := GetAttrPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
}

func TestGetInJsPayloadWithSize(t *testing.T) {
	payloads, size := GetInJsPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
}

func TestGetInJsBreakScriptPayloadWithSize(t *testing.T) {
	payloads, size := GetInJsBreakScriptPayloadWithSize()
	if len(payloads) != size {
		t.Errorf("Expected size %d, but got %d", len(payloads), size)
	}
}

func TestGetBlindPayload(t *testing.T) {
	payloads := GetBlindPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetCommonPayload(t *testing.T) {
	payloads := GetCommonPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetHTMLPayload(t *testing.T) {
	payloads := GetHTMLPayload("")
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetAttrPayload(t *testing.T) {
	payloads := GetAttrPayload("")
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetInJsBreakScriptPayload(t *testing.T) {
	payloads := GetInJsBreakScriptPayload("")
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetInJsPayload(t *testing.T) {
	payloads := GetInJsPayload("")
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetDOMXSSPayload(t *testing.T) {
	payloads := GetDOMXSSPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}

func TestGetDeepDOMXSPayload(t *testing.T) {
	payloads := GetDeepDOMXSPayload()
	if len(payloads) == 0 {
		t.Error("Expected non-empty payloads")
	}
}
