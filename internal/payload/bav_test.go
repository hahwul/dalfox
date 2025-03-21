package payload

import (
	"testing"
)

func TestGetOpenRedirectPayload(t *testing.T) {
	payloads := GetOpenRedirectPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestGetCRLFPayload(t *testing.T) {
	payloads := GetCRLFPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestGetESIIPayload(t *testing.T) {
	payloads := GetESIIPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestGetSQLIPayload(t *testing.T) {
	payloads := GetSQLIPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestGetSSTIPayload(t *testing.T) {
	payloads := GetSSTIPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}
