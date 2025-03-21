package payload

import (
	"testing"
)

func TestRemoteGetOpenRedirectPayload(t *testing.T) {
	payloads := GetOpenRedirectPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestRemoteGetCRLFPayload(t *testing.T) {
	payloads := GetCRLFPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestRemoteGetESIIPayload(t *testing.T) {
	payloads := GetESIIPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestRemoteGetSQLIPayload(t *testing.T) {
	payloads := GetSQLIPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}

func TestRemoteGetSSTIPayload(t *testing.T) {
	payloads := GetSSTIPayload()
	if len(payloads) == 0 {
		t.Errorf("Expected non-empty payloads, got %d", len(payloads))
	}
}
