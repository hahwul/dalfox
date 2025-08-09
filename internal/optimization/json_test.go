package optimization

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestInjectJSONPayload(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		targetPath  string
		payload     string
		expected    string
	}{
		{
			name:       "Simple field injection",
			jsonData:   `{"username": "admin", "password": "secret"}`,
			targetPath: "username",
			payload:    "<script>alert(1)</script>",
			expected:   `{"password":"secret","username":"<script>alert(1)</script>"}`,
		},
		{
			name:       "Nested field injection",
			jsonData:   `{"user": {"name": "admin", "email": "admin@test.com"}}`,
			targetPath: "user.name",
			payload:    "XSS_PAYLOAD",
			expected:   `{"user":{"email":"admin@test.com","name":"XSS_PAYLOAD"}}`,
		},
		{
			name:       "Array index injection",
			jsonData:   `{"tags": ["admin", "user", "guest"]}`,
			targetPath: "tags[1]",
			payload:    "INJECTED",
			expected:   `{"tags":["admin","INJECTED","guest"]}`,
		},
		{
			name:       "Deeply nested injection",
			jsonData:   `{"user": {"profile": {"settings": {"theme": "dark"}}}}`,
			targetPath: "user.profile.settings.theme",
			payload:    "XSS",
			expected:   `{"user":{"profile":{"settings":{"theme":"XSS"}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var originalData interface{}
			err := json.Unmarshal([]byte(tt.jsonData), &originalData)
			assert.NoError(t, err)

			result := injectJSONPayload(originalData, tt.targetPath, tt.payload)
			
			resultBytes, err := json.Marshal(result)
			assert.NoError(t, err)

			// Parse both expected and actual JSON to compare structure (order doesn't matter)
			var expectedJSON, actualJSON interface{}
			json.Unmarshal([]byte(tt.expected), &expectedJSON)
			json.Unmarshal(resultBytes, &actualJSON)

			assert.Equal(t, expectedJSON, actualJSON)
		})
	}
}

func TestMakeJSONRequestQuery(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		param          string
		payload        string
		ptype          string
		action         string
		encode         string
		jsonData       string
		expectedMethod string
		expectedCType  string
	}{
		{
			name:           "Basic JSON injection",
			target:         "http://example.com/api",
			param:          "username",
			payload:        "<script>alert(1)</script>",
			ptype:          "inHTML-JSON",
			action:         "toAppend",
			encode:         "NaN",
			jsonData:       `{"username": "admin", "password": "secret"}`,
			expectedMethod: "POST",
			expectedCType:  "application/json",
		},
		{
			name:           "Nested parameter injection",
			target:         "http://example.com/api/user",
			param:          "user.profile.name",
			payload:        "XSS_TEST",
			ptype:          "inHTML-JSON",
			action:         "toAppend",
			encode:         "NaN",
			jsonData:       `{"user": {"profile": {"name": "original"}}}`,
			expectedMethod: "POST",
			expectedCType:  "application/json",
		},
		{
			name:           "URL encoded payload",
			target:         "http://example.com/api",
			param:          "data",
			payload:        "<test>",
			ptype:          "inHTML-JSON",
			action:         "toAppend",
			encode:         "urlEncode",
			jsonData:       `{"data": "value"}`,
			expectedMethod: "POST",
			expectedCType:  "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := model.Options{
				Data: tt.jsonData,
			}

			req, tempMap := MakeJSONRequestQuery(tt.target, tt.param, tt.payload, tt.ptype, tt.action, tt.encode, options)

			assert.Equal(t, tt.expectedMethod, req.Method)
			assert.Equal(t, tt.expectedCType, req.Header.Get("Content-Type"))
			assert.Equal(t, tt.target, req.URL.String())

			// Check that tempMap contains expected values
			assert.Equal(t, tt.ptype, tempMap["type"])
			assert.Equal(t, tt.action, tempMap["action"])
			assert.Equal(t, tt.encode, tempMap["encode"])
			assert.Equal(t, tt.param, tempMap["param"])

			// Read the request body and verify JSON structure
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				assert.NoError(t, err)

				var bodyData interface{}
				err = json.Unmarshal(bodyBytes, &bodyData)
				assert.NoError(t, err, "Request body should contain valid JSON")

				// Verify the injection was applied
				bodyStr := string(bodyBytes)
				if tt.encode == "urlEncode" {
					// For URL encoded payloads, check for encoded characters
					assert.Contains(t, bodyStr, "%3C", "Should contain URL encoded payload")
				} else {
					// JSON marshal escapes HTML characters, so check for escaped version
					if strings.Contains(tt.payload, "<") || strings.Contains(tt.payload, ">") {
						assert.True(t, strings.Contains(bodyStr, "\\u003c") || strings.Contains(bodyStr, tt.payload), 
							"Should contain the injected payload (possibly HTML-escaped)")
					} else {
						assert.Contains(t, bodyStr, tt.payload, "Should contain the injected payload")
					}
				}
			}
		})
	}
}

func TestMakeJSONRequestQueryWithInvalidJSON(t *testing.T) {
	// Test fallback behavior when JSON parsing fails
	options := model.Options{
		Data: "invalid json data",
	}

	req, tempMap := MakeJSONRequestQuery("http://example.com", "param", "payload", "type", "action", "NaN", options)

	// Should fall back to regular request generation
	assert.NotNil(t, req)
	assert.Equal(t, "param", tempMap["param"])
	assert.Equal(t, "payload", tempMap["payload"])
}

func TestMakeJSONRequestQueryWithHeaders(t *testing.T) {
	// Test that custom headers are properly applied
	options := model.Options{
		Data:      `{"test": "value"}`,
		Header:    []string{"Authorization: Bearer token123", "X-Custom: custom-value"},
		Cookie:    "session=abc123",
		UserAgent: "TestAgent/1.0",
	}

	req, _ := MakeJSONRequestQuery("http://example.com", "test", "payload", "type", "action", "NaN", options)

	assert.Equal(t, "Bearer token123", req.Header.Get("Authorization"))
	assert.Equal(t, "custom-value", req.Header.Get("X-Custom"))
	assert.Equal(t, "session=abc123", req.Header.Get("Cookie"))
	assert.Equal(t, "TestAgent/1.0", req.Header.Get("User-Agent"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
}