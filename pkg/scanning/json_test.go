package scanning

import (
	"encoding/json"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestIsJSONData(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{
			name:     "Valid JSON object",
			data:     `{"username": "admin", "password": "secret"}`,
			expected: true,
		},
		{
			name:     "Valid JSON array",
			data:     `[{"id": 1}, {"id": 2}]`,
			expected: true,
		},
		{
			name:     "Invalid JSON",
			data:     `username=admin&password=secret`,
			expected: false,
		},
		{
			name:     "Empty string",
			data:     "",
			expected: false,
		},
		{
			name:     "Just spaces",
			data:     "   ",
			expected: false,
		},
		{
			name:     "Plain text",
			data:     "hello world",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isJSONData(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractJSONParams(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		expectedParams []string
	}{
		{
			name:     "Simple object",
			jsonData: `{"username": "admin", "password": "secret"}`,
			expectedParams: []string{"username", "password"},
		},
		{
			name:     "Nested object",
			jsonData: `{"user": {"name": "admin", "profile": {"email": "admin@example.com"}}, "settings": {"theme": "dark"}}`,
			expectedParams: []string{"user", "user.name", "user.profile", "user.profile.email", "settings", "settings.theme"},
		},
		{
			name:     "Array with objects",
			jsonData: `{"users": [{"name": "user1"}, {"name": "user2"}]}`,
			expectedParams: []string{"users", "users[0]", "users[0].name", "users[1]", "users[1].name"},
		},
		{
			name:     "Mixed types",
			jsonData: `{"id": 123, "active": true, "tags": ["admin", "user"], "metadata": null}`,
			expectedParams: []string{"id", "active", "tags", "tags[0]", "tags[1]", "metadata"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jsonData interface{}
			err := json.Unmarshal([]byte(tt.jsonData), &jsonData)
			assert.NoError(t, err)

			params := make(map[string]model.ParamResult)
			extractJSONParams(jsonData, "", params)

			// Check that all expected parameters were found
			var foundParams []string
			for paramName := range params {
				foundParams = append(foundParams, paramName)
			}

			for _, expectedParam := range tt.expectedParams {
				assert.Contains(t, foundParams, expectedParam, "Expected parameter %s not found", expectedParam)
			}

			// Verify all params have JSON type and PTYPE marker
			for _, param := range params {
				assert.Equal(t, "JSON", param.Type)
				assert.True(t, param.Reflected)
				// Check that PTYPE: JSON is in the chars
				found := false
				for _, char := range param.Chars {
					if char == "PTYPE: JSON" {
						found = true
						break
					}
				}
				assert.True(t, found, "PTYPE: JSON marker not found in param chars")
			}
		})
	}
}

func TestFindJSONParams(t *testing.T) {
	tests := []struct {
		name             string
		data             string
		expectedCount    int
		shouldDetectJSON bool
	}{
		{
			name:             "JSON data",
			data:             `{"username": "admin", "password": "secret"}`,
			expectedCount:    2,
			shouldDetectJSON: true,
		},
		{
			name:             "Form data",
			data:             "username=admin&password=secret",
			expectedCount:    0,
			shouldDetectJSON: false,
		},
		{
			name:             "Empty data",
			data:             "",
			expectedCount:    0,
			shouldDetectJSON: false,
		},
		{
			name:             "Complex JSON",
			data:             `{"user": {"profile": {"name": "test"}}, "settings": [{"key": "value"}]}`,
			expectedCount:    6, // user, user.profile, user.profile.name, settings, settings[0], settings[0].key
			shouldDetectJSON: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := model.Options{
				Data: tt.data,
			}
			params := make(map[string]model.ParamResult)
			result := findJSONParams(params, options)

			jsonParamCount := 0
			for _, param := range result {
				if param.Type == "JSON" {
					jsonParamCount++
				}
			}

			assert.Equal(t, tt.expectedCount, jsonParamCount)
		})
	}
}

func TestJSONParameterDiscovery(t *testing.T) {
	// Test the integration of JSON parameter discovery in ParameterAnalysis
	options := model.Options{
		Data:    `{"username": "admin", "profile": {"email": "test@example.com"}}`,
		Silence: true, // Suppress log output during tests
	}

	// Mock a simple rate limiter for testing
	rl := &rateLimiter{}

	// Call ParameterAnalysis
	params := ParameterAnalysis("http://example.com/api/user", options, rl)

	// Check that JSON parameters were discovered
	jsonParams := 0
	var paramNames []string
	for name, param := range params {
		if param.Type == "JSON" {
			jsonParams++
			paramNames = append(paramNames, name)
		}
	}

	assert.Greater(t, jsonParams, 0, "Should discover JSON parameters")
	assert.Contains(t, paramNames, "username")
	assert.Contains(t, paramNames, "profile")
	assert.Contains(t, paramNames, "profile.email")
}