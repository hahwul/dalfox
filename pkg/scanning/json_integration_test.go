package scanning

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestJSONParameterIntegration(t *testing.T) {
	// Create a test server that accepts JSON and returns it back
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	t.Run("JSON Parameter Discovery and Injection", func(t *testing.T) {
		jsonData := `{"username": "admin", "profile": {"email": "test@example.com"}}`
		options := model.Options{
			Data:    jsonData,
			Silence: true,
		}

		// Test parameter discovery
		params := make(map[string]model.ParamResult)
		result := findJSONParams(params, options)

		// Should find JSON parameters
		jsonParams := 0
		var paramNames []string
		for name, param := range result {
			if param.Type == "JSON" {
				jsonParams++
				paramNames = append(paramNames, name)
			}
		}

		assert.Greater(t, jsonParams, 0, "Should discover JSON parameters")
		assert.Contains(t, paramNames, "username")
		assert.Contains(t, paramNames, "profile")
		assert.Contains(t, paramNames, "profile.email")

		// Test JSON request generation
		for _, paramName := range paramNames {
			payload := "<script>alert(1)</script>"
			req, meta := optimization.MakeJSONRequestQuery(server.URL, paramName, payload, "inHTML-JSON", "toAppend", "NaN", options)

			assert.Equal(t, "POST", req.Method)
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, paramName, meta["param"])
			assert.Equal(t, payload, meta["payload"])

			// Verify the request body contains valid JSON with injected payload
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				assert.NoError(t, err)

				var bodyData interface{}
				err = json.Unmarshal(bodyBytes, &bodyData)
				assert.NoError(t, err, "Request body should contain valid JSON")

				// The payload should be somewhere in the JSON (possibly HTML-escaped)
				bodyStr := string(bodyBytes)
				assert.True(t, strings.Contains(bodyStr, "\\u003cscript\\u003e") || strings.Contains(bodyStr, payload),
					"Should contain the injected payload in JSON body")
			}
		}
	})

	t.Run("Non-JSON Data Should Not Trigger JSON Handling", func(t *testing.T) {
		formData := "username=admin&password=secret"
		options := model.Options{
			Data:    formData,
			Silence: true,
		}

		// Test parameter discovery
		params := make(map[string]model.ParamResult)
		result := findJSONParams(params, options)

		// Should not find JSON parameters
		jsonParams := 0
		for _, param := range result {
			if param.Type == "JSON" {
				jsonParams++
			}
		}

		assert.Equal(t, 0, jsonParams, "Should not discover JSON parameters for form data")

		// Test that MakeJSONRequestQuery falls back to regular handling
		req, _ := optimization.MakeJSONRequestQuery(server.URL, "username", "payload", "type", "action", "NaN", options)
		assert.NotNil(t, req, "Should create a request even with invalid JSON")
	})

	t.Run("Complex JSON Structure Handling", func(t *testing.T) {
		complexJSON := `{
			"user": {
				"personal": {
					"name": "John Doe",
					"email": "john@example.com"
				},
				"preferences": {
					"theme": "dark",
					"notifications": true
				}
			},
			"data": [
				{"id": 1, "value": "first"},
				{"id": 2, "value": "second"}
			],
			"metadata": {
				"version": "1.0",
				"tags": ["admin", "user"]
			}
		}`

		options := model.Options{
			Data:    complexJSON,
			Silence: true,
		}

		params := make(map[string]model.ParamResult)
		result := findJSONParams(params, options)

		expectedParams := []string{
			"user",
			"user.personal",
			"user.personal.name",
			"user.personal.email",
			"user.preferences",
			"user.preferences.theme",
			"user.preferences.notifications",
			"data",
			"data[0]",
			"data[0].id",
			"data[0].value",
			"data[1]",
			"data[1].id",
			"data[1].value",
			"metadata",
			"metadata.version",
			"metadata.tags",
			"metadata.tags[0]",
			"metadata.tags[1]",
		}

		var foundParams []string
		for name, param := range result {
			if param.Type == "JSON" {
				foundParams = append(foundParams, name)
			}
		}

		for _, expectedParam := range expectedParams {
			assert.Contains(t, foundParams, expectedParam, "Expected parameter %s not found", expectedParam)
		}

		// Test injection at different levels
		deepParam := "user.personal.name"
		payload := "XSS_TEST"
		req, _ := optimization.MakeJSONRequestQuery(server.URL, deepParam, payload, "inHTML-JSON", "toAppend", "NaN", options)

		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			var modifiedData map[string]interface{}
			json.Unmarshal(bodyBytes, &modifiedData)

			// Verify the injection happened at the correct nested location
			user := modifiedData["user"].(map[string]interface{})
			personal := user["personal"].(map[string]interface{})
			assert.Equal(t, payload, personal["name"])
		}
	})
}