package scanning

import (
	"reflect"
	"testing"
)

func TestGrepping(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		regex    string
		expected []string
	}{
		{
			name:     "Simple match",
			data:     "Hello, World!",
			regex:    "Hello",
			expected: []string{"Hello"},
		},
		{
			name:     "Multiple matches",
			data:     "test123test456test789",
			regex:    "test\\d+",
			expected: []string{"test123", "test456", "test789"},
		},
		{
			name:     "No match",
			data:     "Hello, World!",
			regex:    "dalfox",
			expected: []string{},
		},
		{
			name:     "Special characters",
			data:     "email@example.com another@email.com",
			regex:    "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
			expected: []string{"email@example.com", "another@email.com"},
		},
		{
			name:     "Invalid regex",
			data:     "Hello, World!",
			regex:    "[",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Grepping(tt.data, tt.regex)
			if len(result) == 0 && len(tt.expected) == 0 {
				// pass
			} else if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Grepping() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuiltinGrep(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected map[string][]string
	}{
		{
			name: "SSTI pattern",
			data: "The result is 2958816",
			expected: map[string][]string{
				"dalfox-ssti": {"2958816"},
			},
		},
		{
			name: "AWS S3 pattern",
			data: "Please download it from https://bucket-name.s3.amazonaws.com/file.txt",
			expected: map[string][]string{
				"dalfox-aws-s3": {"bucket-name.s3.amazonaws.com"},
			},
		},
		{
			name: "Multiple patterns",
			data: `Please download it from https://bucket-name.s3.amazonaws.com/file.txt
                   MySQL error: Warning: mysql_connect()`,
			expected: map[string][]string{
				"dalfox-aws-s3":       {"bucket-name.s3.amazonaws.com"},
				"dalfox-error-mysql":  {"Warning: mysql_connect()"},
				"dalfox-error-mysql2": {"Warning: mysql"},
			},
		},
		{
			name:     "No patterns",
			data:     "This is a normal text with no sensitive information.",
			expected: map[string][]string{},
		},
		{
			name:     "Invalid slack webhook (negative test)",
			data:     "This is not a real slack webhook: https://hooksXslackYcom/services/T123/B123/123",
			expected: map[string][]string{},
		},
		{
			name: "Valid Google OAuth ID",
			data: "client_id: 1234567890-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com",
			expected: map[string][]string{
				"dalfox-google-oauth-id": {"1234567890-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"},
			},
		},
		{
			name:     "Invalid Google OAuth ID (qooqle)",
			data:     "client_id: 1234567890-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com",
			expected: map[string][]string{},
		},
		{
			name:     "Invalid github token (trailing chars)",
			data:     "user:token@github.commm",
			expected: map[string][]string{},
		},
		{
			name: "Valid sqlite error",
			data: "System.Data.SQLite.SQLiteException: something happened",
			expected: map[string][]string{
				"dalfox-error-sqlite": {"System.Data.SQLite.SQLiteException"},
			},
		},
		{
			name:     "Invalid sqlite error (negative test)",
			data:     "SystemXDataYSQLiteZSQLiteException: something happened",
			expected: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builtinGrep(tt.data)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("builtinGrep() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCustomGrep(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		patterns map[string]string
		expected map[string][]string
	}{
		{
			name: "Single custom pattern",
			data: "The ID is ABC-123-XYZ",
			patterns: map[string]string{
				"custom-id": "[A-Z]+-\\d+-[A-Z]+",
			},
			expected: map[string][]string{
				"custom-id": {"ABC-123-XYZ"},
			},
		},
		{
			name: "Multiple custom patterns",
			data: "Name: John Doe, Phone: 123-456-7890",
			patterns: map[string]string{
				"name":  "Name: ([A-Za-z ]+)",
				"phone": "\\d{3}-\\d{3}-\\d{4}",
			},
			expected: map[string][]string{
				"name":  {"Name: John Doe"},
				"phone": {"123-456-7890"},
			},
		},
		{
			name: "No matches",
			data: "Nothing to see here",
			patterns: map[string]string{
				"secret": "password: \\w+",
			},
			expected: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := customGrep(tt.data, tt.patterns)

			if len(tt.expected) == 0 && len(result) == 0 {
				return // Test passed for empty results
			}

			// Check if all expected keys are in the result with correct values
			for key, expectedValues := range tt.expected {
				resultValues, exists := result[key]
				if !exists {
					t.Errorf("customGrep() missing key %s in result", key)
					continue
				}

				if !reflect.DeepEqual(resultValues, expectedValues) {
					t.Errorf("customGrep() for key %s = %v, want %v", key, resultValues, expectedValues)
				}
			}

			// Check if there are any unexpected keys in the result
			for key := range result {
				if _, exists := tt.expected[key]; !exists {
					t.Errorf("customGrep() unexpected key %s in result", key)
				}
			}
		})
	}
}

func TestGrepPatterns(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		patterns map[string]string
		expected map[string][]string
	}{
		{
			name: "Basic pattern matching",
			data: "The color is #FF0000",
			patterns: map[string]string{
				"hex-color": "#[0-9A-Fa-f]{6}",
			},
			expected: map[string][]string{
				"hex-color": {"#FF0000"},
			},
		},
		{
			name: "Multiple matches for single pattern",
			data: "IP addresses: 192.168.1.1 and 10.0.0.1",
			patterns: map[string]string{
				"ip": "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
			},
			expected: map[string][]string{
				"ip": {"192.168.1.1", "10.0.0.1"},
			},
		},
		{
			name: "No matches",
			data: "Just some text",
			patterns: map[string]string{
				"url": "https?://[\\w.-]+\\.[\\w]{2,}[\\w/.-]*",
			},
			expected: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := grepPatterns(tt.data, tt.patterns)

			if len(tt.expected) == 0 && len(result) == 0 {
				return // Test passed for empty results
			}

			// Check if all expected keys are in the result with correct values
			for key, expectedValues := range tt.expected {
				resultValues, exists := result[key]
				if !exists {
					t.Errorf("grepPatterns() missing key %s in result", key)
					continue
				}

				if !reflect.DeepEqual(resultValues, expectedValues) {
					t.Errorf("grepPatterns() for key %s = %v, want %v", key, resultValues, expectedValues)
				}
			}

			// Check if there are any unexpected keys in the result
			for key := range result {
				if _, exists := tt.expected[key]; !exists {
					t.Errorf("grepPatterns() unexpected key %s in result", key)
				}
			}
		})
	}
}
