package auth

import (
	"errors"
	"net/http"
	"testing"
)

// Test cases for the GetAPIKey function
func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer token"},
			},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name: "Correct Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey your-api-key"},
			},
			expectedKey: "your-api-key",
			expectedErr: nil,
		},
		{
			name: "Authorization Header Without Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name: "Authorization Header With Extra Spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey  your-api-key"},
			},
			expectedKey: "your-api-key",
			expectedErr: ErrMalformedAuthHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("expected key %v, got %v", tt.expectedKey, key)
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}
