package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization header",
			headers: http.Header{
				"Authorization": {""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": {"Bearer somekey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization header - no key",
			headers: http.Header{
				"Authorization": {"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid ApiKey header",
			headers: http.Header{
				"Authorization": {"ApiKey correct-key-123"},
			},
			expectedKey:   "correct-key-123",
			expectedError: nil,
		},
		{
			name: "Extra whitespace in Authorization header",
			headers: http.Header{
				"Authorization": {"ApiKey    extra-spaces-key"},
			},
			expectedKey:   "extra-spaces-key",
			expectedError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}
			if (err != nil && tc.expectedError == nil) ||
				(err == nil && tc.expectedError != nil) ||
				(err != nil && tc.expectedError != nil && err.Error() != tc.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}
		})
	}
}
