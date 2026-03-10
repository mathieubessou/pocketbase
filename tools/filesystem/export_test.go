package filesystem

import "net/http"

// SetSafeHTTPClientForTest replaces the SSRF-safe HTTP client used by
// NewFileFromURL with the provided client and returns a restore function.
// This helper exists solely for testing and must not be used in production code.
func SetSafeHTTPClientForTest(client *http.Client) (restore func()) {
	orig := safeURLHTTPClient
	safeURLHTTPClient = client
	return func() { safeURLHTTPClient = orig }
}
