package openmalleable

import (
	"net/http/httptest"
	"testing"
)

func TestNewHTTPRequestFromHTTPPreservesPlusInQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.test/checkin?id=abc+def%2Fghi%3D", nil)

	httpRequest := NewHTTPRequestFromHTTP(req, nil)

	if got := httpRequest.Query["id"]; got != "abc+def/ghi=" {
		t.Fatalf("query id = %q, want %q", got, "abc+def/ghi=")
	}
}

func TestParseHTTPRequestPreservesPlusInQuery(t *testing.T) {
	httpRequest, err := ParseHTTPRequest("GET /checkin?id=abc+def%2Fghi%3D HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if err != nil {
		t.Fatalf("ParseHTTPRequest returned error: %v", err)
	}

	if got := httpRequest.Query["id"]; got != "abc+def/ghi=" {
		t.Fatalf("query id = %q, want %q", got, "abc+def/ghi=")
	}
}
