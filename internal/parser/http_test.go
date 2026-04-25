package parser

import (
	"testing"
)

func TestParseHTTPRequest(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	info := ParseHTTP(payload)
	if info == nil {
		t.Fatal("expected HTTPInfo, got nil")
	}
	if !info.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if info.Method != "GET" {
		t.Errorf("Method=%q, want GET", info.Method)
	}
	if info.Host != "example.com" {
		t.Errorf("Host=%q, want example.com", info.Host)
	}
}

func TestParseHTTPResponse(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	info := ParseHTTP(payload)
	if info == nil {
		t.Fatal("expected HTTPInfo, got nil")
	}
	if !info.IsResponse {
		t.Error("expected IsResponse=true")
	}
	if info.StatusCode != 200 {
		t.Errorf("StatusCode=%d, want 200", info.StatusCode)
	}
}

func TestParseHTTPNonHTTP(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	if ParseHTTP(payload) != nil {
		t.Error("expected nil for non-HTTP payload")
	}
}

func TestParseHTTPTooShort(t *testing.T) {
	if ParseHTTP([]byte("GET /")) != nil {
		t.Error("expected nil for too-short payload")
	}
}

func TestParseHTTPPost(t *testing.T) {
	payload := []byte("POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n")
	info := ParseHTTP(payload)
	if info == nil || info.Method != "POST" {
		t.Errorf("expected POST request, got %v", info)
	}
}
