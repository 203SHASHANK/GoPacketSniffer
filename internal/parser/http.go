package parser

import (
	"bufio"
	"bytes"
	"net/http"

	"gopacketsniffer/internal/models"
)

// minHTTPLen is the shortest payload worth inspecting. The shortest valid
// request line, "GET / HTTP/1.1", is 14 bytes before its line ending.
const minHTTPLen = 16

// httpMethods lists the request-line prefixes that mark a payload as the
// start of an HTTP request. The trailing space is part of the match so that
// e.g. "GETTING" is not mistaken for GET.
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "),
	[]byte("CONNECT "), []byte("TRACE "),
}

var httpResponsePrefix = []byte("HTTP/")

// ParseHTTP tries to decode the start of an HTTP/1.x request or response
// from a TCP payload. It returns nil if the payload does not look like HTTP.
//
// Detection is per segment and best-effort: there is no stream reassembly,
// so only segments that begin with a request or status line and contain the
// complete header block are recognised. Encrypted (HTTPS) traffic is never
// matched.
func ParseHTTP(payload []byte) *models.HTTPInfo {
	if len(payload) < minHTTPLen {
		return nil
	}
	if looksLikeHTTPRequest(payload) {
		return parseHTTPRequest(payload)
	}
	if bytes.HasPrefix(payload, httpResponsePrefix) {
		return parseHTTPResponse(payload)
	}
	return nil
}

// looksLikeHTTPRequest is a cheap prefix check that keeps the comparatively
// expensive net/http parser away from non-HTTP traffic.
func looksLikeHTTPRequest(data []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

func parseHTTPRequest(data []byte) *models.HTTPInfo {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return nil
	}
	return &models.HTTPInfo{
		IsRequest: true,
		Method:    req.Method,
		URL:       req.URL.String(),
		Host:      req.Host,
	}
}

func parseHTTPResponse(data []byte) *models.HTTPInfo {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return nil
	}
	// Only the status line and headers are needed; the body is never read.
	_ = resp.Body.Close()
	return &models.HTTPInfo{
		IsResponse: true,
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
	}
}
