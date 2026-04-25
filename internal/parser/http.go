package parser

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"

	"gopacketsniffer/internal/models"
)

// ParseHTTP attempts to decode an HTTP/1.x request or response from a TCP
// payload. Returns nil if the payload does not look like HTTP.
func ParseHTTP(payload []byte) *models.HTTPInfo {
	if len(payload) < 16 {
		return nil
	}
	if looksLikeHTTPRequest(payload) {
		return parseHTTPRequest(payload)
	}
	if bytes.HasPrefix(payload, []byte("HTTP/")) {
		return parseHTTPResponse(payload)
	}
	return nil
}

func looksLikeHTTPRequest(data []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
		"OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	prefix := string(data[:min(16, len(data))])
	for _, m := range methods {
		if strings.HasPrefix(prefix, m) {
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
	return &models.HTTPInfo{
		IsResponse: true,
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
