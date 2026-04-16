package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

/* Verify Basic auth matching logic with valid and invalid credentials. */
func TestValidateAuth(t *testing.T) {
	s := NewServer("", "", "", false, map[string]string{"alice": "s3cr3t"})

	validPayload := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	invalidPayload := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))

	tests := []struct {
		name       string
		header     string
		wantResult bool
	}{
		{"valid", "Basic " + validPayload, true},
		{"valid-lowercase-scheme", "basic " + validPayload, true},
		{"invalid-password", "Basic " + invalidPayload, false},
		{"missing-header", "", false},
		{"missing-basic", "Bearer " + validPayload, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.validateAuth(tt.header); got != tt.wantResult {
				t.Fatalf("validateAuth(%q) = %v, want %v", tt.header, got, tt.wantResult)
			}
		})
	}
}

/* Ensure CONNECT lines with valid format are parsed and headers are handled. */
func TestReadConnectRequest(t *testing.T) {
	validAuth := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	req := "" +
		"CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Proxy-Authorization: Basic " + validAuth + "\r\n" +
		"\r\n"

	target, proxyAuth, err := readConnectRequest(bufio.NewReader(strings.NewReader(req)))
	if err != nil {
		t.Fatalf("readConnectRequest() error = %v", err)
	}
	if target != "example.com:443" {
		t.Fatalf("readConnectRequest() target=%q, want %q", target, "example.com:443")
	}
	if proxyAuth != "Basic "+validAuth {
		t.Fatalf("readConnectRequest() proxyAuth=%q, want %q", proxyAuth, "Basic "+validAuth)
	}
}

/* Reject malformed CONNECT requests early and consistently. */
func TestReadConnectRequestRejectsInvalid(t *testing.T) {
	tests := []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"CONNECT example.com HTTP/1.1\r\n\r\n",
		"CONNECT noport HTTP/1.1\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1 extra\r\n\r\n",
		"connect example.com:443 HTTP/1.1\r\n\r\n",
		"",
	}

	for _, raw := range tests {
		_, _, err := readConnectRequest(bufio.NewReader(strings.NewReader(raw)))
		if err == nil || !errors.Is(err, errBadConnectRequest) {
			t.Fatalf("expected errBadConnectRequest, got %v", err)
		}
	}
}

/* Reject oversized CONNECT target headers at the global request limit boundary. */
func TestReadConnectRequestRejectsOversizedTargetPart(t *testing.T) {
	longHost := strings.Repeat("a", requestHeaderLimit)
	req := "CONNECT " + longHost + ":443 HTTP/1.1\r\n\r\n"
	_, _, err := readConnectRequest(bufio.NewReader(strings.NewReader(req)))
	if err == nil || !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("expected errRequestTooLarge, got %v", err)
	}
}

/* Confirm short write counts are included when transfer returns an error. */
func TestTransferCountsPartialWritesOnError(t *testing.T) {
	src := &testConn{
		readData: []byte("hello world"),
	}
	dst := &testConn{
		writeChunk: 3,
		writeErr:   io.ErrUnexpectedEOF,
	}

	n, err := Transfer(dst, src)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected write error, got %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 bytes written before error, got %d", n)
	}
}

/* Enforce request line length accounting at CRLF boundaries. */
func TestReadRequestLineCRLFLimitAccounting(t *testing.T) {
	line := strings.Repeat("a", requestHeaderLimit-3) + "\r\n"
	parsed, n, err := readRequestLine(bufio.NewReaderSize(strings.NewReader(line), requestHeaderLimit), requestHeaderLimit)
	if err != nil {
		t.Fatalf("readRequestLine() error = %v", err)
	}
	if n != requestHeaderLimit-1 {
		t.Fatalf("readRequestLine() n = %d, want %d", n, requestHeaderLimit-1)
	}
	if parsed != strings.Repeat("a", requestHeaderLimit-3) {
		t.Fatalf("readRequestLine() parsed unexpected length = %d", len(parsed))
	}

	lineTooLong := strings.Repeat("a", requestHeaderLimit) + "\r\n"
	_, _, err = readRequestLine(bufio.NewReaderSize(strings.NewReader(lineTooLong), requestHeaderLimit), requestHeaderLimit)
	if err == nil || !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("expected errRequestTooLarge, got %v", err)
	}
}

/* Reject requests whose total CONNECT+headers exceed the size limit. */
func TestReadConnectRequestRejectsCRLFLimitBoundary(t *testing.T) {
	targetBodyLen := (requestHeaderLimit - 3) - len("CONNECT ") - len(" HTTP/1.1")
	target := strings.Repeat("a", targetBodyLen-len(":443")) + ":443"

	req := "CONNECT " + target + " HTTP/1.1\r\n\r\n"
	_, _, err := readConnectRequest(bufio.NewReader(strings.NewReader(req)))
	if err == nil || !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("expected errRequestTooLarge, got %v", err)
	}
}

/* Sanitize CR and LF before logging addresses. */
func TestSanitizeLogValue(t *testing.T) {
	got := sanitizeLogValue("127.0.0.1\r\n127.0.0.1")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitizeLogValue did not escape newline characters: %q", got)
	}
	if !strings.Contains(got, "\\r") || !strings.Contains(got, "\\n") {
		t.Fatalf("sanitizeLogValue did not preserve escaped sequences: %q", got)
	}
}

/* Reject empty listen addresses as invalid configuration. */
func TestValidateConfigRejectsMissingListenAddr(t *testing.T) {
	if err := validateConfig(Config{
		ServerPEM: "server.crt",
		ServerKey: "server.key",
	}); err == nil || err.Error() != "listen_addr is required" {
		t.Fatalf("expected listen_addr validation error, got %v", err)
	}
}

type testConn struct {
	readData  []byte
	readPos   int
	writeData bytes.Buffer

	writeChunk int
	writeErr   error
	closed     bool
}

func (c *testConn) Read(p []byte) (int, error) {
	if c.readPos >= len(c.readData) {
		return 0, io.EOF
	}
	n := copy(p, c.readData[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *testConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}

	if c.writeErr != nil {
		n := len(p)
		if c.writeChunk > 0 && c.writeChunk < n {
			n = c.writeChunk
		}
		written, _ := c.writeData.Write(p[:n])
		if c.writeChunk > 0 {
			return written, c.writeErr
		}
	}

	return c.writeData.Write(p)
}

func (c *testConn) Close() error {
	c.closed = true
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *testConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *testConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string {
	return string(d)
}

func (d dummyAddr) String() string {
	return string(d)
}
