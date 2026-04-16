package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	ServerPEM string `json:"server_pem"`
	ServerKey string `json:"server_key"`
	ClientPEM string `json:"client_pem"`
	/* Use a pointer to distinguish between `false` and missing `mtls` field. */
	MTLS       *bool             `json:"mtls,omitempty"`
	ListenAddr string            `json:"listen_addr"`
	AuthUsers  map[string]string `json:"auth_users,omitempty"`
}

type Server struct {
	serverPEM string
	serverKEY string
	clientPEM string
	mtls      bool
	authUsers map[string]string
}

const (
	requestHeaderLimit   = 16 * 1024
	handshakeTimeout     = 10 * time.Second
	requestReadTimeout   = 5 * time.Second
	responseWriteTimeout = 5 * time.Second
	targetDialTimeout    = 10 * time.Second
)

var (
	errRequestTooLarge   = errors.New("request headers too large")
	errBadConnectRequest = errors.New("malformed CONNECT request")
	logValueSanitizer    = strings.NewReplacer(
		"\r", `\\r`,
		"\n", `\\n`,
	)
)

/* Create a server instance with TLS, authentication, and certificate settings. */
func NewServer(serverPEM string, serverKEY string, clientPEM string, mtls bool, authUsers map[string]string) *Server {
	return &Server{
		serverPEM: serverPEM,
		serverKEY: serverKEY,
		clientPEM: clientPEM,
		mtls:      mtls,
		authUsers: authUsers,
	}
}

/* Process one client connection end to end. */
func (s *Server) handleClient(conn net.Conn) {
	/* Capture client address early. */
	clientAddr := sanitizeLogValue(conn.RemoteAddr().String())

	/*
	 * Ensure connection is closed and log disconnection.
	 */
	defer conn.Close()

	/*
	 * Perform TLS handshake manually.
	 * This allows us to catch handshake errors and verify certificates without spamming logs.
	 */
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "unknown certificate") ||
			strings.Contains(errMsg, "bad certificate") ||
			strings.Contains(errMsg, "certificate required") {
			log.Printf("[CERT-ERROR] %s: Client certificate rejected/missing", clientAddr)
		} else if !strings.Contains(errMsg, "handshake failure") && !strings.Contains(errMsg, "EOF") {
			log.Printf("[TLS-ERROR] %s: %v", clientAddr, err)
		}
		return
	}
	_ = tlsConn.SetReadDeadline(time.Time{})

	/* Parse CONNECT request and proxy auth header. */
	_ = tlsConn.SetReadDeadline(time.Now().Add(requestReadTimeout))
	reader := bufio.NewReaderSize(conn, requestHeaderLimit)
	targetAddr, proxyAuth, err := readConnectRequest(reader)
	_ = tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		switch {
		case errors.Is(err, errRequestTooLarge):
			_, _ = writeResponse(conn, "HTTP/1.1 413 Request Entity Too Large\r\n\r\n")
		case errors.Is(err, errBadConnectRequest) || errors.Is(err, io.EOF):
			_, _ = writeResponse(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		default:
			log.Printf("[REQUEST-ERROR] %s: %v", clientAddr, err)
			_, _ = writeResponse(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		}
		return
	}
	targetAddrLog := sanitizeLogValue(targetAddr)

	/* Validate auth if enabled. */
	if len(s.authUsers) > 0 {
		if !s.validateAuth(proxyAuth) {
			if proxyAuth == "" {
				log.Printf("[AUTH-REQUIRED] %s: Missing credentials", clientAddr)
			} else {
				log.Printf("[AUTH-FAILED] %s: Invalid username or password", clientAddr)
			}
			_, _ = writeResponse(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"HProxy\"\r\n\r\n")
			return
		}
	}

	/* Dial the target. */
	destConn, err := net.DialTimeout("tcp", targetAddr, targetDialTimeout)
	if err != nil {
		log.Printf("[DIAL-ERROR] %s -> %s: %v", clientAddr, targetAddrLog, err)
		/* Reply 503 if dial fails */
		_, _ = writeResponse(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
		return
	}
	defer destConn.Close()

	/* Reply 200 OK to establish the tunnel. */
	_, err = writeResponse(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		return
	}

	/* Log success. */
	log.Printf("[CONNECT] %s -> %s", clientAddr, targetAddrLog)

	/* Track traffic stats. */
	var tx, rx int64

	/* Start bidirectional transfer. */
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		/*
		 * Pass the buffered reader directly. bufio.Reader handles the transition
		 * from its internal buffer to the socket automatically.
		 */
		srcWrapper := &ReaderConn{
			Reader: reader,
			Conn:   conn,
		}
		/* Uplink: Client -> Target */
		n, _ := Transfer(destConn, srcWrapper)
		rx = n
		destConn.Close()
	}()

	go func() {
		defer wg.Done()
		/* Downlink: Target -> Client */
		n, _ := Transfer(conn, destConn)
		tx = n
		conn.Close()
	}()

	wg.Wait()
	log.Printf("[DISCONNECT] %s -> %s (Tx: %d, Rx: %d)", clientAddr, targetAddrLog, tx, rx)
}

/* Write an HTTP response and return the first write error, if any. */
func writeResponse(conn net.Conn, response string) (int, error) {
	_ = conn.SetWriteDeadline(time.Now().Add(responseWriteTimeout))
	wrote, err := conn.Write([]byte(response))
	_ = conn.SetWriteDeadline(time.Time{})
	return wrote, err
}

/* Verify an incoming Basic authorization header against configured credentials. */
func (s *Server) validateAuth(authHeader string) bool {
	if authHeader == "" {
		return false
	}

	/* Parse "Basic base64(username:password)" */
	const prefix = "Basic "
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return false
	}

	/* Decode Base64. */
	encoded := strings.TrimSpace(authHeader[len(prefix):])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	/* Split "username:password". */
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}

	username, password := parts[0], parts[1]

	/* Lookup user and verify password. */
	expectedPassword, exists := s.authUsers[username]
	return exists && expectedPassword == password
}

/* Parse and validate the CONNECT request line and headers. */
func readConnectRequest(reader *bufio.Reader) (string, string, error) {
	readBytes := 0
	nextLine := func() (string, error) {
		line, n, err := readRequestLine(reader, requestHeaderLimit-readBytes)
		readBytes += n
		if readBytes > requestHeaderLimit {
			return "", errRequestTooLarge
		}
		return line, err
	}

	requestLine, err := nextLine()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", "", errBadConnectRequest
		}
		return "", "", err
	}
	parts := strings.Fields(requestLine)
	if len(parts) != 3 || parts[0] != "CONNECT" || !strings.HasPrefix(parts[2], "HTTP/") {
		return "", "", errBadConnectRequest
	}

	targetAddr := parts[1]
	if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		return "", "", errBadConnectRequest
	}

	var proxyAuth string
	for {
		line, err := nextLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", "", errBadConnectRequest
			}
			return "", "", err
		}
		if line == "" {
			return targetAddr, proxyAuth, nil
		}

		headerName, headerValue, found := strings.Cut(line, ":")
		if !found {
			return "", "", errBadConnectRequest
		}
		headerName = strings.TrimSpace(headerName)
		if strings.EqualFold(headerName, "Proxy-Authorization") {
			proxyAuth = strings.TrimSpace(headerValue)
		}
	}
}

/* Read one request line with a hard size limit and return consumed bytes. */
func readRequestLine(reader *bufio.Reader, limit int) (string, int, error) {
	if limit <= 0 {
		return "", 0, errRequestTooLarge
	}

	var builder strings.Builder
	readBytes := 0

	for {
		part, err := reader.ReadSlice('\n')
		readBytes += len(part)
		if readBytes > limit {
			return "", readBytes, errRequestTooLarge
		}

		builder.Write(part)
		if err == nil {
			line := builder.String()
			line = strings.TrimSuffix(line, "\r\n")
			line = strings.TrimSuffix(line, "\n")
			return line, readBytes, nil
		}

		if errors.Is(err, io.EOF) {
			return "", readBytes, io.EOF
		}

		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		return "", readBytes, err
	}
}

/* Escape newlines in log fields to protect parser safety. */
func sanitizeLogValue(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	return logValueSanitizer.Replace(v)
}

/* Start the TLS listener and serve CONNECT tunnels until shutdown. */
func (s *Server) ListenAndServe(addr string) error {
	/* Load keys and certificates for server-side TLS. */
	cert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKEY)
	if err != nil {
		return errors.New("failed to load server certificate and key: " + err.Error())
	}

	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{cert},
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),
	}

	if s.mtls {
		certBytes, err := os.ReadFile(s.clientPEM)
		if err != nil {
			return errors.New("failed to read client CA file: " + err.Error())
		}

		clientCertPool := x509.NewCertPool()
		if ok := clientCertPool.AppendCertsFromPEM(certBytes); !ok {
			return errors.New("failed to parse client CA certificates")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = clientCertPool
		log.Printf("[SYSTEM] Server listening on %s (mTLS Enabled)", addr)
	} else {
		tlsConfig.ClientAuth = tls.NoClientCert
		log.Printf("[SYSTEM] Server listening on %s (mTLS Disabled)", addr)
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}

	/* Setup graceful shutdown via SIGINT/SIGTERM. */
	shutdown := make(chan struct{})
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		select {
		case <-sigChan:
			log.Println("[SYSTEM] Received shutdown signal, closing listener...")
			_ = listener.Close()
		case <-shutdown:
		}
	}()
	defer close(shutdown)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("[SYSTEM] Server shutdown complete.")
				return nil
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("[SYSTEM] Temporary accept error: %v", err)
				continue
			}

			log.Printf("[SYSTEM] Accept error: %v", err)
			return err
		}

		go s.handleClient(conn)
	}
}

/* Adapt a buffered reader into a net.Conn-compatible source type. */
type ReaderConn struct {
	io.Reader
	net.Conn
}

func (r ReaderConn) Read(p []byte) (n int, err error) {
	return r.Reader.Read(p)
}

func validateConfig(config Config) error {
	if config.ListenAddr == "" {
		return errors.New("listen_addr is required")
	}
	if config.ServerPEM == "" {
		return errors.New("server_pem is required")
	}
	if config.ServerKey == "" {
		return errors.New("server_key is required")
	}
	if config.MTLS != nil && *config.MTLS && config.ClientPEM == "" {
		return errors.New("client_pem is required when mtls is enabled")
	}
	return nil
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "c", "hproxy.json", "The configuration file.")
	flag.Parse()

	bytes, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("Failed to read configuration file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("Failed to parse configuration file: %v", err)
	}

	if err := validateConfig(config); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	mtlsEnabled := true
	if config.MTLS != nil {
		mtlsEnabled = *config.MTLS
	}

	s := NewServer(config.ServerPEM, config.ServerKey, config.ClientPEM, mtlsEnabled, config.AuthUsers)

	if err := s.ListenAndServe(config.ListenAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
