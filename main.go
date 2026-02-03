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
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	ServerPEM  string            `json:"server_pem"`
	ServerKey  string            `json:"server_key"`
	ClientPEM  string            `json:"client_pem"`
	ListenAddr string            `json:"listen_addr"`
	AuthUsers  map[string]string `json:"auth_users,omitempty"`
}

type Server struct {
	serverPEM string
	serverKEY string
	clientPEM string
	authUsers map[string]string
}

func NewServer(serverPEM string, serverKEY string, clientPEM string, authUsers map[string]string) *Server {
	return &Server{
		serverPEM: serverPEM,
		serverKEY: serverKEY,
		clientPEM: clientPEM,
		authUsers: authUsers,
	}
}

/* handleClient processes a single client connection. */
func (s *Server) handleClient(conn net.Conn) {
	/*
	 * Capture client address early.
	 * This ensures we have a stable string for logging even after connection closure.
	 */
	clientAddr := conn.RemoteAddr().String()

	/*
	 * Ensure connection is closed and log disconnection.
	 */
	defer func() {
		conn.Close()
	}()

	/*
	 * Perform TLS handshake manually.
	 * This allows us to catch handshake errors (like EOF from scanners)
	 * and verify the certificate without spamming logs.
	 */
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		/* Specific check for mTLS client certificate errors. */
		errMsg := err.Error()
		if strings.Contains(errMsg, "unknown certificate") || strings.Contains(errMsg, "bad certificate") {
			log.Printf("[CERT-ERROR] %s: Client certificate rejected/missing", clientAddr)
		} else if err != io.EOF && !strings.Contains(errMsg, "handshake failure") {
			log.Printf("[TLS-ERROR] %s: %v", clientAddr, err)
		}
		return
	}

	/* Use bufio to read the HTTP request line. */
	reader := bufio.NewReader(conn)

	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	/* Parse headers to extract Proxy-Authorization (case-insensitive). */
	var proxyAuth string
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}

		/* Check for Proxy-Authorization header (case-insensitive). */
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "proxy-authorization:") {
			proxyAuth = strings.TrimSpace(line[len("proxy-authorization:"):])
		}
	}

	/* Validate auth if enabled. */
	if len(s.authUsers) > 0 {
		if !s.validateAuth(proxyAuth) {
			if proxyAuth == "" {
				log.Printf("[AUTH-REQUIRED] %s: Missing credentials", clientAddr)
			} else {
				log.Printf("[AUTH-FAILED] %s: Invalid username or password", clientAddr)
			}
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"HProxy\"\r\n\r\n"))
			return
		}
	}

	/* Parse "CONNECT host:port HTTP/1.1" */
	parts := strings.Split(strings.TrimSpace(reqLine), " ")
	if len(parts) < 2 || parts[0] != "CONNECT" {
		/* Not a CONNECT request. Return 400 Bad Request. */
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	targetAddr := parts[1]

	/* Dial the target. */
	destConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[DIAL-ERROR] %s -> %s: %v", clientAddr, targetAddr, err)
		/* Reply 503 if dial fails */
		conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}
	defer destConn.Close()

	/* Reply 200 OK to establish the tunnel. */
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	/* Log success. */
	log.Printf("[CONNECT] %s -> %s", clientAddr, targetAddr)

	/* Track traffic stats atomically. */
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
		atomic.StoreInt64(&rx, n)
		destConn.Close()
	}()

	go func() {
		defer wg.Done()
		/* Downlink: Target -> Client */
		n, _ := Transfer(conn, destConn)
		atomic.StoreInt64(&tx, n)
		conn.Close()
	}()

	wg.Wait()
	log.Printf("[DISCONNECT] %s -> %s (Tx: %d, Rx: %d)", clientAddr, targetAddr, atomic.LoadInt64(&tx), atomic.LoadInt64(&rx))
}

/* validateAuth checks HTTP Basic Authentication credentials. */
func (s *Server) validateAuth(authHeader string) bool {
	if authHeader == "" {
		return false
	}

	/* Parse "Basic base64(username:password)" */
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	/* Decode Base64. */
	encoded := strings.TrimPrefix(authHeader, prefix)
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

func (s *Server) ListenAndServe(addr string) error {
	/* Load keys and certs same as before... */
	cert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKEY)
	if err != nil {
		return errors.New("failed to load server certificate and key: " + err.Error())
	}

	certBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		return errors.New("failed to read client CA file: " + err.Error())
	}

	clientCertPool := x509.NewCertPool()
	if ok := clientCertPool.AppendCertsFromPEM(certBytes); !ok {
		return errors.New("failed to parse client CA certificates")
	}

	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientCertPool,
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}

	log.Printf("[SYSTEM] Server listening on %s (mTLS Enabled)", addr)

	/* Setup graceful shutdown. */
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("[SYSTEM] Received shutdown signal, closing listener...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			/* Check if it's a shutdown-induced error. */
			if strings.Contains(err.Error(), "use of closed network connection") {
				log.Println("[SYSTEM] Server shutdown complete.")
				return nil
			}
			log.Printf("[SYSTEM] Accept error: %v", err)
			continue
		}

		go s.handleClient(conn)
	}
}

/* Helper to adapt bufio.Reader to net.Conn for Transfer */
type ReaderConn struct {
	io.Reader
	net.Conn
}

func (r ReaderConn) Read(p []byte) (n int, err error) {
	return r.Reader.Read(p)
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

	s := NewServer(config.ServerPEM, config.ServerKey, config.ClientPEM, config.AuthUsers)

	if err := s.ListenAndServe(config.ListenAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
