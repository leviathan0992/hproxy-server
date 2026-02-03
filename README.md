# hproxy-server

A lightweight, secure HTTPS Proxy Server implementation in Golang.

This project provides a standard HTTP/1.1 `CONNECT` proxy server designed for secure network tunneling. It enforces **mTLS (Mutual TLS)** authentication with optional HTTP Basic Auth, ensuring that only authorized clients can establish connections. 

This tool is suitable for zero-trust network access, secure internal infrastructure exposure, or private tunneling requirements.

```
 --------------                                  -----------------
|              |                                |                 |
|  HTTP Client |       HTTPS (mTLS)             |  hproxy-server  |
| (curl/Browser) --------------------------->  |                 |
|              |                                |                 |
 --------------                                  -----------------
```

## Features

- **Standard Compliant**: Full support for RFC 7231 HTTP/1.1 `CONNECT` tunneling.
- **Secure by Design**: Enforced mTLS authentication + optional username/password.
- **Minimalist**: Single binary, zero dependencies, built on Go standard library.
- **Production Ready**: OOM protection, graceful shutdown, atomic counters.

## Quick Start

### 1. Build

```bash
go build .
```

### 2. Configuration

Edit `hproxy.json`:
```json
{
    "listen_addr": "0.0.0.0:443",
    "server_pem": "/path/to/server.crt",
    "server_key": "/path/to/server.key",
    "client_pem": "/path/to/client.pem",
    "auth_users": {
        "your-username": "your-secure-password"
    }
}
```

| Field | Description |
|-------|-------------|
| `listen_addr` | Address and port to listen on |
| `server_pem` | Server certificate (PEM format) |
| `server_key` | Server private key |
| `client_pem` | CA certificate for verifying client certs |
| `auth_users` | (Optional) Username/password pairs for HTTP Basic Auth |

### 3. Run

```bash
./hproxy-server -c hproxy.json
```

## Docker Quick Start

You can quickly launch a containerized instance using our `fast.sh` script:

```bash
# Pull and run hproxy container
fast run --image hproxy --run-as leviathan

# If using a private image or GHCR:
fast run --token [GITHUB_TOKEN] --image hproxy --run-as leviathan
```

This will automatically pull the image, handle configurations, and start the server.

## Client Configuration

### Using cURL

```bash
curl -v https://example.com \
  --proxy https://your-server:443 \
  --proxy-cert client.crt \
  --proxy-key client.key \
  --proxy-cacert ca.crt \
  --proxy-user alice:your-secure-password
```

### Using Mobile/Desktop Clients

Any client that supports "HTTPS Proxy" with client certificate authentication can be used:

- **Protocol**: HTTPS
- **Authentication**: Client Certificate (mTLS) + Basic Auth
- **Certificate**: Import your client certificate and private key
- **Username/Password**: As configured in `auth_users`

## Log Format

```
[SYSTEM]       Server startup/shutdown messages
[CONNECT]      Successful tunnel establishment
[DISCONNECT]   Tunnel closed with traffic stats (Tx/Rx bytes)
[CERT-ERROR]   Client certificate validation failed
[AUTH-REQUIRED] Missing credentials
[AUTH-FAILED]  Invalid username or password
[DIAL-ERROR]   Failed to connect to target host
[TLS-ERROR]    Other TLS handshake errors
```

## Security Features

- **mTLS Enforcement**: Clients must present a valid certificate signed by the configured CA.
- **OOM Protection**: HTTP handshake limited to 16KB to prevent memory exhaustion.
- **Log Sanitization**: Target addresses are filtered to prevent log injection attacks.
- **Graceful Shutdown**: Handles SIGINT/SIGTERM for clean connection termination.

## License

Apache-2.0
