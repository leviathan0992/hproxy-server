# hproxy-server

A lightweight, secure HTTPS Proxy Server implementation in Golang.

This project provides a standard HTTP/1.1 `CONNECT` proxy server designed for secure network tunneling. It supports optional **mTLS (Mutual TLS)** authentication with optional HTTP Basic Auth so operators can choose the access controls they need.

This tool is suitable for zero-trust network access, secure internal infrastructure exposure, or private tunneling requirements.

```
 ----------------                                  -----------------
|                |                                |                 |
|  HTTP Client   |   HTTPS (optional mTLS)        |  hproxy-server  |
| (curl/Browser) | --------------------------->   |                 |
|                |                                |                 |
 ----------------                                  -----------------
```

## Features

- **Standard Compliant**: Full support for RFC 7231 HTTP/1.1 `CONNECT` tunneling.
- **Secure by Design**: Optional mTLS authentication + mandatory/optional HTTP Basic Auth.
- **Minimalist**: Single binary, zero dependencies, built on Go standard library.
- **Production Ready**: OOM protection, graceful shutdown, safe concurrent traffic accounting.

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
    "mtls": true,
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
| `client_pem` | CA certificate for verifying client certs (only if `mtls` is `true`) |
| `mtls` | (Optional) Enable/disable Client Certificate verification (Default: `true`) |
| `auth_users` | (Optional) Username/password pairs for HTTP Basic Auth |

### 3. Run

```bash
./hproxy-server -c hproxy.json
```

## Client Configuration

### Using cURL

The example below matches the sample config above (`mtls: true`). If you set
`mtls` to `false`, omit the client certificate flags.

```bash
curl -v https://example.com \
  --proxy https://your-server:443 \
  --proxy-cert client.crt \
  --proxy-key client.key \
  --proxy-cacert ca.crt \
  --proxy-user alice:your-secure-password
```

## Security Features

- **Optional mTLS**: Toggleable client certificate verification via the `mtls` config.
- **OOM Protection**: HTTP handshake limited to 16KB to prevent memory exhaustion.
- **Log Sanitization**: Target addresses are filtered to prevent log injection attacks.
- **Graceful Shutdown**: Handles SIGINT/SIGTERM by stopping new accepts and closing the listener.

## License

Apache-2.0
