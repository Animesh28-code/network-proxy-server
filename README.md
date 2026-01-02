# Design and Implementation of a Custom Network Proxy Server

## Overview
This project implements a TCP-based HTTP forward proxy server. The proxy accepts client
connections, parses HTTP requests, applies domain-based filtering rules, forwards allowed
requests to destination servers, and relays responses back to clients. Blocked requests are
rejected with HTTP 403 Forbidden and logged.

## Features
- HTTP forward proxy over TCP
- Concurrent client handling (thread-per-connection)
- Domain/IP-based blocking using configuration file
- Streaming request/response forwarding
- Request logging with timestamps

## Project Structure
```
proxy-project/
├── src/
│   └── proxy.py
├── config/
│   └── blocked_domains.txt
├── logs/
│   └── proxy.log
└── README.md
```
## How to Run

### 1. Start the proxy server
```bash
python src/proxy.py
```

The proxy listens on:
```
127.0.0.1:8888
```

### 2. Test the proxy (Windows)
```powershell
curl.exe -x http://127.0.0.1:8888 http://example.com
```

### 3. Blocking test
Add a domain to:
```
config/blocked_domains.txt
```

Example:
```
example.com
```

Then run:
```powershell
curl.exe -x http://127.0.0.1:8888 http://example.com
```

Expected output:
```
403 Forbidden
```
## Logging
All proxy activity is logged in `logs/proxy.log`.

Each log entry includes:
- Timestamp
- Client IP and port
- Destination host and port
- Action (allowed / blocked)
- HTTP status code
- Bytes transferred

Example log entry:
```
2026-01-02T19:22:32Z client=127.0.0.1:53456 dest=example.com:80 action=blocked status=403
```
## Limitations
- HTTPS CONNECT tunneling is not implemented
- Chunked transfer encoding is not explicitly parsed
- Persistent HTTP connections are not supported
