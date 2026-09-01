# Local MITM Forward Proxy

Python-based local-only HTTP/HTTPS forward proxy for development.

## Setup

```powershell
pip install -r requirements.txt
```

## Run

```powershell
python main.py run --port 8080
```

Configure your browser or client to use:

```text
HTTP proxy: 127.0.0.1
Port: 8080
```

The proxy registers a local CA in the Windows CurrentUser Root store while it is running and removes it during handled shutdown.

## Cleanup

Use this after forced termination, Task Manager termination, power loss, or any case where the process could not run shutdown cleanup:

```powershell
python main.py cleanup
```

## Current Limits

- Local use only.
- HTTP/1.1 request forwarding.
- HTTPS is intercepted through CONNECT and a generated per-host certificate.
- Chunked request bodies are rejected.
- Each proxied response closes the connection.
