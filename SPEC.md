# User Directed Development Proxy Spec

## Specification State

- proxy_type: HTTP/HTTPS forward proxy [USER, CONFIRMED]
- access_scope: local PC only, bind to localhost [USER, CONFIRMED]
- https_handling: certificate-based MITM [USER, CONFIRMED]
- ca_registration: register the local CA in the Windows trust store automatically [USER, CONFIRMED]
- ca_cleanup_policy: remove the registered CA on Ctrl+C, normal exit, process exit, internal shutdown, and handled crash errors; provide separate cleanup for power loss, forced process kill, and Task Manager termination recovery [USER, CONFIRMED]

## Implementation State

- unit_ca_lifecycle:
  - status: COMPLETE
  - responsibility: generate a local MITM CA, register it in the Windows CurrentUser Root store, remove it during handled shutdown, and expose cleanup for stale CA state
  - files: `proxy_ca.py`, `requirements.txt`
- unit_forward_proxy_core: localhost-only HTTP forward proxy request handling.
  - status: COMPLETE
  - responsibility: accept local HTTP proxy requests with absolute `http://` targets and forward them upstream without HTTPS MITM.
  - files: `proxy_server.py`
- unit_connect_mitm:
  - status: COMPLETE
  - responsibility: intercept CONNECT, generate per-host leaf certificates signed by the local CA, wrap the client side in TLS, and forward decrypted HTTP requests to the upstream HTTPS server.
  - files: `proxy_ca.py`, `proxy_server.py`
- unit_proxy_cli:
  - status: COMPLETE
  - responsibility: provide one command that registers the CA, runs the local proxy, removes the CA on handled shutdown, and exposes cleanup for stale trust entries.
  - files: `main.py`, `README.md`

## Pending Units
