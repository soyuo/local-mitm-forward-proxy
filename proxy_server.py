from __future__ import annotations

import argparse
import http.client
import ssl
import socketserver
from http.server import BaseHTTPRequestHandler
from typing import Iterable
from urllib.parse import SplitResult, urlsplit

from proxy_ca import ensure_leaf_certificate


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class LocalOnlyThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ForwardProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "UDDForwardProxy/0.1"
    mitm_host: str | None = None
    mitm_port: int | None = None

    def do_CONNECT(self) -> None:
        host, port = self._parse_connect_target()
        if not host:
            self.send_error(400, "Expected CONNECT host:port")
            return

        try:
            cert_path, key_path = ensure_leaf_certificate(host)
        except Exception as exc:
            self.send_error(500, f"Could not prepare MITM certificate: {exc}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        try:
            tls_socket = context.wrap_socket(self.connection, server_side=True)
        except ssl.SSLError:
            self.close_connection = True
            return

        self.connection = tls_socket
        self.rfile = tls_socket.makefile("rb", self.rbufsize)
        self.wfile = tls_socket.makefile("wb", self.wbufsize)
        self.mitm_host = host
        self.mitm_port = port
        self.close_connection = False

        self.handle_one_request()
        self.close_connection = True

    def do_GET(self) -> None:
        self._proxy_http_request()

    def do_HEAD(self) -> None:
        self._proxy_http_request()

    def do_POST(self) -> None:
        self._proxy_http_request()

    def do_PUT(self) -> None:
        self._proxy_http_request()

    def do_PATCH(self) -> None:
        self._proxy_http_request()

    def do_DELETE(self) -> None:
        self._proxy_http_request()

    def do_OPTIONS(self) -> None:
        self._proxy_http_request()

    def _proxy_http_request(self) -> None:
        if self.mitm_host:
            target_host = self.mitm_host
            target_port = self.mitm_port or 443
            path = self.path
            use_https = True
        else:
            target = urlsplit(self.path)
            if target.scheme.lower() != "http" or not target.hostname:
                self.send_error(400, "Expected an absolute http:// proxy request target")
                return
            target_host = target.hostname
            target_port = target.port or 80
            path = self._origin_form_path(target)
            use_https = False

        body = self._read_request_body()
        if body is False:
            return
        headers = self._forward_headers(target_host)

        connection_class = http.client.HTTPSConnection if use_https else http.client.HTTPConnection
        connection = connection_class(
            target_host,
            target_port,
            timeout=30,
        )
        try:
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            self._send_response(response)
        except TimeoutError:
            self.send_error(504, "Upstream request timed out")
        except OSError as exc:
            self.send_error(502, f"Upstream request failed: {exc}")
        finally:
            connection.close()

    def _read_request_body(self) -> bytes | None | bool:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self.send_error(501, "Chunked request bodies are not implemented yet")
            return False

        length = self.headers.get("Content-Length")
        if not length:
            return None
        try:
            body_length = int(length)
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return False
        return self.rfile.read(body_length)

    def _forward_headers(self, target_host: str) -> dict[str, str]:
        headers = {}
        for name, value in self.headers.items():
            if name.lower() not in HOP_BY_HOP_HEADERS:
                headers[name] = value
        headers["Host"] = self.headers.get("Host", target_host)
        headers["Connection"] = "close"
        return headers

    def _send_response(self, response: http.client.HTTPResponse) -> None:
        self.send_response(response.status, response.reason)
        for name, value in response.getheaders():
            if name.lower() not in HOP_BY_HOP_HEADERS:
                self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        if self.command != "HEAD":
            self._copy_response_body(response)

    def _copy_response_body(self, response: http.client.HTTPResponse) -> None:
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            self.wfile.write(chunk)

    @staticmethod
    def _origin_form_path(target: SplitResult) -> str:
        path = target.path or "/"
        if target.query:
            path += f"?{target.query}"
        return path

    def _parse_connect_target(self) -> tuple[str | None, int]:
        if ":" not in self.path:
            return None, 443
        host, port_text = self.path.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return None, 443
        return host.strip("[]"), port

    def log_message(self, format: str, *args: object) -> None:
        client_ip = self.client_address[0]
        if client_ip not in ("127.0.0.1", "::1"):
            return
        super().log_message(format, *args)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("This proxy is local-only; bind to 127.0.0.1, localhost, or ::1.")

    with LocalOnlyThreadingServer((host, port), ForwardProxyHandler) as server:
        actual_host, actual_port = server.server_address
        print(f"HTTP forward proxy listening on {actual_host}:{actual_port}")
        server.serve_forever()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local-only forward proxy.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)

    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        print("Proxy stopped.")
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
