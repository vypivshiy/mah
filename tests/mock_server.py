"""Mock HTTP server for testing updater network requests."""

from __future__ import annotations

import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer


class _MockHandler(BaseHTTPRequestHandler):
    mock_server: MockServer

    def do_GET(self) -> None:
        handler = self.mock_server.routes.get(self.path)
        if handler:
            handler(self)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format: str, *args: object) -> None:
        # Suppress standard logging to keep test output clean
        pass


class MockServer:
    """Threaded HTTP server for local integration testing."""

    def __init__(self) -> None:
        self.routes: dict[str, Callable[[BaseHTTPRequestHandler], None]] = {}
        self._server = HTTPServer(("127.0.0.1", 0), _MockHandler)
        _MockHandler.mock_server = self
        self.port: int = self._server.server_port
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def register_xml(self, path: str, xml_content: str, status: int = 200) -> None:
        data = xml_content.encode("utf-8")

        def handle(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(status)
            handler.send_header("Content-Type", "application/xml; charset=utf-8")
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)

        self.routes[path] = handle

    def register_bytes(
        self,
        path: str,
        content: bytes,
        status: int = 200,
        support_range: bool = True,
    ) -> None:
        def handle(handler: BaseHTTPRequestHandler) -> None:
            range_header = handler.headers.get("Range")
            if support_range and range_header and range_header.startswith("bytes="):
                # e.g., bytes=100-
                ranges = range_header[len("bytes=") :].split("-")
                start = int(ranges[0]) if ranges[0] else 0
                end = int(ranges[1]) if len(ranges) > 1 and ranges[1] else len(content) - 1
                if start >= len(content):
                    handler.send_response(416)
                    handler.send_header("Content-Range", f"bytes */{len(content)}")
                    handler.end_headers()
                    return
                chunk = content[start : end + 1]
                handler.send_response(206)
                handler.send_header("Content-Type", "application/octet-stream")
                handler.send_header("Content-Range", f"bytes {start}-{end}/{len(content)}")
                handler.send_header("Content-Length", str(len(chunk)))
                handler.end_headers()
                handler.wfile.write(chunk)
            else:
                handler.send_response(status)
                handler.send_header("Content-Type", "application/octet-stream")
                handler.send_header("Content-Length", str(len(content)))
                handler.end_headers()
                handler.wfile.write(content)

        self.routes[path] = handle

    def register_error(self, path: str, status: int = 500, message: str = "Error") -> None:
        body = message.encode("utf-8")

        def handle(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(status)
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)

        self.routes[path] = handle

    def register_abort(self, path: str, chunk_size: int = 100) -> None:
        def handle(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Type", "application/octet-stream")
            handler.send_header("Content-Length", "10000")
            handler.end_headers()
            try:
                handler.wfile.write(b"A" * chunk_size)
                handler.wfile.flush()
                handler.connection.close()
            except OSError:
                pass

        self.routes[path] = handle

