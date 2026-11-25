import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentid_adk import AgentIDBeforeToolCallback, decide


class FakeTool:
    name = "purchase"


class FakeServer:
    def __init__(self, response):
        self.response = response
        self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(inner):
                length = int(inner.headers.get("Content-Length", "0"))
                self.received.append(json.loads(inner.rfile.read(length)))
                inner.send_response(200)
                inner.send_header("Content-Type", "application/json")
                inner.end_rows = None
                inner.end_headers()
                inner.wfile.write(json.dumps(self.response).encode())

            def log_message(inner, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class TestADKAdapter(unittest.TestCase):
    def test_allow_returns_none(self):
        server = FakeServer({"allow": True, "receipt_id": "rcp_1"})
        endpoint = server.start()
        try:
            callback = AgentIDBeforeToolCallback(endpoint)
            self.assertIsNone(callback(FakeTool(), {"amount": "100.00"}, object()))
            self.assertEqual(server.received[0]["tool_name"], "purchase")
        finally:
            server.stop()

    def test_deny_returns_truthy_short_circuit(self):
        server = FakeServer({"allow": False, "receipt_id": "rcp_2", "reason": "over cap"})
        endpoint = server.start()
        try:
            result = AgentIDBeforeToolCallback(endpoint)(
                FakeTool(), {"amount": "5000.00"}, object()
            )
            self.assertIsInstance(result, dict)
            self.assertIn("rcp_2", result["result"])
        finally:
            server.stop()

    def test_unavailable_fails_closed(self):
        callback = AgentIDBeforeToolCallback("http://127.0.0.1:1", timeout=0.2)
        result = callback(FakeTool(), {"amount": "10.00"}, object())
        self.assertIsInstance(result, dict)
        self.assertIn("blocked", result["result"])

    def test_malformed_response_fails_closed(self):
        server = FakeServer({"unexpected": True})
        endpoint = server.start()
        try:
            self.assertFalse(decide(endpoint, "purchase", {"amount": "10"})["allow"])
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
