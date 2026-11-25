import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentid_crewai import AgentIDPreToolHook, HookAborted, decide


class FakeContext:
    tool_name = "purchase"
    tool_input = {"amount": "100.00"}


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


class TestCrewAIAdapter(unittest.TestCase):
    def test_allow_returns_none(self):
        server = FakeServer({"allow": True, "receipt_id": "rcp_1"})
        endpoint = server.start()
        try:
            self.assertIsNone(AgentIDPreToolHook(endpoint)(FakeContext()))
            self.assertEqual(server.received[0]["tool_name"], "purchase")
        finally:
            server.stop()

    def test_deny_raises_hook_aborted(self):
        server = FakeServer({"allow": False, "receipt_id": "rcp_2", "reason": "over cap"})
        endpoint = server.start()
        try:
            with self.assertRaises(HookAborted) as context:
                AgentIDPreToolHook(endpoint)(FakeContext())
            self.assertIn("rcp_2", str(context.exception))
        finally:
            server.stop()

    def test_unavailable_service_fails_closed(self):
        hook = AgentIDPreToolHook("http://127.0.0.1:1", timeout=0.2)
        with self.assertRaises(HookAborted):
            hook(FakeContext())

    def test_malformed_response_fails_closed(self):
        server = FakeServer({"unexpected": True})
        endpoint = server.start()
        try:
            self.assertFalse(decide(endpoint, "purchase", {"amount": "10"})["allow"])
            with self.assertRaises(HookAborted):
                AgentIDPreToolHook(endpoint)(FakeContext())
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
