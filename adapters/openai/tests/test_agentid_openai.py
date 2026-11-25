import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentid_openai import ToolGuardrailFunctionOutput, agentid_tool_guardrail, decide


class FakeContext:
    tool_name = "purchase"
    tool_arguments = json.dumps({"amount": "100.00"})


class FakeData:
    context = FakeContext()


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


class TestOpenAIAdapter(unittest.TestCase):
    def test_allow(self):
        server = FakeServer({"allow": True, "receipt_id": "rcp_1"})
        endpoint = server.start()
        try:
            result = agentid_tool_guardrail(endpoint)(FakeData())
            self.assertEqual(result.behavior, "allow")
            self.assertEqual(server.received[0]["tool_name"], "purchase")
            self.assertEqual(server.received[0]["tool_input"], {"amount": "100.00"})
        finally:
            server.stop()

    def test_deny_rejects_content(self):
        server = FakeServer({"allow": False, "receipt_id": "rcp_2", "reason": "over cap"})
        endpoint = server.start()
        try:
            result = agentid_tool_guardrail(endpoint)(FakeData())
            self.assertEqual(result.behavior, "reject_content")
            self.assertIn("rcp_2", result.message)
        finally:
            server.stop()

    def test_unavailable_fails_closed(self):
        result = agentid_tool_guardrail("http://127.0.0.1:1", timeout=0.2)(FakeData())
        self.assertEqual(result.behavior, "reject_content")

    def test_malformed_response_fails_closed(self):
        server = FakeServer({"unexpected": True})
        endpoint = server.start()
        try:
            self.assertFalse(decide(endpoint, "purchase", {"amount": "10"})["allow"])
            self.assertEqual(agentid_tool_guardrail(endpoint)(FakeData()).behavior, "reject_content")
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
