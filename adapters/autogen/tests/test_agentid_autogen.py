import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentid_autogen import AgentIDInterventionHandler, ToolException, decide


class FakeMessage:
    name = "purchase"
    arguments = {"amount": "100.00"}
    id = "call_1"


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


def send(handler, message):
    return asyncio.run(handler.on_send(message, message_context=object(), recipient="tool_agent"))


class TestAutoGenAdapter(unittest.TestCase):
    def test_allow_returns_message(self):
        server = FakeServer({"allow": True, "receipt_id": "rcp_1"})
        endpoint = server.start()
        try:
            message = FakeMessage()
            result = send(AgentIDInterventionHandler(endpoint), message)
            self.assertIs(result, message)
            self.assertEqual(server.received[0]["tool_name"], "purchase")
        finally:
            server.stop()

    def test_deny_raises_tool_exception(self):
        server = FakeServer({"allow": False, "receipt_id": "rcp_2", "reason": "over cap"})
        endpoint = server.start()
        try:
            with self.assertRaises(ToolException) as context:
                send(AgentIDInterventionHandler(endpoint), FakeMessage())
            self.assertIn("rcp_2", str(context.exception))
        finally:
            server.stop()

    def test_unavailable_fails_closed(self):
        with self.assertRaises(ToolException):
            send(AgentIDInterventionHandler("http://127.0.0.1:1", timeout=0.2), FakeMessage())

    def test_malformed_response_fails_closed(self):
        server = FakeServer({"unexpected": True})
        endpoint = server.start()
        try:
            self.assertFalse(decide(endpoint, "purchase", {"amount": "10"})["allow"])
            with self.assertRaises(ToolException):
                send(AgentIDInterventionHandler(endpoint), FakeMessage())
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
