import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentid_langchain import AgentIDDenied, AgentIDMiddleware, decide


class FakeRequest:
    def __init__(self, name, args):
        self.tool_call = {"name": name, "args": args}


class HandlerServer:
    def __init__(self, response):
        self.response = response
        self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(inner):
                length = int(inner.headers.get("Content-Length", "0"))
                body = inner.rfile.read(length)
                self.received.append(json.loads(body))
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


class TestLangChainAdapter(unittest.TestCase):
    def test_allow_calls_handler_once(self):
        server = HandlerServer({"allow": True, "receipt_id": "rcp_1"})
        endpoint = server.start()
        try:
            calls = []
            middleware = AgentIDMiddleware(endpoint)
            result = middleware.wrap_tool_call(
                FakeRequest("purchase", {"amount": "100.00"}),
                lambda request: calls.append(request) or "ok",
            )
            self.assertEqual(result, "ok")
            self.assertEqual(len(calls), 1)
            self.assertEqual(server.received[0]["tool_name"], "purchase")
        finally:
            server.stop()

    def test_deny_never_calls_handler(self):
        server = HandlerServer({
            "allow": False, "receipt_id": "rcp_2", "reason": "over cap",
        })
        endpoint = server.start()
        try:
            calls = []
            middleware = AgentIDMiddleware(endpoint)
            with self.assertRaises(AgentIDDenied) as context:
                middleware.wrap_tool_call(
                    FakeRequest("purchase", {"amount": "5000.00"}),
                    lambda request: calls.append(request) or "ok",
                )
            self.assertIn("rcp_2", str(context.exception))
            self.assertEqual(calls, [])
        finally:
            server.stop()

    def test_unavailable_service_fails_closed(self):
        middleware = AgentIDMiddleware("http://127.0.0.1:1", timeout=0.2)
        calls = []
        with self.assertRaises(AgentIDDenied):
            middleware.wrap_tool_call(
                FakeRequest("purchase", {"amount": "10.00"}),
                lambda request: calls.append(request) or "ok",
            )
        self.assertEqual(calls, [])

    def test_malformed_response_fails_closed(self):
        server = HandlerServer({"unexpected": True})
        endpoint = server.start()
        try:
            decision = decide(endpoint, "purchase", {"amount": "10.00"})
            self.assertFalse(decision["allow"])
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
