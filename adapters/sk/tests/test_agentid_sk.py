import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentid_sk import agentid_filter, decide


class FakeFunction:
    plugin_name = "ads"
    name = "purchase"


class FakeContext:
    function = FakeFunction()
    arguments = {"amount": "100.00"}
    result = None


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


def run_filter(filter_fn, context):
    calls = []

    async def next_fn(ctx):
        calls.append(ctx)

    asyncio.run(filter_fn(context, next_fn))
    return calls


class TestSKAdapter(unittest.TestCase):
    def test_allow_calls_next(self):
        server = FakeServer({"allow": True, "receipt_id": "rcp_1"})
        endpoint = server.start()
        try:
            context = FakeContext()
            calls = run_filter(agentid_filter(endpoint), context)
            self.assertEqual(len(calls), 1)
            self.assertEqual(server.received[0]["tool_name"], "purchase")
        finally:
            server.stop()

    def test_deny_does_not_call_next_and_sets_result(self):
        server = FakeServer({"allow": False, "receipt_id": "rcp_2", "reason": "over cap"})
        endpoint = server.start()
        try:
            context = FakeContext()
            calls = run_filter(agentid_filter(endpoint), context)
            self.assertEqual(calls, [])
            self.assertIn("rcp_2", context.result)
        finally:
            server.stop()

    def test_unavailable_fails_closed(self):
        context = FakeContext()
        calls = run_filter(agentid_filter("http://127.0.0.1:1", timeout=0.2), context)
        self.assertEqual(calls, [])
        self.assertIn("blocked", context.result)

    def test_malformed_response_fails_closed(self):
        server = FakeServer({"unexpected": True})
        endpoint = server.start()
        try:
            self.assertFalse(decide(endpoint, "purchase", {"amount": "10"})["allow"])
            context = FakeContext()
            self.assertEqual(run_filter(agentid_filter(endpoint), context), [])
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
