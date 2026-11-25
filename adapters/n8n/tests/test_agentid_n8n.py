import json
import unittest

from agentid_n8n import build_workflow


class TestN8nWorkflow(unittest.TestCase):
    def test_workflow_is_importable_skeleton(self):
        workflow = build_workflow("http://127.0.0.1:8092", "purchase")
        self.assertEqual(workflow["name"], "agentid-gate-purchase")
        self.assertIn("nodes", workflow)
        self.assertIn("connections", workflow)
        self.assertIn("settings", workflow)

    def test_http_request_calls_pre_tool_with_tool_name_and_args(self):
        workflow = build_workflow("http://127.0.0.1:8092", "purchase")
        http = next(n for n in workflow["nodes"] if n["type"] == "n8n-nodes-base.httpRequest")
        self.assertEqual(http["parameters"]["url"], "http://127.0.0.1:8092/v1/pre-tool")
        body = json.dumps(http["parameters"]["bodyParameters"])
        self.assertIn("purchase", body)
        self.assertIn("{{ $json }}", body)

    def test_if_false_branch_stops_and_true_branch_is_open(self):
        workflow = build_workflow("http://127.0.0.1:8092", "purchase")
        connections = workflow["connections"]["If allowed"]["main"]
        self.assertEqual(connections[0], [])
        self.assertEqual(connections[1][0]["node"], "Stop And Error")

    def test_no_inline_credentials_or_secrets(self):
        workflow = build_workflow("http://127.0.0.1:8092", "purchase")
        data = json.dumps(workflow)
        self.assertNotIn("credential", data.lower())
        self.assertNotIn("api_key", data.lower())


if __name__ == "__main__":
    unittest.main()
