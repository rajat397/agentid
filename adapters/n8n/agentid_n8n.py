"""Generate an importable n8n sub-workflow that gates a tool call.

Import the JSON, publish the workflow, connect the IF true output to the real
tool node, and attach the sub-workflow to an AI Agent with Call n8n Workflow
Tool. The decision service at /v1/pre-tool owns authority mapping; the
workflow contains no credentials.
"""


def build_workflow(endpoint, tool_name):
    endpoint = endpoint.rstrip("/")
    return {
        "name": f"agentid-gate-{tool_name}",
        "nodes": [
            {
                "parameters": {}, "id": "1", "name": "Execute Workflow Trigger",
                "type": "n8n-nodes-base.executeWorkflowTrigger", "typeVersion": 1,
                "position": [0, 0],
            },
            {
                "parameters": {
                    "method": "POST",
                    "url": f"{endpoint}/v1/pre-tool",
                    "sendBody": True,
                    "contentType": "json",
                    "bodyParameters": {
                        "parameters": [
                            {"name": "tool_name", "value": tool_name},
                            {"name": "tool_input", "value": "={{ $json }}"},
                        ]
                    },
                    "options": {},
                },
                "id": "2", "name": "agentid pre-tool",
                "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2,
                "position": [220, 0],
            },
            {
                "parameters": {
                    "conditions": {
                        "options": {"version": 2},
                        "conditions": [{
                            "leftValue": "={{ $json.allow }}",
                            "rightValue": True,
                            "operator": {"type": "boolean", "operation": "true"},
                        }],
                        "combinator": "and",
                    },
                    "options": {},
                },
                "id": "3", "name": "If allowed",
                "type": "n8n-nodes-base.if", "typeVersion": 2.2,
                "position": [440, 0],
            },
            {
                "parameters": {
                    "errorMessage": "=agentid blocked the tool call: {{ $json.reason }} receipt={{ $json.receipt_id }} approval={{ $json.approval_request_id }}",
                },
                "id": "4", "name": "Stop And Error",
                "type": "n8n-nodes-base.stopAndError", "typeVersion": 1,
                "position": [660, 120],
            },
        ],
        "connections": {
            "Execute Workflow Trigger": {
                "main": [[{"node": "agentid pre-tool", "type": "main", "index": 0}]]
            },
            "agentid pre-tool": {
                "main": [[{"node": "If allowed", "type": "main", "index": 0}]]
            },
            "If allowed": {
                "main": [
                    [],
                    [{"node": "Stop And Error", "type": "main", "index": 0}],
                ]
            },
        },
        "settings": {},
    }
