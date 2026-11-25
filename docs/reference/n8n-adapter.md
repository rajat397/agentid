# n8n adapter — importable gate sub-workflow

Generate and import a sub-workflow:

```python
from agentid_n8n import build_workflow
print(json.dumps(build_workflow("http://127.0.0.1:8092", "purchase")))
```

In n8n: import the JSON, publish the workflow, connect the IF true output to
the real tool node, then attach the sub-workflow to the AI Agent with
**Call n8n Workflow Tool**. The IF false output ends at Stop And Error, so a
denied call never reaches the tool.

The HTTP Request node posts `tool_name` and the trigger payload to the local
decision service. Authority fields are resolved server-side from operator
config; the workflow carries no credentials. Credentials for the downstream
tool remain in the n8n instance, as usual.

Adversarial tests check the importable skeleton, the pre-tool URL and body,
the deny branch, and absence of inline credentials.
