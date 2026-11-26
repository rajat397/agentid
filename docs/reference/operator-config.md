# Operator config

The operator config is JSON. It is validated before deployment and used by CLI commands that wrap a tool path.

## Example

```json
{
  "version": "v1",
  "mode": "enforce",
  "tools": [
    {
      "name": "purchase_ad_credit",
      "action": "ad.credit.purchase",
      "system": "meta-ads",
      "resource_type": "ad_credit_account",
      "allowed_args": ["amount", "currency"]
    }
  ],
  "delegations": "delegations.jsonl",
  "profile": "spec/validation-profile.example.json",
  "root_key": "keys/root.pem",
  "signer_key": "keys/signer.pem"
}
```

See [spec/operator-config.example.json](../../spec/operator-config.example.json).

## Fields

| Field | Meaning |
|---|---|
| `version` | Config schema version. Current value: `v1`. |
| `mode` | `enforce` or `shadow`. Empty defaults to `enforce`. |
| `tools` | Tool-name to action/system mapping. Authority fields come from here, never from tool arguments. |
| `allowed_args` | Agent-supplied argument names. Authority field names are rejected here. |
| `delegations`, `profile`, `root_key`, `signer_key` | Paths used by the wrapper to build the decision path. No secret value is stored in the config. |
| `status_token`, `status_keys`, `approval`, `fleet` | Optional operational inputs. |

## Validate

```bash
go run ./cmd/agentid config check --config spec/operator-config.example.json
```

The validator checks JSON shape, mode, tool mappings, duplicate tool names and attempted authority-field injection through `allowed_args`. It does not read referenced artifacts; startup paths still fail closed if referenced files are missing.

## Health

```bash
go run ./cmd/agentid health --config spec/operator-config.example.json
```

Output is canonical JSON:

```json
{"mode":"enforce","status":"ok","tools":1,"version":"dev"}
```

## Shadow mode

`mode: shadow` runs validation and mints proposed-verdict receipts but never denies and never blocks the call. The downstream reply is annotated with:

```json
"_meta": {
  "receipt_id": "...",
  "agentid_shadow": {"receipt_id": "...", "verdict": "deny"}
}
```

Shadow mode is for observing a live tool path before enforcement. It is not an enforcement boundary.

## JSON only

The operator config is JSON to keep the Go core standard-library only. TOML/YAML can be added later as conversion front-ends; the canonical on-disk contract remains JSON.
