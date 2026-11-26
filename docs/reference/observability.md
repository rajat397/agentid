# Observability pack

`agentid` exposes a dependency-free Prometheus-style metrics endpoint from `agentid serve`.

## Endpoint

```bash
go run ./cmd/agentid serve --bundle bundle.json --addr 127.0.0.1:8080
curl http://127.0.0.1:8080/metrics
```

The same server mounts `/receipts/verify` and `/v1/keys`.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `agentid_decisions_total{outcome="allow|deny"}` | counter | Decisions produced by the MCP wrapper. |
| `agentid_verification_failures_total` | counter | Decisions that could not be verified or derived. |
| `agentid_status_age_seconds` | gauge | Age of the revocation status material. |
| `agentid_anchor_gaps` | gauge | Number of detected anchor gaps. |
| `agentid_pep_latency_seconds_sum` / `_count` | counter pair | Decision-overhead measurement. No public latency SLO is claimed. |
| `agentid_adapter_healthy{adapter="..."}` | gauge | Adapter health, `1` healthy and `0` unhealthy. |
| `agentid.mismatch` | OTel counter | Existing span/receipt reconciliation signal from the OTel evidence layer. |

## Integration

A caller that constructs `MCPWrapperConfig` directly can attach metrics:

```go
metrics := agentid.NewMetrics()
wrapper, err := agentid.NewMCPWrapper(agentid.MCPWrapperConfig{
    Metrics: metrics,
    // chain, profile, tools, keys, signer...
})
```

The wrapper records allow/deny decisions and decision latency automatically. Verification failures are recorded on policy-resolution and receipt-construction errors.

## Alert templates

See [examples/alerts/agentid-alerts.yaml](../../examples/alerts/agentid-alerts.yaml) for starting Prometheus rules for verification failures, stale status, anchor gaps, adapter health and PEP latency.

Thresholds are starting templates, not product SLOs. Ratified production readiness measures latency and availability before promising either.
