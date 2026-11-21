# Approval workflow — reviewable obligations

E32 supplies the human surface for obligations the validator already enforces.

## Flow

1. The PEP validates an action. If the result is `indeterminate` with
   `cosign_above` or `cosign_untrusted`, it creates an `ApprovalRequest`
   bound to the action envelope digest and returns JSON-RPC `-32000` with
   `error.data.approval_request_id`. No approval means no downstream call.
2. A reviewer lists pending requests and approves or rejects. Approval produces
   a signed artifact via `SignApproval`, including
   `approves_request_id` and the `acknowledges_untrusted` flag where relevant.
3. The agent retries with the opaque `approval_request_id`. The PEP checks the
   request is approved **and** that its envelope digest still matches the
   retried action, then supplies the artifact to the validator.

`approval_request_id` is excluded from the action envelope so the digest stays
stable across retries. Rejected or mismatched requests never reach the
validator as approvals.

## Integration scenario (test-first)

`integration/approval_workflow_test.go` went RED (no workflow) → GREEN: an
over-threshold denial produced a request, approval allowed the retry, rejection
left the action blocked.

## Falsifier

A denial without a request id, a rejected request authorizing a call, or an
approval for a different action digest being accepted — scenario and unit tests
attack all three.
