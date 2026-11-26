# Local key lifecycle

Tier 2 allows hardened local keys with rotation. KMS/HSM adapters are recommended and required for Tier 3.

## Directory layout

```text
keys/
  kid-one/
    private.pem   0600
    public.pem    0644
    meta.json     0644
  kid-two/
    private.pem   0600
    public.pem    0644
    meta.json     0644
```

`meta.json` records `kid`, `algorithm`, `state` (`active` or `previous`) and `created_at`. Private keys are written with mode `0600`; public material with `0644`; key directories with `0700`.

## Generate

```bash
go run ./cmd/agentid key generate --dir keys --kid kid-one
```

The command refuses to overwrite an existing key id.

## Rotate with overlap

```bash
go run ./cmd/agentid key rotate --dir keys --kid kid-two
```

Rotation marks the current `active` key as `previous` and creates the new key as `active`. Both keys remain in the directory so verifiers can validate receipts signed before and after the cutover.

## Publish public key set

```bash
go run ./cmd/agentid key publish --dir keys --out public-keys.json
```

Output is canonical JSON:

```json
{"keys":[{"kid":"kid-one","public_key":"-----BEGIN PUBLIC KEY...","state":"previous"},{"kid":"kid-two","public_key":"-----BEGIN PUBLIC KEY...","state":"active"}],"version":"v1"}
```

Publish the generated file to the location your verifiers use. Do not publish `private.pem`.

## Boundary

These commands manage local signer material. They do not provide KMS/HSM custody, remote key escrow or automatic rotation scheduling. Those belong to the commercial operator layer and Tier 3.
