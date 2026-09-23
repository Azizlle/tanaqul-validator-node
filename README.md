# Tanaqul Validator Node

Official Docker validator node for [Tanaqul](https://explorer.tanaqul.app), a Saudi precious-metals custody platform.

The node takes part in Tanaqul's **permissioned distributed ledger**: it polls for block records that Tanaqul has sealed, **independently recomputes each one from its contents**, and returns an ECDSA signature only if its own arithmetic agrees. It is not a peer in a decentralized network — there is no peer-to-peer layer, no consensus algorithm and no smart contracts. Tanaqul seals the blocks; your node checks and co-signs them.

Runs on any always-on machine — home desktop, Raspberry Pi, cheap VPS, or laptop. No server administration required.

## Run

You'll receive a one-time email from `validators@exit.sa` containing your validator ID and API key. Then:

```bash
docker run -d --restart always --name tanaqul-validator \
  -v tanaqul-data:/data \
  -p 8080:8080 \
  -e TANAQUL_VALIDATOR_ID="your-validator-id" \
  -e TANAQUL_API_KEY="your-api-key" \
  -e TANAQUL_BACKEND_URL="https://api.tanaqul.app" \
  ghcr.io/azizlle/tanaqul-validator-node:latest
```

That's it. The container will:

- Generate a local ECDSA key on first run (persisted in the `tanaqul-data` volume)
- Send a heartbeat every 30 seconds
- Poll for pending blocks every 15 seconds, verify each one, and sign or refuse
- Expose `/health` and `/metrics` on port 8080

## What your node actually checks

Your signature is not a receipt. For every block, the node fetches the block's
contents, rebuilds each leaf from its fields, merkles them into three roots, and
recomputes the block hash — then compares that to the hash Tanaqul stores.

Two of those three roots are served by no endpoint. The only way to hold them is
to build the leaves yourself, so a valid signature could not have been produced by
a node that skipped the work.

The node also checks that each block follows the previous block **it verified
itself**, not the one Tanaqul says came before.

There are three outcomes, and `/metrics` counts them separately:

| Outcome | Metric | What it means |
|---|---|---|
| Validated | `validator_blocks_validated_total` | Recomputed, agreed, signed |
| Attested | `validator_blocks_attested_v1_total` | An older-format block your node cannot recompute. Signed as receipt only — never counted as validation |
| Refused | `validator_blocks_refused_total` | Your node checked, disagreed, and filed a signed objection saying exactly where |

A refusal is signed with your key and states both hashes, so the disagreement is
evidence rather than a flag. If the block is later corrected, your node signs it on
the next poll — no restart needed.

## Verifying the node against the protocol

`spec/agreement_vectors.json` holds the protocol's hashing vectors: inputs and the
exact bytes both implementations must produce. This repo's test suite runs them
against the node's implementation, and Tanaqul's cross-repo CI job runs the same
file against the platform's.

**Which CI catches what**, stated exactly, because a vaguer promise here was
wrong: a change to the *platform's* implementation reddens Tanaqul's CI; a change
to the *node's* reddens this repo's CI. A change that edits the node's code and
its vectors together would agree with itself — so it is caught instead by the
correctness tests in `tests/test_verify.py`, which are written from the
documented rules rather than from either implementation. That is why both kinds
of test exist, and why neither is redundant.

```bash
pip install -r requirements.txt pytest && pytest -q
```

The vectors prove the two sides *agree*. That they are *correct* is pinned
separately, by tests written from the documented rules rather than from either
implementation. Agreement alone would pin two copies of the same mistake.

## Where to run

The node runs in a Docker container on any always-on machine. It doesn't need a fancy server.

**Good options:**
- **Home desktop** — always-on PC, runs 24/7, free
- **Raspberry Pi** — low-power, ARM-compatible build included (multi-arch image)
- **Cheap VPS** — Hetzner, DigitalOcean, Contabo, roughly $4–6/month
- **Laptop** — works but only signs while the laptop is on; earnings drop when it sleeps
- **AWS / Azure / GCP** — enterprise option, usually overkill for a single validator

**Minimum specs:**
- 256 MB RAM
- 50 MB disk
- Constant internet connection
- Outbound HTTPS to `https://api.tanaqul.app` (port 443) — that's it

**No inbound ports needed.** The node polls outbound; nothing connects to it from the internet. Your home router and any firewall will work as-is.

**Why always-on matters:** Blocks seal when enough custody activity has accumulated to fill one — so on a quiet week there may be no block at all, and on a busy day several. There is no timer, and a block is never minted with nothing in it. Earnings come from a commission pool shared between active validators and apportioned by Tanaqul's per-validator block count — not per signature, and not per block missed. Uptime still matters: an unreachable node is skipped when Tanaqul selects which node creates the next block, and signing promptly is what the role exists for.

## Verify it's running

```bash
docker logs -f tanaqul-validator
curl http://localhost:8080/health
```

## Environment variables

| Name | Required | Default | Notes |
|---|---|---|---|
| `TANAQUL_VALIDATOR_ID` | yes | — | UUID from your welcome email |
| `TANAQUL_API_KEY` | yes | — | Secret from your welcome email — store securely |
| `TANAQUL_BACKEND_URL` | yes | — | Use `https://api.tanaqul.app` |
| `TANAQUL_HEARTBEAT_INTERVAL` | no | `30` | seconds |
| `TANAQUL_POLL_INTERVAL` | no | `15` | seconds |
| `TANAQUL_HEALTH_PORT` | no | `8080` | inside the container |
| `TANAQUL_LOG_LEVEL` | no | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `TANAQUL_REGION` | no | `Riyadh` | label sent in heartbeat |

## State

The validator's signing key is generated on first run and saved to `/data/validator_key.pem`. **Always mount `/data` as a Docker volume** — losing this file means losing your validator identity.

## Updates

```bash
docker pull ghcr.io/azizlle/tanaqul-validator-node:latest
docker stop tanaqul-validator && docker rm tanaqul-validator
# then re-run with the same `docker run` command
```

The data volume is preserved across updates.

## Support

Open an issue at github.com/Azizlle/tanaqul-validator-node or email validators@exit.sa.
