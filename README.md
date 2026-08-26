# Tanaqul Validator Node

Official Docker validator node for [Tanaqul](https://explorer.tanaqul.app), a Saudi precious-metals custody platform.

The node takes part in Tanaqul's **permissioned distributed ledger**: it polls for block records that Tanaqul has sealed and returns an ECDSA signature over each one. It is not a peer in a decentralized network — there is no peer-to-peer layer, no consensus algorithm and no smart contracts. Tanaqul seals the blocks; your node co-signs them.

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
- Poll for pending blocks every 15 seconds and sign each one
- Expose `/health` and `/metrics` on port 8080

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

**Why always-on matters:** Blocks seal roughly once every 24 hours (or sooner if trading is heavy). Earnings come from a commission pool shared between active validators and apportioned by Tanaqul's per-validator block count — not per signature, and not per block missed. Uptime still matters: an unreachable node is skipped when Tanaqul selects which node creates the next block, and signing promptly is what the role exists for.

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
