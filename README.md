# Tanaqul Validator Node

Official Docker validator for the [Tanaqul](https://tanaqul.app) precious-metals blockchain.

## Run

You'll receive a one-time email from `noreply@tanaqul.app` containing your validator ID and API key. Then:

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

Open an issue at github.com/Azizlle/tanaqul-validator-node or email validators@tanaqul.app.
