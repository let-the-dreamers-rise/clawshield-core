# Operating GENKAI

Three things get deployed, and they have different owners.

| Component | Where it runs | Holds secrets |
|---|---|---|
| GENKAI program, PolicyRecord, MXE | Solana and Arcium (devnet today) | No; the policy is ciphertext |
| Gateway | Infrastructure the operator controls | Yes: the vault key and, sealed, the policy authority key |
| Verifier site and API | Anywhere; the public one is on Vercel | No |

The gateway is self-hosted on purpose. It signs transfers, so it belongs where the operator
controls the disk, the network and who can shell in.

## Running the gateway

### With Docker Compose

```bash
mkdir -p secrets
npm run --silent genkai -- keygen secrets/vault.json     # or copy an existing solana-keygen file
docker compose up -d
docker compose exec gateway node --experimental-strip-types --no-warnings \
  src/cli/main.ts gateway-admin create-admin-key --db /data/genkai.db
```

The container runs as uid 1000 on a read-only root filesystem with every capability dropped.
The vault key is mounted as a Docker secret, so it must be readable by uid 1000; the ledger
lives on the `genkai-data` volume. The port is published on loopback only.

The image is published to `ghcr.io/let-the-dreamers-rise/genkai-gateway` by
`.github/workflows/image.yml`. Every published image has passed `scripts/smoke-gateway.sh`,
which boots it and drives a full decision cycle, and carries build provenance and an SBOM.

### From source

```bash
GENKAI_VAULT_KEY_FILE=vault.keypair.json \
GENKAI_POLICY_FILE=examples/devnet/policy.json \
  npm run genkai -- gateway --db data/genkai.db
```

Node 22.13 or later (`node:sqlite` without a flag). There are no runtime npm dependencies.

### Configuration

Everything comes from the environment and is validated before the port opens. A bad
configuration exits with status 2 and lists every problem at once.

| Variable | Meaning | Default |
|---|---|---|
| `GENKAI_DB_PATH` | SQLite ledger | `./data/genkai.db` (`/data/genkai.db` in the image) |
| `GENKAI_VAULT_KEY_FILE` | The vault keypair, solana-keygen JSON. It signs transfers and receipts | required, or `GENKAI_VAULT_KEY` inline |
| `GENKAI_POLICY_FILE` | Plaintext mode: the policy | one of the two modes |
| `GENKAI_DEPLOYMENT_FILE` | Sealed mode: the deployment manifest, e.g. `arcium/genkai/deployments/devnet.json` | one of the two modes |
| `GENKAI_AUTHORITY_KEY_FILE` | Sealed mode: the policy authority's keypair. Only it may call `evaluate` | required when sealed |
| `GENKAI_RPC_URL` | Solana RPC | required when sealed or broadcasting |
| `GENKAI_CLUSTER` | `devnet`, `testnet`, `mainnet-beta` or `localnet` | `devnet` |
| `GENKAI_EXECUTION` | `sign` returns the signed transaction; `broadcast` also submits it | `sign` |
| `GENKAI_WINDOW_SECONDS` | Spend window. Sealed mode needs it: the policy is not readable | the policy's `windowSeconds` |
| `GENKAI_PUBLIC_RECEIPTS` | Serve receipts without a key | `true` |
| `GENKAI_TRUST_PROXY` | Take the client address from `X-Forwarded-For` | `false` |
| `PORT`, `HOST` | Listen address | `8788`, `127.0.0.1` (`0.0.0.0` in the image) |

Secrets are read from files (the Docker and Kubernetes convention) or, where a platform only
offers environment variables, inline. Neither is ever logged, and a malformed key fails with a
fixed message that never quotes the file.

### Sealed mode against the devnet deployment

```yaml
    environment:
      GENKAI_VAULT_KEY_FILE: /run/secrets/vault_key
      GENKAI_DEPLOYMENT_FILE: /config/devnet.json
      GENKAI_AUTHORITY_KEY_FILE: /run/secrets/authority_key
      GENKAI_RPC_URL: https://api.devnet.solana.com
      GENKAI_WINDOW_SECONDS: "86400"
    volumes:
      - ./arcium/genkai/deployments/devnet.json:/config/devnet.json:ro
```

Boot checks that the authority key is the manifest's authority before anything is sent. Each
decision then queues an Arcium computation and waits for the cluster's callback, so it costs
the authority a transaction fee and takes seconds rather than milliseconds.

## Keys and access

| Key | Created by | Can |
|---|---|---|
| Vault keypair | `genkai keygen` | Sign transfers from the vault and sign receipts. Fund it; guard it |
| Policy authority keypair | at deployment | Register and activate policies, request evaluations |
| Admin API key | `gateway-admin create-admin-key` | Register agents, issue and revoke keys, kill switch, audit |
| Agent API key | `POST /v1/agents/:id/keys` | Ask for decisions for its own agent, read its own data |

**The first admin key** is created against the database file, because nothing else exists to
authenticate with. The same command is the break-glass path when every admin key is lost:
whoever holds the database file holds the gateway, so protect the volume accordingly.

**Rotating an agent key**: issue a new key, deploy it to the agent, confirm traffic on it in the
request log (the `key` field), then `DELETE /v1/keys/:keyId` for the old one. Revocation takes
effect on the next request. List keys, without their secrets, with
`GET /v1/agents/:id/keys` or `gateway-admin list-keys`.

**Rotating the vault key** changes the receipt-signing key and the vault address. Start a new
gateway database for it: an agent's receipt chain should be signed by one key.

## Stopping an agent

- **Kill switch**: `POST /v1/agents/:id/revoke`. Every later decision is a denial with a receipt
  saying so. `POST /v1/agents/:id/reinstate` lifts it.
- **Drawdown halt**: `PUT /v1/agents/:id/drawdown` with the agent's losses from peak. Past the
  policy's `drawdownHaltThreshold` every request is denied.
- **Revoking its key** stops the agent from reaching the gateway at all. Prefer the kill switch
  when the record of refused attempts matters.

Each of these is written to the audit log (`GET /v1/audit`) with the acting key's id.

## Storage

The ledger is SQLite in WAL mode. Migrations run at startup and are forward-only.

**One gateway process per database.** Decisions for an agent are serialised in-process. A
second process on the same file would not corrupt it (each commit checks the ledger version
it read and fails with 409 otherwise), but it would turn contention into errors. Scale by
sharding agents across gateways, each with its own database and vault.

**Backups** while running, as a consistent snapshot:

```bash
docker compose exec gateway node --no-warnings -e \
  "const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync('/data/genkai.db'); db.exec(\"VACUUM INTO '/data/genkai-backup.db'\"); db.close();"
```

Copy the snapshot off the volume and treat it like the key: it contains every agent's key
hashes, the ledger and the signed transactions. Receipts are designed to be public; the rest is
not.

## Network

Terminate TLS in front of the gateway (Caddy, nginx, a cloud load balancer) and keep the
container port off the public interface. Set `GENKAI_TRUST_PROXY=true` only behind such a
proxy, and make sure the proxy overwrites `X-Forwarded-For`, or a client can choose the address
its rate limit is counted against.

## Observability

- `GET /healthz`: the process is up. `GET /readyz`: the database answers; it also reports the
  RPC and execution mode. The image's `HEALTHCHECK` uses `/readyz`.
- Logs are JSON lines on stdout: `gateway.start` with mode, vault address and cluster, then one
  line per request with `id`, `method`, `path`, `route`, `status`, `ms` and the key id. Never a
  credential, never a body. Every response carries the same id in `X-Request-Id`, so a client
  reporting a 500 can name the log line that explains it.

## The verifier site and API

```bash
npm run build:web                         # writes .vercel/output
npx vercel deploy --prebuilt --prod       # or: vercel deploy --prebuilt --prod
```

Nothing is built on Vercel's side: the deployment is exactly the Build Output the script
produced, which CI also builds on every push. The functions read devnet unless
`GENKAI_RPC_URL` is set in the Vercel project. `npm run preview:web` serves the same build
locally with the same headers.

## The on-chain program

The program is upgradeable today, which means its upgrade authority could replace the code
that checks the cluster's signature or change the circuit its computation definition pins.
After an external review, make it immutable:

```bash
solana program set-upgrade-authority AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk --final --url devnet
```

This cannot be undone, which is why no script here runs it.
