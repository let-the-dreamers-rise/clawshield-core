# syntax=docker/dockerfile:1

# The GENKAI gateway: authenticated agent decisions, a SQLite ledger and signed receipts.
#
# Self-hosted by design. It holds the vault key that signs transfers and keeps its ledger on a
# persistent volume, so it belongs on infrastructure the operator controls. The runtime has no
# npm dependencies: the image is Node and the TypeScript sources, run with type stripping.
#
#   docker build -t genkai-gateway .
#   docker compose up -d          see docker-compose.yml and docs/OPERATIONS.md

# node:22-alpine (22.23.3), pinned by digest; Dependabot proposes updates.
ARG NODE_IMAGE=node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
FROM ${NODE_IMAGE}

LABEL org.opencontainers.image.title="GENKAI gateway" \
      org.opencontainers.image.description="Authenticated decision gateway for Solana agents: SQLite ledger, sealed or plaintext policy, signed receipts" \
      org.opencontainers.image.source="https://github.com/let-the-dreamers-rise/clawshield-core" \
      org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8788 \
    GENKAI_DB_PATH=/data/genkai.db

WORKDIR /app
COPY package.json LICENSE ./
COPY src ./src

# The sources stay root-owned and read-only to the process; only /data is writable.
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8788

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 8788) + '/readyz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

ENTRYPOINT ["node", "--experimental-strip-types", "--no-warnings", "src/cli/main.ts"]
CMD ["gateway"]
