# ============================================================================
# Shadow : Helix Nebula (SHN) — Production Multi-Stage Hardened Container
#
# Authoritative Spec: Phase 0.3 Perimeter A/B, Phase 0.11 Trust Boundaries,
#                     Phase 0.4 Invariants (INV-01, INV-09, INV-14)
# ============================================================================

# ----------------------------------------------------------------------------
# Stage 1: Build & Compilation Environment
# ----------------------------------------------------------------------------
FROM node:24-alpine AS builder

WORKDIR /app

# Install build dependencies
COPY package*.json ./
COPY tsconfig*.json ./

# Copy packages source trees
COPY packages/ ./packages/

# Install all workspace dependencies and compile TypeScript & Web Console assets
RUN npm ci
RUN npm run build
RUN npm run web:bundle

# ----------------------------------------------------------------------------
# Stage 2: Hardened Sovereign Runtime
# ----------------------------------------------------------------------------
FROM node:24-alpine AS runner

WORKDIR /app

# Production environment variables
ENV NODE_ENV=production \
    SHN_PORT=8080 \
    SHN_HOST=0.0.0.0

# Copy root package manifests and node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node --from=builder /app/node_modules ./node_modules

# Copy compiled package outputs, manifests, migrations, and bundled Web Console
COPY --chown=node:node --from=builder /app/packages/ ./packages/

# Drop root privileges: run strictly as unprivileged 'node' user
USER node

# Expose primary Ingress Gateway HTTP & SSE streaming port
EXPOSE 8080

# Container liveness health probe
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8080/health/live').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# Sovereign Platform Entrypoint
CMD ["node", "packages/ingress-gateway/dist/standalone.js"]
