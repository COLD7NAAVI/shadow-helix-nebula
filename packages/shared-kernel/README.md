# @shn/shared-kernel

Core Shared Domain Kernel for Shadow : Helix Nebula (SHN).

## Purpose
Enforces `INV-09`, `MOD-INV-01`, and `API-INV-06`:
- Nominal branded entity identifiers (`UUIDv7` validation & generation).
- Network domain value objects (`IPv4`, `IPv6`, `CIDR`, `Port`, `PortRange`, `FQDN`).
- Algebraic `Result<T, E>` monads for fail-closed, exception-free error propagation.
- Canonical Event Envelope contracts & metadata models.
- Immutable `SecurityContextToken` and `ScopeEnvelope` contracts.
- Abstract configuration contracts.
- Zero external runtime dependencies.
