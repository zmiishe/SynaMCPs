# Delivery Phases

## Phase 1: pgvector-first baseline

- streamable HTTP + legacy SSE
- OAuth/Teleport auth gateway
- knowledge save/get/search/delete
- metadata catalog + in-memory pgvector adapter
- web admin and integration API

## Phase 2: Qdrant adapter

- switchable `vector_backend.active=qdrant`
- parity tests between pgvector and qdrant behavior

## Phase 3: hardening and observability

- structured logs and request IDs
- metrics for auth/search/ingest/session
- retries and circuit-breakers for external LLM APIs
- stricter JWT validation and JWKS caching
- load and soak tests
