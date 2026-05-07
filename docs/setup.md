# Setup Guide

## Prerequisites

- Docker + Docker Compose
- Go 1.23+

## Local Run

```bash
make compose-up
```

Server starts on `http://localhost:8080`.

## Config

- default config: `configs/config.example.yaml`
- override with `CONFIG_PATH=/path/to/config.yaml`

Key sections:

- `embedding`: embedding provider/model/api/tokens
- `summarization`: separate LLM for summary provider/model/api/tokens
- `vector_backend.active`: `pgvector` or `qdrant`
- `api.allowed_origins`: strict CORS allowlist (unknown origins are rejected)
- `redis`: session backend settings (`addr`, `password`, `db`, key prefix, TTL)

## Stop

```bash
make compose-down
```
