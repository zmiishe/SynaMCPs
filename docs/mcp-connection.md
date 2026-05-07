# MCP Connection Guide

This server supports:

- Streamable HTTP transport (`/mcp`)
- Legacy HTTP+SSE transport (`/sse` + `/messages`) when enabled

## Auth Options

- Keycloak (OIDC/OAuth 2.1)
- Google OIDC (with optional domain restrictions)
- Generic OIDC/OAuth 2.1
- Teleport Proxy JWT

## Streamable HTTP Example

1. Obtain bearer token from configured provider.
2. Send initialize request:

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}'
```

3. Save returned `Mcp-Session-Id`.
4. Open SSE stream:

```bash
curl -N http://localhost:8080/mcp -H "Mcp-Session-Id: <session_id>"
```

## Legacy HTTP+SSE

If `transport.legacy_sse=true`:

- connect to `GET /sse`
- post messages to `/messages`

## Troubleshooting

- `401`: missing/invalid token
- `403`: issuer/audience/scope/policy mismatch
- `404` on `/mcp` stream: expired or unknown session ID
