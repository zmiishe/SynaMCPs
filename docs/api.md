# API Guide

## Auth Modes

- `cookieAuth`: web UI session (`session_id` cookie)
- `bearerAuth`: `Authorization: Bearer <access-token>`

## Knowledge Endpoints

- `GET /api/knowledge`
- `GET /api/knowledge/{docId}`
- `POST /api/knowledge`
- `POST /api/admin/knowledge` (web admin create path, defaults `source=admin`)
- `POST /api/knowledge/search`
- `DELETE /api/knowledge/{docId}`

## Source Metadata

- `source`: optional source type
  - default by channel: `mcp`, `api`, `admin`
- `sourceUrl`: optional source URL
- filtering:
  - `source`: exact match only
  - `sourceUrl`: exact + optional partial (controlled by `search.filters.source_url.allow_partial_match`)

## Example: Create

```bash
curl -X POST http://localhost:8080/api/knowledge \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title":"Runbook",
    "text":"Long knowledge text...",
    "mimeType":"text/plain",
    "visibility":"personal",
    "source":"api",
    "sourceUrl":"https://docs.example.com/runbook"
  }'
```

## Error Codes

- `401` unauthorized
- `403` forbidden
- `404` not found
- `409` conflict
- `422` validation error
