# External Source Integration

Use API with bearer token to import knowledge from external systems.

## Create Knowledge

`POST /api/knowledge`

Fields:

- `title`
- `text`
- `visibility`
- optional `groupIds`
- optional `source`
- optional `sourceUrl`

If `source` is omitted for API calls, backend defaults it to `api`.

## Search and Filters

`POST /api/knowledge/search`

- `filters.source` exact match
- `filters.sourceUrl` exact or partial (`filters.sourceUrlMode=partial`)

## Batch Import Tips

- keep documents below `limits.max_upload_bytes`
- provide stable `sourceUrl` for traceability
- include source-specific labels via `source`
