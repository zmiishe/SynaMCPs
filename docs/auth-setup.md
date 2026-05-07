# Authorization Setup

## Keycloak

1. Create realm `syna`.
2. Create client `syna-mcp`.
3. Configure issuer and audience in `oauth.providers`.

## Google

1. Register OAuth client in Google Cloud.
2. Set provider issuer `https://accounts.google.com`.
3. Restrict domains in `oauth.google_allowed_domains`.

## Generic OIDC

Add provider entry with `issuer`, `audience`, `jwks_url`.
Tokens are verified using provider JWKS and strict issuer/audience checks.

## Teleport Proxy JWT

Enable `teleport.enabled`.

- configure trusted `teleport.issuer`
- configure `teleport.audience`

If request token matches issuer/audience, auth source is `teleport_proxy`.

## Access Tokens

- user delegated tokens are supported
- service tokens should be scope-limited (`knowledge.read`, `knowledge.write`, `knowledge.search`, `knowledge.delete`)
