#!/usr/bin/env bash
set -euo pipefail
# ====== Настройки (можно переопределить через env) ======
KC_CONTAINER="${KC_CONTAINER:-keycloak}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
REALM="${REALM:-syna}"
CLIENT_ID="${CLIENT_ID:-syna-mcp}"
TEST_USER="${TEST_USER:-mcp-user}"
TEST_USER_PASS="${TEST_USER_PASS:-mcp-password}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:*/*}"
WEB_ORIGINS_CSV="${WEB_ORIGINS_CSV:-http://localhost:8080,http://localhost:3000}"
ROLES=(knowledge.read knowledge.write knowledge.search knowledge.delete)
KCADM="/opt/keycloak/bin/kcadm.sh"
# ====== helpers ======
kcexec() {
  docker compose exec -T "${KC_CONTAINER}" "$@"
}
json_get_id_by_field() {
  local field="$1" value="$2"
  python3 - <<PY
import json,sys
arr=json.load(sys.stdin)
for x in arr:
    if x.get("${field}")=="${value}":
        print(x.get("id",""))
        break
PY
}
split_csv_to_json_array() {
  python3 - <<PY
import json
vals="${WEB_ORIGINS_CSV}".split(",")
print(json.dumps([v.strip() for v in vals if v.strip()]))
PY
}
echo "==> Проверка доступности Keycloak container..."
docker compose ps "${KC_CONTAINER}" >/dev/null
echo "==> Логин в kcadm..."
kcexec "${KCADM}" config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user "${KC_ADMIN_USER}" \
  --password "${KC_ADMIN_PASS}" >/dev/null
echo "==> Realm ${REALM}..."
if ! kcexec "${KCADM}" get "realms/${REALM}" >/dev/null 2>&1; then
  kcexec "${KCADM}" create realms -s "realm=${REALM}" -s enabled=true >/dev/null
  echo "    created"
else
  echo "    exists"
fi
echo "==> Client ${CLIENT_ID}..."
CLIENTS_JSON="$(kcexec "${KCADM}" get clients -r "${REALM}" -q "clientId=${CLIENT_ID}")"
CLIENT_UUID="$(echo "${CLIENTS_JSON}" | json_get_id_by_field clientId "${CLIENT_ID}")"
WEB_ORIGINS_JSON="$(split_csv_to_json_array)"
if [[ -z "${CLIENT_UUID}" ]]; then
  kcexec "${KCADM}" create clients -r "${REALM}" \
    -s "clientId=${CLIENT_ID}" \
    -s "name=${CLIENT_ID}" \
    -s "protocol=openid-connect" \
    -s "publicClient=false" \
    -s "enabled=true" \
    -s "standardFlowEnabled=true" \
    -s "directAccessGrantsEnabled=true" \
    -s "serviceAccountsEnabled=true" \
    -s 'attributes."oauth2.device.authorization.grant.enabled"=false' \
    -s "redirectUris=[\"${REDIRECT_URI}\"]" \
    -s "webOrigins=${WEB_ORIGINS_JSON}" >/dev/null
  CLIENT_UUID="$(kcexec "${KCADM}" get clients -r "${REALM}" -q "clientId=${CLIENT_ID}" | json_get_id_by_field clientId "${CLIENT_ID}")"
  echo "    created (${CLIENT_UUID})"
else
  echo "    exists (${CLIENT_UUID})"
fi
echo "==> Обновление client settings..."
kcexec "${KCADM}" update "clients/${CLIENT_UUID}" -r "${REALM}" \
  -s "enabled=true" \
  -s "publicClient=false" \
  -s "standardFlowEnabled=true" \
  -s "directAccessGrantsEnabled=true" \
  -s "serviceAccountsEnabled=true" \
  -s "redirectUris=[\"${REDIRECT_URI}\"]" \
  -s "webOrigins=${WEB_ORIGINS_JSON}" >/dev/null
echo "==> Audience mapper (aud=${CLIENT_ID})..."
MAPPERS_JSON="$(kcexec "${KCADM}" get "clients/${CLIENT_UUID}/protocol-mappers/models" -r "${REALM}")"
if ! echo "${MAPPERS_JSON}" | grep -q "\"name\" : \"aud-${CLIENT_ID}\""; then
  kcexec "${KCADM}" create "clients/${CLIENT_UUID}/protocol-mappers/models" -r "${REALM}" \
    -s "name=aud-${CLIENT_ID}" \
    -s "protocol=openid-connect" \
    -s "protocolMapper=oidc-audience-mapper" \
    -s 'config."included.client.audience"='"${CLIENT_ID}" \
    -s 'config."id.token.claim"=false' \
    -s 'config."access.token.claim"=true' >/dev/null
  echo "    created"
else
  echo "    exists"
fi
echo "==> Realm roles..."
for role in "${ROLES[@]}"; do
  if ! kcexec "${KCADM}" get "roles/${role}" -r "${REALM}" >/dev/null 2>&1; then
    kcexec "${KCADM}" create roles -r "${REALM}" -s "name=${role}" >/dev/null
    echo "    + ${role}"
  else
    echo "    = ${role}"
  fi
done
echo "==> User ${TEST_USER}..."
USERS_JSON="$(kcexec "${KCADM}" get users -r "${REALM}" -q "username=${TEST_USER}")"
USER_UUID="$(echo "${USERS_JSON}" | json_get_id_by_field username "${TEST_USER}")"
if [[ -z "${USER_UUID}" ]]; then
  kcexec "${KCADM}" create users -r "${REALM}" \
    -s "username=${TEST_USER}" \
    -s "enabled=true" \
    -s "emailVerified=true" >/dev/null
  USER_UUID="$(kcexec "${KCADM}" get users -r "${REALM}" -q "username=${TEST_USER}" | json_get_id_by_field username "${TEST_USER}")"
  echo "    created (${USER_UUID})"
else
  echo "    exists (${USER_UUID})"
fi
kcexec "${KCADM}" set-password -r "${REALM}" --username "${TEST_USER}" --new-password "${TEST_USER_PASS}" --temporary false >/dev/null
echo "==> Назначение ролей пользователю..."
for role in "${ROLES[@]}"; do
  kcexec "${KCADM}" add-roles -r "${REALM}" --uusername "${TEST_USER}" --rolename "${role}" >/dev/null || true
done
echo "==> Service account roles..."
SA_USER_JSON="$(kcexec "${KCADM}" get "clients/${CLIENT_UUID}/service-account-user" -r "${REALM}")"
SA_USER_ID="$(echo "${SA_USER_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')"
for role in "${ROLES[@]}"; do
  kcexec "${KCADM}" add-roles -r "${REALM}" --uid "${SA_USER_ID}" --rolename "${role}" >/dev/null || true
done
echo "==> Client secret:"
CLIENT_SECRET_JSON="$(kcexec "${KCADM}" get "clients/${CLIENT_UUID}/client-secret" -r "${REALM}")"
CLIENT_SECRET="$(echo "${CLIENT_SECRET_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("value",""))')"
echo "CLIENT_ID=${CLIENT_ID}"
echo "CLIENT_SECRET=${CLIENT_SECRET}"
cat <<EOF
Готово.
Проверка token endpoint:
curl -X POST "http://localhost:8081/realms/${REALM}/protocol/openid-connect/token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=password" \\
  -d "client_id=${CLIENT_ID}" \\
  -d "client_secret=${CLIENT_SECRET}" \\
  -d "username=${TEST_USER}" \\
  -d "password=${TEST_USER_PASS}"
EOF