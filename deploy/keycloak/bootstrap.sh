#!/usr/bin/env bash
# Prepara el Keycloak de PRUEBAS para el login con OIDC de InfraWard (idempotente):
#   1. Crea la contraseña del admin de Keycloak (deploy/secrets/keycloak/admin-password, 600) y
#      levanta el servicio `keycloak` del compose (perfil oidc), que importa el realm
#      `infraward` (cliente confidencial con PKCE S256, grupos infraward-* y claim `groups`).
#   2. La primera vez (o con --rotate-client-secret) regenera el secreto del cliente y lo guarda
#      en el proveedor de secretos de la API con `secrets:put` (por stdin: nunca en argv ni en un
#      fichero en claro). Referencia: $KEYCLOAK_SECRET_REF (por defecto
#      secret://local/oidc/keycloak); en apps/api/.env, OIDC_CLIENT_SECRET_REF=<ref>#client_secret.
#   3. Crea los usuarios de prueba si no existen, con contraseña aleatoria guardada en
#      deploy/secrets/keycloak/users.txt (600):
#        ana@example.test    email verificado, grupo infraward-editors
#        bruno@example.test  email verificado, sin grupos
#        carla@example.test  email SIN verificar, grupo infraward-admins
#      Los grupos solo se ponen al crearlos: después se cambian en la consola de Keycloak.
#
# Requisitos: curl, jq, la API configurada (apps/api/.env) y su BD en marcha.
# Uso: pnpm keycloak:bootstrap [-- --rotate-client-secret]
#      CONTAINER_ENGINE=podman deploy/keycloak/bootstrap.sh
set -euo pipefail

ROTATE=false
for arg in "$@"; do
  case "$arg" in
    --rotate-client-secret) ROTATE=true ;;
    --) ;;
    *) echo "Opción desconocida: $arg" >&2; exit 2 ;;
  esac
done

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
SECRETS_DIR="$DEPLOY_DIR/secrets/keycloak"
ENV_FILE="$DEPLOY_DIR/.env"
[ -f "$ENV_FILE" ] || ENV_FILE="$DEPLOY_DIR/.env.example"
PORT="$(sed -n 's/^KEYCLOAK_PORT=//p' "$ENV_FILE" | tail -1)"
PORT="${PORT:-8081}"
BASE="http://localhost:$PORT"
REALM=infraward
SECRET_REF="${KEYCLOAK_SECRET_REF:-secret://local/oidc/keycloak}"

for tool in curl jq openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Falta $tool en el PATH" >&2; exit 1; }
done
if [ -z "${CONTAINER_ENGINE:-}" ]; then
  if command -v docker >/dev/null 2>&1; then CONTAINER_ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then CONTAINER_ENGINE=podman
  else echo "Ni docker ni podman en el PATH" >&2; exit 1
  fi
fi
compose() {
  "$CONTAINER_ENGINE" compose -f "$DEPLOY_DIR/docker-compose.yml" \
    --env-file "$ENV_FILE" --profile oidc "$@"
}

umask 077
mkdir -p "$SECRETS_DIR"
if [ ! -s "$SECRETS_DIR/admin-password" ]; then
  openssl rand -base64 24 | tr -d '\n' >"$SECRETS_DIR/admin-password"
  echo "Contraseña del admin de Keycloak en deploy/secrets/keycloak/admin-password"
fi

# Keycloak solo usa la contraseña de arranque la primera vez (cuando no hay admin).
KEYCLOAK_ADMIN_PASSWORD="$(cat "$SECRETS_DIR/admin-password")" compose up -d keycloak >/dev/null

echo -n "Esperando a Keycloak"
for _ in $(seq 1 120); do
  curl -fs -o /dev/null "$BASE/realms/$REALM/.well-known/openid-configuration" && break
  echo -n "."; sleep 1
done
echo
curl -fs -o /dev/null "$BASE/realms/$REALM/.well-known/openid-configuration" ||
  { echo "Keycloak no responde en $BASE" >&2; exit 1; }

# Token del admin: la contraseña va por fichero y el token por un fichero de cabeceras (600)
# que se borra al salir, para que ninguno aparezca en la línea de órdenes (ps).
HEADERS="$(mktemp "$SECRETS_DIR/.headers.XXXXXX")"
trap 'rm -f "$HEADERS"' EXIT
TOKEN="$(curl -fsS "$BASE/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin \
  --data-urlencode "password@$SECRETS_DIR/admin-password" | jq -r .access_token)"
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$TOKEN" >"$HEADERS"
unset TOKEN
api() { curl -fsS -H "@$HEADERS" "$@"; }
ADMIN_API="$BASE/admin/realms/$REALM"

# 2. Secreto del cliente → proveedor de secretos de la API.
CLIENT_ID="$(api "$ADMIN_API/clients?clientId=infraward" | jq -r '.[0].id')"
MARKER="$SECRETS_DIR/.client-secret-stored"
if $ROTATE || [ ! -f "$MARKER" ]; then
  [ -f "$ROOT_DIR/apps/api/dist/cli/secret-put.js" ] ||
    pnpm --dir "$ROOT_DIR" --filter @infraward/api... build >/dev/null
  api -X POST "$ADMIN_API/clients/$CLIENT_ID/client-secret" |
    jq -c '{client_secret: .value}' |
    pnpm --silent --dir "$ROOT_DIR" --filter @infraward/api secrets:put "$SECRET_REF"
  printf '%s\n' "$SECRET_REF" >"$MARKER"
  echo "Secreto del cliente regenerado y guardado en $SECRET_REF"
else
  echo "El secreto del cliente ya está en $(cat "$MARKER") (--rotate-client-secret para cambiarlo)"
fi

# 3. Usuarios de prueba.
group_id() { api "$ADMIN_API/groups?search=$1&exact=true" | jq -r '.[0].id'; }
ensure_user() {
  local email="$1" first="$2" last="$3" verified="$4" group="${5:-}"
  local id
  id="$(api "$ADMIN_API/users?username=$email&exact=true" | jq -r '.[0].id // empty')"
  if [ -n "$id" ]; then
    echo "  $email ya existe"
    return
  fi
  jq -n --arg u "$email" --arg f "$first" --arg l "$last" --argjson v "$verified" \
    '{username: $u, email: $u, firstName: $f, lastName: $l, emailVerified: $v, enabled: true}' |
    api -X POST "$ADMIN_API/users" -d @- >/dev/null
  id="$(api "$ADMIN_API/users?username=$email&exact=true" | jq -r '.[0].id')"
  local password
  password="$(openssl rand -base64 18 | tr -d '\n/+=')"
  jq -n --arg p "$password" '{type: "password", value: $p, temporary: false}' |
    api -X PUT "$ADMIN_API/users/$id/reset-password" -d @- >/dev/null
  printf '%s %s\n' "$email" "$password" >>"$SECRETS_DIR/users.txt"
  if [ -n "$group" ]; then
    api -X PUT "$ADMIN_API/users/$id/groups/$(group_id "$group")" >/dev/null
  fi
  echo "  $email creado${group:+ (grupo $group)}"
}
echo "Usuarios de prueba (contraseñas en deploy/secrets/keycloak/users.txt):"
ensure_user ana@example.test Ana García true infraward-editors
ensure_user bruno@example.test Bruno Pérez true
ensure_user carla@example.test Carla López false infraward-admins

cat <<EOF

Keycloak listo: consola en $BASE/admin (usuario admin, contraseña en
deploy/secrets/keycloak/admin-password). Configuración mínima de apps/api/.env:

OIDC_ISSUER=$BASE/realms/$REALM
OIDC_CLIENT_ID=infraward
OIDC_CLIENT_SECRET_REF=$SECRET_REF#client_secret
OIDC_REDIRECT_URI=http://localhost:4200/api/auth/oidc/callback
OIDC_PROVIDER_NAME=Keycloak
OIDC_ROLE_MAPPING=infraward-admins=admin,infraward-editors=editor,infraward-operators=operator,infraward-auditors=auditor,infraward-viewers=viewer
EOF
