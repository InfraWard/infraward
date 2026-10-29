#!/usr/bin/env bash
# Prepara el OpenBao de DESARROLLO para InfraWard (idempotente; se puede relanzar):
#   1. Crea la clave de desellado automático (deploy/secrets/openbao/unseal.key) y levanta el
#      servicio `openbao` del compose (perfil openbao).
#   2. Lo inicializa si hace falta y guarda el material de init (clave de recuperación y token
#      root) en deploy/secrets/openbao/init.json (600, fuera de git). El token root solo se usa
#      aquí, para configurar; la app entra siempre por AppRole.
#   3. Activa KV v2 en `secret/` y AppRole, escribe la política `infraward` (solo
#      secret/{data,metadata}/infraward/*, firmar con infraward-ssh/sign/inventory y listar
#      las claves públicas de la CA) y el rol `infraward`.
#   3b. CA SSH: motor `ssh` en `infraward-ssh/`, primer emisor ed25519 generado DENTRO de
#      OpenBao (no exportable) y rol `inventory` (certificados de usuario de vida corta, un único
#      principal `inventory`, sin extensiones). La rotación de la CA no la hace este script.
#   3c. Caja fuerte (QoL-7): política `infraward-vault` (solo secret/{data,metadata}/
#      infraward-vault/*) y rol `infraward-vault`, que solo usa la API: el worker no la lee.
#   3d. Terminal (sesión 21): rol `infraward-operator` del motor SSH (principal de rol
#      `infraward-operators`, solo `permit-pty`, vida de minutos), política y AppRole
#      `infraward-terminal`, que solo usa la API: el worker no puede firmar certificados de
#      administración.
#   4. Muestra los role_id y deja los secret_id en deploy/secrets/openbao/secret-id,
#      vault-secret-id y terminal-secret-id (600). Con --rotate-secret-id genera otros y revoca
#      los anteriores.
#
# Uso: pnpm openbao:bootstrap [-- --rotate-secret-id]
#      CONTAINER_ENGINE=podman deploy/openbao/bootstrap.sh
set -euo pipefail

ROTATE=false
for arg in "$@"; do
  case "$arg" in
    --rotate-secret-id) ROTATE=true ;;
    --) ;;
    *) echo "Opción desconocida: $arg" >&2; exit 2 ;;
  esac
done

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="$DEPLOY_DIR/secrets/openbao"
ENV_FILE="$DEPLOY_DIR/.env"
[ -f "$ENV_FILE" ] || ENV_FILE="$DEPLOY_DIR/.env.example"
PORT="$(sed -n 's/^OPENBAO_PORT=//p' "$ENV_FILE" | tail -1)"
PORT="${PORT:-8200}"

if [ -z "${CONTAINER_ENGINE:-}" ]; then
  if command -v docker >/dev/null 2>&1; then CONTAINER_ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then CONTAINER_ENGINE=podman
  else echo "Ni docker ni podman en el PATH" >&2; exit 1
  fi
fi
compose() {
  "$CONTAINER_ENGINE" compose -f "$DEPLOY_DIR/docker-compose.yml" \
    --env-file "$ENV_FILE" --profile openbao "$@"
}
# CLI de OpenBao dentro del contenedor; el token viaja por variable de entorno, nunca en argv.
bao() {
  compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="${ROOT_TOKEN:-}" \
    openbao bao "$@"
}

umask 077
mkdir -p "$SECRETS_DIR"
if [ ! -s "$SECRETS_DIR/unseal.key" ]; then
  openssl rand -out "$SECRETS_DIR/unseal.key" 32
  echo "Clave de desellado creada en deploy/secrets/openbao/unseal.key"
fi

compose up -d openbao >/dev/null
# bao status: 0 = desellado, 2 = sellado o sin inicializar, 1 = no responde.
status() { bao status -format=json 2>/dev/null || true; }
echo -n "Esperando a OpenBao"
for _ in $(seq 1 60); do
  STATUS="$(status)"
  [ -n "$STATUS" ] && break
  echo -n "."; sleep 1
done
echo
[ -n "$STATUS" ] || { echo "OpenBao no responde" >&2; exit 1; }

INIT_FILE="$SECRETS_DIR/init.json"
if grep -q '"initialized": false' <<<"$STATUS"; then
  bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json >"$INIT_FILE"
  echo "Inicializado; material de init en deploy/secrets/openbao/init.json (no lo compartas)"
  for _ in $(seq 1 30); do
    grep -q '"sealed": false' <<<"$(status)" && break
    sleep 1
  done
elif [ ! -s "$INIT_FILE" ]; then
  echo "OpenBao ya está inicializado pero falta $INIT_FILE: no hay token para configurarlo." >&2
  echo "Para empezar de cero: $CONTAINER_ENGINE compose ... --profile openbao down -v" >&2
  exit 1
fi
ROOT_TOKEN="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$INIT_FILE")"
[ -n "$ROOT_TOKEN" ] || { echo "No se encontró root_token en $INIT_FILE" >&2; exit 1; }

if ! bao secrets list -format=json | grep -q '"secret/"'; then
  bao secrets enable -path=secret -version=2 kv >/dev/null
  echo "KV v2 activado en secret/"
fi
if ! bao auth list -format=json | grep -q '"approle/"'; then
  bao auth enable approle >/dev/null
  echo "AppRole activado"
fi

# CA SSH (DESIGN §6): mismos parámetros que sshRoleParams() de los tests de integración.
SSH_MOUNT=infraward-ssh
if ! bao secrets list -format=json | grep -q "\"$SSH_MOUNT/\""; then
  bao secrets enable -path="$SSH_MOUNT" ssh >/dev/null
  echo "Motor SSH activado en $SSH_MOUNT/"
fi
# Solo el primer emisor: con emisores ya creados no se toca nada (rotar no es cosa de este script).
if ! bao list -format=json "$SSH_MOUNT/issuers" >/dev/null 2>&1; then
  bao write "$SSH_MOUNT/issuers/import/ca-1" \
    generate_signing_key=true key_type=ssh-ed25519 set_default=true >/dev/null
  echo "CA SSH creada (emisor ca-1, ed25519)"
fi
bao write "$SSH_MOUNT/roles/inventory" - >/dev/null <<'JSON'
{
  "key_type": "ca",
  "allow_user_certificates": true,
  "allow_host_certificates": false,
  "allowed_users": "inventory",
  "default_user": "inventory",
  "allow_user_key_ids": true,
  "ttl": "5m",
  "max_ttl": "30m",
  "allowed_extensions": "",
  "default_extensions": {},
  "allowed_critical_options": "",
  "allowed_user_key_lengths": { "ssh-ed25519": [0] },
  "not_before_duration": "30s"
}
JSON

# Política mínima: solo el subárbol de InfraWard (OPENBAO_KV_PREFIX=infraward). renew-self,
# lookup-self y revoke-self los da la política `default`, que OpenBao añade a todo token.
bao policy write infraward - >/dev/null <<'HCL'
path "secret/data/infraward/*" {
  capabilities = ["create", "read", "update"]
}
path "secret/metadata/infraward/*" {
  capabilities = ["read", "delete"]
}
# CA SSH: solo firmar con el rol `inventory` y leer las claves públicas de los emisores.
# Nada de config/*, issuers/import ni roles/*: la CA solo la cambia un operador.
path "infraward-ssh/sign/inventory" {
  capabilities = ["update"]
}
path "infraward-ssh/issuers" {
  capabilities = ["list"]
}
HCL

bao write auth/approle/role/infraward \
  token_policies=infraward token_ttl=1h token_max_ttl=24h \
  secret_id_ttl=0 secret_id_num_uses=0 token_type=service >/dev/null
ROLE_ID="$(bao read -field=role_id auth/approle/role/infraward/role-id)"

# Caja fuerte de credenciales (QoL-7): otro subárbol (infraward-vault/), otra política y otra
# AppRole, que SOLO tiene la API. La política `infraward` (la del worker) no alcanza este prefijo:
# el worker no puede leer nunca la caja fuerte. Versiones de KV v2 (max_versions lo fija la API
# en la metadata de cada ruta: por eso `create`/`update` en metadata).
bao policy write infraward-vault - >/dev/null <<'HCL'
path "secret/data/infraward-vault/*" {
  capabilities = ["create", "read", "update"]
}
path "secret/metadata/infraward-vault/*" {
  capabilities = ["create", "read", "update", "delete"]
}
HCL

bao write auth/approle/role/infraward-vault \
  token_policies=infraward-vault token_ttl=1h token_max_ttl=24h \
  secret_id_ttl=0 secret_id_num_uses=0 token_type=service >/dev/null
VAULT_ROLE_ID="$(bao read -field=role_id auth/approle/role/infraward-vault/role-id)"

# Terminal (sesión 21, DESIGN §11): certificados de pocos minutos para la cuenta de administración
# de los servidores (`infraward-admin`), con el principal de rol `infraward-operators` y solo
# `permit-pty` (sin reenvíos ni agente). Mismos parámetros que terminalSshRoleParams() de los
# tests. Otra política y otra AppRole, que SOLO tiene la API (tras comprobar el permiso y la
# reautenticación): la AppRole `infraward` (la del worker) no puede firmar con este rol.
bao write "$SSH_MOUNT/roles/infraward-operator" - >/dev/null <<'JSON'
{
  "key_type": "ca",
  "allow_user_certificates": true,
  "allow_host_certificates": false,
  "allowed_users": "infraward-operators",
  "default_user": "infraward-operators",
  "allow_user_key_ids": true,
  "ttl": "2m",
  "max_ttl": "5m",
  "allowed_extensions": "permit-pty",
  "default_extensions": {},
  "allowed_critical_options": "",
  "allowed_user_key_lengths": { "ssh-ed25519": [0] },
  "not_before_duration": "30s"
}
JSON

bao policy write infraward-terminal - >/dev/null <<'HCL'
path "infraward-ssh/sign/infraward-operator" {
  capabilities = ["update"]
}
HCL

bao write auth/approle/role/infraward-terminal \
  token_policies=infraward-terminal token_ttl=1h token_max_ttl=24h \
  secret_id_ttl=0 secret_id_num_uses=0 token_type=service >/dev/null
TERMINAL_ROLE_ID="$(bao read -field=role_id auth/approle/role/infraward-terminal/role-id)"

# secret_id de un rol en <fichero> (600); con --rotate-secret-id, uno nuevo y destruye el anterior.
issue_secret_id() {
  local role="$1" file="$2"
  local accessor_file="$file.accessor"
  if [ "$ROTATE" = true ] || [ ! -s "$file" ]; then
    bao write -f -format=json "auth/approle/role/$role/secret-id" >"$SECRETS_DIR/.secret-id.json"
    local new_accessor
    new_accessor="$(sed -n 's/.*"secret_id_accessor": *"\([^"]*\)".*/\1/p' "$SECRETS_DIR/.secret-id.json")"
    sed -n 's/.*"secret_id": *"\([^"]*\)".*/\1/p' "$SECRETS_DIR/.secret-id.json" >"$file.new"
    rm -f "$SECRETS_DIR/.secret-id.json"
    if [ -s "$accessor_file" ]; then
      bao write "auth/approle/role/$role/secret-id-accessor/destroy" \
        secret_id_accessor="$(cat "$accessor_file")" >/dev/null 2>&1 || true
    fi
    mv "$file.new" "$file"
    echo "$new_accessor" >"$accessor_file"
    echo "secret_id nuevo en deploy/secrets/openbao/$(basename "$file")"
  fi
}

SECRET_ID_FILE="$SECRETS_DIR/secret-id"
VAULT_SECRET_ID_FILE="$SECRETS_DIR/vault-secret-id"
TERMINAL_SECRET_ID_FILE="$SECRETS_DIR/terminal-secret-id"
issue_secret_id infraward "$SECRET_ID_FILE"
issue_secret_id infraward-vault "$VAULT_SECRET_ID_FILE"
issue_secret_id infraward-terminal "$TERMINAL_SECRET_ID_FILE"

cat <<EOF

OpenBao listo en http://127.0.0.1:$PORT (KV v2 en secret/, CA SSH en $SSH_MOUNT/, política y rol 'infraward').
Añade a apps/api/.env y apps/worker/.env:

  SECRETS_PROVIDERS=openbao,local
  OPENBAO_ADDR=http://127.0.0.1:$PORT
  OPENBAO_ROLE_ID=$ROLE_ID
  OPENBAO_SECRET_ID_FILE=$SECRET_ID_FILE

Y SOLO a apps/api/.env (nunca al worker), para la caja fuerte en OpenBao:

  VAULT_PROVIDER=openbao
  VAULT_OPENBAO_ROLE_ID=$VAULT_ROLE_ID
  VAULT_OPENBAO_SECRET_ID_FILE=$VAULT_SECRET_ID_FILE

Y SOLO a apps/api/.env (nunca al worker ni al gateway), para la terminal:

  TERMINAL_OPENBAO_ROLE_ID=$TERMINAL_ROLE_ID
  TERMINAL_OPENBAO_SECRET_ID_FILE=$TERMINAL_SECRET_ID_FILE
EOF
