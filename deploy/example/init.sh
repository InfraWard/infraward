#!/usr/bin/env bash
# Prepara el despliegue de ejemplo antes del primer `up` (idempotente; se puede relanzar):
#   0. Directorios de datos (data/postgres, data/redis, data/worker y, con OpenBao, data/openbao)
#      con el propietario y permisos de cada contenedor; si ya existen, los comprueba y corrige.
#   1. Clave maestra del proveedor local (secrets/master.key), legible por los contenedores, y
#      la de la caja fuerte de credenciales (secrets/vault.master.key), que solo monta la API.
#   2. Si COMPOSE_FILE (en .env) incluye compose.openbao.yml, OpenBao:
#      - clave de desellado automático (secrets/openbao/unseal.key);
#      - init, con el material (clave de recuperación y token root) en secrets/openbao/init.json.
#        El token root solo se usa aquí, para configurar; la app entra siempre por AppRole;
#      - KV v2 en secret/, CA SSH en infraward-ssh/ (emisor ed25519 generado dentro de OpenBao y
#        rol `inventory`), política `infraward` mínima y rol AppRole `infraward`;
#      - caja fuerte: política `infraward-vault` y rol `infraward-vault` (solo la API);
#      - terminal: rol `infraward-operator` del motor SSH, política y AppRole
#        `infraward-terminal` (solo la API);
#      - secret_id en secrets/openbao/secret-id, vault-secret-id y terminal-secret-id, y
#        OPENBAO_ROLE_ID, VAULT_OPENBAO_ROLE_ID y TERMINAL_OPENBAO_ROLE_ID escritos en .env.
#   3. Secreto compartido entre la API y el gateway (secrets/gateway-api.secret).
#
# Uso: ./init.sh [--rotate-secret-id]     (CONTAINER_ENGINE=podman para forzar Podman)
set -euo pipefail

ROTATE=false
for arg in "$@"; do
  case "$arg" in
    --rotate-secret-id) ROTATE=true ;;
    *) echo "Opción desconocida: $arg" >&2; exit 2 ;;
  esac
done

cd "$(dirname "${BASH_SOURCE[0]}")"
[ -f .env ] || { echo "Falta .env: cp .env.example .env y ajústalo" >&2; exit 1; }

if [ -z "${CONTAINER_ENGINE:-}" ]; then
  if command -v docker >/dev/null 2>&1; then CONTAINER_ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then CONTAINER_ENGINE=podman
  else echo "Ni docker ni podman en el PATH" >&2; exit 1
  fi
fi
compose() { "$CONTAINER_ENGINE" compose "$@"; }

OPENBAO_IMAGE=quay.io/openbao/openbao:2.6.4
# Los contenedores no corren con el uid del host (api y worker: 1000; OpenBao: 100). El chown se
# hace desde un contenedor para que valga también con Podman rootless (uids del espacio de nombres).
chown_in_container() {
  local owner="$1" file="$2"
  "$CONTAINER_ENGINE" run --rm --user 0 --entrypoint chown \
    -v "$PWD/$(dirname "$file"):/target" "$OPENBAO_IMAGE" "$owner" "/target/$(basename "$file")"
}

# Directorios de datos (bind mounts) y uid:gid con el que escribe cada imagen:
#   postgres:18-alpine -> 70:70 (postgres), redis:7-alpine -> 999:1000 (redis),
#   worker (node) -> 1000:1000, openbao -> 100:1000 (openbao).
# Se corrige solo la raíz de cada directorio salvo que el propietario no coincida, en cuyo caso se
# hace chown -R (p. ej. tras copiar datos de un volumen con nombre o restaurar un backup).
fix_data_dir() {
  local dir="$1" owner="$2" mode="$3"
  mkdir -p "data/$dir"
  # shellcheck disable=SC2016 # se expanden dentro del contenedor
  "$CONTAINER_ENGINE" run --rm --user 0 --entrypoint sh -v "$PWD/data:/data" "$OPENBAO_IMAGE" -c '
    d="/data/$1"; o="$2"; m="$3"
    if [ "$(stat -c %u:%g "$d")" != "$o" ] || [ -n "$(find "$d" ! -user "${o%%:*}" -print -quit)" ]; then
      echo "  data/$1: propietario corregido a $o"; chown -R "$o" "$d"
    fi
    if [ "$(stat -c %a "$d")" != "$m" ]; then
      echo "  data/$1: permisos corregidos a $m"; chmod "$m" "$d"
    fi' sh "$dir" "$owner" "$mode"
}

COMPOSE_FILE_LINE="$(sed -n 's/^COMPOSE_FILE=//p' .env | tail -1)"
WITH_OPENBAO=false
[[ "$COMPOSE_FILE_LINE" == *compose.openbao.yml* ]] && WITH_OPENBAO=true

echo "Comprobando directorios de datos en data/"
mkdir -p data
chmod 755 data
fix_data_dir postgres 70:70 700
fix_data_dir redis 999:1000 700
fix_data_dir worker 1000:1000 700
[ "$WITH_OPENBAO" = true ] && fix_data_dir openbao 100:1000 700

umask 077
mkdir -p secrets

if [ ! -s secrets/master.key ]; then
  openssl rand -base64 32 >secrets/master.key
  chmod 400 secrets/master.key
  chown_in_container 1000:1000 secrets/master.key
  echo "Clave maestra creada en secrets/master.key."
  echo "  ¡Haz copia! Sin ella los secretos guardados son irrecuperables (nunca junto al backup de la BD)."
fi

if [ ! -s secrets/vault.master.key ]; then
  openssl rand -base64 32 >secrets/vault.master.key
  chmod 400 secrets/vault.master.key
  chown_in_container 1000:1000 secrets/vault.master.key
  echo "Clave de la caja fuerte creada en secrets/vault.master.key (solo la monta la API)."
  echo "  ¡Haz copia aparte! Sin ella las credenciales de la caja fuerte local son irrecuperables."
fi

if [ ! -s secrets/gateway-api.secret ]; then
  openssl rand -base64 48 | tr -d '\n' >secrets/gateway-api.secret
  chmod 400 secrets/gateway-api.secret
  chown_in_container 1000:1000 secrets/gateway-api.secret
  echo "Secreto del gateway creado en secrets/gateway-api.secret (lo montan la API y el gateway)."
fi

# Contraseña de Redis (secreto redis_password: la montan redis, api, worker y gateway). De
# 1000:1000 con 440: redis corre como 999:1000 y la lee por el grupo.
if [ ! -s secrets/redis.password ]; then
  openssl rand -hex 32 | tr -d '\n' >secrets/redis.password
  chmod 440 secrets/redis.password
  chown_in_container 1000:1000 secrets/redis.password
  echo "Contraseña de Redis creada en secrets/redis.password."
fi

if [ "$WITH_OPENBAO" != true ]; then
  echo "Sin OpenBao (COMPOSE_FILE no incluye compose.openbao.yml). Listo: $CONTAINER_ENGINE compose up -d"
  exit 0
fi

mkdir -p secrets/openbao
if [ ! -s secrets/openbao/unseal.key ]; then
  openssl rand -out secrets/openbao/unseal.key 32
  chmod 400 secrets/openbao/unseal.key
  chown_in_container 100:1000 secrets/openbao/unseal.key
  echo "Clave de desellado creada en secrets/openbao/unseal.key."
fi
# El servicio exige el fichero del secret_id aunque aún no exista: uno vacío hasta crearlo.
[ -e secrets/openbao/secret-id ] || : >secrets/openbao/secret-id
[ -e secrets/openbao/vault-secret-id ] || : >secrets/openbao/vault-secret-id
[ -e secrets/openbao/terminal-secret-id ] || : >secrets/openbao/terminal-secret-id
# Sin OPENBAO_ROLE_ID aún en .env, el compose no valida: valor provisional para levantar OpenBao.
export OPENBAO_ROLE_ID="${OPENBAO_ROLE_ID:-pendiente}"
export VAULT_OPENBAO_ROLE_ID="${VAULT_OPENBAO_ROLE_ID:-pendiente}"
export TERMINAL_OPENBAO_ROLE_ID="${TERMINAL_OPENBAO_ROLE_ID:-pendiente}"

compose up -d openbao >/dev/null
# CLI de OpenBao dentro del contenedor; el token viaja por variable de entorno, nunca en argv.
bao() {
  compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="${ROOT_TOKEN:-}" \
    openbao bao "$@"
}
# bao status: 0 = desellado, 2 = sellado o sin inicializar, 1 = no responde.
status() { bao status -format=json 2>/dev/null || true; }
echo -n "Esperando a OpenBao"
STATUS=""
for _ in $(seq 1 60); do
  STATUS="$(status)"
  [ -n "$STATUS" ] && break
  echo -n "."; sleep 1
done
echo
[ -n "$STATUS" ] || { echo "OpenBao no responde: $CONTAINER_ENGINE compose logs openbao" >&2; exit 1; }

INIT_FILE=secrets/openbao/init.json
if grep -q '"initialized": false' <<<"$STATUS"; then
  bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json >"$INIT_FILE"
  echo "OpenBao inicializado; material de init en $INIT_FILE (guárdalo fuera del servidor y bórralo de aquí)."
  for _ in $(seq 1 30); do
    grep -q '"sealed": false' <<<"$(status)" && break
    sleep 1
  done
elif [ ! -s "$INIT_FILE" ]; then
  echo "OpenBao ya está inicializado pero falta $INIT_FILE: no hay token para configurarlo." >&2
  echo "Si ya está configurado, no hace falta relanzar este script." >&2
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

# CA SSH (docs/DESIGN.md §6): mismos parámetros que deploy/openbao/bootstrap.sh.
SSH_MOUNT=infraward-ssh
if ! bao secrets list -format=json | grep -q "\"$SSH_MOUNT/\""; then
  bao secrets enable -path="$SSH_MOUNT" ssh >/dev/null
  echo "Motor SSH activado en $SSH_MOUNT/"
fi
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

# Política mínima: solo el subárbol de InfraWard (OPENBAO_KV_PREFIX=infraward) y firmar con la CA.
bao policy write infraward - >/dev/null <<'HCL'
path "secret/data/infraward/*" {
  capabilities = ["create", "read", "update"]
}
path "secret/metadata/infraward/*" {
  capabilities = ["read", "delete"]
}
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
ROLE_ID="$(bao read -field=role_id auth/approle/role/infraward/role-id | tr -d '\r')"

# Caja fuerte (QoL-7): su propio subárbol, política y AppRole, que solo usa la API. La política
# `infraward` (la del worker) no alcanza infraward-vault/: el worker no puede leerla.
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
VAULT_ROLE_ID="$(bao read -field=role_id auth/approle/role/infraward-vault/role-id | tr -d '\r')"

# Terminal (sesión 21): rol del motor SSH para la cuenta de administración de los servidores
# (principal de rol infraward-operators, solo permit-pty, minutos de vida), con su política y
# AppRole, que solo usa la API. Mismos parámetros que deploy/openbao/bootstrap.sh.
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
TERMINAL_ROLE_ID="$(bao read -field=role_id auth/approle/role/infraward-terminal/role-id | tr -d '\r')"

# secret_id de un rol en <fichero> (400, uid 1000); con --rotate-secret-id destruye el anterior.
issue_secret_id() {
  local role="$1" file="$2" accessor_file="$2.accessor"
  if [ "$ROTATE" = true ] || [ ! -s "$file" ]; then
    local response new_accessor
    response="$(bao write -f -format=json "auth/approle/role/$role/secret-id")"
    new_accessor="$(sed -n 's/.*"secret_id_accessor": *"\([^"]*\)".*/\1/p' <<<"$response")"
    if [ -s "$accessor_file" ]; then
      bao write "auth/approle/role/$role/secret-id-accessor/destroy" \
        secret_id_accessor="$(cat "$accessor_file")" >/dev/null 2>&1 || true
    fi
    rm -f "$file"
    sed -n 's/.*"secret_id": *"\([^"]*\)".*/\1/p' <<<"$response" >"$file"
    unset response
    chmod 400 "$file"
    chown_in_container 1000:1000 "$file"
    echo "$new_accessor" >"$accessor_file"
    echo "secret_id nuevo en $file"
    [ "$ROTATE" = true ] && echo "Reinicia api y worker para que lo usen: $CONTAINER_ENGINE compose restart api worker gateway"
  fi
  return 0
}

issue_secret_id infraward secrets/openbao/secret-id
issue_secret_id infraward-vault secrets/openbao/vault-secret-id
issue_secret_id infraward-terminal secrets/openbao/terminal-secret-id

# role_id en .env (no es secreto por sí solo: sin el secret_id no sirve).
if grep -q '^OPENBAO_ROLE_ID=' .env; then
  sed -i.bak "s|^OPENBAO_ROLE_ID=.*|OPENBAO_ROLE_ID=$ROLE_ID|" .env && rm -f .env.bak
else
  printf '\nOPENBAO_ROLE_ID=%s\n' "$ROLE_ID" >>.env
fi
if grep -q '^VAULT_OPENBAO_ROLE_ID=' .env; then
  sed -i.bak "s|^VAULT_OPENBAO_ROLE_ID=.*|VAULT_OPENBAO_ROLE_ID=$VAULT_ROLE_ID|" .env && rm -f .env.bak
else
  printf 'VAULT_OPENBAO_ROLE_ID=%s\n' "$VAULT_ROLE_ID" >>.env
fi

if grep -q '^TERMINAL_OPENBAO_ROLE_ID=' .env; then
  sed -i.bak "s|^TERMINAL_OPENBAO_ROLE_ID=.*|TERMINAL_OPENBAO_ROLE_ID=$TERMINAL_ROLE_ID|" .env && rm -f .env.bak
else
  printf 'TERMINAL_OPENBAO_ROLE_ID=%s\n' "$TERMINAL_ROLE_ID" >>.env
fi

echo
echo "OpenBao listo (KV v2 en secret/, CA SSH en $SSH_MOUNT/, AppRoles 'infraward', 'infraward-vault' e 'infraward-terminal'; sus role_id en .env)."
echo "Siguiente paso: $CONTAINER_ENGINE compose up -d"
