# OpenBao del despliegue de ejemplo (compose.openbao.yml); lo inicializa y configura init.sh.
# Solo es accesible desde la red interna del compose (sin puerto publicado), sin TLS.
ui            = false
disable_mlock = true
api_addr      = "http://openbao:8200"

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Desellado automático con una clave en fichero (secrets/openbao/unseal.key, la crea init.sh):
# OpenBao vuelve solo tras un reinicio. Pero con la clave en el mismo host que los datos, quien
# lea el disco lo tiene todo. Para más garantías, quita este bloque (desellado manual con Shamir:
# `docker compose exec openbao bao operator unseal` tras cada arranque) o usa auto-unseal con un
# servicio externo (KMS de un proveedor cloud o `transit` de otro OpenBao).
seal "static" {
  current_key_id = "infraward-1"
  current_key    = "file:///openbao/unseal/unseal.key"
}
