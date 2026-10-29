# OpenBao de DESARROLLO para InfraWard (ver docs/DESIGN.md §6 y deploy/openbao/bootstrap.sh).
# Producción: TLS en el listener, un seal real (KMS/HSM o Shamir) y almacenamiento raft.
ui            = false
disable_mlock = true
api_addr      = "http://127.0.0.1:8200"

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Desellado automático con una clave en fichero: SOLO DESARROLLO. La crea bootstrap.sh en
# deploy/secrets/openbao/unseal.key, fuera de git. Con la clave en el mismo host que los datos,
# quien lea el disco lo tiene todo. En producción: desellado manual (Shamir, claves repartidas)
# o auto-unseal con un servicio externo (KMS de un proveedor cloud o `transit` de OTRO OpenBao).
seal "static" {
  current_key_id = "infraward-dev-1"
  current_key    = "file:///openbao/unseal/unseal.key"
}
