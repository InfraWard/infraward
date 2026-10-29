# InfraWard

Inventario inteligente de infraestructura: un CMDB ligero que se rellena solo. Das de alta un servidor con un comando y InfraWard se conecta por SSH, recoge su información con Ansible, descubre lo que contiene (CT y VMs de Proxmox, contenedores Docker, dominios de Plesk…), escanea sus imágenes con Trivy y mantiene el inventario al día mediante reconciliación periódica.

## Funcionalidades

- **Alta de servidores en un paso**: un token de un solo uso y un `curl … | bash` que crea un usuario de inventario con un `sudoers` mínimo: una sola regla para un ayudante de root con una lista cerrada de consultas. Son de solo lectura salvo en los nodos Proxmox, donde `pct-exec` ejecuta como root cualquier comando dentro de sus CT (así se recogen con Ansible; un CT privilegiado no aísla del host). En los hosts Docker, las consultas al demonio exponen la configuración de los contenedores. Ver [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md). Las huellas de las host keys quedan fijadas desde el primer momento. El progreso se sigue en tiempo real desde la web.
- **Descubrimiento recursivo** de Proxmox (CT y VMs), Docker (contenedores, imágenes, redes y volúmenes) y Plesk, con relaciones entre assets y vista de topología.
- **Vulnerabilidades y SBOMs**: escaneo de imágenes y servidores con Trivy, SBOMs CycloneDX guardados y reevaluados periódicamente, y un buscador que responde al momento a «¿qué está afectado por este CVE?». «Buscar vulnerabilidades nuevas» reevalúa los SBOMs con la última BD de Trivy sin volver a escanear.
- **Priorización**: KEV de CISA, EPSS, ruido («sin corrección prevista», kernel que no está en uso) y contexto de servicio (expuesto a Internet, qué dominios sirve), con avisos de los CVE críticos en KEV y expuestos.
- **Reconciliación**: el inventario se actualiza solo, con historial de snapshots y retirada de lo que desaparece.
- **Inventario de dominios**: Cloudflare, RDAP, certificados TLS y detección de registros DNS colgantes, enlazados con los servidores, avisos de caducidad y el camino de cada dominio hasta el servicio que lo sirve (nginx, Nginx Proxy Manager, etiquetas de Traefik y Caddy, y reenvíos NAT declarados).
- **Terminal web**: terminal interactiva en el navegador sobre servidores, CT y contenedores, con certificados SSH de pocos minutos, permisos por asset, etiqueta o proyecto (`AccessPolicy`) y cortes al momento. Solo en servidores con el acceso de administración activado.
- **Caja fuerte de credenciales**: contraseñas de consola, paneles web, IPMI…, en un almacén separado que el worker no puede leer, con revelado tras reautenticación, versiones y papelera.
- **Secretos por referencia**: en la base de datos solo hay referencias `secret://…`. Los valores viven en OpenBao (KV v2 y CA SSH con certificados de vida corta) o en un proveedor local cifrado con AES-256-GCM.
- **Usuarios y auditoría**: roles (admin, editor, operador, auditor, lector), login local u OIDC, MFA con TOTP (obligatorio para los admins) y reautenticación reciente para las acciones sensibles, sesión en cookie httpOnly con CSRF, tokens de API personales y registro de auditoría.
- **Organización y operaciones en lote**: proyectos, etiquetas con estilo y políticas de inventario, búsqueda con sintaxis de filtros (`tag:prod ip:10.0.0.0/24 -estado:retirado`), acciones sobre varios assets a la vez y exportación a CSV o JSON.
- **Paneles personalizables**: widgets en una rejilla editable, por usuario y por proyecto, con gráficos de evolución.
- **Varias réplicas del worker**: colas por tipo de trabajo, límite de jobs por servidor, locks y líder en Redis.

Pendiente: grabación de las sesiones de la terminal, gateway SSH con `ssh` nativo, proveedor Vaultwarden y workers remotos por sitio (ver [docs/DESIGN.md](docs/DESIGN.md)).

## Arquitectura

| Servicio | Tecnología | Función |
|---|---|---|
| `web` | Angular + OptimusNG, servido por nginx | Interfaz; reenvía `/api/` a la API |
| `api` | NestJS + Fastify + TypeORM | REST con OpenAPI (`/docs`, en producción solo con `DOCS_PUBLIC=true`), autenticación, alta de servidores; aplica las migraciones al arrancar |
| `worker` | NestJS standalone + Ansible + Trivy | Recolección, descubrimiento, escaneos y reconciliación (consume las colas; escalable a varias réplicas) |
| `gateway` | La imagen del worker en modo `gateway` | Terminal interactiva (WebSocket → SSH con PTY) con la cuenta de administración de cada servidor; sin colas y sin acceso a los secretos |
| PostgreSQL 18 | | Inventario, SBOMs, findings, auditoría |
| Redis 7 | | Cola de trabajos (BullMQ) |
| OpenBao | opcional | Proveedor de secretos y CA SSH |

La API nunca ejecuta Ansible ni Trivy: todo el trabajo pesado va por la cola al worker.

## Despliegue con contenedores

Cada versión `vX.Y.Z` publica tres imágenes en GitHub Container Registry: `ghcr.io/infraward/web`, `ghcr.io/infraward/api` y `ghcr.io/infraward/worker`, con los tags `vX.Y.Z` y `latest`. En [deploy/example/](deploy/example/) hay un despliegue de ejemplo con las tres más PostgreSQL, Redis y, por defecto, OpenBao.

```bash
cd deploy/example
cp .env.example .env          # registro, versión, URL pública, admin inicial y contraseña de PostgreSQL
./init.sh                     # clave maestra y OpenBao (init, KV v2, CA SSH y AppRole)
docker compose up -d          # o: podman compose up -d (CONTAINER_ENGINE=podman ./init.sh)
```

La web queda en `INFRAWARD_PUBLIC_URL` (por defecto `http://localhost:8080`) y la API detrás, en `/api`. Notas:

- **OpenBao** ([compose.openbao.yml](deploy/example/compose.openbao.yml)) está activado por defecto con `COMPOSE_FILE` en el `.env`. Guarda los secretos (`SECRETS_PROVIDERS=openbao,local`) y hace de CA SSH, así que los servidores se dan de alta con certificados de vida corta en lugar de claves por servidor. `init.sh` deja el material de init (clave de recuperación y token root) en `secrets/openbao/init.json`: guárdalo fuera del servidor y bórralo de ahí. OpenBao se desella solo con `secrets/openbao/unseal.key`; para más garantías, cambia a desellado manual o a auto-unseal externo (ver [openbao/config.hcl](deploy/example/openbao/config.hcl)). Para usar solo el proveedor local, borra `COMPOSE_FILE` y `OPENBAO_ROLE_ID` del `.env` antes de `init.sh`. La **caja fuerte de credenciales** (contraseñas de consola, paneles web, IPMI…) va en OpenBao con su propia AppRole (`infraward-vault`, `VAULT_OPENBAO_ROLE_ID` en el `.env`) y su propio prefijo, montada solo en la API: el worker no puede leerla. `./init.sh --rotate-secret-id` renueva las credenciales de las dos AppRoles. **Al actualizar desde una versión anterior** a la caja fuerte, vuelve a ejecutar `./init.sh` antes del `up`: crea su clave, su política, su AppRole y su secret_id y escribe `VAULT_OPENBAO_ROLE_ID` en el `.env` (sin eso, `compose.openbao.yml` no valida).
- **HTTPS**: la cookie de sesión es `Secure` (`__Host-`). Los navegadores la aceptan en `http://localhost`, pero en cualquier otro host hace falta un proxy con TLS delante de `web`. `INFRAWARD_PUBLIC_URL` debe ser la URL https final, porque los servidores descargan de ahí el script de alta.
- **Claves maestras** (`secrets/master.key` y, para la caja fuerte sin OpenBao, `secrets/vault.master.key`, que solo monta la API; las crea `init.sh`): sin ellas los secretos del proveedor local y las credenciales de la caja fuerte son irrecuperables. Haz copia, pero nunca en el mismo backup que la base de datos. Los ficheros de `secrets/` quedan con el propietario de los contenedores (uid 1000 y, para OpenBao, uid 100).
- **Datos persistentes** en `data/` (bind mounts, no volúmenes con nombre), junto al `compose.yml`, así que se respaldan y se mueven como cualquier directorio. `init.sh` crea cada directorio y comprueba (y corrige, también al relanzarlo) su propietario y permisos (`700`):

  | Directorio | Servicio | Propietario (uid:gid) |
  |---|---|---|
  | `data/postgres` | PostgreSQL (`/var/lib/postgresql`) | `70:70` |
  | `data/redis` | Redis, AOF (`/data`) | `999:1000` |
  | `data/worker` | Worker: caché de Trivy (unos 3 GB) y escaneos (`/var/lib/infraward`) | `1000:1000` |
  | `data/openbao` | OpenBao, almacenamiento `file` (`/openbao/file`) | `100:1000` |

  Con SELinux (Podman en Fedora/RHEL) puede hacer falta añadir `:Z` a los montajes.
- **Migrar desde los volúmenes con nombre** (despliegues anteriores con `postgres-data`, `redis-data`, `worker-data` y `openbao-data`):

  ```bash
  docker compose down
  ./init.sh                                    # crea data/*
  for v in postgres redis worker openbao; do   # openbao solo si lo usabas
    docker run --rm -v infraward-stack_$v-data:/from:ro -v "$PWD/data/$v:/to" \
      docker.io/library/alpine sh -c 'cp -a /from/. /to/'
  done
  ./init.sh                                    # corrige propietarios tras la copia
  docker compose up -d
  ```

  Comprueba que todo funciona antes de borrar los volúmenes viejos (`docker volume rm infraward-stack_postgres-data …`). La caché de Trivy (`worker`) no hace falta copiarla: se vuelve a descargar.
- **Redis con contraseña**: en `secrets/redis.password` (la crea `init.sh`). Redis, la API, el worker y el gateway la montan como secreto (`REDIS_PASSWORD_FILE`), así que no aparece en el entorno de los contenedores ni en `docker inspect`. Al actualizar desde una versión anterior, ejecuta `./init.sh` antes de `docker compose up -d`. PostgreSQL, Redis y OpenBao están en una red interna, sin puerto publicado.
- **Varias réplicas del worker**: `docker compose up -d --scale worker=3` (o `WORKER_REPLICAS=3` en el `.env`). Se reparten los jobs sin duplicarlos, con como mucho `HOST_MAX_JOBS` (2) jobs a la vez contra un mismo servidor —un CT cuenta contra su nodo— y `HOST_MAX_SCAN_JOBS` (1) escaneos, sumando todas. Comparten `data/worker` (obligatorio: una sola descarga de la BD de Trivy). Al parar, cada réplica espera a sus jobs como mucho `WORKER_SHUTDOWN_GRACE` (90 s) y devuelve a la cola los que no terminen; el job de una réplica caída lo retoma otra. La Actividad dice qué réplica ejecuta cada job. Ver [DESIGN §20](docs/DESIGN.md).
- **Terminal (gateway)**: el servicio `gateway` usa la imagen del worker con `command: ["node", "dist/main.js", "gateway"]` y publica el WebSocket en `INFRAWARD_GATEWAY_PORT` (3010); fuera de localhost, ponlo detrás de un proxy con TLS y cambia `INFRAWARD_GATEWAY_URL` a `wss://…`. Habla con la API por la red interna con `secrets/gateway-api.secret` (lo crea `init.sh`) y nunca recibe los secretos de la app. Los certificados de la terminal los firma la API con su propia AppRole de OpenBao (`infraward-terminal`, `TERMINAL_OPENBAO_ROLE_ID` en el `.env`): sin OpenBao no hay terminal. **Al actualizar**, vuelve a ejecutar `./init.sh` antes del `up` (crea el secreto, el rol, la AppRole y su secret_id). Solo se abre en servidores con el acceso de administración activado. Ver [DESIGN §7 y §11](docs/DESIGN.md).
- Para OIDC y el resto de opciones, ver las variables comentadas en [apps/api/.env.example](apps/api/.env.example) y [apps/worker/.env.example](apps/worker/.env.example). Se pasan como `environment` a `api` y `worker`.

Para construir las imágenes en local:

```bash
docker build --target api -t infraward-api .      # también: worker, web
```

### Requisitos de los servidores inventariados

`sudo` (el script de alta puede instalarlo con `--install-sudo`) y `python3` para la recolección con Ansible. Dentro de los CT de Proxmox también hace falta `python3`.

## Desarrollo

Requiere Node 24, pnpm (por Corepack) y Docker o Podman para PostgreSQL y Redis.

```bash
corepack enable
pnpm install
cp deploy/.env.example deploy/.env
cp apps/api/.env.example apps/api/.env
cp apps/worker/.env.example apps/worker/.env
(umask 177; mkdir -p deploy/secrets && openssl rand -base64 32 > deploy/secrets/master.key)
pnpm infra:up                 # PostgreSQL + Redis (deploy/docker-compose.yml)
pnpm dev                      # paquetes, API (:3000), worker y web (:4200) en modo watch
```

El worker necesita `ansible-playbook` y `trivy` en el `PATH` para recoger y escanear.

La **caja fuerte de credenciales** viene desactivada (`VAULT_PROVIDER=none`). Para activarla, solo en `apps/api/.env` (nunca en el worker): con OpenBao, `pnpm openbao:bootstrap` imprime `VAULT_PROVIDER=openbao`, `VAULT_OPENBAO_ROLE_ID` y `VAULT_OPENBAO_SECRET_ID_FILE`; sin OpenBao, `VAULT_PROVIDER=local` y una clave propia (`(umask 177; openssl rand -base64 32 > deploy/secrets/vault.master.key)` en `VAULT_LOCAL_MASTER_KEY_FILE`, distinta de `master.key`). Ver `apps/api/.env.example`.

| Comando | Qué hace |
|---|---|
| `pnpm -r build` / `lint` / `test` | Compilación, lint y tests unitarios de todo el monorepo |
| `pnpm --filter @infraward/api test:e2e` | E2E de la API (PostgreSQL y Redis por `DATABASE_URL`/`REDIS_URL` o Testcontainers) |
| `pnpm --filter @infraward/api test:integration` | Alta, ayudante de root y SSH contra sshd y OpenBao reales (Testcontainers) |
| `pnpm openbao:bootstrap` | OpenBao de desarrollo con KV, CA SSH y las AppRoles de la app, de la caja fuerte y de la terminal |
| `pnpm keycloak:bootstrap` | Keycloak de pruebas para OIDC |

Las reglas del monorepo están en [docs/DESIGN.md](docs/DESIGN.md) (§4).

### Estructura

```
apps/web               Angular + OptimusNG
apps/api               API NestJS (migraciones en src/database/migrations)
apps/worker            Worker NestJS standalone
packages/shared-types  DTOs compartidos (lo único que importa la web)
packages/domain        Entidades TypeORM del inventario
packages/secrets       SecretsService y proveedores (local, OpenBao)
packages/connectors    Descubridores y conectores de dominios
ansible/               Script de alta y playbook de recolección
deploy/                Compose de desarrollo, OpenBao, Keycloak y despliegue de ejemplo
```

## CI/CD

El CI del proyecto compila, pasa lint y tests (unitarios, e2e, integración) y comprueba que no falten migraciones en cada cambio. Cada tag `vX.Y.Z` construye además las imágenes (`docker build --target …`, como en [Despliegue con contenedores](#despliegue-con-contenedores)), las escanea con Trivy y, si todo ha pasado, las publica en GitHub Container Registry y publica el código de esa versión en [GitHub](https://github.com/InfraWard/infraward).

## Documentación

- [docs/DESIGN.md](docs/DESIGN.md): diseño completo (modelo de datos, secretos, alta, descubrimiento, seguridad).
- [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md): modelo de autorización, compromisos de seguridad del diseño y lista de comprobación del despliegue.

## Licencia

[GNU Affero General Public License v3.0](LICENSE). Si ofreces una versión modificada de InfraWard como servicio de red, debes poner su código fuente a disposición de sus usuarios.
