# InfraWard

Inventario inteligente de infraestructura (CMDB ligero con descubrimiento automático vía Ansible, escaneo con Trivy y secretos por referencias).

**El diseño completo está en [docs/DESIGN.md](docs/DESIGN.md). Lee solo la sección relevante para cada tarea.**

## Stack
- web: Angular 22 + OptimusNG (`@openng/optimus-ui`, preset Aura), iconos Bootstrap Icons (`bi bi-…`); rejilla editable del panel con gridstack.js (solo se carga al personalizar; en lectura, CSS grid); terminal con xterm.js (perezoso) en `/assets/:id/terminal`, por WebSocket al gateway a través de la propia web (`/gateway`, mismo origen: la cookie de la sesión viaja y el gateway la exige)
- api: NestJS 12 (ESM) + Fastify, TypeORM 1.x (solo migraciones, nunca `synchronize`), OpenAPI con Scalar (`/docs`, `/openapi.json`; en producción solo con `DOCS_PUBLIC=true`), sesión en cookie httpOnly + CSRF con guards globales (`@Public()` para excepciones) o token de API personal (`Authorization: Bearer iwt_…`; `@SessionOnly()` para lo que exige la sesión web), login local y OIDC (`openid-client`), TOTP para usuarios locales (obligatorio para admins) y reautenticación reciente de las acciones sensibles con `@RecentAuth()` (lista en `SENSITIVE_ACTIONS`), auditoría con `AuditService`, config validada con class-validator
- worker: NestJS 12 standalone (sin HTTP); consume las colas BullMQ, una por tipo de job con su concurrencia (también la muestra diaria de métricas de los gráficos del panel, `metrics.sample`, y las alertas fuera de la app: el líder reparte las notificaciones nuevas a los canales y `alert.deliver` (cola propia `alerts`) las envía por webhook firmado o SMTP, con protección SSRF; DESIGN §10); escalable a varias réplicas: límite por host, locks y líder en Redis, fencing con `job_runs.attempt` (DESIGN §20)
- gateway: modo `gateway` del worker (`node dist/main.js gateway`, otro proceso y contenedor; DESIGN §11): WebSocket de la terminal (`ws`), `ssh -tt` en un PTY con un puente en Python, saltos `pct enter`/`docker exec -it`; sin colas y **sin acceso al gestor de secretos** (no arranca con `SECRETS_*`/`OPENBAO_*`/`VAULT_*`): canjea tickets (con el hash de la cookie del upgrade) y pide los certificados a la API (`/internal/gateway/*`, secreto compartido); la API los firma con su propia AppRole de OpenBao (`TERMINAL_OPENBAO_*`); latido a la API y cortes al momento por Redis (`infraward:terminal:control`); quién abre terminal además de los admins: AccessPolicy (por asset, etiqueta o proyecto, `@CanOnAsset`)
- PostgreSQL 18 + Redis 7; pnpm workspaces (sin Nx); TypeScript ~6.0 (Angular no soporta TS 7); Vitest; ESLint 10 (flat config)

## Comandos
```bash
pnpm install
pnpm -r build                     # respeta el grafo: shared-types primero
pnpm -r lint
pnpm -r test
pnpm -r --if-present run test:cov && node scripts/ci/lcov-paths.mjs   # cobertura lcov (rutas desde la raíz del repo)
pnpm --filter @infraward/api test:e2e        # requiere el worker compilado; DATABASE_URL (crea BDs <bd>_e2e_*) y REDIS_URL o, si no, Testcontainers
pnpm dev                          # todo en modo watch: compila packages/ y lanza sus tsc --watch, API, worker, gateway (si existe apps/worker/.env.gateway; node --watch sobre dist/) y web (no levanta PostgreSQL/Redis)
pnpm --filter @infraward/api start:dev      # :3000; aplica migraciones al arrancar
pnpm --filter @infraward/api migration:generate src/database/migrations/<Nombre>  # y registrarla en migrations/index.ts (un test lo exige)
pnpm --filter @infraward/api migration:check    # falla si una entidad cambió sin migración (también en CI)
pnpm --filter @infraward/worker start:dev
pnpm --filter @infraward/worker start:gateway   # gateway suelto (tras compilar; pnpm dev ya lo lanza con dev:gateway); config en apps/worker/.env.gateway (cp .env.gateway.example), nunca el .env del worker
pnpm --filter @infraward/worker gateway:cli -- --api http://localhost:3000 --asset <id> [--gateway ws://localhost:3010]   # cliente de pruebas de la terminal (email/contraseña/TOTP por la terminal; manda la cookie de su login)
pnpm --filter @infraward/web start          # :4200; /api → API en :3000 (proxy.conf.json)
pnpm --filter @infraward/shared-types dev   # tsc --watch

cp deploy/.env.example deploy/.env
cp apps/api/.env.example apps/api/.env      # sesión, admin inicial, BD, Redis y clave maestra de secretos
(umask 177; mkdir -p deploy/secrets && openssl rand -base64 32 > deploy/secrets/master.key)  # SECRETS_LOCAL_MASTER_KEY_FILE
cp apps/worker/.env.example apps/worker/.env  # Redis, concurrencia, BD y la MISMA clave maestra que la API
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d   # o: pnpm infra:up
podman compose -f deploy/docker-compose.yml --env-file deploy/.env up -d   # con Podman
pnpm openbao:bootstrap            # OpenBao de desarrollo (perfil openbao): init, KV v2, CA SSH (infraward-ssh/, roles inventory e infraward-operator), AppRoles infraward, infraward-vault (caja fuerte) e infraward-terminal (las dos últimas solo API) y sus secret_id en deploy/secrets/openbao/ (CONTAINER_ENGINE=podman)
pnpm keycloak:bootstrap           # Keycloak de pruebas para OIDC (perfil oidc, :8081): secreto del cliente al proveedor de secretos y usuarios de prueba en deploy/secrets/keycloak/
printf '{"campo":"valor"}' | pnpm --filter @infraward/api secrets:put secret://local/<ruta>   # guarda un secreto (por stdin) con la config de la API
pnpm --filter @infraward/secrets test:integration   # contra OpenBao real: OPENBAO_TEST_ADDR + OPENBAO_TEST_ROOT_TOKEN o, si no, Testcontainers
pnpm --filter @infraward/worker test:integration    # coordinación entre réplicas (semáforo por host, locks, líder, identidad, JobRunner) contra Redis real: REDIS_TEST_URL o Testcontainers
pnpm --filter @infraward/api test:integration       # script de alta (estático, CA y acceso de administración), ayudante de root con sudo y sudo-rs, y SshClient del worker contra sshd y OpenBao reales (Testcontainers; requiere el worker compilado)
```

## Estructura
```
apps/web              Angular CLI + OptimusNG
apps/api              Nest CLI
apps/worker           Nest standalone (y el modo gateway: src/gateway/)
packages/shared-types DTOs, interfaces y lógica pura compartida por web y API (filtros del árbol, parser de la sintaxis de búsqueda, exclusiones, pesos y textos de la prioridad), sin dependencias de runtime (ESM, tsc -> dist/; tests con Vitest)
packages/domain       Entidades TypeORM (Asset, AssetRelation, Snapshot…), consultas de árbol y clasificación de paquetes del kernel; solo backend
packages/secrets      SecretsService/SecretsModule, parseSecretRef, claves SSH (generación ed25519, huellas), proveedores (local AES-256-GCM, OpenBao KV v2 + AppRole + CA SSH) y el almacén aparte de la caja fuerte (VaultStore: local con su clave u OpenBao con su AppRole; solo lo crea la API); solo backend
packages/connectors   Descubridores (interfaz Discoverer, Proxmox, Docker, Podman, Plesk), conectores de dominios (DomainProvider, Cloudflare, RDAP, lectura TLS, enlazado DNS), consultas del ayudante de root (privileged.ts), paquetes de los procesos en marcha (script que corre en el servidor, v6), rutas de proxies (filtro de `nginx -T` que corre en el servidor, etiquetas de Traefik/Caddy), caminos registro → servicio (services/, resolutores como plugins) y reconciliación pura; solo backend
ansible/enroll/       Plantilla del script de alta (la API la rellena y la sirve en /enroll/<token>); sudoers v8: una regla con el ayudante de root infraward-query (lista cerrada en packages/connectors/src/privileged.ts); acceso de administración opcional (cuenta infraward-admin con sudo, solo certificados de la CA, v1)
ansible/collect/      Playbook de recolección (solo lectura, sudo -n acotado) y plugin infraward_pct (CT por pct exec); lo lanza el worker
deploy/               docker-compose.yml (PostgreSQL + Redis; OpenBao con el perfil openbao; Keycloak de pruebas con el perfil oidc), openbao/ y keycloak/ (config y bootstrap) y .env.example
deploy/example/       despliegue con las imágenes publicadas (proyecto infraward-stack): compose.yml, compose.openbao.yml (OpenBao por defecto vía COMPOSE_FILE) e init.sh (clave maestra y bootstrap de OpenBao)
Dockerfile            imágenes con un target por servicio (api, worker, web); el CI las publica con cada tag vX.Y.Z
docs/                 DESIGN.md, SECURITY-NOTES.md
```
Dependencias internas con `workspace:*`. El gateway no es una app aparte: es un modo de `apps/worker`.

## Reglas duras
- **La web solo puede importar `@infraward/shared-types`.** Lo refuerza `no-restricted-imports` en `apps/web/eslint.config.js`.
- **La API nunca ejecuta Ansible ni Trivy**; todo trabajo pesado va por la cola al worker.
- **La terminal nunca entra con `inventory`** (solo con la cuenta del acceso de administración) y **el gateway nunca accede al gestor de secretos**.
- **Los secretos nunca se guardan en claro ni junto a su clave, ni se loguean, ni se devuelven al frontend.** En la BD solo hay referencias `secret://<proveedor>/<ruta>#<campo>` y, en `local_secrets`, el texto cifrado del proveedor local (su clave maestra vive fuera de la BD). Todo acceso a secretos pasa por `SecretsService` de `@infraward/secrets`, salvo la caja fuerte de credenciales: su propio `VaultStore`, solo en la API (el worker nunca lleva variables `VAULT_*`) y con «Revelar» como única salida del valor (solo admins, con reautenticación).
- **Los paquetes de `packages/` se compilan a `dist/`**; su `package.json` apunta a `dist/`. No usar `paths` de TypeScript al código fuente.
- Las entidades del inventario viven en `packages/domain`; las migraciones, en `apps/api` (la API las aplica). Los índices que TypeORM no sabe declarar (GIN, DESC) van en la migración y en la entidad con `@Index(..., { synchronize: false })`.
- Código ESM: los imports relativos en backend y packages llevan extensión `.js`.
- Nuevas dependencias con scripts de instalación: autorizarlas en `allowBuilds` de `pnpm-workspace.yaml`.
- **Al terminar cada sesión, hacer commit** (mensaje convencional: `feat:`, `chore:`, `fix:`…).
