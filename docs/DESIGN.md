# InfraWard — Documento de diseño

> InfraWard es un inventario inteligente de infraestructura. Documento de referencia del proyecto. Describe la visión, la arquitectura y las decisiones técnicas tomadas. Pensado para servir de contexto a agentes de código y a cualquier persona que se incorpore al proyecto.

---

## 1. Visión

Un **CMDB ligero con descubrimiento automático**. El objetivo es que el usuario añada un servidor con un clic y un comando, y que a partir de ahí la aplicación:

- Se conecte por SSH y recoja toda la información del servidor mediante **Ansible**.
- Detecte qué tipo de máquina es (Proxmox, Plesk, host Docker, servidor genérico) y **descubra recursivamente** todo lo que contiene: CT y VMs de Proxmox, contenedores Docker, dominios de Plesk, etc.
- Escanee vulnerabilidades con **Trivy** y guarde los **SBOMs** para poder responder al instante a la pregunta "¿qué servidores y servicios están afectados por este CVE?".
- Mantenga el inventario **actualizado solo** mediante reconciliación periódica, con historial de cambios.
- Gestione las credenciales a través de un **proveedor de secretos intercambiable** (OpenBao, Vaultwarden o un proveedor local cifrado).
- Permita abrir una **terminal interactiva en el navegador** en cualquier asset (servidor, CT, contenedor) y, como evolución, actúe de **gateway SSH** con auditoría y grabación de sesiones.
- Inventaríe **dominios y registros DNS** conectando cuentas de proveedores (Cloudflare, registradores) y los relacione con los servidores del inventario.

Caso ideal: añades tu Proxmox principal, ejecutas un comando y en unos minutos tienes el árbol completo de CT, VMs, contenedores y sus vulnerabilidades, que se mantiene al día sin intervención.

---

## 2. Stack tecnológico

| Capa | Tecnología |
|---|---|
| Frontend | Angular + **OptimusNG** (fork de PrimeNG por temas de licencia) |
| API | NestJS + Fastify + TypeORM + Scalar (documentación OpenAPI) |
| Worker | NestJS standalone, con dos modos de arranque: `worker` (jobs) y `gateway` (sesiones interactivas) |
| Gateway | Modo `gateway` del worker (NestJS + `ssh2`): terminal web y gateway SSH |
| Terminal web | xterm.js sobre WebSocket |
| Base de datos | PostgreSQL (con JSONB e índices GIN) |
| Cola | BullMQ sobre Redis |
| Automatización | Ansible (`ansible-playbook` con callback JSON o `ansible-runner`) |
| Seguridad | Trivy (escaneo de vulnerabilidades y generación de SBOM CycloneDX) |
| Secretos | OpenBao / Vaultwarden (`bw serve`) / proveedor local cifrado |
| Monorepo | **pnpm workspaces** (sin Nx). Turborepo opcional en el futuro |
| CI/CD | GitLab CI (el pipeline no forma parte del código publicado) |

---

## 3. Componentes

### Servicios propios (desplegables)

1. **web** — Frontend Angular + OptimusNG.
2. **api** — NestJS + Fastify. Gestiona el inventario, la autenticación, el alta de servidores (tokens de enrolamiento y endpoint que sirve el script), la búsqueda de CVEs y encola jobs. **Nunca ejecuta Ansible ni Trivy directamente.**
3. **worker** — Consume la cola y hace el trabajo pesado: lanza playbooks, ejecuta Trivy, re-evalúa SBOMs, llama a las APIs de Proxmox, Plesk y proveedores de dominios y resuelve secretos.
4. **gateway** — Mismo código e imagen que el worker, arrancado en modo `gateway` (`node dist/main.js gateway`: otro comando, **otro proceso** y otro contenedor). Atiende solo las conexiones interactivas de larga duración: el WebSocket de la terminal (`/terminal`) y, más adelante, un servidor SSH. No consume colas, no se presenta a líder y **no accede al gestor de secretos** (no arranca si recibe `SECRETS_*`, `OPENBAO_*`, `VAULT_*` o `TERMINAL_OPENBAO_*`): los certificados de cada sesión los firma la API. Reutiliza el cliente SSH, las rutas de los assets y el semáforo por host del worker, pero un escaneo pesado o un reinicio del worker no corta las terminales abiertas. Hecho en la sesión 21 (§11); ver también §12 y §18.

El **scheduler** (jobs periódicos) son *job schedulers* de BullMQ que programa la réplica **líder** del worker (§20). El worker se puede escalar a varias réplicas (§20).

El **contenido de Ansible** (playbooks, roles, plantilla del script de alta) no es un servicio: se empaqueta dentro de la imagen del worker.

### Dependencias externas

- PostgreSQL
- Redis
- Opcionales: OpenBao, o sidecar `bw serve` para Vaultwarden; un proveedor OIDC (Keycloak, Authentik, Google, Entra…) para el login (§14). En desarrollo, un Keycloak de pruebas bajo el perfil `oidc` del compose (`pnpm keycloak:bootstrap`).

En producción: **4 servicios propios** (web, api, worker y gateway) **+ 2 dependencias** en un `docker compose` (más OpenBao, necesario para la terminal).

---

## 4. Estructura del monorepo

Un único repositorio con **pnpm workspaces**.

```
infraward/
├── pnpm-workspace.yaml
├── package.json
├── tsconfig.base.json
├── apps/
│   ├── web/              # Angular CLI + OptimusNG
│   ├── api/              # Nest CLI
│   └── worker/           # Nest standalone; modos `worker` y `gateway`
├── packages/
│   ├── shared-types/     # DTOs e interfaces puras, sin dependencias
│   ├── domain/           # Entidades TypeORM y lógica de dominio (solo backend)
│   ├── secrets/          # SecretProvider + openbao, vaultwarden, local (solo backend)
│   └── connectors/       # Descubridores: proxmox, plesk, docker, dominios (solo backend)
├── ansible/
│   ├── playbooks/        # Detección, facts, descubrimiento
│   ├── roles/
│   └── enroll/           # Plantilla del script de alta
└── deploy/
    └── docker-compose.yml
```

```yaml
# pnpm-workspace.yaml
packages:
  - "apps/*"
  - "packages/*"
```

### Reglas del monorepo

- Las dependencias internas se declaran con `workspace:*` (por ejemplo `"@infraward/domain": "workspace:*"`).
- Cada paquete de `packages/` **se compila a `dist/`** (con `tsc` o `tsup`) y su `package.json` apunta a `dist/index.js` y `dist/index.d.ts`. En desarrollo se usa `tsc --watch`. No usar *paths* de TypeScript apuntando al código fuente.
- `pnpm -r build` construye respetando el grafo de dependencias.
- En CI: `pnpm --filter "...[origin/main]" build` para construir solo lo afectado.
- **La web solo puede importar `@infraward/shared-types`.** `domain`, `secrets` y `connectors` son exclusivos del backend. Se refuerza con `no-restricted-imports` de ESLint en `apps/web` para evitar arrastrar TypeORM al bundle del navegador.
- El **gateway no es una app aparte**: es un modo de arranque de `apps/worker` (por ejemplo `node dist/main.js gateway`), con su propio contenedor en el compose. Todo el backend sigue en TypeScript y comparte tipos sin generadores. Se descartó Go para no duplicar en otro lenguaje la lógica de conexión ni, sobre todo, el código criptográfico de secretos.

---

## 5. Modelo de datos

El inventario debe poder guardar "cualquier cosa", así que el modelo es **genérico**, no una tabla por tipo de recurso.

### Asset
Entidad base de todo el inventario.
- `type`: `server`, `vm`, `lxc`, `container`, `image`, `volume`, `network`, `subscription`, `domain`, `database`, `certificate`, `dns_record`, `dns_provider`, … (`image`, `volume`, `network`, `subscription`, `certificate` y `dns_provider` solo los crean los descubridores, el escaneo y `/connectors`: `DISCOVERED_ASSET_TYPES`)
- Nombre (QoL-3): `discoveredName` (`discovered_name`, lo escribe el descubridor —o el alta a mano— y la reconciliación lo mantiene al día), `displayName` (`display_name`, puesto a mano; null = no renombrado) y `name`, el **nombre visible**: columna **generada** por PostgreSQL (`COALESCE(display_name, discovered_name)`, `STORED`), así todas las consultas leen el visible sin cambios y nadie puede escribirlo (TypeORM la ignora al guardar y la relee tras insertar o actualizar; en la entidad es `readonly`). Se busca por los dos.
- `status` (`pending_enrollment`, `active`, `missing`, `retired`, …)
- `roles`: roles detectados (`proxmox-node`, `plesk`, `docker-host`, …)
- `tags`: puestos a mano (API); ningún descubridor ni la reconciliación los toca (los de Proxmox se quedan en `facts.proxmox.tags`). Color opcional en `TagStyle`.
- `notes`: Markdown escrito a mano (≤ 20 000 caracteres; solo en `GET /assets/:id`, nunca en el árbol ni en listas)
- `effectiveProjects` (`effective_projects uuid[]`, índice GIN): proyectos a los que pertenece, heredados incluidos, calculados junto con la política (abajo y §10)
- `naturalKey`: identificador estable entre ejecuciones (ver §8)
- `facts`: JSONB con los datos variables
- `hostKeyFingerprint`: huella SSH guardada en el primer contacto
- `connection`: cómo se conecta el worker (`host`, `port`, `user`); no contiene secretos
- `credentials`: **referencias** a secretos, nunca valores (p. ej. `sshPrivateKey: secret://local/assets/<id>/ssh#privateKey`; en un conector de dominios, `apiToken: secret://<proveedor>/connectors/<id>/<tipo>#apiToken`). La baja o la purga borran del proveedor la ruta de cada referencia
- `effectivePolicy`: la política de inventario efectiva (§10) con el origen de cada campo, calculada y guardada
- Mantenimiento (§10): `missingRuns` y `missingSince` (descubrimientos completos sin verlo), `missingScopeId` (quién cuenta esas ausencias: su padre o, en una imagen, el último host que la tenía), `retiredAuto` (retirado por la reconciliación, no a mano) y `reconciledAt` (nodos raíz: última reconciliación)

### Enrollment
Proceso de alta (`initial`) o de actualización del sudoers (`sudoers_update`) de un servidor (§7): método (`script` o `manual`), estado (`pending → confirmed → verified | failed`, o `cancelled`), hash SHA-256 del token (nunca el token), caducidad, clave pública instalada, usuario SSH, huellas de host key reportadas por el script, versión del sudoers leída al verificar y error. **No se borra al completarse**: es el historial de cuándo y cómo se dio de alta cada servidor y sirve para las rotaciones. Como mucho hay uno abierto (`pending`/`confirmed`) por asset.

### AssetRelation
Relaciones dirigidas (origen = `parent`). `contains` es la jerarquía padre-hijo (`Proxmox → CT → contenedor Docker`, `Plesk → suscripción → dominio → base de datos/certificado`) y forma la vista en árbol. Las que mantienen el worker y los descubridores (`DISCOVERED_RELATION_TYPES`, no se crean a mano):
- `instance_of`: contenedor → la imagen que ejecuta (como mucho una).
- `mounts`: contenedor → volumen de Docker que monta; `attached_to`: contenedor → red de Docker. Responden a «qué contenedor usa este volumen» y «qué contenedores comparten esta red» con las relaciones entrantes del volumen o la red.
- `stores`: host Docker → imagen que tiene (la use o no algún contenedor).
- `secured_by`: dominio (Plesk) o registro DNS → certificado TLS que usa o que sirve en su 443.
- `resolves_to` (QoL-5): registro DNS → asset al que apunta (A/AAAA → servidor, VM o CT con esa IP; CNAME → registro o dominio del inventario con ese nombre). Lo mantiene el enlazado de §13; ya no se crea a mano.
- `served_by` (QoL-5b): registro DNS → asset final que lo sirve (contenedor, CT, servidor), calculado o fijado a mano; `routes_to`: eslabón → siguiente eslabón de esos caminos (host → contenedor que publica el puerto, proxy → contenedor de destino). Los mantiene el `ServiceLinker` de §13.

No forman parte del árbol (`TREE_HIDDEN_ASSET_TYPES`): las imágenes (compartidas por contenedores de distintos hosts) y los volúmenes y redes de Docker (cuelgan con `contains` de su host, pero un host con decenas ahogaría el árbol; se ven en la ficha del host con `GET /assets/:id/docker` y en las relaciones de cada contenedor). La baja en cascada sí los recorre.

En la API, `GET /assets/tree` y `GET /assets/:id/tree` devuelven siempre nodos **resumidos** (`AssetTreeSummaryNode`: id, nombre, tipo, estado, roles, tags, `openFindings` —los findings `open` por severidad; en un contenedor, los de su imagen— y `fixableFindings` —los CRITICAL y HIGH abiertos con parche—); nunca facts, conexión ni credenciales, que la ficha carga con `GET /assets/:id`. Para distinguir assets con el mismo nombre, cada nodo lleva además, leídos con rutas de JSONB concretas (sin cargar los facts):
- `address`: host de conexión (con el puerto si no es el 22, y la IPv4 propia si es otra, p. ej. tras un NAT) o la IPv4 por defecto de un servidor; la IPv4 de una interfaz real de un CT/VM (o la fija de `net0`); los puertos publicados de un contenedor (`8080→80/tcp`).
- `runtimeState` (`running` | `stopped` | `paused` | `other`) y `runtimeDetail`: el **estado de ejecución** según Docker o Proxmox, distinto del estado de inventario (`status`). Un contenedor `exited` o `created` está `stopped` aunque siga `active` en el inventario.
- `sudoersOutdated` y `collectionWarnings` (número de avisos de recolección parcial de `facts.infraward`): los filtros de «avisos» del inventario y del panel.
- `machineIdClone` (clon sin regenerar, §8), `expiresAt` (fin de validez de un certificado o caducidad de un dominio por RDAP) y `dnsWarning` (registro DNS colgante sin marcar como esperado: `high` o `info`, §13).

`GET /assets/:id/ancestors` da los antepasados `contains` de la raíz al padre (migas de la ficha). `GET /assets/:id/relations` acompaña cada relación con el resumen del otro extremo (`peer`).

**Grafos de relaciones (QoL-4)**, con nodos resumidos como el árbol (`GraphNode`: id, nombre, tipo, estado, dirección, estado de ejecución, CRITICAL abiertos —un contenedor, los de su imagen—, severidad máxima, `parentId`, `depth`, `hidden` y `hiddenCritical`; nunca facts, conexión ni credenciales) y aristas `GraphEdge` (`source` = `parent` de la relación, `type`, `count`). Ninguno carga el grafo entero sin control:
- `GET /assets/:id/graph?depth=1..3`: **mapa** centrado en el asset (en un registro DNS lleva además `servicePath`, los assets de su camino hasta el servicio, que siempre entran en el mapa con las relaciones entre ellos, QoL-5b); recorre las relaciones de cualquier tipo en los dos sentidos, salto a salto (una consulta por nivel, `expandGraph` en `packages/domain`). Cada nodo carga como mucho **25 vecinos nuevos** (primero `contains`, `instance_of`, `mounts`, `attached_to`…; `stores` el último) y el mapa, **150 nodos** (`truncated`); lo que no entra va en `hidden` por tipo, también lo que queda a un salto más del borde (la web dibuja «+N más»). Sin `includeRetired`, los retirados quedan fuera (salvo el propio centro).
- `GET /assets/topology?projectId=&rootId=&expand=a,b`: **topología por niveles** (`buildTopology`, pura). Sin `expand`, el **nivel host**: las raíces y sus hijos `server`/`vm`/`lxc`/`subscription`, cada uno con lo que tiene debajo sin cargar (`hidden` por tipo, imágenes de su Docker incluidas) y sus CRITICAL (`hiddenCritical`: suma por asset, sin las imágenes, que ya cuentan en sus contenedores). Cada id de `expand` añade su contenido (hijos `contains`, volúmenes y redes incluidos, e imágenes que guarda) con `parentId` = el host: la web lo dibuja **dentro**. Una imagen guardada en un solo host expandido va dentro de él; si está en varios, fuera. Las relaciones de lo oculto se **agregan** entre sus antepasados visibles (`count`). `projectId` filtra por `effective_projects` (cada asset cuelga de su antepasado más cercano del proyecto); `rootId`, solo ese subárbol. Tope de **500 nodos** (`truncated`).

### Source / Connector
De dónde viene el asset (inventario Ansible, API de Proxmox, API de Plesk, manual), con referencias a sus credenciales.

### Snapshot
Foto de un asset **cuando cambia** (§10): al recogerlo (`source: collect`) o al descubrirlo (`discover`; también los assets que solo se descubren: VM, contenedores, volúmenes, dominios, certificados…), solo si hay cambios reales respecto al anterior. Guarda `facts`, `roles`, `previousId` y el **diff** calculado al guardarlo (`diff`: cambios `{ path, kind, before, after }` y su resumen por sección). `GET /assets/:id/snapshots` lleva el resumen (`changeSummary`) y `GET /snapshots/:id` el diff completo. Es el **historial de cambios** (versión de SO, paquetes, puertos, configuración de un CT…).

### Project (`projects`) y ProjectMembership (`project_memberships`) (QoL-3)
Proyecto o grupo de assets: `name` (único sin distinguir mayúsculas, índice de expresión), `description`, `color` (`#rrggbb` o null). La pertenencia se decide con **filas directas** `(project_id, asset_id, mode)`: `include` (el asset y lo que contiene entran) o `exclude` (**excepción**: el asset y lo que contiene salen de ese proyecto aunque lo hereden). Reglas (`resolveProjects`, pura, en `packages/domain`):
- un asset puede estar en **varios proyectos**; cada proyecto se resuelve por separado;
- para cada proyecto decide **la fila más cercana del camino `contains`**, empezando por el propio asset (`include` ⇒ dentro, `exclude` ⇒ fuera; sin ninguna, fuera): meter un nodo Proxmox mete sus CT, contenedores, volúmenes y redes; una excepción en un CT saca su subárbol solo de ese proyecto y un `include` más abajo vuelve a meter una rama;
- **imágenes** (fuera del árbol): los proyectos de sus hosts (`stores`) y contenedores (`instance_of`) no retirados, más sus propias filas (`include` añade, `exclude` quita).

La efectiva se materializa en `assets.effective_projects` en la misma pasada que la política (`recomputePolicies`, con los mismos llamadores), así los filtros por proyecto son un `@>`/`= ANY` sobre un índice GIN y no un recorrido del árbol. `GET /assets/:id/projects` da el motivo de cada proyecto (`direct`, `inherited` + antepasado, `holders`) y las excepciones propias. Es la base de los **permisos por proyecto** futuros (ver un asset si se tiene permiso en alguno de sus proyectos). Borrar un proyecto borra en cascada sus filas y su regla de política.
- API: `GET /projects` (con su resumen: assets no retirados por tipo, findings abiertos por severidad de dueños que escanean, CRITICAL/HIGH con parche, CVE distintos), `GET /projects/:id` (y sus filas directas), `POST|PATCH|DELETE /projects/:id`, `PUT|DELETE /projects/:id/members/:assetId` (`{ mode }`), `GET /assets/:id/projects`. Filtro `projectId` en `GET /assets`, `GET /vulnerabilities` y `/findings` (los contenedores afectados, solo los del proyecto) y `GET /dashboard`.

### Dashboard (`dashboards`) y MetricSample (`metric_samples`) (QoL-8)
**Panel guardado** (entidad de la API, con FK a `users`): el personal de un usuario (`owner_user_id`, FK en cascada) o el de un proyecto (`project_id`, FK en cascada); exactamente uno de los dos (`CHECK num_nonnulls(...) = 1`) y como mucho uno de cada (índices únicos). `layout` (jsonb) con el diseño entero (`DashboardLayout` de shared-types: `schema`, y por widget `id`, `type`, `x`/`y`/`w`/`h` en una rejilla de 12 columnas, `title`, `filters` —`projectId`, `tags`, `types`, `site`— y `options`), `version` (concurrencia optimista: el PUT trae la que se editó y da 409 si cambió), `updated_by_id` (`SET NULL`) y fechas. **Sin fila, el por defecto**: `DEFAULT_DASHBOARD` o `projectDashboardTemplate(id)` en código (mejorarlo llega a todos los que no lo personalizaron); «Restablecer» borra la fila. Los widgets van juntos en jsonb y no en una tabla: siempre se leen y se guardan a la vez, nunca se consulta uno suelto y el guardado es atómico. Lo guardado se vuelve a validar al leerlo (`validateDashboardLayout`, la misma que en el PUT y en la web).

**Muestra de métrica** (`packages/domain`, para los gráficos de evolución): `day` (date UTC), `project_id` (null = global; FK en cascada), `metric` (`cves_by_band`: CVE de la vista principal por banda y en KEV; `assets_by_status`), `values` (jsonb) y `granularity` (`day`/`week`). Una por día, ámbito y métrica: índice único `NULLS NOT DISTINCT` en la migración (`@Index(..., { synchronize: false })`), que también hace único el global. La escribe el job `metrics.sample` del worker (§15).

### TagStyle (`tag_styles`) (QoL-3)
Color opcional de un tag (`tag` PK, `color` `#rrggbb`). `GET /tags` (tags en uso en assets no retirados con su número de assets, y los que tienen color: autocompletado) y `PUT /tags/:tag/style` (`{ color | null }`).

### InventoryPolicy (`inventory_policies`)
Reglas de la política de inventario (§10): una `global` (los tres campos fijados), una por asset (se hereda hacia abajo), una por etiqueta y una por proyecto (`project_id`, FK en cascada). Campos: `reconcileIntervalMinutes` (0 = nunca; 5 min–30 días), `scanEnabled`, `scanPeriodic`; null = no lo fija. Desde QoL-6b, `scan_exclusions` (jsonb, null = nada): tipos, patrones de nombre y assets que no se escanean (§10).

### Notification (`notifications`)
Avisos del mantenimiento del inventario (§10): `kind` (`asset_created`, `asset_missing`, `asset_reactivated`, `asset_retired`, `reconcile_failed`, y desde QoL-5 `expiry_warning` y `dns_dangling`, §13; `vulnerability_kev`, sesión 19; `vault_revealed`, QoL-7), asset principal (FK `SET NULL`) y su nombre, mensaje, hasta 20 assets afectados (id, nombre, tipo) y el total. Nunca facts, conexión ni credenciales. Desde QoL-7, **público**: `audience_roles` (null = todos; un revelado de la caja fuerte, solo `admin`) y `exclude_user_id` (quien la provocó no la ve); la campana filtra con ellos en la lista y en el contador. Se purgan con `JOB_RUNS_RETENTION_DAYS`. «Leídas» por usuario con `users.notificationsSeenAt`.

### Package
Paquetes normalizados a partir del SBOM, por asset (servidor, CT o imagen; nunca por contenedor). Se reemplazan todos al guardar un SBOM nuevo. `GET /assets/:id/packages?q=&ecosystem=` (en un contenedor, los de su imagen) con el resumen del SBOM.
- `asset`, `name`, `version`, `ecosystem` (deb, rpm, npm, pip, go, …)
- `purl` (por ejemplo `pkg:deb/debian/openssl@3.0.11-1`)

### Sbom
SBOM CycloneDX completo de cada asset (servidor, CT o asset `image`; uno por asset, tabla `sboms`), guardado comprimido (gzip) para re-evaluarlo sin conectarse a las máquinas. Una imagen compartida por varios contenedores tiene un solo SBOM. Sin las etiquetas de la imagen (`aquasecurity:trivy:Labels:*`, pueden llevar secretos) ni vulnerabilidades: es solo inventario. Guarda `source` (`docker_save` | `rootfs`), SO, `content_sha256` (la re-evaluación comprueba que no lo reemplazó un escaneo entretanto), `packages_sha256` (mismo software ⇒ no se reescribe) y los datos de la última evaluación (`evaluatedAt`, `dbUpdatedAt`, `vulnerabilityCount`, `evaluationError`). `GET /assets/:id/sbom` lo descarga; `GET /assets/:id/findings|vulnerabilities` llevan su resumen (`sbom`).

### ContainerImage
Ficha 1:1 del asset `image` (clave natural = **image ID**, `sha256:…`, lo que de verdad corre): `repoDigests`, `repoTags`, plataforma, estado del escaneo (`pending`, `scanned`, `skipped` —no escaneada por un motivo conocido—, `failed`) con su motivo, versión de Trivy, fecha de su base de datos y número de vulnerabilidades del último escaneo. Se escanea una vez; sus findings, su SBOM y sus paquetes cuelgan del asset `image`, y los contenedores llegan a ellos con `instance_of`.

### Finding
Vulnerabilidad detectada en un asset: una imagen (una sola vez para todos sus contenedores), un servidor o un CT (`trivy rootfs`).
- `asset`, paquete (`packageName`, `installedVersion`, `pkgPath`), `vulnerabilityId` (CVE, GHSA…)
- `severity`, `fixedVersion`, `fixStatus` (el de la distribución según Trivy)
- `status`: `open`, `fixed`, `accepted`; `firstSeenAt`, `lastSeenAt`, `fixedAt` y `openedAt` (cuándo se abrió por última vez: al aparecer o al reabrirse; índice `(status, opened_at)` para «CVEs nuevos»). En una imagen, aceptar un riesgo vale para todos sus contenedores; un contenedor recreado con otra imagen deja de estar afectado porque su `instance_of` apunta a la nueva
- `fingerprint` = sha256(vulnerabilidad | paquete | versión | clase | tipo | ruta): **único por asset**, así un re-escaneo actualiza en lugar de duplicar
- `cvssScore` (de Trivy: NVD primero; V3, si no V4 o V2)
- `priority` (0–100), `priorityReasons` (motivos con datos, nunca texto) y `noiseReason` (`kernel_not_running` | `no_fix_planned`): los calcula el worker (`findings.prioritize`, §9); índice `(status, priority DESC)`
- `kevAlertedAt`: cuándo se avisó de que es crítico, en KEV y expuesto (una vez por apertura; al reabrirse se borra)

### VulnerabilityIntel (`vulnerability_intel`) e IntelFeed (`intel_feeds`) (sesión 19)
Inteligencia **por CVE** (no en `findings`: una descarga no reescribe miles de findings): `inKev`, `kevAdded`, `kevDue`, `kevRansomware`, `kevName`, `epss`, `epssPercentile`. EPSS entero (~390 000 filas pequeñas): un CVE nuevo ya tiene dato. `intel_feeds`, una fila por fuente (`kev`, `epss`): `enabled`, `fetchedAt` (datos vigentes), `checkedAt`, `etag`, `lastModified`, `version` (`catalogVersion` o fecha de las puntuaciones), `recordCount`, `lastError` y `lastErrorAt`.

### Usuario (`users`)
`email`, `name` (nombre visible; los anteriores a QoL-1, la parte del email antes de `@`), hash argon2id (nunca sale de la API), `role` (`admin`, `editor`, `operator`, `auditor`, `viewer`; permisos en §14), `origin` (`local`: alta en Ajustes o admin inicial, con contraseña; `oidc`: alta automática al entrar con el proveedor, sin contraseña), `oidcIssuer` + `oidcSubject` (identidad OIDC enlazada; única entre las enlazadas por un índice parcial), `disabledAt` (null = activo; desactivado no puede entrar y pierde sus sesiones al momento), `mustChangePassword` + `tempPasswordExpiresAt` (el hash es una **contraseña temporal** de un solo uso: alta o restablecimiento, 24 h), `passwordChangedAt`, `lastLoginAt`, `vulnerabilitiesSeenAt` (el último «Marcar como vistos» del panel de CVEs nuevos; null = nunca entró en Vulnerabilidades) y `notificationsSeenAt` (el último «Marcar como leídas» de la campana), y la **verificación en dos pasos** (§14): `totpSecretRef` (referencia `secret://…#secret` al secreto TOTP, cifrado en el proveedor de secretos escribible; null = sin TOTP), `totpPendingRef` (el de un alta sin confirmar), `totpEnabledAt` y `totpLastStep` (último paso de 30 s aceptado: solo valen los posteriores, así un código no se usa dos veces).

### UserSession (`user_sessions`)
Sesión web opaca (§14): `userId`, `tokenHash` (sha256 del token de 32 bytes; el token en claro solo viaja en la cookie), `csrfToken`, `purpose` (`full`; `password_change`: tras entrar con una temporal, 15 min y solo para cambiarla; `mfa`: contraseña buena y falta el código TOTP, 5 min y como mucho 5 códigos fallidos —`mfaFailures`—), `authMethod` (`password` u `oidc`), `reauthenticatedAt` (última confirmación de la identidad: login con TOTP, código en el diálogo de reautenticación o `auth_time` del proveedor; las acciones sensibles la quieren reciente), `lastSeenAt` (inactividad), `expiresAt` (caducidad absoluta), `ip`, `userAgent` y `oidcIdToken` (solo en sesiones abiertas por OIDC: el `id_token_hint` del cierre de sesión en el proveedor; nunca sale en respuestas ni logs). Revocar = borrar la fila.

### UserRecoveryCode (`user_recovery_codes`) (MFA)
Códigos de recuperación de la verificación en dos pasos: `userId` (FK `CASCADE`), `codeHash` (sha256, único; 16 caracteres de un alfabeto de 31, ≈ 79 bits: no hace falta un hash lento), `usedAt` (gastarlo es una actualización condicionada a `used_at IS NULL`: de dos usos simultáneos solo gana uno) y `createdAt`. Se generan 10 al activar el TOTP o al pedir unos nuevos (los anteriores se borran); en claro solo salen en esa respuesta.

### ApiToken (`api_tokens`) (QoL-6)
Token de API personal (§14): `userId` (FK `CASCADE`), `name`, `prefix` (los 12 primeros caracteres, `iwt_ab12cd34`: reconocible, inservible solo), `tokenHash` (sha256, único; el token en claro solo sale en la respuesta de alta), `scope` (`read` o `role`), `expiresAt` (obligatoria, ≤ 1 año), `lastUsedAt` + `lastUsedIp` (como mucho una vez por minuto o al cambiar de IP), `revokedAt` + `revokedById` (revocar marca la fila; se conserva para ver qué hubo).

### VaultEntry (`vault_entries`) y VaultEntryVersion (`vault_entry_versions`) (QoL-7)
Caja fuerte de credenciales (§19). Entidades **de la API** (no están en `packages/domain`: el worker no las conoce). `vault_entries`: `assetId` (FK `SET NULL`: al purgar el asset la entrada queda suelta), `kind` (`console`, `web`, `ipmi`, `other`), `name`, `username`, `url`, `notes`, `secretRef` (`secret://vault-openbao|vault-local/entries/<id>#password`; null = aún sin secreto), `currentVersion`, `lastRotatedAt`, `rotationDays` (null = el de los ajustes), quién y cuándo la creó y la cambió, y el **borrado lógico** (`deletedAt`, `deletedById`). `vault_entry_versions`: una fila por versión del secreto con su origen (`created`, `replaced`, `restored` + `restoredFrom`), fecha y autor; **nunca el valor**.

### VaultLocalSecret (`vault_local_secrets`) (QoL-7)
Texto cifrado del almacén local de la caja fuerte: una fila por `(path, version)` con `key_id`, IV, texto cifrado y tag, cifrada con **su propia clave** (`VAULT_LOCAL_MASTER_KEY_FILE`), distinta de la de `local_secrets`. Está en `VAULT_ENTITIES` de `@infraward/secrets`, que solo registra la API.

### AuditEvent (`audit_events`)
Registro de auditoría (§14), solo se añaden filas: `occurredAt`, `actorId` (FK `SET NULL`) y `actorEmail` (copiado; el tecleado en un login fallido), `action` (`AUDIT_ACTIONS` en shared-types), `outcome` (`success`/`failure`), `targetType`, `targetId` y `targetLabel` (nombre copiado: sobrevive a una purga), `ip` y `details` (JSONB pequeño y plano, saneado). Índices DESC por fecha, actor y acción, y por objetivo.

### JobRun
Historial de ejecuciones de jobs (la **Actividad**): BullMQ borra los jobs terminados (1 h los completados, 24 h los fallidos), así que cada ejecución se guarda en `job_runs`.
- `id` = jobId de BullMQ, `name`, `queue`, `asset` (FK `ON DELETE SET NULL`) y `assetName` (copia: el historial sobrevive a la purga), `parentJobId` (el job que lo encadenó: recolección → descubrimiento → recolecciones y escaneos; o la operación en lote que lo lanzó, índice parcial `IDX_job_runs_parent`).
- **Operaciones en lote** (QoL-6): una fila `assets.bulk` (cola `system`, **nunca se encola**) que la API graba ya terminada, con `assetName` = «web1, web2, cache y 4 más» y `message` = «Escanear · 3 assets · 1 omitido · 2 tareas · 1 ya en curso · por ana@…»; los jobs que lanza llevan su id en `parentJobId`. Un job deduplicado (ya pendiente de antes) sigue colgando de quien lo lanzó.
- `state` (`queued`, `active`, `completed`, `failed`), `progress`, `message` (último evento de progreso) y `error` (el `failedReason`, que el worker ya deja apto para mostrarse); `createdAt`, `startedAt`, `finishedAt`. Nunca los datos ni el resultado del job.
- La fila la crea **quien encola** (la API en `JobsService.enqueue` y el worker al encadenar, con `INSERT … ON CONFLICT DO NOTHING` por la deduplicación). La réplica que lo ejecuta la pone en `active` al empezar con su nombre (`worker`, p. ej. `worker-2`) e incrementa `attempt` (**fencing token**, §20); el resto (progreso, final, fallo, vuelta a la cola, *stalled*) lo escribe el **único oyente de eventos de las colas, en la réplica líder** (§20), en orden por job y con upsert (si falta la fila, la crea). El asset sale de `data.assetId`; en `enrollment.verify`, del enrolamiento; en `image.scan`, del asset `image`.
- Filas huérfanas: el líder **barre** cada minuto las pendientes de más de 2 min y las concilia con BullMQ (perdida ⇒ `failed` «El job se perdió: worker-2 dejó de responder…»; terminada o fallida ⇒ su estado; de vuelta en la cola ⇒ `queued`). La API mantiene su comprobación al listar. El líder borra las terminadas hace más de `JOB_RUNS_RETENTION_DAYS` (30).
- `GET /jobs?assetId=&state=&name=&parentJobId=` (con `state=running` = en cola o en curso; `assetId` incluye los escaneos de la imagen de un contenedor). Cada fila con hijos lleva `children` (`total`, `running`, `failed`).

### UserSshKey
Claves públicas que cada usuario registra para conectarse a través del gateway SSH.

### AccessPolicy (`access_policies`, sesión 22)
Permisos de acceso interactivo: concede `terminal.open` a una **persona** (`subject_type = user`, `user_id`, CASCADE) o a **todas las de un rol** (`role`) en un **asset** (`asset_id`, CASCADE: vale para él y todo lo que contiene), en los assets con una **etiqueta** (`tag`) o en los de un **proyecto** (`project_id`, CASCADE: sus miembros efectivos, heredados incluidos). Solo concede (no hay reglas que quiten) y lo que da el rol (`admin`) no se toca aquí. `permission` (de momento solo `terminal.open`, CHECK), `created_by` (SET NULL) y `created_at`; CHECKs de un solo sujeto y un solo objetivo e índices únicos parciales por sujeto (una regla igual no se repite). Entidad de la API (como `users`). Resolución en §11.

### TerminalSession
Registro de cada sesión interactiva (`terminal_sessions`, entidad de la API, sesión 21): persona (`user_id`) y la sesión web que la pidió (`auth_session_id`, `SET NULL`), asset y servidor por el que se entra (`asset_id`, `host_asset_id`, `SET NULL`; `asset_name` se conserva), cuenta, estado (`pending` → `starting` → `active` → `closed`, o `rejected`), **sha256 del ticket** (`ticket_hash`, único; null al gastarlo) y su caducidad, `redeemed_at`, `certificates_issued` (tope), gateway que la atiende (desde el canje), **`heartbeat_at`** (último latido de su gateway) y **`revoke_requested_at`** (cuándo pidió la API cortarla; una vez), IP de la petición y del cliente, inicio, fin, `close_reason` (`exit`, `client`, `idle`, `max_duration`, `gateway_shutdown`, `limit`, `connect_failed`, `expired`, `denied` y, desde la sesión 22, `revoked` y `gateway_lost`), `exit_code` y `close_message`. Índices por `auth_session_id` y parcial de las vivas (`starting`, `active`). Nunca la clave ni el certificado. La grabación (`.cast`) llega en la sesión 23.

### Acceso de administración (`assets.admin_access`, `enrollments.admin_access`)
`Asset.adminAccess` (jsonb, null = sin acceso): `{ mode: 'operator', account: 'infraward-admin', version, enabledAt }`. Lo escribe el **worker al verificar** un alta que lo pedía, según lo que el servidor tiene de verdad (`/etc/infraward/admin-access-version`, legible sin sudo): `operator` lo activa, `none` o la falta del fichero lo quitan y sin pedir nada se conserva si sigue instalado (nunca se activa solo). `Enrollment.adminAccess` (`operator` | `none` | null) es lo que pide el comando. Lo tiene el servidor con SSH propio; sus CT y contenedores se alcanzan a través de él.

### Datos de dominios (QoL-5)
Los dominios y registros DNS son `Asset` (`domain`, `dns_record`); los de Plesk los crea su descubridor (§8) y los de un proveedor DNS, su conector (§13): cuenta `dns_provider` (`facts.connector`: tipo, última prueba del token y última sincronización; nunca el token) → `domain` (`facts.zone` y `facts.registration`, RDAP) → `dns_record` (`facts.dns`: nombre, tipo, valor ≤ 2 KB, TTL, proxy, prioridad; sin los comentarios ni las etiquetas del proveedor; y `facts.tls`, la lectura del 443) y `certificate` (los del 443, uno por huella). Claves naturales `cloudflare:zone:<id>`, `cloudflare:record:<id>` y `tls:<SHA-256>`.
- `DnsRecordCheck` (`dns_record_checks`, 1:1 con el registro A/AAAA/CNAME): `level` (`high`/`info`/null), `reason`, `target`, `ambiguous`, `takeover_service`, `value_hash` (sha256 de tipo y valor), `accepted_value_hash`/`accepted_by`/`accepted_at` («Marcar como esperado»: vale mientras el hash no cambie) y `notified_value_hash` (ya avisado).
- `ExpiryAlert` (`expiry_alerts`, PK asset + fecha de caducidad + umbral): avisos de caducidad ya enviados.
- `AppSetting` (`app_settings`, clave → JSON): de momento `expiry_warning_days` (sembrado `[30, 7]`).
- `DnsServicePath` (`dns_service_paths`, 1:1 con el registro A/AAAA/CNAME, QoL-5b): `status` (`complete`, `partial`, `manual`, `none`), `final_asset_id`, `hops` (JSONB: cada eslabón con asset, etiqueta, puerto, resolutor, origen y confianza), `confidence`, `cut_reason`, `public` (IP pública, proxy de Cloudflare o túnel), `via_asset_ids` (GIN: «por aquí pasan») y el destino fijado a mano (`pinned_asset_id`/`pinned_by`/`pinned_at`), que gana al calculado.
- `NatForward` (`nat_forwards`): reenvío NAT declarado a mano (IP pública, puerto, protocolo → asset y puerto), único por IP, puerto y protocolo.
- API (§13): `GET|POST /connectors`, `GET|DELETE /connectors/:id`, `PUT /connectors/:id/token`, `POST /connectors/:id/test|sync`, `GET /assets/:id/domains`, `GET /assets/:id/dns-check`, `POST|DELETE /assets/:id/dns-check/acceptance`, `POST /dns-checks/acceptance` (`{ target }`, en bloque) y `GET|PUT /settings/expiry-warnings`. QoL-5b: `GET /assets/:id/service-path` (registro), `GET /assets/:id/service-paths` (dominio), `GET /assets/:id/served-domains`, `POST|DELETE /assets/:id/service-path/pin` y `GET|POST /settings/nat-forwards`, `PUT|DELETE /settings/nat-forwards/:id`.

---

## 6. Gestión de secretos

### Principio: referencias, no secretos

La base de datos **nunca** guarda valores secretos, solo referencias con el formato:

```
secret://<proveedor>/<ruta>#<campo>
```

Ejemplos:

```json
{ "sshKey": "secret://openbao/infra/proxmox-pve1#private_key" }
{ "apiToken": "secret://vaultwarden/<item-id>#api_token" }
```

El worker resuelve la referencia en el momento de ejecutar el job, usa el secreto y lo descarta.

### Abstracción

```typescript
export interface SecretProvider {
  readonly id: string; // 'openbao', 'vaultwarden', 'local'...
  get(path: string, field?: string): Promise<string>;
  set?(path: string, data: Record<string, string>): Promise<void>;
  healthCheck(): Promise<boolean>;
}

// Capacidad opcional: CA SSH (solo la implementan los proveedores que la soportan)
export interface SshCertificateCapable {
  // Certificado de usuario para una clave efímera: un principal, key_id y vida en segundos
  signSshKey(request: { publicKey: string; principal: string; keyId: string; ttlSeconds: number }): Promise<string>;
  // Claves públicas de las CA vigentes (durante una rotación, la actual y la siguiente)
  sshCaPublicKeys(): Promise<{ publicKey: string; fingerprint: string; active: boolean }[]>;
}
```

```typescript
@Injectable()
export class SecretsService {
  constructor(@Inject(SECRET_PROVIDERS) private providers: SecretProvider[]) {}

  async resolve(ref: string): Promise<string> {
    const { provider, path, field } = parseSecretRef(ref);
    const impl = this.providers.find(p => p.id === provider);
    if (!impl) throw new Error(`Proveedor de secretos no configurado: ${provider}`);
    return impl.get(path, field);
  }
}
```

`SecretsModule.forRoot()` es un módulo dinámico que registra solo los proveedores activos según configuración (por ejemplo `SECRETS_PROVIDERS=openbao,local`). Pueden convivir varios para facilitar migraciones.

### Proveedores

**local** (por defecto): secretos cifrados con AES-256-GCM en la propia base de datos, con la clave maestra fuera de ella. Permite usar la app sin instalar nada extra.

- Tabla `local_secrets`: una fila por ruta con el objeto `{ campo: valor }` cifrado (IV aleatorio de 12 bytes por escritura y *tag* de 16). Nunca hay texto en claro en la BD.
- **AAD = la ruta** (`infraward:local:v1:<ruta>`): si alguien con acceso a la BD intercambia dos filas (p. ej. para que la referencia de un servidor apunte a la clave de otro), el descifrado falla en lugar de devolver el secreto equivocado.
- Clave maestra de 32 bytes en base64, por `SECRETS_LOCAL_MASTER_KEY_FILE` (recomendado: secret de Podman/Docker) o `SECRETS_LOCAL_MASTER_KEY`; exactamente una. La app no arranca si falta, si están las dos o si no mide 32 bytes (el error nunca muestra el valor). Se genera con `openssl rand -base64 32`.
- Cada fila guarda el **id de la clave**: una huella derivada de ella (primeros 8 bytes de SHA-256 con separación de dominio), no un número manual. Con una clave equivocada el error dice «se cifró con la clave X y está cargada la Y», y permite rotar en el futuro.
- **Backups: sin la clave maestra los secretos son irrecuperables; un volcado de la BD sin la clave no sirve.** La clave se respalda aparte, nunca en el mismo backup que la BD.

**openbao**:
- Motor **KV v2** para almacenar secretos. La ruta de la referencia se cuelga de un prefijo (`OPENBAO_KV_PREFIX`, por defecto `infraward`): `secret://openbao/assets/<id>/ssh#privateKey` vive en `secret/data/infraward/assets/<id>/ssh`. Así la política de la app se limita a `secret/data/infraward/*` (`create`, `read`, `update`) y `secret/metadata/infraward/*` (`read`, `delete`; borrar una ruta borra todas sus versiones). Una última versión borrada o destruida cuenta como «no encontrado».
- Autenticación de la app con **AppRole** (nunca tokens root): `OPENBAO_ADDR`, `OPENBAO_ROLE_ID` y exactamente una de `OPENBAO_SECRET_ID_FILE` (recomendada) u `OPENBAO_SECRET_ID`; opcionales `OPENBAO_KV_MOUNT` (`secret`), `OPENBAO_APPROLE_MOUNT` (`approle`) y `OPENBAO_TIMEOUT_MS` (5000). Con `http://` hacia un host no local se avisa al arrancar; para una CA propia, `NODE_EXTRA_CA_CERTS`.
- Login perezoso y de un solo vuelo. **Renovación** (`renew-self`) a los 2/3 de la vida del token; si ya no se alarga (cerca de `token_max_ttl`), no es renovable o falla, nuevo login. Un 403 descarta el token y se reintenta una vez (token revocado desde fuera). Al cerrar la app, `revoke-self`. El token y el secret_id viven en campos privados y los errores llevan solo el estado HTTP o el tipo de fallo, nunca el cuerpo de la respuesta.
- Con `SECRETS_PROVIDERS=openbao,local` conviven: las claves nuevas van al primer proveedor con escritura (OpenBao) y las referencias `secret://local/…` siguen resolviendo.
- Desarrollo: servicio `openbao` del compose (perfil `openbao`, desellado automático con `seal "static"`) y `pnpm openbao:bootstrap`, que lo inicializa y crea KV, AppRole, política y rol (`token_ttl=1h`, `token_max_ttl=24h`). El token root solo lo usa ese script.
- **Desellado: el automático con la clave en el mismo host es solo para desarrollo.** Con `seal "static"` la clave de desellado vive junto a los datos cifrados: quien lea el disco (o un backup del volumen) tiene ambos. En producción, **desellado manual** (claves de Shamir repartidas entre varias personas; tras un reinicio, OpenBao queda sellado hasta que se introducen) o **auto-unseal con un servicio externo** que nunca entrega la clave: el KMS de un proveedor cloud o el motor `transit` de **otro** OpenBao. La clave de recuperación y el token root iniciales se guardan fuera de línea, no en el servidor.
- Implementa `SshCertificateCapable` mediante el **motor SSH en modo CA** (DESIGN §7 «Modo CA»): certificados SSH de vida corta por job, sin claves privadas permanentes.
  - Montaje `infraward-ssh/` (`OPENBAO_SSH_MOUNT`) con emisores ed25519 **generados dentro de OpenBao** (`generate_signing_key`: la clave privada de la CA no sale nunca) y el rol `inventory` (`OPENBAO_SSH_ROLE`): solo certificados de usuario, `allowed_users=inventory`, `allow_user_key_ids` (el key_id lo pone la app), sin extensiones ni opciones críticas (equivale a `restrict`: sin pty ni reenvíos), solo claves ed25519, `ttl=5m`, `max_ttl=30m` y `not_before_duration=30s`. Lo crea `pnpm openbao:bootstrap` (el primer emisor `ca-1` solo si no hay ninguno).
  - Política de la app: solo `infraward-ssh/sign/inventory` (`update`) e `infraward-ssh/issuers` (`list`, para las claves públicas). Nada de `config/*`, `issuers/import` ni `roles/*`: **cambiar la CA es cosa de un operador**, no de la app.
  - `signSshKey` valida antes de pedir la firma (solo ed25519, principal y key_id con lista blanca —el key_id admite `@` y `+` y hasta 200 caracteres, para el email de la terminal—, TTL 30–3600 s y extensiones de una lista blanca: solo `permit-pty`) y que la respuesta sea un certificado; un rechazo del rol da `provider_error` sin el cuerpo de la respuesta. `SecretsService.sshCertificates()` devuelve el primer proveedor con la capacidad.
  - **Terminal (sesión 21)**: rol `infraward-operator` del mismo motor (`allowed_users=infraward-operators`, `allowed_extensions=permit-pty`, sin opciones críticas, solo ed25519, `ttl=2m`, `max_ttl=5m`, `allow_user_key_ids`) con su **propia política y AppRole `infraward-terminal`** (solo `infraward-ssh/sign/infraward-operator`), que **solo tiene la API** (`TERMINAL_OPENBAO_ROLE_ID` y `TERMINAL_OPENBAO_SECRET_ID[_FILE]`; `TERMINAL_OPENBAO_SSH_ROLE`). La AppRole `infraward` (la que comparte el worker) no puede firmar con ese rol: un worker comprometido no emite certificados de administración (lo comprueba la integración). `TerminalCertSigner` (`packages/secrets/src/terminal/`) es una instancia aparte del proveedor que siempre pide `permit-pty`; la API no arranca si su AppRole o su rol coinciden con los de la app. Lo crean `pnpm openbao:bootstrap` y `deploy/example/init.sh`.

#### Rotación de la CA SSH

**Qué pasa si cambia la clave de la CA.** Cada servidor en modo CA solo acepta certificados de las claves que tiene en su fichero de CAs (`TrustedUserCAKeys`). Si OpenBao firma con una clave nueva que el servidor no tiene, **rechaza todos los certificados**: todos los servidores en modo CA pierden el acceso a la vez y recuperarlo exige root en cada uno (el worker es de solo lectura). Los certificados ya emitidos duran minutos y no cuentan; los servidores con clave estática y las host keys no se ven afectados. Robar un certificado sirve unos minutos; el caso grave es un compromiso de OpenBao (con la CA se entra como `inventory`, con el principal `inventory` y el sudoers acotado, en todos los servidores en modo CA).

**Rotación en tres fases, sin cortes** (emisores múltiples del motor SSH: `issuers/import/<nombre>`, `config/issuers`, `LIST issuers`):
1. **Preparar**: el operador crea el emisor N+1 sin marcarlo por defecto. Se sigue firmando con N y la app considera vigentes las dos claves (`sshCaPublicKeys`).
2. **Distribuir (manual)**: el fichero de CAs del servidor admite varias claves y lleva versión. El worker lo lee en cada recolección (es público, sin sudo) y guarda las huellas en `facts.infraward.sshCa`; si no coinciden exactamente con las vigentes, la app avisa **«CA SSH desactualizada»** (ficha, árbol, panel e `/inventory?attention=ssh-ca`) con «Generar el comando»: volver a ejecutar el script (`sudoers_update`) instala las claves vigentes. Que el worker las instale él mismo exigiría una regla de sudo de escritura: rompería el «solo lectura» de §14.
3. **Activar y retirar**: el operador marca N+1 por defecto (el comando se niega mientras quede algún servidor en modo CA sin la clave nueva, salvo `--force`); después borra N, los servidores vuelven a salir como «desactualizados» (siguen confiando en N) y se vuelve a ejecutar el script.

**Emergencia (compromiso)**: activar N+1 y borrar N con `--force`. Los servidores en modo CA quedan sin acceso hasta que alguien con root vuelva a ejecutar el script; los de clave estática siguen funcionando.

**Hecho (sesión 13)**: fichero de CAs con varias claves y versión, lectura de huellas en la recolección, aviso «CA SSH desactualizada» y comando para actualizar. **Pendiente**: el script de operador `deploy/openbao/ssh-ca.sh status|prepare|activate|retire` (con el token root), un endpoint de estado de solo admin (emisores y servidores con o sin cada clave) en el que se apoye para negarse a activar, y su test de integración.
- Posible uso futuro del motor **Transit**.

**vaultwarden**:
- Vaultwarden implementa la API del gestor de contraseñas de Bitwarden, **no la de Bitwarden Secrets Manager**, y el cifrado es en cliente.
- Se usa el CLI de Bitwarden en modo **`bw serve`** como sidecar del worker (red interna, nunca expuesto), autenticado con la API key de una cuenta de servicio dedicada con acceso solo a una organización o colección del inventario.
- Las referencias usan el **ID del ítem**, no el nombre (los renombrados romperían referencias). La UI muestra el nombre.
- Proveedor de solo lectura, sin secretos dinámicos.

### Reglas de manejo

- La API **nunca devuelve valores de secretos** al frontend; solo la referencia y si resuelve correctamente.
  Endpoints (solo admin): `GET /secrets/providers` (id, salud, capacidades) y `POST /secrets/check` (`{ ref }` → `{ ref, provider, resolves, error? }`). No hay endpoint de escritura hasta que lo necesite un caso de uso (conectores con tokens).
- Paso de secretos a Ansible: variables de entorno o fichero de `--extra-vars` temporal con permisos 600 en tmpfs, borrado al terminar. Las tareas que los usan llevan `no_log: true`.
- Caché en memoria de vida corta (segundos o pocos minutos) en el worker.
- Componente de UI para seleccionar secretos listando lo que hay en el proveedor.

Añadir proveedores futuros (Infisical, Bitwarden Secrets Manager, 1Password Connect, Kubernetes Secrets) consiste en implementar `SecretProvider` y registrarlo.

**La caja fuerte de credenciales (§19) no usa `SecretsService`.** Ese servicio lo comparten la API y el worker (misma clave maestra, misma tabla, misma AppRole); la caja fuerte tiene su propio almacén (`VaultStore` de `@infraward/secrets`) que solo crea la API, con su clave o su AppRole. Sus referencias (`secret://vault-local/…`, `secret://vault-openbao/…`) son de proveedores que `SecretsService` no conoce: en el worker, en `POST /secrets/check` o en la CLI `secrets:put` dan `provider_not_configured`.

---

## 7. Alta de servidores (enrolamiento)

### Flujo

1. El usuario pulsa **"Añadir servidor"** e introduce IP o hostname (y opcionalmente un nombre). Desde QoL-6b puede elegir también **tags, proyectos y la regla de política** (o una plantilla, §10 «Organización y política en el alta»), que se aplican antes de la primera recolección.
2. La API **genera un par de claves ed25519**. La privada se guarda en el proveedor de secretos activo; en la base de datos solo queda la referencia. El asset se crea en estado `pending_enrollment`.
3. La UI muestra un comando listo para copiar:
   ```bash
   curl -fsSL https://infraward.tudominio/enroll/<token> | sudo bash
   ```
   - El token es de **un solo uso** y caduca en 15–30 minutos (`ENROLLMENT_TOKEN_TTL`). En la BD solo se guarda su hash; el comando con el token se muestra una única vez (se puede regenerar, lo que invalida el anterior).
   - `GET /enroll/<token>` sirve el script y se puede repetir mientras el token siga vigente (el script no lleva secretos: clave pública, token y URL `PUBLIC_URL`). Lo **consume** `POST /enroll/<token>/done`, de forma atómica. Token desconocido, caducado o usado: 404 indistinguible. Ambos endpoints son públicos y están limitados por IP.
   - El script (`ansible/enroll/enroll.sh.tmpl`) crea el usuario dedicado `inventory` (sin contraseña), añade la clave pública a su `authorized_keys` con `restrict`, instala el **ayudante de root** `infraward-query` y un `sudoers` que solo permite ese ayudante (§7 «Versión del sudoers») y avisa a la API con `POST /enroll/<token>/done`, enviando las **huellas de las host keys** del servidor (`ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub`). Es idempotente.
   - Alternativa manual: la línea `echo "ssh-ed25519 AAAA... inventory@infraward:<asset>" >> ~/.ssh/authorized_keys` y un botón "Ya lo he añadido", indicando el usuario en cuya cuenta se añadió. **Nunca `root`**: se rechaza en la API y el worker rechaza además cualquier usuario con uid 0. Sin sudoers, la recolección será parcial.
   - **Requisitos del servidor**: `sudo` y `python3` (la UI lo avisa; Proxmox no trae sudo de serie). Sin `sudo`, el script se para sin tocar nada; con la opción explícita **`--install-sudo`** (casilla en el alta, `installSudo` en la API) lo instala con el gestor de paquetes que haya (`apt-get`, `dnf`/`yum`, `apk`, `zypper`); es lo único que instala, y entonces el comando se ejecuta como root sin `sudo` (`curl … | bash -s -- --install-sudo`). Sin `python3` solo avisa: la verificación funciona, la recolección no.
   - **Script embebido** (servidores que no llegan a `PUBLIC_URL`: VPN, NAT): `echo '<script en gzip+base64>' | base64 -d | gunzip | sudo bash`. Se genera en modo `embedded`: **sin token ni URL** y sin `/done`; al terminar imprime las huellas de las host keys. La confirmación manual exige **pegarlas** (`POST …/enrollment/confirm` con `hostKeys`): el worker solo acepta una de esas claves, igual que con las del `/done`, así que la verificación fuera de banda se mantiene. La alternativa de solo añadir la clave sigue siendo TOFU.
4. El `/done` (o el "Ya lo he añadido") **no activa el asset**: cualquiera con el token puede llamarlo. Encola el job `enrollment.verify`, y el asset pasa a `active` solo cuando el worker consigue conectarse por SSH con la clave. Si falla, sigue en `pending_enrollment` con el error visible y se puede reintentar.
5. **Fijado de la host key**: el worker lee las host keys con `ssh-keyscan` y elige la que coincide con la huella ya fijada en el asset; si no hay, con una de las reportadas por el script; en el camino manual (sin huellas reportadas), TOFU. Se conecta con un `known_hosts` temporal con solo esa clave y `StrictHostKeyChecking=yes` (**nunca** `no` ni `accept-new`). Si no coincide, el job falla («posible suplantación») y la huella guardada no se toca. La clave privada pasa por un fichero 600 en tmpfs que se borra siempre.
6. Se lanza el playbook de detección y el descubrimiento correspondiente.

En la UI, un stepper: *Comando generado → Esperando clave → Conectando → Escaneando → Listo*, con progreso en tiempo real por **SSE** (`GET /assets/:id/enrollment/events`, con la cookie de sesión; la web usa `fetch`; si la sesión se revoca, el flujo se corta al momento). Cada evento `progress` lleva el estado completo (`EnrollmentProgress`): enrolamiento, fase y la cadena de jobs que encadena la verificación —recolección → descubrimiento → recolecciones de los hijos y escaneos—, que la API sigue con los ids que cada job deja en su resultado (`collectJobId`, `discoveryJobId`, `collectJobIds`, `scanJobIds`; tope de 500). Se alimenta de los `QueueEvents` de BullMQ y de los cambios del propio enrolamiento, con un sondeo de respaldo cada 10 s; latido cada 15 s y cierre a los 30 min (el cliente reconecta). Solo nombres, estados, progreso y mensajes: nunca datos ni resultados de los jobs. «Listo» = verificado y sin jobs de la cadena pendientes (un fallo de la cadena se muestra como aviso).

El formulario de alta ofrece el **modo de acceso** (§7 «Modo CA»), cada uno explicado en una línea: certificados de la CA («Sin claves permanentes: cada tarea entra con un certificado que caduca en minutos», preseleccionado si hay un proveedor sano con `ssh_certificates`) y, como alternativa, clave estática («Una clave fija en authorized_keys; admite el alta manual»). Sin ningún proveedor con CA SSH, la opción de CA no se puede elegir y queda la estática. Mientras no se sabe, ninguna marcada; si el usuario no la toca, la web no envía `authMode` y decide la API con la misma regla (así no se cuela la estática por enviar antes de tiempo). En modo CA el stepper no tiene la pestaña «Manual» (solo el script, por URL o embebido) y explica que el script configura sshd; al regenerar el comando se mantiene el modo del enrolamiento en curso.

### Modo CA: certificados de vida corta

Cada servidor tiene un modo de acceso (`Asset.sshAuth`): **`static_key`** (clave ed25519 permanente; la privada en el proveedor de secretos y la pública en `authorized_keys`) o **`ca_certificate`** (sin claves permanentes). El alta elige modo (`authMode`): por defecto, CA si hay un proveedor con CA SSH y alguna CA; si no, clave estática. La ficha lo muestra («Autenticación»).

- **En cada job** (verificación, recolección, descubrimiento, escaneo), si el asset (o el nodo por el que se llega a él) está en modo CA y el proveedor lo soporta, el worker genera un **par ed25519 efímero** en el directorio 700 del tmpfs del job, pide a OpenBao que firme la pública (principal fijo **`inventory`**, **key_id `infraward:asset=<id>:job=<id>`**, vida **`SSH_CERT_TTL`**, 300 s por defecto, 60–1800) y conecta con `CertificateFile`. El key_id queda en el log de sshd (`Accepted publickey for inventory … ED25519-CERT … ID infraward:asset=…:job=…`). Clave y certificado se borran siempre con el directorio.
- **Una sola autenticación por job**: el worker abre un **ControlMaster** (`ssh -M -N -f`, socket en el directorio del job, o en uno corto aparte si la ruta no cabe en un socket unix) y todo lo demás (los comandos de los descubridores, `docker save`, Ansible con `ControlMaster=auto`) va por esa conexión. OpenSSH solo comprueba el certificado al autenticar. Antes de abrir una conexión nueva, si al certificado le quedan menos de `SSH_CERT_RENEW_MARGIN` segundos (60), se firma otro para la misma clave; sin temporizadores. Al terminar, `ssh -O exit` y, si el maestro no responde, se mata: ningún `ssh` sobrevive al job.
- **Sin proveedor capaz**: con clave estática, se usa la estática (aviso en el log); sin ella, el job falla con un mensaje claro. La verificación de un alta en modo CA es estricta: nunca prueba otra cosa que el certificado.
- **Script en modo CA** (mismo `enroll.sh.tmpl`, marcadores `__INFRAWARD_AUTH__`, `__INFRAWARD_CA_KEYS__` y `__INFRAWARD_CA_VERSION__`, validados con lista blanca): además del usuario y el sudoers, instala `/etc/ssh/infraward/trusted_user_ca_keys` (644, cabecera `# infraward-ssh-ca-version: <n>` y las claves de las CA vigentes), `/etc/ssh/infraward/principals/inventory` (solo `inventory`) y el drop-in `/etc/ssh/sshd_config.d/00-infraward.conf` con un **`Match User inventory`** (`TrustedUserCAKeys`, `AuthorizedPrincipalsFile …/%u`, `PermitTTY no`, `DisableForwarding yes`, `PermitUserRC no`): no afecta a otros usuarios ni a otra CA que tenga el servidor. Antes de tocar nada comprueba el reloj: el script lleva la hora a la que se generó y, si el del servidor va más de 5 min por detrás, se para (sshd rechazaría los certificados como «not yet valid»). Guarda copia de lo anterior, valida con **`sshd -t`** y comprueba con `sshd -T -C user=inventory,…` que la configuración efectiva es la suya (si falta el `Include` de `sshd_config.d` u otro fichero fija antes esos valores); si algo falla, **restaura y no recarga**. El `sshd_config` principal no se toca. Recarga sshd (systemd, socket, OpenRC o `HUP`) y deja `/etc/infraward/ssh-ca-version`. **No instala ninguna clave estática** y quita la de su asset si la había. Idempotente; la versión de lo que instala es `SSH_CA_CONFIG_VERSION` (sube si cambia la configuración, no las claves).
- **Migración** de estático a CA (acción «Pasar a certificados (CA)» en la ficha, o `POST /assets/:id/enrollment/token` con `authMode: 'ca_certificate'`; enrolamiento `ca_migration`): volver a ejecutar el script en modo CA. El script quita la línea del asset de `authorized_keys` **después** de que sshd acepte los certificados; cuando el worker conecta con un certificado, el asset pasa a `ca_certificate` y la clave estática se **borra del proveedor**. Si la verificación falla, la clave estática se conserva y se puede reintentar. Volver a clave estática no está soportado (dar de baja y de alta). Solo para altas con el script (usuario `inventory`): no hay alta manual en modo CA, pero sí el **script embebido** con las huellas pegadas.
- **Verificación del alta**: igual en los dos modos (huellas del `/done` o pegadas; host key fijada).
- **Baja en modo CA**: el comando quita el drop-in, las claves de la CA y los principals y recarga sshd tras validarlo; el sudoers y el usuario, como en estático. Esa configuración es del usuario `inventory`: si otro asset en modo CA apunta al mismo servidor, también deja de entrar.

### Versión del sudoers

El fichero `/etc/sudoers.d/infraward-inventory` lleva la cabecera `# infraward-sudoers-version: <n>` (y una copia legible en `/etc/infraward/sudoers-version`). La lista de comandos cambiará con el tiempo: no hace falta reenrolar. El worker lee la versión al conectar; si es antigua, la app muestra "sudoers desactualizado" y un comando nuevo (`POST /assets/:id/enrollment/token` con el asset activo abre un enrolamiento `sudoers_update` con la **misma** clave) que actualiza los permisos sin regenerar la clave.

Versiones:
- **v1**: comandos de lectura de la recolección y los descubridores.
- **v2**: además `docker save sha256:<id>` con regex de sudo, para escanear imágenes con Trivy (§9).
- **v3**: `docker volume ls -q` y `docker network ls --format {{.Name}}` (volúmenes y redes sin uso) y el ayudante de consultas de Plesk `plesk-query`.
- **v4**: **una sola regla**, el ayudante de root. Sustituye a todas las anteriores.
- **v5** (QoL-5b): la misma regla; el ayudante suma `nginx-routes` y `docker-nginx-routes` (rutas de nginx y NPM **filtradas en el servidor**) y la plantilla de `docker inspect` sus etiquetas de Traefik/Caddy (lista blanca). Sin ella el servidor no sale desactualizado: es una **nota** y el camino de los dominios se corta en ese proxy.
- **v6** (sesión 19): la misma regla; el ayudante suma `process-packages` (qué paquete es el ejecutable y cuáles las librerías de cada proceso en marcha o en escucha, **calculado en el servidor**). También es una **nota**: sin ella la prioridad de los paquetes del servidor no sabe si están en marcha ni en qué puertos, y lo dice («sin datos de procesos (sudoers v6)»).
- **v7** (actual, QoL-7): la misma regla; el ayudante suma `sshd-auth` (`sshd -T` filtrado en el servidor: solo `PermitRootLogin`, `PasswordAuthentication` y `KbdInteractiveAuthentication`), para avisar del login de root o por contraseña. Otra **nota**: sin ella no hay aviso.

**Por qué v4: sudo-rs.** Ubuntu ≥ 25.10 trae **sudo-rs** por defecto (`sudo -V` imprime «sudo-rs …» en stderr), que no admite comodines, ni espacios en los argumentos de las reglas, ni expresiones regulares, ni `Defaults !requiretty, !lecture`. Con las reglas de v1–v3, en cualquier Ubuntu nuevo solo funcionaban `ss`, `dmidecode` y Plesk; Docker, Proxmox y `docker save` no. La v4 vale igual con los dos sudo:

```
# infraward-sudoers-version: 4
Defaults:inventory !requiretty, !lecture        # solo con sudo clásico
inventory ALL=(root) NOPASSWD: /usr/local/libexec/infraward/infraward-query
```

Sin argumentos en la regla, sudo permite cualquiera: **el filtro es el ayudante**. `/usr/local/libexec/infraward/infraward-query <consulta> [argumentos…]` es un script bash que instala el alta (siempre, root:root 0755, escritura atómica; antes comprueba que ni su directorio ni los padres los puede modificar nadie más que root) y borra la baja (también el `plesk-query` de la v3). Admite una **lista cerrada** de consultas, la misma que `PRIVILEGED_QUERIES` en `packages/connectors/src/privileged.ts`: valida la aridad y **cada argumento antes de ejecutar nada** (si algo no cuadra, sale con 64 y `infraward-query: rechazado: …`) y ejecuta el binario con `exec`, **sin shell en medio**, con `PATH` fijo de root y `LC_ALL=C`. Los binarios se buscan al ejecutar (Docker o Plesk instalados después funcionan sin volver a dar de alta; si falta, 127).

| Consulta | Argumentos (validación) | Ejecuta como root |
|---|---|---|
| `dmidecode-system` | — | `dmidecode -t system` |
| `ss` | — | `ss -Htulpn` |
| `pveversion` | — | `pveversion` |
| `pve-cluster-status` | — | `pvesh get /cluster/status --output-format json` |
| `pve-cluster-resources` | — | `pvesh get /cluster/resources --type vm --output-format json` |
| `pve-guest-config` | `lxc\|qemu`, nodo, vmid; el guest existe en ese nodo | `pvesh get /nodes/<nodo>/<tipo>/<vmid>/config --output-format json` |
| `pve-lxc-interfaces` | nodo, vmid; el CT existe en ese nodo | `pvesh get /nodes/<nodo>/lxc/<vmid>/interfaces --output-format json` |
| `pct-exec` | vmid de un CT de este nodo (`/etc/pve/lxc/<vmid>.conf`), comando (≥ 1 argumento) | `pct exec <vmid> -- <comando…>` |
| `docker-version` | — | `docker info --format {{.ServerVersion}}` |
| `docker-ps` | — | `docker ps -a -q --no-trunc` |
| `docker-inspect-containers` | 1–256 × `^[0-9a-f]{64}$` | `docker inspect --format <plantilla> <ids>` |
| `docker-images` | — | `docker images -q --no-trunc` |
| `docker-image-inspect` | 1–256 × `^sha256:[0-9a-f]{64}$` | `docker image inspect --format <plantilla> <ids>` |
| `docker-volumes` / `docker-networks` | — | `docker volume ls -q` / `docker network ls --format {{.Name}}` |
| `docker-volume-inspect` / `docker-network-inspect` | 1–256 × `^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$` | `docker inspect --type volume\|network --format <plantilla> <nombres>` |
| `docker-save` | exactamente 1 × `^sha256:[0-9a-f]{64}$` | `docker save <id>` (a la salida estándar) |
| `nginx-routes` (v5) | — | `sh -c <filtro> sh nginx -T` |
| `docker-nginx-routes` (v5) | exactamente 1 × `^[0-9a-f]{64}$` | `sh -c <filtro> sh docker exec <id> nginx -T` |
| `process-packages` (v6) | — | `sh -c <script> sh` |
| `sshd-auth` (v7) | — | `sh -c <script> sh` (dentro, `sshd -T -C user=root,host=localhost,addr=127.0.0.1`) |
| `plesk-version` | — | `plesk version` |
| `plesk-domains`, `-aliases`, `-databases`, `-certificates` | — | `plesk db -B -N -r -e <consulta fija>` (§8) |

- Nodo: `^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`; vmid: `^[1-9][0-9]{2,8}$`. **Las rutas de pvesh no se aceptan**: el ayudante las compone con piezas validadas (nada de `/access/…`, `../`, `set` ni opciones extra) y comprueba que el guest existe en `/etc/pve/nodes/<nodo>/…`.
- Ids y nombres de Docker anclados y sin `-` inicial: no se cuelan opciones (`docker save -o <ruta>` escribiría como root). Las plantillas `--format` son constantes del ayudante (las de `docker/formats.ts`).
- **Filtro de nginx (v5)**: `NGINX_ROUTES_SCRIPT` (`packages/connectors/src/proxies/nginx-filter.ts`; el ayudante y el playbook llevan copia literal, un test la fija) guarda la salida de `nginx -T` en una variable del shell, en el servidor, y la pasa por un awk POSIX que solo deja salir líneas normalizadas de `server`, `listen`, `server_name`, `location`, `proxy_pass`/`grpc_pass`/`fastcgi_pass`/`uwsgi_pass` **sin `usuario:contraseña@`**, `upstream … server` y las variables de NPM `$server`, `$port` y `$forward_scheme`; cada valor, por una lista blanca de caracteres. Cabeceras, `auth_basic_user_file`, claves, `set` de otras variables y el resto de la configuración **no salen nunca de la máquina**. Si `nginx -T` falla, sale con 3 y un mensaje sin la configuración. Probado con el awk de macOS, mawk (Debian) y BusyBox (Alpine). En un CT, el mismo `sh -c` va dentro de `pct-exec`: el filtro corre en el CT.
- **Procesos (v6)**: `PROCESS_PACKAGES_SCRIPT` (`packages/connectors/src/processes/process-packages.ts`; copia literal en el ayudante y el playbook, un test la fija) toma los PID que escuchan (`ss -Htulpn`) y el primero de cada servicio de systemd en marcha (sus cgroups), descarta los de contenedores, CT y VMs (su ejecutable no es del servidor), lee `/proc/<pid>/exe` y las `.so` de `/proc/<pid>/maps` y busca el paquete de todas las rutas en una sola llamada (`dpkg -S` o `rpm -qf`, con la otra forma de usrmerge, `/usr/lib/x` ↔ `/lib/x`). Solo salen líneas `P pid nombre unidad paquete librerías` con nombres de una lista blanca: **nunca rutas, entorno ni línea de órdenes**. Topes: 300 procesos, 100 paquetes de librerías por proceso. Probado con el awk de macOS, mawk y BusyBox y, a través de sudo y sudo-rs reales, con el sshd de verdad (→ `openssh-server` y sus librerías).
- **sshd (v7)**: `SSHD_AUTH_SCRIPT` (`packages/connectors/src/sshd/sshd-auth.ts`; copia literal en el ayudante, un test la fija; el playbook la recibe del worker en `infraward_sshd_filter`) busca `sshd` y ejecuta `sshd -T` para una conexión de `root` (cuentan los bloques `Match User root`; necesita root para cargar las host keys) y un awk que solo deja salir esas tres opciones (`challengeresponseauthentication` en OpenSSH < 8.7). **Solo lee**: nada de claves, rutas ni el resto de la configuración, y nunca la cambia. Sin sshd, sale con 3. En un CT va dentro de `pct-exec`. Probado con un `sshd` falso que imprime una configuración completa con centinelas y, a través de sudo y sudo-rs reales, con el sshd del contenedor de integración (con un drop-in que abre root por contraseña).
- **Lo que no limita**: `pct-exec` ejecuta como root dentro de un CT del nodo el comando que se le pase. Así se recogen los CT con Ansible (módulos por stdin), igual que antes `pct exec *`; el ayudante valida el vmid, no el comando. Y `docker inspect` sigue exponiendo la configuración de los contenedores (§14). El aviso va en el propio sudoers.
- **Una fuente de verdad**: el worker nunca construye el comando privilegiado; pide `HostExec.query({ name, args })`. Por SSH es `sudo -n infraward-query <consulta> <args…>`; en un CT (`pct exec` desde el nodo, ya root, sin ayudante) es `pct-exec <vmid> <comando real>` con el comando de `expandQuery`, que valida igual que el ayudante. El playbook lleva `query` y `argv` por elemento (un test exige que coincidan con la tabla) y el plugin `infraward_pct` usa `pct-exec`.
- **Tests**: el unitario ejecuta el ayudante de la plantilla con bash y binarios falsos (con el `sh` y el `awk` de verdad: el filtro de nginx se prueba con una configuración con `proxy_set_header Authorization`, `auth_basic_user_file`, una clave y credenciales en la URL que no pueden salir): cada consulta llega con el argv de `expandQuery` (paridad con TypeScript, formatos y consultas de Plesk incluidos) y una batería de inyección (otras rutas de pvesh, `docker save -o`, `--output=`, opciones en ids, `;`, `$(…)`, acentos graves, `&&`, `|`, saltos de línea, aridad, guests de otro nodo) sale con 64 sin ejecutar nada. La integración repite todo **a través de sudo** en Debian 13 (sudo 1.9) y en **Ubuntu 26.04 con sudo-rs**, y comprueba que cualquier otro comando con sudo se deniega, que `inventory` no puede tocar el ayudante y que la baja lo quita.

**Corte limpio**: el worker solo usa el ayudante. Un servidor con v1–v3 sale «sudoers desactualizado (vN, hace falta v4)» y su recolección es parcial («sudo denegado…») hasta que se vuelve a ejecutar el script; la denegación de sudo-rs («I'm sorry … can't do that») y el 64 del ayudante se reconocen igual que las de sudo.

Qué versión exige cada cosa lo dice una única tabla, `SUDOERS_CAPABILITIES` (§14): de ella salen el aviso «sudoers desactualizado» (`facts.infraward.sudoersOutdated`), las notas informativas (`facts.infraward.sudoersNotes`, en la ficha con el enlace «Generar el comando»; con la v4, la de los proxies) y las comprobaciones del worker (`sudoersAllows`). Solo para servidores con el sudoers de InfraWard: ni los CT recogidos con `pct exec` (root en el CT) ni las altas manuales.

### Acceso interactivo de administración (opcional)

El usuario `inventory` es solo de lectura y **nunca** se usa para la terminal. Para poder administrar el servidor desde InfraWard (por ejemplo un `apt upgrade`), el alta ofrece una casilla aparte, **desactivada por defecto**: «Permitir acceso interactivo de administración». Cambia el nivel de confianza que se da a InfraWard en ese servidor, por eso es explícita, por asset y auditada.

- Requiere el **modo CA** (§6): no hay contraseñas ni claves estáticas para el acceso humano.
- El script configura una cuenta de administración que acepta certificados de la CA para los **principales de las personas autorizadas**. Dos variantes, a elegir en el alta:
  - **Cuenta de operador** (`infraward-admin`) con sudo. El sudo puede ser sin contraseña: el certificado ya es de pocos minutos, se emite tras MFA y queda auditado.
  - **Root con certificado**: `PermitRootLogin prohibit-password` y un `AuthorizedPrincipalsFile` para root con las personas autorizadas.
- El fichero de principales lo mantiene el script (idempotente y versionado, como el sudoers). Dar o quitar acceso a una persona se hace en InfraWard (`AccessPolicy`); el fichero del servidor puede listar un principal por rol (por ejemplo `infraward-operators`) para no tener que tocar los servidores al cambiar de personas.
- Quitar el acceso a alguien no exige tocar el servidor: deja de recibir certificados y los que tenga caducan en minutos.
- Se puede activar o desactivar después volviendo a ejecutar el script; al desactivarlo, la cuenta de operador o la configuración de root por certificado se retiran.

**Hecho (sesión 21, variante `operator`, versión 1, `ADMIN_ACCESS_VERSION`; la web, en la 22)**:
- **Alta** (sesión 22): casilla «Permitir acceso interactivo de administración», **desmarcada**, solo para quien tiene `users.manage` y solo habilitada con el modo CA (con clave estática se desmarca y explica por qué). `POST /assets/enroll` admite `adminAccess: 'operator'` con las mismas reglas que el comando nuevo (`users.manage`, modo CA —si no, 409— y reautenticación reciente `admin_access.enable`) y lo audita como `enrollment.admin_access_requested`.
- **Ficha** (sesión 22): en «Red y acceso» de un servidor, «Administración: Activado · `infraward-admin` (v1 desde …)» o «Desactivado» y, para un admin, **Activar**/**Retirar** (confirmación con lo que cambia → comando con `adminAccess: operator|none` → stepper). Deshabilitado con el motivo si no está activo, no se dio de alta con el script o no está en modo CA. El stepper conserva el `adminAccess` del enrolamiento al regenerar el comando.
- `POST /assets/:id/enrollment/token` con `adminAccess: 'operator' | 'none'` (sin indicar, no se toca). Activarlo exige el modo CA, un servidor (no un CT ni un contenedor), **`users.manage`** y **reautenticación reciente** (`admin_access.enable`); retirarlo no. Auditado como `enrollment.admin_access_requested`. El script lo recibe en `__INFRAWARD_ADMIN_ACCESS__` (`keep`, `operator` o `none`, lista blanca; `operator` sin modo CA no se genera) y `__INFRAWARD_ADMIN_ACCESS_VERSION__`.
- `configure_admin_access` (en `enroll.sh.tmpl`, tras `configure_ssh_ca`): cuenta `infraward-admin` (`useradd -m -s /bin/bash`, contraseña `*`: sin contraseña posible pero no bloqueada, para que PAM deje entrar con certificado; marca `/etc/infraward/admin-access-created-user` si la creó InfraWard), `/etc/sudoers.d/infraward-admin` con cabecera de versión y `infraward-admin ALL=(ALL:ALL) NOPASSWD: ALL` (validado con `visudo -cf`; vale con sudo y sudo-rs), `/etc/ssh/infraward/principals/infraward-admin` = `infraward-operators` y su **propio drop-in** `/etc/ssh/sshd_config.d/01-infraward-admin.conf` con `Match User infraward-admin`: `TrustedUserCAKeys` (el mismo fichero de CAs), `AuthorizedPrincipalsFile …/%u`, **`AuthorizedKeysFile none`**, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitTTY yes`, `DisableForwarding yes`, `PermitUserRC no`. Copia previa de todo; `sshd -t`; `sshd -T -C user=infraward-admin,…` con exactamente esos valores; y la configuración efectiva de `inventory` **igual antes y después**. Si algo falla, restaura (y borra la cuenta si la acababa de crear) y no recarga. Escribe solo lo que cambia: con la misma versión no toca nada (ni la fecha) ni recarga sshd. Deja `/etc/infraward/admin-access-version`.
- `none` (`remove_admin_access`) quita drop-in, sudoers, principales y versión, valida y recarga; la cuenta solo se borra si la creó InfraWard y no tiene procesos (si los tiene, se bloquea y caduca, con aviso). La **baja** del asset en modo CA hace lo mismo antes de quitar la CA.
- Al verificar, el worker lee `/etc/infraward/admin-access-version` y marca `Asset.adminAccess` (§5); si el comando lo pedía y el fichero no está, la verificación falla («vuelve a ejecutarlo»).
- Probado (integración, sshd reales en Debian 13 con sudo y Ubuntu 26.04 con sudo-rs, OpenBao real): idempotencia sin cambios de fecha, `inventory` intacto, entrada con el certificado de la terminal con PTY y `sudo -n`, `Accepted publickey for infraward-admin … ED25519-CERT … ID infraward:session=…` en el log de sshd; rechazados una clave en `authorized_keys`, el certificado del inventario, el de la terminal como `inventory` y otro principal; la AppRole de la app no firma con el rol de la terminal; `none` lo retira todo e `inventory` sigue entrando.

### Gestión del ciclo de vida de la clave

- **Rotar**: genera una nueva clave, la despliega usando la antigua y retira la antigua.
- **Una línea por asset**: cada clave lleva el comentario `inventory@infraward:<asset-id>`. El script de alta solo sustituye la línea que termina en el comentario de **su** asset y la baja solo borra esa: las de otros assets en la misma cuenta y las que haya añadido el administrador no se tocan (test de integración con dos assets en el mismo sshd real).
- **Dar de baja**: al retirar o purgar un asset (`DELETE /assets/:id`) se cancelan sus enrolamientos abiertos, se borra la clave del gestor de secretos y se devuelve el comando para quitarla de `authorized_keys`. Con el usuario dedicado, si no le quedan claves de InfraWard se borra también el sudoers, y el usuario solo si no le queda ninguna otra clave.

---

## 8. Descubrimiento

### Detección del tipo

Un primer playbook ligero identifica la máquina:

| Comprobación | Rol asignado |
|---|---|
| Existe `pveversion` | `proxmox-node` |
| Existe `plesk version` | `plesk` |
| Responde `docker info` | `docker-host` |

Además recoge siempre los facts básicos: SO, CPU, RAM, discos, red, paquetes (`package_facts`), servicios (`service_facts`) y puertos en escucha.

**Recolección** (job `asset.collect`, cola `discovery`; se encadena tras la verificación del alta y se relanza con `POST /assets/:id/collect`, solo admin, deduplicado por asset): playbook `ansible/collect/collect.yml` con `ansible-core` y `python3` en el servidor.
- **Solo lectura**: sin `become`; lo que necesita root va con `sudo -n <comando del sudoers>` y sus argumentos exactos (`pveversion`, `plesk version`, `docker info --format …`, `ss -Htulpn` —en lugar de `listen_ports_facts`, que sin root no ve los procesos—, `dmidecode -t system`). `pipelining` activado: no se escriben ficheros temporales en el servidor. Si sudo deniega algo (alta manual, sudoers antiguo) la recolección sigue y queda como **parcial** con avisos.
- `package_facts` con apt necesita `python3-apt`; si no está, los paquetes se leen con `dpkg-query`/`rpm`/`apk`.
- **Conexión**: la misma que la verificación (clave en fichero 600 en tmpfs, `known_hosts` temporal con solo la host key fijada, `StrictHostKeyChecking=yes`). Huella fijada distinta ⇒ el job falla («posible suplantación») sin escribir nada; sin huella, TOFU y se fija con el snapshot. Ninguna variable de Ansible lleva secretos, solo la ruta de la clave.
- El playbook deja un JSON en el tmpfs del job; el worker lo normaliza a `facts` (`machineId`, `os`, `hardware`, `mounts`, `network`, `packages`, `services`, `ports`, `processes` (v6), `detected` e `infraward`: versión del sudoers, `sudoersOutdated` y avisos). El entorno remoto (`ansible_env`) se descarta.
- **nginx del sistema (QoL-5b)**: si hay `nginx`, la consulta `nginx-routes` (v5; en un CT, el mismo `sh -c` con el filtro, que el worker pasa en `infraward_nginx_filter`) → `facts.proxy` con sus rutas. Una denegación (sudoers v4) no hace la recolección parcial: `proxy: null` y la nota del sudoers.
- **Procesos (sesión 19)**: la consulta `process-packages` (v6; en un CT, el mismo `sh -c` con el script que el worker pasa en `infraward_process_filter`) → `facts.processes` (`pid`, `name`, `unit`, `exePackage`, `libPackages`). Sin la v6, `processes: null` y la nota; tampoco hace la recolección parcial. En los snapshots, el `pid` es volátil y la lista se compara por proceso.
- Guarda un `Snapshot` y actualiza `facts`, `roles` (solo se sustituyen los detectados; los puestos a mano se conservan) y `naturalKey` = `machine-id` (o la de un clon, abajo). Nunca se pisa una clave natural distinta ni se quita la de otro asset: aviso. `missing` vuelve a `active`.

### Descubridores como plugins

Cada descubridor declara qué rol lo activa y qué tipos de hijos genera. Viven en `packages/connectors` (solo backend) y no saben de SSH ni de secretos: el worker les da la ejecución en el padre (`HostExec`, un argv tal cual con `sudo -n` opcional, sobre la conexión fijada del padre) y la recolección la hace siempre el `AnsibleRunner` del worker con los mismos playbooks:

```typescript
export interface Discoverer {
  readonly role: string;                       // 'proxmox-node'
  readonly childTypes: readonly AssetType[];   // ['lxc', 'vm']
  discover(parent: DiscoveryParent, host: HostExec): Promise<DiscoveryListing>;
  collectTarget(child): { target: CollectTarget } | { target: null; reason: string };
}
```

- **Jobs** (cola `discovery`): `asset.discover` (`POST /assets/:id/discover`, solo admin, deduplicado con `discover:<id>`) lista los hijos, los reconcilia y encola `asset.collect` de los que se pueden recoger. Tras recoger un asset, si algún rol tiene descubridor, se encola su `asset.discover` (descubrimiento recursivo). El descubrimiento usa la huella fijada del padre: sin TOFU.
- **Hijos anidados** (Plesk): un hijo puede colgar de otro del mismo listado (`parent`); el ámbito de lo que puede desaparecer es el subárbol del padre recorriendo solo hijos de los tipos del descubridor (el de Docker de un nodo no ve los contenedores de sus CT). Completitud por tipo con `partialTypes`.
- **Reconciliación** (`planReconcile`, pura; se aplica en una transacción con el mismo `pg_advisory_xact_lock` que las relaciones `contains` de la API): crea lo nuevo con su relación `contains`, actualiza lo conocido (solo las claves de `facts` del descubridor, p. ej. `facts.proxmox`; los facts recogidos se conservan), cambia de padre lo que se ha movido (migración entre nodos) y pasa a `missing` lo que ya no existe. **Solo si el listado es completo**: si el comando falla, da timeout o devuelve algo que no se entiende, no se toca ningún estado. Lo que existe en el ámbito del descubridor pero cuelga de otro padre (un CT en otro nodo del clúster) no ha desaparecido. Los dados de baja a mano no se reactivan (aviso); los retirados por la reconciliación (`retiredAuto`) y los `missing` vuelven a `active` al reaparecer. El paso a `retired`, los snapshots y las notificaciones son de §10.
- Los hijos recogidos a través del padre conservan la clave natural del descubridor (no el machine-id: los CT clonados lo comparten) y no fijan host key propia.

### Descubrimiento por API (conectores de dominios, QoL-5)

No todo se descubre por SSH: un conector de dominios (§13) lista por la API de su proveedor y produce un `DiscoveryListing` igual que un descubridor, que aplica el mismo **`ListingReconciler`** del worker (extraído del descubrimiento por SSH: candado `contains`, `planReconcile`, snapshots, `missing` → `retired`, notificaciones agrupadas, `replaceLinks` y la política recalculada). Con `externalTargets`, los enlaces pueden apuntar a assets de fuera del listado por su clave natural (un registro → el certificado de Plesk con la misma huella).

### Proxmox

1. Lista CT y VMs con las consultas `pve-cluster-status` (nodo local y nombre del clúster) y `pve-cluster-resources` del ayudante de root (`pvesh get … --output-format json`; rutas fijas, §7). Son hijos del nodo los guests con `node` = nodo local; los de otros nodos solo cuentan como «siguen existiendo».
2. Crea cada uno como asset hijo (`lxc` o `vm`) con `facts.proxmox`: vmid, nodo, clúster, estado, plantilla, CPU, memoria, disco, uptime, etiquetas, la configuración de `pve-guest-config` (`pvesh get /nodes/<n>/<lxc|qemu>/<vmid>/config`) **saneada** (fuera toda clave que coincida con `pass|secret|token|key|cred` —`cipassword`, `sshkeys`…— y `description`, donde la gente apunta contraseñas) y, en los CT en marcha, las IPs reales de `pve-lxc-interfaces`.
3. **CT en marcha**: la recolección se ejecuta dentro con `pct exec <vmid> -- <comando>`, **sin necesidad de SSH dentro del CT**. El *connection plugin* `ansible/collect/connection_plugins/infraward_pct.py` es el plugin `ssh` contra el **nodo** (misma clave, mismo `known_hosts` fijado) que antepone `sudo -n infraward-query pct-exec <vmid> ` a cada comando (el ayudante valida que el CT es del nodo y ejecuta `pct exec <vmid> -- …`) y prohíbe copiar o traer ficheros (con `pipelining` los módulos van por stdin). El playbook es el mismo, con `infraward_via=pct` e `infraward_query_prefix=[]` (`pct exec` ya es root en el CT: se ejecuta el comando real de cada consulta; no hay sudoers que mirar ni `dmidecode`). Necesita `python3` dentro del CT. Los CT parados y las plantillas no se recogen.
4. **VMs**: quedan inventariadas solo con los datos de Proxmox (`qm guest exec` con *qemu-guest-agent* queda para más adelante: no está en el sudoers) y la UI ofrecerá "Añadir con SSH".
5. Si un CT o VM tiene Docker, recibe el rol `docker-host` y se encola su descubrimiento (los comandos van por la consulta `pct-exec` del ayudante del nodo).

### Plesk

Descubridor de solo lectura (rol `plesk`, sesión 14). `plesk bin` no da las bases de datos por dominio ni la caducidad de los certificados, y la API REST/XML exige crear una credencial: se usan **consultas fijas** a la base de datos de Plesk (`psa`) con `plesk db -B -N -r -e` (una fila `JSON_OBJECT` por línea), metidas en el ayudante de root `infraward-query` (consultas `plesk-<nombre>`, sin argumentos; §7, sudoers v4): el usuario de inventario no puede lanzar otra consulta. Las consultas (`packages/connectors/src/plesk/queries.ts`; un test ejecuta el ayudante y exige que lleve exactamente esas) solo leen columnas de una lista blanca: **nunca** `accounts`, `db_users`, `DatabaseServers.admin_password`, ni la clave privada (`pvt_key`) o el CSR de los certificados.
- Árbol: **servidor → suscripción → dominio → (base de datos, certificado)**. Claves naturales con el id del asset del servidor: `plesk:<host>:subscription:<dominio principal>`, `plesk:<host>:domain:<nombre>`, `plesk:<host>:db:<servidor de BD>:<nombre>`, `plesk:<host>:cert:<repositorio>:<nombre>`.
- `subscription` (los dominios sin webspace): estado, propietario (login) y alta. `domain` (hijos de su suscripción): principal, adicional, subdominio o alias, tipo de hosting, estado y dominio padre. `database` (hija de su dominio): motor y servidor `host:puerto`; nunca usuarios ni contraseñas.
- `certificate`: hijo del dominio de cuyo repositorio es, o del servidor si es del pool del administrador (con su huella como alias `tls:<SHA-256>`: si el mismo certificado se leyó antes en el 443 de un registro DNS, §13, Plesk **adopta** ese asset en lugar de duplicarlo); `secured_by` dominio → certificado en uso (`hosting.certificate_id`). Plesk guarda el certificado **codificado como un formulario** (`%2D%2D…BEGIN+CERTIFICATE…`): se decodifica y se parsea la parte pública con `X509Certificate` (sujeto, SAN, emisor, validez, SHA-256, autofirmado, Let's Encrypt, dominios que lo usan). No se guarda el PEM. Lo que no es un certificado X.509 (la clave pública con la que Plesk firma las copias, solicitudes sin certificado) no es un asset.
- La caducidad sale en el árbol (`expiresAt`, «caduca en N días») y en el panel (`certificatesExpiring`: caducados o antes del umbral mayor de los avisos de caducidad, §13; `/inventory?attention=cert-expiring`).
- Una consulta que falla (otro esquema de `psa`) hace fallar solo el descubridor de Plesk, sin tocar estados; el de Docker sigue.
- Si el servidor tiene Docker, sus contenedores, volúmenes, redes e imágenes los descubre el de Docker (los dos se ejecutan) y sus imágenes se encolan para Trivy como las demás.

### Docker

Rol `docker-host`, en servidores (SSH con sudo) y en CT (`pct exec` desde el nodo, root en el CT). Contenedores desde la sesión 9; volúmenes, redes e imágenes sin uso desde la 14:
- `docker ps -a -q --no-trunc` → `docker inspect --format <plantilla>` → `docker image inspect --format <plantilla>` (consultas `docker-ps`, `docker-inspect-containers` y `docker-image-inspect` del ayudante, de 256 en 256 ids). **Las plantillas solo sacan lo necesario**: el entorno (`Config.Env`, donde suele haber secretos) nunca sale del servidor, y de las etiquetas solo el proyecto y el servicio de compose y, desde la v5, una **lista blanca** de Traefik/Caddy (`proxyLabels`: `traefik.enable`, `traefik.docker.network`, `traefik.http.routers.<n>.rule|service`, `traefik.http.services.<n>.loadbalancer.server.port`, `caddy[_N]` y `caddy[_N].reverse_proxy`; nunca middlewares con `basicauth` ni el resto). La plantilla filtra en el servidor (comprobado con el motor de plantillas de Go real) y el parser vuelve a filtrar.
- Hijos `container` (en marcha y parados) con `facts.docker`: id, nombre, imagen, **image ID**, RepoDigests/RepoTags, plataforma, tamaño de la imagen, estado, puertos expuestos y publicados (parado: los configurados), proyecto de compose y fechas. No se recogen con Ansible.
- `docker ps` que falla o no se entiende ⇒ el job falla sin tocar estados; un `inspect` a medias (contenedor borrado entretanto) ⇒ listado incompleto: nada pasa a `missing`. Cada descubridor del asset se ejecuta por separado: si falla el de Docker en un nodo, el de Proxmox sigue.
- **Volúmenes y redes** como assets propios (`volume`, `network`), hijos `contains` del host, con `facts.docker` (driver, ámbito, punto de montaje o subredes; **nunca** `Options` —un volumen NFS/CIFS lleva ahí `password=`— ni `Labels`). Claves `docker-volume:<host>:<nombre>` y `docker-network:<host>:<nombre>` (el id de una red cambia con `compose down/up`). Se listan con `docker volume ls -q` y `docker network ls --format {{.Name}}` y se leen con `docker inspect --type volume|network` (consultas `docker-volumes`, `docker-networks` y `docker-*-inspect`). Si sudo no deja listarlos, salen solo los que usan los contenedores y esos tipos van como listado **parcial** (`partialTypes`): nada de ellos pasa a `missing`.
- En `facts.docker` del contenedor, `mounts` (tipo, volumen u origen del bind, destino, solo lectura) y `networks` (nombre, IP y alias), campo a campo con `index` en la plantilla (un bind no tiene `Name`). Enlaces `mounts`/`attached_to` sustituidos en cada descubrimiento (`linkTypes`).
- **Proxies (QoL-5b)**: las etiquetas de Traefik/Caddy se convierten en `facts.docker.proxyRoutes` (nombres de host y destino: el propio contenedor y su puerto). De cada contenedor en marcha con imagen de nginx, OpenResty, SWAG o Nginx Proxy Manager se lee `docker exec <id> nginx -T` filtrado en el servidor (consulta `docker-nginx-routes`, v5) → `facts.docker.proxy` (`source: npm` en NPM). Sin la v5 o si falla, `proxy: null` y el listado sigue completo.
- «Sin uso» = ningún contenedor **activo** lo usa (se calcula, no se guarda). `GET /assets/:id/docker` da los volúmenes, redes e imágenes del host con cuántos contenedores activos los usan.
- **Imágenes**: tras descubrir, cada imagen del host (`docker images -q --no-trunc`, las use o no algún contenedor) se registra como asset `image` (con su ficha `container_images` y su tamaño en `facts.image.sizeBytes`), con `stores` host → imagen; cada contenedor activo se enlaza con `instance_of` (sustituyendo el enlace a su imagen anterior). Con el listado completo, se quita el `stores` de las que ya no están; una imagen sin ningún host pasa a `missing` y vuelve a `active` al reaparecer. Las no escaneadas se encolan para Trivy (§9); las que no usa nadie, con prioridad baja de BullMQ.

### Claves naturales (identidad estable)

| Tipo | Clave |
|---|---|
| Servidor Linux | `machine-id` |
| CT / VM de Proxmox | `proxmox:cluster:<cluster_name>:<vmid>`; en un nodo sin clúster, `proxmox:node:<machine-id del nodo>:<vmid>`. Si el nodo se une a un clúster, el descubridor encuentra la clave antigua como alias y la **renombra** (mismo asset, historial y snapshots) |
| Contenedor Docker | `docker:<id del asset host>:<nombre>` (el ID del contenedor cambia al recrearlo; el del asset host es estable aunque se renombre su clave) |
| Imagen de contenedor | image ID (`sha256:…`); la misma imagen en varios hosts es un único asset |
| Volumen / red de Docker | `docker-volume:<id del host>:<nombre>` / `docker-network:<id del host>:<nombre>` |
| Suscripción, dominio, base de datos y certificado de Plesk | `plesk:<id del host>:subscription|domain:<nombre>`, `plesk:<id del host>:db:<servidor>:<nombre>`, `plesk:<id del host>:cert:<repositorio>:<nombre>` |
| Dominio y registro DNS de un conector | `<proveedor>:zone:<id de la zona>`, `<proveedor>:record:<id del registro>` |
| Certificado leído en el 443 | `tls:<SHA-256>` (alias de los de Plesk con la misma huella) |

**Servidores duplicados**: si al recoger un servidor su machine-id ya es la clave natural de **otro asset no retirado** y alguna de las host keys que presenta (`ssh-keyscan`) es la huella fijada de ese asset (la misma máquina dada de alta dos veces, p. ej. tras restaurar un snapshot y volver a darla de alta), no se sobrescribe nada: ni snapshot, ni facts, ni roles, ni clave natural, ni descubrimiento. Solo se marca `duplicateOfId` (FK con `ON DELETE SET NULL`) y el job termina con `duplicateOf`. La ficha avisa «este servidor ya está en el inventario como <nombre>» (y el original, «también aparece como…»), con botones para purgar uno de los dos; el panel lo cuenta en avisos (`/inventory?attention=duplicate`). Al purgar uno, la marca desaparece y la siguiente recolección guarda con normalidad. Si el dueño del machine-id está retirado, se recoge con un aviso y sin clave natural.

**Clones** (VM, CT o servidores creados desde la misma plantilla: copian `/etc/machine-id`, pero suelen tener host keys propias): si el machine-id es de otro asset vivo y **ninguna** de las host keys coincide con su huella fijada, es otra máquina. Se recoge con normalidad con la clave natural compuesta **`<machine-id>+<huella fijada del clon>`** y `facts.infraward.machineIdClone` (`{ machineId, sharedWith: [{id, name}] }`), que la ficha muestra como «machine-id clonado» con la sugerencia de regenerarlo (`rm /etc/machine-id && systemd-machine-id-setup`; también `/var/lib/dbus/machine-id` si no es un enlace). No cuenta como recolección parcial; el árbol lleva `machineIdClone` y el panel el aviso `clones` (`/inventory?attention=clone`).
- Los candidatos son los assets con clave = machine-id o `<machine-id>+…`: un tercer clon se compara con todos, y si comparte host key con uno de ellos es ese clon dado de alta dos veces (duplicado).
- Un candidato sin huella fijada cuenta como la misma máquina (conservador).
- **Regenerado**: un asset con clave de clon cuyo machine-id ya no es el de su clave pasa a tener el nuevo machine-id como clave (mismo asset, historial y snapshots) y el aviso desaparece. Mientras el machine-id no cambie, la clave compuesta se conserva aunque se purgue el original (estable).
- El original (clave = machine-id) no cambia ni recibe aviso.

---

## 9. Seguridad y CVEs

### Escaneo con Trivy

- `trivy image` para imágenes de contenedores (sesión 9, abajo).
- `trivy rootfs` para servidores y CT (sesión 15, abajo); `trivy config` para configuraciones (Dockerfiles, etc.): pendiente.
- **Todo finding sale de un SBOM**: Trivy genera el CycloneDX (`--format cyclonedx` sin `--scanners`: solo inventario) y se evalúa con `trivy sbom <fichero> --scanners vuln --format json`, igual en el escaneo y en la re-evaluación, así que dan los mismos fingerprints (comprobado con nginx:1.25: los 791 de `trivy image` idénticos; el SBOM añade 3 del paquete `nginx` de nginx.org).

**Política de inventario** (§10): con `scanEnabled = false` no se generan SBOM ni se lanza Trivy para ese asset (ni automático ni bajo demanda: `POST /assets/:id/scan` responde 409 y «Re-escanear afectados» lo deja en `skipped`); la re-evaluación y el relleno lo saltan, y sus findings se conservan pero salen de las listas globales, del panel, de los «nuevos», del árbol de afectados de un CVE y de los contadores del inventario (`includeScanDisabled=true`, que la web manda con «Ver todas», los incluye; la pestaña del asset los enseña siempre con un aviso). Con `scanPeriodic = false` no hay escaneos encadenados (tras recoger, tras descubrir, relleno): solo bajo demanda; la re-evaluación offline sigue. Los procesadores comprueban la política al empezar (un job encolado antes del cambio no escanea).

**Imágenes de contenedores** (job `image.scan`, cola `image-scan`, `IMAGE_SCAN_CONCURRENCY`; antes `scan`/`SCAN_CONCURRENCY`, que se acepta como alias):
- **Trivy se ejecuta en el worker, nunca en los servidores** (no se deja binario, base de datos ni ficheros). Alternativas valoradas: registro desde el worker (no sirve para imágenes locales o con el tag movido y obliga a salir a registros que dicta el servidor, con riesgo de SSRF y credenciales), Trivy en el servidor (descartado) e híbrido (la ruta de registro queda como mejora futura).
- **Identidad = image ID**, no el tag: asset `image`. Se escanea una sola vez (deduplicado `scan:<imageId>`); una imagen ya escaneada no se vuelve a analizar salvo `force`. Sus findings se guardan **una sola vez, en el asset `image`**; cada contenedor llega a ellos por su relación `instance_of`.
- **Origen: `docker save sha256:<id>`** desde un host que la tenga (`stores` o un contenedor activo; también las imágenes sin uso), por la salida estándar de ssh (`Compression=yes`) **directamente a disco** en un directorio propio del job dentro de `WORKER_SCAN_DIR` (en disco, no tmpfs), que se borra siempre. En un CT va por `pct exec` (root, sin sudoers); en un servidor necesita el **sudoers v2**: `docker ^save sha256\:[0-9a-f]{64}$` (regex de sudo ≥ 1.9.10; un comodín permitiría `-o <ruta>`). Con sudo antiguo el script de alta avisa y no pone la regla.
- **Límites** `TRIVY_MAX_IMAGE_SIZE` (se comprueba antes con el tamaño de `docker image inspect` y durante la descarga) y `TRIVY_SCAN_TIMEOUT` (descarga + análisis). Superarlos, un sudoers < v2 o un sudo que deniega ⇒ imagen `skipped` con su motivo y **el job termina bien**. Un error real (conexión, `docker save`, Trivy) ⇒ `failed` y el job falla. Un re-escaneo forzado que no se completa conserva el escaneo anterior y anota el motivo.
- `trivy image --input <tar> --cache-dir <TRIVY_CACHE_DIR> --cache-backend memory --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json`, con `HOME` y `TMPDIR` en el directorio del job. `--offline-scan`: Trivy no consulta nada fuera con nombres de artefactos internos.
- **Verificación**: se guarda solo si lo analizado es la imagen pedida: `Metadata.ImageID` de Trivy (digest del config) = image ID con el almacén clásico; con el de containerd (Docker ≥ 29), el image ID es el del índice y debe aparecer en el `index.json` del tar.
- **Caché compartida** de las bases de datos (vulnerabilidades y Java, ~3 GB) en `TRIVY_CACHE_DIR`, **la misma para todas las réplicas** (volumen compartido, obligatorio con varias): por **generaciones** (`gen-<fecha>-<id>/` y el enlace `current` a la vigente). Se descargan como mucho cada `TRIVY_DB_MAX_AGE` horas, **bajo un lock de Redis** (`trivy-db`: una réplica descarga, las demás esperan y ven que ya está fresca), en una generación nueva que se publica de golpe (symlink temporal + `rename`). Cada job resuelve `current` al empezar y usa esa generación hasta terminar (la anota en `.readers/`): nadie lee nunca una BD a medio escribir. Las sustituidas se borran cuando nadie las lee y llevan más de 2 × `TRIVY_SCAN_TIMEOUT` sustituidas; las descargas a medias y la caché de antes de las generaciones (`db/` en la raíz), en la siguiente descarga. Sin red, el job sigue con la generación que haya. La caché de capas va en memoria, así que los escaneos pueden ir en paralelo.
- **Imágenes sin uso** (ningún contenedor activo): se escanean igual, con prioridad baja en la cola, y sus findings no cuentan como accionables: el panel y el filtro accionable de `/vulnerabilities` (`inUse=true`) los dejan fuera; «Ver todas» los muestra y cada CVE dice cuántas de sus imágenes no se usan (`unusedImages`).
- **Findings**: upsert por `(asset image, fingerprint)`; lo que un re-escaneo de la imagen deja de ver pasa de `open` a `fixed`, lo que reaparece vuelve a `open` y `accepted` se conserva. Un contenedor recreado con otra imagen no cambia findings: cambia su `instance_of`.
- **API**: `POST /assets/:id/scan[?force=true]` (solo admin; contenedor, imagen o host `docker-host`; un job por imagen), `GET /assets/:id/findings` (en un contenedor, los de su imagen, con el estado de su escaneo), `GET /assets/:id/vulnerabilities` (lo mismo agrupado por CVE: una fila por vulnerabilidad con su severidad máxima, si hay parche y los paquetes afectados; los filtros se aplican a cada finding y se pagina por CVE) y `GET /findings?vulnerabilityId=&severity=&status=` (búsqueda de CVEs: cada finding lleva `affected`, los contenedores no retirados de la imagen —recorriendo `instance_of`— con su padre `contains` para situarlos en el árbol).

**Servidores y CT** (job `host.scan`, cola `scan`; se encadena tras cada recolección correcta y con `POST /assets/:id/scan`):
- Trivy tampoco se ejecuta en el servidor: el worker copia **sin sudo** (ficheros legibles por todos; en un CT, por `pct-exec` desde el nodo) una **lista cerrada** de ficheros: identificación del SO (`os-release`, `debian_version`, `lsb-release` —sin él Trivy toma Ubuntu por Debian testing—, `*-release` de RHEL y derivadas, Alpine, Amazon, Mariner/Azure, SUSE) y BDs de paquetes (`var/lib/dpkg/status`, `lib/apk/db/installed`, rpmdb). Un `ls` y un `cat -- <ruta>` por fichero directo a disco, en su ruta canónica, en un directorio del job que se borra siempre; nada se desempaqueta ni se escribe en el servidor. Límites `HOST_SBOM_MAX_SIZE` (256 MiB) y `TRIVY_SCAN_TIMEOUT`. Luego `trivy rootfs` sobre la copia.
- De dpkg se quitan los paquetes sin ficheros instalados (`config-files`, `not-installed`): Trivy solo descarta `deinstall`/`purge` y contaría como instalado un paquete desinstalado con su configuración. Así el número de paquetes coincide con el de Ansible.
- **No cubre librerías de lenguajes sueltas en el disco** de los servidores (jar, `node_modules`, pip, binarios Go…): solo los paquetes del SO. En las imágenes sí, porque Trivy analiza la imagen entera.
- Sin ninguna BD de paquetes reconocida, sin host key fijada o con un CT cuyo nodo no permite `pct-exec` ⇒ `skipped` con el motivo; el job termina bien. Mismos paquetes y misma BD de Trivy que en la última evaluación ⇒ no se evalúa ni se reescribe nada.
- Los findings van en el propio asset (servidor o CT).

### SBOMs: inventario de software separado de las vulnerabilidades

- **Qué hay instalado** (SBOM) cambia poco y solo se actualiza con un escaneo.
- **Qué es vulnerable** cambia a diario.

Cuando sale un CVE nuevo **no se tocan los servidores**: se re-evalúan los SBOMs guardados con `trivy sbom <fichero>`, offline y en segundos.

**No comparar versiones con semver propio**: las distribuciones aplican backports de seguridad sin cambiar la versión principal. La detección se delega en Trivy, que tiene en cuenta los avisos de cada distribución. La app solo guarda e indexa.

### Job periódico de re-evaluación

Job `sbom.reevaluate` (cola `sbom`), cada `SBOM_REEVALUATE_INTERVAL` horas (24; 0 = desactivada) con un job scheduler de BullMQ que programa el líder (§20); a mano con `POST /sboms/reevaluate` (`assets.operate`, auditado como `vulnerabilities.reevaluate_requested`), que es lo que hace «Buscar con la BD actual» en el panel de fuentes de Vulnerabilidades. Con `{ "downloadDb": true }` («Descargar la BD y buscar») el worker descarga antes la BD **aunque no haya caducado**, con el mismo lock y la misma publicación por generaciones (§9, §20); si otra réplica publicó una después de pedirla, no la repite. Deduplicada: si ya hay una pendiente o en curso, la respuesta lo dice (`deduplicated`) y se espera a esa. El job del scheduler (id `repeat:…`, que no cabe en `job_runs`) solo encola otro con UUID, deduplicado, que es el que sale en la Actividad.
1. Actualizar la base de datos de Trivy (como mucho cada `TRIVY_DB_MAX_AGE` horas). Si no hay red, se evalúa con la de la caché y se dice en `dbUpdateError`.
2. Re-evaluar con `trivy sbom` todos los SBOMs guardados de assets no retirados y con el escaneo activado (§10), **sin conectarse a ninguna máquina** (el job no usa SSH). Uno que falla se anota en `evaluationError` y no para al resto.
3. Sincronizar los `Finding` de cada asset con la fila del SBOM bloqueada: los nuevos se abren, los que desaparecen pasan a `fixed`, los que reaparecen vuelven a `open` y `accepted` se conserva. Guarda también el CVSS del informe (así la re-evaluación lo rellena en los findings de antes de la sesión 19).
4. Al terminar, pide un `findings.prioritize` (prioridad y avisos, abajo). KEV y EPSS tienen su propio job.
5. **Relleno**: las imágenes escaneadas antes de los SBOMs (`scanned` sin SBOM) se vuelven a escanear con prioridad baja, **una a la vez por host** (cada una encola la siguiente del mismo host) y sin reintentos en bucle: si falla o no se puede, `container_images.sbom_backfill_failed_at` y ya solo con un escaneo manual.

### Priorización con contexto de servicio (sesión 19)

**KEV y EPSS** (job `vulnerability.intel`, cola `system`): catálogo **CISA KEV** (JSON) y puntuaciones **EPSS** de FIRST (CSV con gzip) cada `VULN_INTEL_INTERVAL` horas (worker, 12; 0 = nunca) con un job scheduler como el de la re-evaluación (el del scheduler solo encola otro con UUID, que es el que sale en la Actividad), y a mano con `POST /vulnerabilities/intel/refresh` (`assets.operate`, auditado). URLs `KEV_URL` y `EPSS_URL` (vacías = esa fuente desactivada: entorno sin salida o espejo propio).
- **Caché**: GET condicional (`If-None-Match`/`If-Modified-Since` con el ETag y la fecha guardados): un 304 no descarga nada; la misma `catalogVersion` o fecha de EPSS no reescribe nada. La manual fuerza la descarga. Topes de tamaño (64 MiB descargados, 256 MiB descomprimidos) y tiempo (`VULN_INTEL_TIMEOUT_MS`).
- **Tolerante a fallos**: un error de red, HTTP o formato (gzip roto, catálogo vacío) **conserva los datos anteriores** y anota `lastError`/`lastErrorAt`; el job termina bien y su resultado dice qué fuente falló. Volcado en una transacción: lo que sale del catálogo KEV deja de estar en KEV; solo se reescribe lo que cambia.
- `GET /vulnerabilities/intel`: estado de cada fuente con su antigüedad (`stale` con más de 3 días). La web lo enseña en la cabecera de Vulnerabilidades («KEV del 19 oct · EPSS del 19 oct», en ámbar si falla o está viejo; el detalle, en el panel «Fuentes de datos»).
- Medido: 1 748 CVE de KEV y 391 411 de EPSS en unos 5 s.

**Ruido** (`noise_reason`, sale de la vista principal con su motivo):
- **Kernel no en uso** (`kernelPackageUse`, `packages/domain/src/kernel.ts`, con tests; patrones solo ahí): Trivy cuelga los CVE del kernel de **cada** paquete binario de la fuente `linux` (en Ubuntu, miles y casi todos `affected`). Solo ejecutan ese código la imagen y los módulos del kernel que arrancó (`facts.os.kernel` = `uname -r`). Otro kernel instalado (`linux-image|modules-<versión>`, `proxmox-kernel-*`, `pve-kernel-*`; en RHEL, la versión de `kernel*`) ⇒ «kernel no en uso (en ejecución: …)»; cabeceras, herramientas, `linux-perf`, `bpftool`, `linux-libc-dev` y metapaquetes ⇒ «cabeceras o herramientas, no el kernel en ejecución»; cualquiera en un CT o una imagen ⇒ usan el del nodo/host. Sin `uname -r`, la imagen y los módulos cuentan como en uso. **En plesk-pruebas no bastaba con comparar con `uname -r`**: su kernel instalado es el que corre; el ruido eran sus 8 paquetes auxiliares.
- **Sin corrección prevista**: `will_not_fix` y `fix_deferred` de Trivy, aparte de `affected` («sin parche aún»). **Un CVE en KEV nunca se oculta por esto.**
- Imágenes sin uso y assets con el escaneo desactivado: como antes (se calculan al consultar).

**Prioridad explicable** (`scoreFinding`, `packages/shared-types/src/priority.ts`, pura; **pesos solo en `PRIORITY_WEIGHTS`**, que un test fija): base CVSS × 4 (sin CVSS, por severidad: 9,5 · 7,5 · 5 · 2,5 · 4), **+30 en KEV**, EPSS (≥ 0,5 +15 · ≥ 0,1 +10 · ≥ 0,01 +4), **+5 parche disponible**, **+5 en marcha** (el paquete es el ejecutable o una librería de un proceso en marcha, v6; o la imagen tiene contenedores en marcha), **+10 puerto expuesto** (ese proceso escucha en `0.0.0.0`/`::`/una IP no loopback, o el contenedor publica fuera de `127.0.0.1`), **+10 nombre público delante** (QoL-5b), × 0,5 imagen sin uso; acotada a 0–100. Bandas: urgente ≥ 70, alta ≥ 50, media ≥ 30, baja. Cada finding guarda sus **motivos** en orden de peso (códigos con datos; el texto lo pone `priorityReasonText`, compartido por web, API y exportación): «en KEV · EPSS 92 % · expuesto en 22 (sshd) · cargado por sshd · parche disponible». Un CVE toma la prioridad y los motivos de su finding **que no es ruido** más prioritario (un CVE del kernel en uso y de sus cabeceras es del kernel en uso).

**Cálculo** (job `findings.prioritize`, cola `system`, `FindingPrioritizer` en `apps/worker/src/intel/prioritizer.ts`): pasada entera por tandas de 50 assets con su contexto (kernel, procesos y puertos de los facts; contenedores de cada imagen por `instance_of` con su estado y puertos publicados; nombres públicos con `EXPOSED_ASSETS_SQL`, que pasó a `packages/domain`; KEV y EPSS) y **solo escribe lo que cambia**. Lo piden los escaneos y la re-evaluación, la recolección, el descubrimiento, la sincronización de dominios, los caminos y la descarga de KEV/EPSS, y el arranque del worker; las peticiones de 3 s se juntan en un job (id `prioritize-<uuid>`: no sale en la Actividad). Medido: 30 441 findings en unos 2 s.

**Aviso inmediato**: un finding abierto, **CRITICAL, en KEV y expuesto** (puerto expuesto o nombre público) sin `kev_alerted_at` ⇒ notificación `vulnerability_kev` por asset con sus CVE (`items` de tipo `vulnerability`, enlazan a la ficha) y se marca. Marcar y avisar van en una transacción con `UPDATE … WHERE kev_alerted_at IS NULL RETURNING`: dos pasadas a la vez no avisan dos veces. Al reabrirse, se borra la marca y vuelve a avisar. El resto va al panel («Vulnerabilidades prioritarias»).

**API**: `GET /vulnerabilities`, `/findings`, `/assets/:id/vulnerabilities`, `/vulnerabilities/new` y la exportación llevan `priority` (`score`, `band`, `reasons`), `kev`, `epss`, `cvss` y `noiseReason`; ordenan por prioridad (`sort=severity` para lo de antes). Filtros: `minPriority`, `kev`, `minEpss`, `exposure=any` (cualquier exposición; `public` sigue), `includeNoise` (por defecto el ruido sale de las listas globales; la ficha de un asset lo incluye siempre, marcado) y `hidden=<motivo>` (solo lo que la vista oculta por él). `GET /vulnerabilities` devuelve `hidden`: los findings que el filtro deja fuera por el **primer** motivo que los oculta (escaneo desactivado, imagen sin uso, kernel no en uso, sin corrección prevista, prioridad por debajo de la pedida), solo de los motivos que aplica. `prioridad:` en la búsqueda (urgente, alta, media, baja; se puede negar). `GET /vulnerabilities/:id`: `enrichment` (`kev: { added, due, ransomware, name }`, `epss: { score, percentile }`), `priority` y la de cada nodo del árbol.

**Resultado en el entorno de pruebas** (copia de la BD, 2026-10-19): en plesk-pruebas, de 24 858 findings abiertos quedan **187** en la vista principal (el 99,2 % fuera: 21 840 kernel no en uso, 2 831 de prioridad baja); en todo el inventario, 845 CVE visibles de 4 138, y las primeras filas son las de KEV (freetype y HTTP/2 Rapid Reset) y las expuestas en el 80 de Traefik.

### Búsqueda de CVEs en la UI

Implementada en la sesión 16.

**Barra de búsqueda global** en la barra superior (atajo `/`; en móvil, una lupa que la despliega): `GET /search/suggest?q=` da **recursos** (cualquier asset no retirado: por nombre, dirección de conexión o IPv4, rol o etiqueta; con su tipo, padre y dirección), CVE por prefijo (de los findings) y paquetes por subcadena (de los SBOMs y los findings) con sus CVE abiertos y assets. Un recurso abre su ficha; un CVE escrito entero, la suya aunque no esté en el inventario; un paquete, la lista con sus CVE abiertos de cualquier severidad. Enter sobre otro texto lo busca en el inventario (`/inventory?q=`; la otra opción, en vulnerabilidades). Enter elige siempre la primera opción: pasar el ratón no la cambia.

**Ficha de un CVE** (`GET /vulnerabilities/:id`):
- **Resumen**: título, descripción, CVSS por fuente (NVD primero), CWE, fechas y referencias, de la **BD de vulnerabilidades de Trivy**; severidad máxima, versiones que lo corrigen y estados de la distribución, de los findings; KEV y EPSS (`enrichment`) y la prioridad con su porqué (sesión 19).
- **Árbol de afectados** con la jerarquía real (nodo → CT → contenedor → imagen): servidor o CT con findings ⇒ «actualizar paquete»; imagen ⇒ cuelga de cada contenedor que la usa (`instance_of`) y «reconstruir imagen»; imagen sin contenedor activo ⇒ bajo el host que la guarda (`stores`), «sin uso»; los antepasados por `contains` son contexto. Cada nodo lleva paquete y versión instalada, estado de ejecución y **puertos expuestos** (en escucha fuera de loopback o publicados por Docker). Activos antes que desaparecidos.
- Si no afecta a nada: «ningún asset afectado según los últimos SBOM, evaluados el …» (con los findings ya corregidos, si los hubo). Si además Trivy no lo conoce: **CVE desconocido**. Si no se pudo consultar Trivy: «no se pudo comprobar si existe».
- **Re-escanear los afectados** (`POST /vulnerabilities/:id/rescan`, admin): `host.scan` de cada servidor o CT e `image.scan` de cada imagen, con `force`; lo no escaneable va en `skipped`. La web sigue cada job (`GET /jobs/:id`) y recarga al terminar.

**Detalles desde la BD de Trivy** (job `vulnerability.lookup`, cola `system`): la API no toca Trivy; encola una consulta que el worker resuelve con un **lector propio de BoltDB de solo lectura** (`scan/trivy-db.ts`) sobre `<TRIVY_CACHE_DIR>/current/db/trivy.db` (la generación vigente, resuelta una vez por consulta; sin generaciones, la caché antigua), bucket `vulnerability`. Sin dependencias, con lecturas posicionales y **sin flock ni mmap** (no bloquea a Trivy, que lo abre al escanear y lo reemplaza al descargar); valida las dos meta (magic, versión, checksum FNV-1a, txid) y que las páginas estén en rango. Exige `metadata.json` con `Version: 2` (esquema de trivy-db); si no, o si algo no cuadra ⇒ `unavailable` con el motivo (una descarga en curso ya no afecta: va en otra generación), y la ficha sigue con lo de los findings («detalles del CVE no disponibles»). La API espera como mucho 5 s (`JobsService.runQuick`) y guarda en memoria 10 min lo definitivo (`found`/`not_found`). El id del job es `lookup-<uuid>`: no es un UUID, así que no entra en `job_runs` ni en la Actividad.

**CVEs nuevos desde tu última visita**: panel en Vulnerabilidades con los findings **abiertos** con `opened_at` posterior a `users.vulnerabilities_seen_at`, agrupados por CVE (`GET /vulnerabilities/new`; filtro `openedSince` de `findingWhere`). Un finding reabierto (`fixed` → `open`) cuenta como nuevo. La fecha **solo avanza con «Marcar como vistos»** (`POST /vulnerabilities/new/seen`); la primera vez se inicializa a ahora.

---

## 10. Reconciliación y mantenimiento del inventario

Cada X tiempo (configurable por asset o etiqueta) se relanza el descubrimiento de los nodos raíz y se compara con la base de datos:

- **Nuevo** → se añade automáticamente y se notifica.
- **Cambiado** → nuevo snapshot en el historial.
- **Desaparecido** → **no se borra**. Pasa a `missing`, y tras varias ejecuciones sin verlo, a `retired`. Así un CT apagado o un fallo de red no rompen el inventario.

Opcional: escuchar eventos o webhooks de Proxmox para reaccionar sin esperar al siguiente ciclo. El sondeo periódico es lo imprescindible.

### Política de inventario

Tres campos por asset: **intervalo de reconciliación** (`reconcileIntervalMinutes`, 0 = nunca), **escaneo** (`scanEnabled`) y **escaneo automático** (`scanPeriodic`); efecto de los dos últimos en §9. Reglas (`inventory_policies`): la **global** (sembrada: 6 h, sí, sí; editable en Ajustes), una por **asset**, una por **etiqueta** y una por **proyecto**. Se resuelve **campo a campo** (`resolvePolicies`, pura, en `packages/domain`):
1. la regla del propio asset;
2. la del antepasado `contains` más cercano que fija ese campo (una regla en un nodo vale para todo lo que contiene);
3. las de sus etiquetas: la más restrictiva (`false` gana; en el intervalo, «nunca» y si no el más largo);
4. las de sus **proyectos** efectivos (heredados incluidos): la más restrictiva, con el mismo criterio;
5. la global.

La etiqueta va antes que el proyecto porque se pone **en el propio asset** y el proyecto suele llegar heredado de un nodo; las reglas de asset (propia o de un antepasado), puestas a propósito en una rama, ganan a las dos.

Las **imágenes** (fuera del árbol) sin regla propia ni de etiqueta escanean si **alguno** de los hosts (`stores`) o contenedores (`instance_of`) no retirados que las usan lo permite: una imagen compartida sirve también al host que sí escanea. La efectiva se guarda en `assets.effective_policy` con el origen de cada campo (`own`, `inherited` + asset, `tag` + etiqueta, `project` + proyecto, `holders`, `global`; a las imágenes los proyectos no se les aplican directamente sino a través de quienes las usan, así una imagen compartida con un proyecto que no escanea sigue escaneando para el que sí) y se recalcula entera (`recomputePolicies`, con el candado de `contains`) al cambiar reglas, etiquetas, estado o relaciones (API), tras reconciliar los hijos y las imágenes (worker) y al arrancar la API. El intervalo solo actúa en los nodos raíz.
- API: `GET /inventory-policies`, `PUT /inventory-policies/global`, `POST|PATCH|DELETE /inventory-policies/:id` (asset, etiqueta o proyecto; al menos un campo, las exclusiones cuentan), `GET|PUT|DELETE /assets/:id/policy` (efectiva con orígenes, regla propia, nodo raíz que lo reconcilia, última y siguiente reconciliación). Cambios con `policy.write`.

### Exclusiones del escaneo (QoL-6b)

Cualquier regla (asset, etiqueta, proyecto o la global) puede **excluir del escaneo** recursos concretos sin dejar de inventariarlos (`scanExclusions`): por **tipo** (solo los que se escanean: `image`, `server` y `lxc`; volúmenes y redes no se escanean nunca, así que no se ofrecen), por **patrón de nombre** (glob con `*` y `?`, sin mayúsculas, sobre el nombre visible o el descubierto; hasta 20 de 100 caracteres) o por **asset** (hasta 200). Funciones puras en shared-types: `normalizeScanExclusions`, `scanExclusionMatch` y `scanDisabledReason`/`scanExclusionText` (el motivo legible, que comparten la API, el worker y la web).
- **Herencia**: las exclusiones que alcanzan a un asset son la **unión** de las de su regla, sus antepasados `contains`, sus etiquetas, sus proyectos y la global (sumar es lo más restrictivo, como `false` en los demás campos, y gana a un `scanEnabled: true` explícito). Si alguna lo atrapa, su `scanEnabled` efectivo es `false` con el origen `excluded` (`by`: la regla; `match`: tipo, patrón o asset). Así todo lo que ya mira `scanEnabled` (worker, `FindingsService.scan`, listas, árbol) lo respeta sin más.
- **Imágenes**: excluidas por su regla, sus etiquetas o la global, o cuando **ningún** host o contenedor que la usa la deja escanear (cada uno tiene el escaneo desactivado o una exclusión que la atrapa; `holderId` dice por cuál). Una imagen compartida sigue escaneando para el host que la permite, como antes.
- **Motivo visible**: la tarjeta de política de la ficha («excluido por la regla de pve-pruebas, que alcanza a pruebas (tipo: imágenes de contenedor)»), el botón «Escanear» deshabilitado con ese texto y el 409 de `POST /assets/:id/scan`.

### Organización y política en el alta (QoL-6b)

`POST /assets/enroll` admite `tags`, `projectIds` (requiere `projects.write`) y `policy` (la regla propia, requiere `policy.write`; 403 sin el permiso). Se aplican **en la misma transacción** que crea el asset, con `recomputePolicies`; el `asset.created` de la auditoría lleva tags, proyectos y la regla. Las **plantillas** (`INVENTORY_POLICY_PRESETS`: Estándar, Solo inventario, Sin imágenes, Escaneo bajo demanda) solo rellenan el formulario, que se puede retocar. Para que la primera recolección automática la respete, el worker recalcula la política al marcar el alta como verificada (`markVerified`) y la recolección relee la política efectiva justo antes de decidir el SBOM del host (antes la leía al empezar: un asset recién creado tenía `{}`, es decir, los valores por defecto).

### Reconciliación periódica

Job `inventory.reconcile` (cola `reconcile`) que un job scheduler de BullMQ (lo programa el líder, §20) lanza cada `RECONCILE_TICK` segundos (worker, 300; 0 = apagada; el del scheduler no entra en la Actividad). Una comprobación completa a la vez (lock `reconcile:all`) y cada nodo raíz bajo su lock (`reconcile:<id>`, revisando de nuevo si le toca): con varias réplicas, una manual y la periódica nunca lo encolan dos veces. Elige los **nodos raíz** (sin padre `contains`, con conexión —o conectores `dns_provider` con token—, activos, no duplicados) con el intervalo vencido según `reconciledAt` y encola su `asset.collect` con `trigger: 'reconcile'` (deduplicado por asset), que encadena el descubrimiento, la recolección de los hijos y sus descubrimientos (§8); a un conector de dominios, su `domains.sync` (§13). En cada tick sin `assetId` también se rehacen los **enlaces de los registros DNS** (sin DNS: un servidor que cambia de IP o se retira se refleja sin esperar a la sincronización) y se revisan los **avisos de caducidad** (§13); un fallo ahí solo va al log. `reconciledAt` se fija al encolar y en cada recolección correcta (la migración lo inicializó con la última). A mano: `POST /inventory/reconcile` (admin; con `assetId`, ese nodo raíz ahora).
- **Nodos raíz que fallan** (sin red, host key, sudo…) **no pasan a `missing`**: se notifica (`reconcile_failed`), igual que el fallo de cualquier job de la cadena; el mismo fallo del mismo asset no se repite en 24 h.

### Desaparecidos y retirados

- Con el listado **completo** de un descubridor (§8), lo que no aparece pasa a `missing` con `missingRuns = 1`, `missingSince` y su padre como ámbito; **sus descendientes activos** también (un CT destruido se lleva sus contenedores; vuelven con su propio descubrimiento). Cada descubrimiento completo de su ámbito sin verlo suma uno; con `missingRuns ≥ RECONCILE_RETIRE_AFTER` (worker, 3) pasa a `retired` con `retiredAuto` **con todo su subárbol**; se quitan los `stores` de los hosts retirados y las imágenes que se quedan sin host se retiran también. Nunca se borra nada: snapshots, findings y relaciones se conservan.
- **Imágenes**: sin ningún host pasan a `missing` con el último host como ámbito; cada descubrimiento Docker completo de ese host suma uno, y a `RECONCILE_RETIRE_AFTER`, retirada automática.
- **Reaparición**: un `missing` o un retirado automáticamente que vuelve a verse pasa a `active` con los contadores a cero (las imágenes, en cualquier host). Uno **dado de baja a mano** no se reactiva (aviso); un cambio de estado a mano pone los contadores a cero.

### Snapshots solo con cambios

`diffSnapshots` (puro, `packages/domain/src/snapshot-diff.ts`) compara facts y roles con el último snapshot del asset sin lo volátil; sin cambios no se guarda snapshot (los facts del asset sí se actualizan; el job dice «sin cambios»). La **lista de lo volátil está centralizada y con test** (cada entrada debe existir en los facts de ejemplo de su tipo y cualquier otra hoja cuenta como cambio):
- rutas: `infraward.collectedAt`, `mounts.*.availableBytes`, `ports.*.pid`, `proxmox.uptime|discoveredAt|config.lock`, `docker.discoveredAt|startedAt`, `plesk.discoveredAt`, `certificate.discoveredAt`;
- elementos de lista: interfaces de Docker (`veth…`, `docker0`, `br-<id>`) en `network.interfaces` y `proxmox.interfaces` (cambian de nombre y MAC al reiniciar contenedores; las redes de Docker ya son assets) y los servicios de systemd bajo demanda (`systemd-timedated|hostnamed|localed` y sus alias D-Bus: los despierta la propia recolección).

Las listas de objetos se comparan **por clave** (paquetes por nombre y arquitectura, servicios por nombre, puertos por protocolo, dirección y puerto, montajes, interfaces, puertos publicados, montajes y redes de contenedores) y las de valores simples como conjuntos: `packages[openssl:amd64].version`, `proxmox.config.memory`. Como mucho 2000 cambios por snapshot (`truncated`; el resumen cuenta todos).

### Notificaciones

En la app (sin canales externos por ahora): las escribe el worker en la misma transacción que el cambio, **agrupadas por descubrimiento y padre** («Pruebas Limpia: 1 desaparecido — pruebas-alpine (lxc)»), más los fallos de la reconciliación y el **aviso inmediato** de CVE críticos, en KEV y expuestos (`vulnerability_kev`, uno por asset y apertura, §9). `GET /notifications` (con `unread`), `GET /notifications/unread-count` y `POST /notifications/seen` («leídas» por usuario). Campana en la barra superior (§15).

---

## 11. Terminal web interactiva

Permite abrir una terminal interactiva en el navegador sobre cualquier asset del inventario.

### Funcionamiento

- Frontend: **xterm.js**, conectado por WebSocket al **gateway**.
- El gateway abre una sesión SSH con PTY contra el destino y hace de puente, con soporte de redimensionado, colores y programas interactivos (`htop`, `vim`…).
- La terminal web es **un cliente más del gateway** (§12): xterm.js → WebSocket → gateway → máquina. Una sola implementación de la lógica de conexión, permisos y grabación.

### Salto según el tipo de asset

| Asset | Cómo se llega |
|---|---|
| Servidor | SSH directo |
| CT de Proxmox | SSH al nodo + `pct enter <vmid>` (sin SSH dentro del CT) |
| Contenedor Docker | SSH al host + `docker exec -it <contenedor> sh` |
| VM | SSH propio si está dada de alta |

La ficha de cada asset tiene un botón **"Abrir terminal"** que resuelve el salto automáticamente recorriendo el árbol de relaciones.

### Seguridad

Esta funcionalidad rompe el modelo de solo lectura, así que tiene reglas propias:

- **Nunca se usa el usuario `inventory`** del descubrimiento; su sudo está acotado a propósito. La terminal entra con la cuenta de administración del «acceso interactivo de administración» (§7), solo en los assets que lo tengan activado; en los demás, la terminal no está disponible o es de solo lectura.
- **Identidad personal**: con OpenBao, se firma un certificado SSH de pocos minutos con el *principal* del usuario logueado en la app, para que los logs del servidor reflejen quién hizo qué. Sin OpenBao, se usa una credencial de acceso interactivo separada por asset.
- **Permiso explícito** `terminal.open` por asset, etiqueta o proyecto (AccessPolicy), y **reautenticación o MFA** antes de abrir sesión.
- **Grabación de sesiones** en formato asciinema (`.cast`), reproducibles desde la web.
- **Timeout de inactividad** y duración máxima por sesión.
- Toda sesión queda registrada en `TerminalSession`.

### Implementación (sesión 21: gateway I, sin web)

**Flujo**
1. **Cliente → API**: `POST /terminal/sessions { assetId }` (`@SessionOnly`, `@Can('terminal.open')`, `@RecentAuth('terminal.open')`; con un token de API, nunca). La API comprueba el destino: servidor, CT o contenedor activo; el CT con su vmid y el contenedor con su id de Docker; y el **servidor por el que se entra** (el propio asset o el antecesor más cercano con conexión SSH) con `adminAccess`, en modo CA y con la host key fijada. Si no, 409 con el motivo (y auditoría `terminal.session_rejected`); sin firmante o sin `GATEWAY_PUBLIC_URL`, 409 `terminal_unavailable`. Crea la fila `pending` con el sha256 de un **ticket de un solo uso** (32 bytes, 60 s), audita `terminal.session_requested` y devuelve `{ sessionId, ticket, gatewayUrl, expiresAt }` (`Cache-Control: no-store`).
2. **Cliente → gateway**: WebSocket en `/terminal`; el primer mensaje es `{ type: 'auth', ticket, cols, rows }` (el ticket nunca va en la URL). Datos de la terminal en frames **binarios** en los dos sentidos; control en JSON (`resize` del cliente; `ready`, `notice` y `exit { reason, code, message }` del gateway; `parseTerminalClientMessage` en shared-types valida tamaños y ticket). Con `Origin`, solo los de `WEB_ORIGIN`; sin `Origin` (el cliente de pruebas), se admite. Mensajes de hasta 256 KiB.
3. **Gateway → API** (`/internal/gateway/sessions/*`, `@Public()` + `GatewayAuthGuard`: `Authorization: Gateway <secreto>` comparado por sha256 en tiempo constante con `GATEWAY_API_SECRET_FILE`; sin él, las rutas dan 404; fuera de OpenAPI; el nginx de la web no las publica): `redeem` gasta el ticket (`pending` → `starting`, condicionado: de dos canjes solo gana uno) y **vuelve a comprobar** usuario activo, rol con `terminal.open`, sesión web viva y destino válido (si no, `rejected`/`denied`); `:id/certificate` firma la clave efímera del gateway (solo en `starting`, en el minuto siguiente al canje y como mucho 3 veces): principal **`infraward-operators`**, **key_id `infraward:session=<id>:user=<email>:asset=<id>`** (con el id del usuario si el email no pasa la lista blanca), `permit-pty`, `TERMINAL_CERT_TTL` (120 s); `:id/opened` y `:id/closed` registran apertura y cierre y los auditan a nombre de la persona (`terminal.session_opened|closed|rejected`, con motivo, código y duración).
4. **Gateway → servidor**: `InteractiveRoutes` (sobre `AssetRoutes` del worker): servidor → SSH directo; CT → SSH al nodo + `sudo -n pct enter <vmid>`; contenedor → SSH a su host Docker (o al nodo, con `sudo -n pct exec <vmid> -- …` si el host es un CT) + un script fijo que comprueba que está en marcha y hace `docker exec -it <id> /bin/bash`, o `/bin/sh` si no hay bash, o avisa «El contenedor no tiene shell (sh ni bash)»; el id va como `$1`, nunca interpolado. Siempre con la cuenta de `adminAccess`, nunca `inventory` ni `root`. `SshClient.interactive` reutiliza el material del worker (clave efímera, `CertificateFile`, known_hosts con la host key fijada, `StrictHostKeyChecking=yes`) sin maestro (`ControlMaster=no`), `ssh -tt` con `ServerAliveInterval`; la firma la pide la misma `SshIdentity { kind: 'certificate', sign }` del worker, cuyo `sign` llama a la API. Clave y certificado se borran en cuanto llega el primer byte (ya autenticado) y siempre al terminar (directorio `infraward-term-*`, que el limpiador del worker no toca).
5. **PTY**: un **puente en Python** (`pty`, `select`, `TIOCSWINSZ`; solo la biblioteca estándar: `python3` ya va en la imagen por Ansible) en lugar de un módulo nativo (node-pty no trae binarios para Linux y exigiría compilar en la imagen): `ssh` corre en un PTY local, stdin/stdout en bruto y un fd de control con `<columnas> <filas>`; el núcleo avisa a ssh con SIGWINCH y ssh manda el window-change al servidor. El puente cierra el PTY (SIGHUP a la shell) al cerrarse stdin o al recibir SIGHUP/SIGTERM, y mata el comando a los 3 s. Entorno mínimo (`PATH` y `TERM=xterm-256color`): ni agente SSH ni nada más.
6. **Host key**: `PinnedHostKeys` escanea primero **solo ED25519** y, si no coincide con la huella fijada, el resto; recuerda la clave que coincide (por host, puerto y huella) y la olvida si la conexión falla. Motivo: OpenSSH ≥ 9.8 (Debian 13, Proxmox 9) penaliza por IP las conexiones que no se autentican (`PerSourcePenalties noauth`) y cada tipo de `ssh-keyscan` es una; con tres tipos por sesión, sshd acababa rechazando la conexión («penalty: connections without attempting authentication»).

**Límites y tiempos**: cupo propio en el semáforo por host (`HostSlots.acquireTerminal`, mismo Lua sobre `slots:<host>:terminal`; `HOST_MAX_TERMINAL_SESSIONS`, 4), **aparte del de los jobs** (una terminal no frena la recolección ni al revés), y por persona (`terminal-user:<id>`, `TERMINAL_MAX_SESSIONS_PER_USER`, 3), entre todas las réplicas; las concesiones se renuevan cada 20 s y caducan solas si el gateway muere. Sin cupo: `exit` con `limit` y el motivo. Inactividad `TERMINAL_IDLE_TIMEOUT` (900 s) y duración máxima `TERMINAL_MAX_DURATION` (8 h), con aviso un minuto antes.

**Parada ordenada** (`GatewayLifecycle`): deja de aceptar conexiones (`/healthz` da 503), avisa a cada sesión («El gateway se va a reiniciar: guarda tu trabajo, la sesión se cerrará en N s», en amarillo dentro de la terminal y como `notice`), espera como mucho `GATEWAY_SHUTDOWN_GRACE` (60 s, menor que su `stop_grace_period` de 90 s; antes si terminan todas) y después cierra cada una con `gateway_shutdown` (SIGHUP a la shell, `exit` y cierre 1001 del WebSocket, cierre registrado en la API) y suelta los cupos.

**Identidad**: `gateway-<n>` (o `GATEWAY_NAME`), con el lease de `WorkerIdentity`; no publica ficha de réplica (no sale entre los workers). Va en `terminal_sessions.gateway` y en la auditoría (`viaApi: gateway:<nombre>`).

**Configuración** (`GatewayEnvironment`, fichero `apps/worker/.env.gateway`, distinto del del worker): BD (solo lee el inventario: sus entidades son las de `packages/domain`, sin `local_secrets`), Redis, `GATEWAY_API_URL`, `GATEWAY_API_SECRET_FILE`, `GATEWAY_PORT` (3010), `GATEWAY_HOST`, `WEB_ORIGIN`, `GATEWAY_TRUST_PROXY`, los límites y tiempos y `WORKER_TMP_DIR`/`SSH_CONNECT_TIMEOUT`. La API: `GATEWAY_API_SECRET_FILE`, `GATEWAY_PUBLIC_URL` (`ws://` o `wss://`), `TERMINAL_CERT_TTL` y `TERMINAL_OPENBAO_*` (§6). `deploy/example`: servicio `gateway` (misma imagen, `command: ["node", "dist/main.js", "gateway"]`, sin secretos salvo `gateway_api_secret`, puerto 3010 publicado: detrás de un proxy con TLS fuera de localhost).

**Cliente de pruebas** (`apps/worker/src/gateway/cli.ts`, `pnpm --filter @infraward/worker gateway:cli -- --api <url> --asset <id>`): entra en la API como la persona (email, contraseña y TOTP por la terminal o `INFRAWARD_EMAIL`/`INFRAWARD_PASSWORD`/`INFRAWARD_TOTP`, nunca como argumentos), pide la terminal, se conecta con el ticket, pone la terminal en modo raw y manda `resize` en cada SIGWINCH.

### Implementación (sesión 22: terminal web, AccessPolicy y cortes)

**Terminal web** (`/assets/:id/terminal`, dentro del shell, a pantalla completa): «Abrir terminal» en la cabecera de la ficha (solo si `GET /assets/:id/terminal` dice `allowed`; deshabilitado con el motivo si no está `available`) la abre **en otra pestaña** (`window.open(…, '_blank', 'noopener')`): cada pestaña es una sesión, con los cupos por persona y por host. El título de la pestaña es «Terminal · <asset>». xterm.js 5 y su `addon-fit` se cargan perezosos (`TERMINAL_ENGINE`, inyectable para los tests; su CSS va en los estilos globales). Al cargar pide el ticket (`POST /terminal/sessions`; si la reautenticación caducó, el interceptor abre el diálogo y repite la petición; con OIDC sale al proveedor y vuelve a la misma ruta, que vuelve a abrir la terminal sola), abre el WebSocket y manda el ticket en el primer mensaje. Datos en binario (`TextEncoder` a la ida, `Uint8Array` a la vuelta); `ResizeObserver` + `fit()` con rebote de 120 ms → `resize`. Barra: estado («Conectando…», «Conectada como infraward-admin», o el motivo del cierre), **Copiar** (la selección, también Ctrl+Shift+C), **Pegar** (`navigator.clipboard`, también Ctrl+Shift+V; Cmd+C/V en macOS ya van), **Reconectar** (ticket nuevo: vuelve a comprobar permiso y reautenticación) y «Volver a la ficha». Tema desde las variables de OptimusNG con `matchMedia` (cambia en vivo con el modo oscuro; en claro, una paleta ANSI más oscura). Confirmación al salir con la sesión abierta (`canDeactivate`) y al cerrar o recargar (`beforeunload`). Si la sesión web se cierra en esa pestaña, cierra el WebSocket. Los `notice` salen también como toast y el `exit` se escribe dentro de la terminal con su motivo.

**Mismo origen y cookie**: el navegador conecta a `GATEWAY_PUBLIC_URL` + `/terminal`, por defecto la ruta relativa **`/gateway`** del mismo origen que la web (`terminalSocketUrl` la completa: `ws:`/`wss:` según la página). La web hace de proxy: `proxy.conf.json` (`ws: true`) en desarrollo y `location ^~ /gateway/` en el nginx de la imagen (`GATEWAY_UPSTREAM`, con `resolver` de `NGINX_LOCAL_RESOLVERS`: sin gateway desplegado la web arranca igual). Así la CSP sigue en `connect-src 'self'`, el gateway no publica puerto y **la cookie httpOnly de la sesión viaja en el upgrade**: el gateway calcula su sha256 en memoria (nunca la guarda ni la registra) y lo manda en el canje (`redeem { ticket, gateway, sessionCookieHash }`); la API exige que sea el `token_hash` de la sesión web que pidió el ticket. Un ticket robado no sirve sin la cookie, ni con la de otra sesión de la misma persona. `Origin`: con cabecera, solo los de `WEB_ORIGIN` (403 en el upgrade, sin gastar el ticket); sin ella (el cliente de pruebas, que manda la cookie de su login), se admite.

**AccessPolicy** (§5): `terminal.open` lo da el rol (solo `admin`) o una regla. **Resolución** (pura, `canAccess`/`accessRuleApplies` en shared-types; la usan la API al decidir y al explicarlo): una regla de la persona o de su rol alcanza al asset si es suya (`own`), de un antepasado `contains` (`inherited`: una regla en un nodo vale para sus CT y contenedores), de una de sus etiquetas (`tag`) o de uno de sus proyectos efectivos (`project`). Sin reglas que quiten. `AccessService` (API) lee las reglas de la persona y, solo si tiene alguna, el contexto del asset (etiquetas, `effective_projects`, antepasados). **Comprobación**: `@CanOnAsset('terminal.open', req => req.body.assetId)` en `POST /terminal/sessions`, que `PermissionsGuard` resuelve (token `ACCESS_CHECKER`) **antes que `RecentAuthGuard`**: sin permiso, 403 sin pedir reautenticación; el canje y el latido vuelven a usar `AccessService.can`. **API** (`users.manage`): `GET /access-policies?assetId=&userId=`, `POST /access-policies` (reautenticación reciente, `access.grant`; 404 si el sujeto o el objetivo no existen, 400 si su rol ya lo tiene, 409 si se repite), `DELETE /access-policies/:id`, `GET /assets/:id/access` (roles que lo tienen siempre y reglas que alcanzan al asset con su origen); y para cualquiera `GET /assets/:id/terminal` (`{ allowed, available, reason, host, account }`; sin permiso no dice por qué no estaría disponible). Auditoría `access.granted|revoked` (sujeto, ámbito, etiqueta). **Web**: tarjeta «Acceso a la terminal» en el Resumen de servidores, CT y contenedores (admins: quién puede y por qué, «Dar acceso» en este asset a una persona o un rol, «Quitar» las propias) y **Ajustes › Acceso** (todas las reglas, alta por asset, etiqueta o proyecto, retirar).

**Cortes al momento**: la API vuelve a comprobar las terminales abiertas (`TerminalService.recheck`, la misma `denial` que el canje: persona activa, sesión web viva, permiso en el asset, destino con acceso) cuando se **cierran sesiones web** (`SessionRegistry.onSessionsClosed`: logout, desactivar, restablecer o cambiar la contraseña, restablecer el MFA), cuando **cambia el rol** de alguien (`PATCH /users/:id` y la sincronización por OIDC, `onUserChanged`) y cuando se **borra una regla** (`AccessService.onChange`). Como la FK pone `auth_session_id` a null al borrar la sesión, se revisan todas las abiertas (pocas). Las que ya no pueden seguir se marcan (`revoke_requested_at`, condicionado: se audita una vez, `terminal.session_revoked`) y se publican en el canal de Redis **`infraward:terminal:control`** (`{ type: 'revoke', sessions: [{ id, message }] }`); cada gateway (suscrito con una conexión aparte) corta las suyas: el motivo **en rojo dentro de la terminal** y como `notice`, SIGHUP a la shell y `exit` con `revoked` («Se ha cerrado la sesión de InfraWard desde la que se abrió la terminal», «Tu cuenta de InfraWard está desactivada», «Ya no tienes permiso para abrir terminales en <asset>»…), que se registra como un cierre normal.

**Latido y barrido**: el gateway late cada `GATEWAY_HEARTBEAT_INTERVAL` (15 s) a `POST /internal/gateway/heartbeat { gateway, sessions: [{ id, active }] }`; la API pone `heartbeat_at`, mantiene viva la sesión web de quien **teclea** (`active`: la salida no cuenta; `SessionService.touch` nunca revive una caducada) y devuelve las que hay que cortar (las que ya no pasan la comprobación y las que la API ya dio por cerradas): es el respaldo de lo indirecto (etiquetas y proyectos que cambian, la sesión web que caduca, el acceso de administración retirado) y de un aviso perdido, en ≤ 15 s. La API **barre** cada `TERMINAL_SWEEP_INTERVAL` (30 s; un `setInterval` en cada réplica, idempotente con `UPDATE … RETURNING`): las `starting`/`active` sin latido desde hace `TERMINAL_HEARTBEAT_TIMEOUT` (60 s) quedan `closed` (o `rejected` si no llegaron a abrirse) con `gateway_lost` y «El gateway <n> dejó de responder», auditadas; también caduca los tickets pendientes vencidos.

**Pendiente** (sesión 23): la grabación `.cast`.

---

## 12. Gateway SSH (mejora futura)

El gateway (modo `gateway` del worker), además de servir la terminal web, actúa como **servidor SSH** propio, implementado con `ssh2` (que incluye servidor SSH).

### Flujo

1. El usuario registra su clave pública en la app (o obtiene un certificado de corta duración tras iniciar sesión).
2. La app muestra el comando para cada asset al que tiene acceso, por ejemplo:
   ```bash
   ssh -p 2222 ana+pve1-ct105@gw.infraward.example.com
   ```
3. El gateway autentica al usuario y pide a la API acceso al asset. La API comprueba `AccessPolicy` y devuelve un **certificado SSH de pocos minutos** para el principal del usuario (firmado con la CA de OpenBao). El gateway abre la conexión real (con el salto `pct enter` / `docker exec` si aplica) y hace de puente. **El gateway nunca accede al gestor de secretos.**

### Extras

- Endpoint que genera un `~/.ssh/config` con los assets accesibles para poder hacer `ssh pve1-ct105` directamente.
- Soporte de `scp`/SFTP y *port forwarding* a través del gateway (con permisos específicos).
- Grabación, permisos y auditoría idénticos a la terminal web.

### Referencias

Proyectos a estudiar como inspiración: **Warpgate** (open source, muy similar en concepto) y **Teleport**. La ventaja del gateway propio es la integración directa con el inventario y el proveedor de secretos.

---

## 13. Inventario de dominios

Hecho en QoL-5 con Cloudflare; los registradores (OVH, Namecheap, Porkbun, GoDaddy…) quedan para más adelante.

### Conectores

- **`DomainProvider`** (`packages/connectors/src/domains/`): `verify(api)` y `list(api)` → zonas y registros, de **solo lectura**. Reciben un `DomainApi` ya autenticado que da el worker (`BearerApi`): el conector nunca ve el token. Errores con el estado HTTP y el código del proveedor, nunca el cuerpo ni las cabeceras (`DomainApiError`).
- **Cloudflare** (`CloudflareProvider`): `GET /user/tokens/verify` (si falla, el de su cuenta: `/accounts/<id>/tokens/verify`, para tokens de cuenta), `GET /zones` (50 por página) y `GET /zones/<id>/dns_records` (1000 por página), todas las páginas (`result_info.total_pages`). Nombres validados y en minúsculas; tipos fuera de `DNS_RECORD_TYPES` se ignoran; una zona o un registro que falla ⇒ listado **incompleto** (nada pasa a `missing`). La prueba avisa si falta *Zone:Read* (no lista zonas) o *DNS:Read* (no lee registros).
- **Catálogo** `DOMAIN_PROVIDERS` (shared-types): nombre, icono, qué se inventaría, etiqueta y dónde se crea la credencial, permisos mínimos y enlace a la documentación. Ajustes > Conectores sale de él: añadir un proveedor = una entrada ahí, su `DomainProvider` y su URL de API en el worker.
- **Cuenta como asset raíz** `dns_provider`: la crea `POST /connectors` (`connectors.write`) y su token se guarda con `SecretsService.store` en el **primer proveedor de secretos con escritura** (`secret://<prov>/connectors/<id>/<tipo>#apiToken`; si la transacción falla, se borra). El token solo viaja en esa petición y en `PUT /connectors/:id/token`; nunca vuelve a salir, ni va en los datos de un job (en Redis solo hay `assetId`). Varias cuentas o tokens = varios conectores; una zona que ya es de otro conector activo se omite con un aviso (no salta de uno a otro). Dar de baja (`DELETE /connectors/:id` o la baja de siempre) retira su subárbol y **borra el token del proveedor**.
- **Jobs** (cola `discovery`): `domains.test` (la API lo espera con `runQuick`, 20 s; guarda `facts.connector.verify`) y `domains.sync` (deduplicado por conector; manual con `assets.operate` o en la reconciliación periódica, §10, con la política de inventario del conector como intervalo). El alta prueba el token y, si vale, encola la primera sincronización.

### Sincronización (`DomainSync`, worker)

1. Zonas y registros del proveedor.
2. **Caducidad del dominio por RDAP** (`RdapClient`): bootstrap de IANA (`RDAP_BOOTSTRAP_URL`, en memoria 24 h; solo servidores https), `domain/<zona>`, eventos `expiration`/`registration`, registrador (vCard) y estados. Cada dominio como mucho una vez al día (si no, el resultado anterior). Un TLD sin RDAP (`.es`) queda `unsupported` («sin RDAP»); un error, `error` con su motivo.
3. **Certificado del 443** de cada nombre A/AAAA/CNAME no comodín (`probeTls`, como mucho 1000 por sincronización, `DOMAINS_CONCURRENCY` a la vez, `DOMAINS_TLS_TIMEOUT_MS`): solo el apretón de manos con SNI, sin exigir una cadena válida pero diciéndolo (`authorized`, `hostnameMatch`). Un certificado = un asset `certificate` por huella (`tls:<SHA-256>`, hijo del primer dominio en el que se ve), con `secured_by` desde cada registro; si la huella ya es de un certificado de Plesk, se enlaza ese. Una lectura que falla deja los certificados como listado parcial (no pasan a `missing`). Se conecta al nombre tal como lo resuelve el worker (lo que ve el público: con el proxy de Cloudflare, su borde) y solo al puerto 443 de los nombres de tus zonas.
4. `ListingReconciler` (§8): altas, cambios con snapshot, `missing` → `retired` y notificaciones, como el resto del inventario.
5. **Enlazado y colgantes** (`DomainLinker` + `linkDnsRecords`, pura), con los CNAME externos resueltos en este momento (`DomainResolver`; `DOMAINS_DNS_SERVERS` opcional).

### Enlaces y registros colgantes

- **IPs del inventario** (`assetIps`): interfaces reales de servidores, VMs y CT (recogidas o de Proxmox), las fijas de `net0…net9` y el host de conexión si es una IP (la pública de un NAT); sin loopback, enlace local ni interfaces virtuales (`docker0`, `veth`, `br-…`, `tailscale`, `wg`…), cuyas IPs se repiten entre hosts.
- **A/AAAA** → `resolves_to` a los assets activos con esa IP (varios: todos, `ambiguous`). Sin ninguno activo: si la tienen assets retirados o desaparecidos, se enlazan igual y el aviso es **alto** (`retired_target`); si nadie la tiene, **alto** si es privada (RFC 1918, CGNAT, ULA: debería estar en el inventario, `private_unknown`) e **informativo** si es pública (`public_unknown`: un tercero, quizá esperado).
- **CNAME** a un nombre de una zona inventariada → `resolves_to` a sus registros (o al comodín que lo cubre, o al dominio si es la raíz); sin ninguno, **alto** (`cname_internal_missing`). Externo: se resuelve A, AAAA y CNAME; solo **NXDOMAIN en todas** es «no existe» ⇒ **alto** (`cname_nxdomain`, *subdomain takeover*, con el servicio si es uno conocido: Azure, Heroku, GitHub Pages, S3…). «Sin datos de ese tipo» significa que el nombre existe (un DKIM solo tiene TXT). Los servicios con **DNS comodín** (Heroku, GitHub Pages, S3) responden a cualquier nombre, así que un CNAME a ellos que resuelve no prueba que la app siga siendo tuya: **informativo** (`cname_takeover_service`). Un túnel de Cloudflare (`*.cfargotunnel.com`) no avisa; un error del resolutor, «sin comprobar». En el tick (sin DNS) se usa el último resultado de cada CNAME.
- **«Marcar como esperado»** (`assets.write`, auditado): silencia el aviso de ese registro mientras su valor no cambie (`value_hash`). Los **informativos** se pueden marcar **en bloque por destino** (`POST /dns-checks/acceptance`: p. ej. los 28 registros a la IP pública de casa); los altos, nunca en bloque.
- Avisos: `dnsWarning` en el árbol (filtros `?attention=dns-dangling|dns-unknown`), `attention.dnsDangling` (alto) y `dnsUnknown` (informativo, discreto) en el panel, y una notificación `dns_dangling` por los **altos nuevos** (una vez por valor del registro).
- **«Dominios que le apuntan»** (`GET /assets/:id/domains`): los registros que llegan a un servidor, VM o CT, directos y por cadenas de CNAME (hasta 5 saltos, con los intermedios), con su certificado. En la ficha, en el mapa de relaciones (arista «resuelve a», discontinua y del color de los registros) y en la topología (el dominio es un grupo con «N registros DNS · N certificados»).

### Caducidades

- Umbrales **configurables** en Ajustes > Inventario (`GET|PUT /settings/expiry-warnings`, `policy.write`, auditado; 1–365 días, hasta 4, sin repetir; por defecto 30 y 7). Valen para dominios (RDAP) y **todos** los certificados (también los de Plesk): sustituyen a la antigua constante de 30 días.
- El **mayor** marca «caduca pronto» (panel: `certificatesExpiring`, `domainsExpiring`; árbol y fichas: etiqueta ámbar; caducado o por debajo del menor, roja).
- **Avisos** (`ExpiryAlerts`, en cada tick): lo que cruza un umbral (o caduca) manda una notificación `expiry_warning` agrupada («11 caducidades: grafana.example.com (certificado) caduca en 31 días; …»), **una vez por asset, fecha y umbral** (`expiry_alerts`): una renovación trae otra fecha y vuelve a avisar.

### Qué servicio sirve cada dominio (QoL-5b)

Para cada registro A/AAAA/CNAME, el asset final que lo sirve (servidor, CT o contenedor), encadenando **solo datos de solo lectura** del inventario. El cálculo es puro (`resolveServicePaths`, `packages/connectors/src/services/resolve.ts`); lo ejecuta el `ServiceLinker` del worker tras cada sincronización de un conector, en cada tick de la reconciliación, al terminar un descubrimiento (o una recolección sin descubrimiento) y con el job `services.link` (lo encola la API tras un cambio a mano y espera hasta 10 s).

- **Entrada**: un A/AAAA llega al **reenvío NAT** declarado para su IP y el puerto (Ajustes › Inventario › Reenvíos NAT: IP pública:puerto → asset:puerto; gana si existe) o al host con esa IP (`resolves_to`). Se prueba el **443 y el 80**: gana el primer camino completo y confirmado; si no hay, el primero completo (el `default_server` de un proxy, deducido); si ninguno llega, el que más avanza. Un CNAME interno sigue la cadena de QoL-5 hasta el A (el `Host` sigue siendo el nombre original); uno a `<id>.cfargotunnel.com`, la **regla de entrada del túnel** (API de Cloudflare, permiso opcional *Account · Cloudflare Tunnel · Read*; se guarda en el conector solo nombre, ruta y servicio de cada regla, nunca `originRequest`) y el servicio visto desde quien ejecuta `cloudflared` (contenedor con su imagen o proceso en `ss`; si hay varios, deducido).
- **Resolutores como plugins** (`ServiceResolver { kind, applies, next }`, `SERVICE_RESOLVERS`, en orden): `docker-proxy` (el puerto lo publica un contenedor del host: confirmado si `ss` muestra `docker-proxy`; deducido si solo lo dice Docker), `traefik` y `caddy` (etiquetas `Host(…)`/`caddy` de un contenedor vecino; sin puerto, el único expuesto, deducido), `npm` y `nginx` (rutas filtradas: `server_name` exacto o comodín, si no el `default_server`, deducido; sin `proxy_pass`, lo sirve el propio nginx; si un proxy ya eligió ese destino por el nombre —etiqueta, `server_name`, regla del túnel—, el `server_name` del destino da igual: su `default_server` cuenta como confirmado y, si sirve él mismo, no añade otro eslabón, como el nginx de una imagen `nginx` detrás de Traefik) y `listener` (un proceso cualquiera en escucha: el destino es el host o CT; un contenedor con la red del host cuyo proceso escucha, deducido). Un contenedor sin proxy es el destino final.
- **Destinos de un proxy**: `127.0.0.1`/`localhost` es el propio asset (en un contenedor, él mismo salvo con la red del host); un nombre, el contenedor vecino con ese nombre, servicio de compose o alias en una red compartida; una IP, el contenedor con esa IP en una red de Docker, la puerta de enlace (`172.x.0.1`, `host.docker.internal`) = el host, o el asset del inventario con esa IP.
- **Tope de 10 saltos y ciclos** (un `asset:puerto` repetido). Si la cadena se corta, se guarda hasta dónde llegó y por qué (`no_target`, `no_listener`, `no_route_for_host`, `unknown_upstream`, `proxy_unreadable` —p. ej. sudoers v4—, `tunnel_unknown`, `tunnel_no_config`, `no_cloudflared`, `max_hops`, `cycle`).
- **Cada eslabón** guarda su asset (o la IP pública), el puerto, el resolutor, el origen («npm: server_name app.x → app:3000») y la confianza (`confirmed`/`deduced`); el camino es confirmado solo si lo son todos.
- **Persistencia**: `dns_service_paths` (§5) y las relaciones `served_by` (registro → asset final) y `routes_to` (eslabón → siguiente), por diferencia como `resolves_to`. **Fijar el destino a mano** (`POST /assets/:id/service-path/pin`, `assets.write`, auditado `service.path_pinned|unpinned`; servidor, VM, CT, contenedor o base de datos) gana al calculado, que se sigue mostrando.
- **Lo que se guarda de los proxies**: solo nombres de host y destinos (`ProxyRoute`), filtrados en el propio servidor (§7) o con la lista blanca de etiquetas (§8); los túneles, sin `originRequest`. Tests de fugas con centinelas en cabeceras, ficheros de contraseñas, claves, credenciales en URLs, middlewares de `basicauth` y cabeceras del túnel: unitarios, el ayudante con sudo y sudo-rs reales y el e2e (`service-paths.e2e-spec.ts`: facts, snapshots, `job_runs`, auditoría, caminos, respuestas, log del worker y Redis).
- **Web**: ficha del registro, tarjeta **«Servido por»** (los eslabones con su icono, origen y confianza; el corte en rojo con el motivo; «Fijar el destino» con un buscador de assets / «Quitar»); ficha del dominio, **«Qué sirve cada nombre»**; ficha de servidor, VM, CT, contenedor o base de datos, **«Dominios que sirve»** y «Por aquí pasan»; mapa de relaciones con las aristas «servido por» y «envía a» y, centrado en un registro, **el camino completo resaltado**; Ajustes › Inventario › **Reenvíos NAT** (`policy.write`, auditado `settings.nat_*`).
- **Vulnerabilidades**: un nombre público delante es uno de los motivos de la prioridad (§9).

### Pendiente

- Detección de *takeover* en servicios con DNS comodín por huella HTTP («No such app», «There isn't a GitHub Pages site here»…): hoy son informativos.
- Registradores (caducidad sin RDAP, p. ej. `.es`).
- De QoL-5b: la configuración de Caddy por fichero (Caddyfile), el proveedor de ficheros de Traefik y los túneles gestionados localmente (config.yml), que hoy cortan el camino.
- De QoL-5b: **Apache** (resolutor con `apachectl -S` y un filtro en el servidor de `ServerName`/`ServerAlias`/`Listen`/`ProxyPass`/`RewriteRule [P]`, sudoers v6 como nota). Hoy un Apache en escucha es el destino final y su `ProxyPass` no se sigue (también en Plesk, detrás de su nginx).

---

## 14. Seguridad de la propia aplicación

La aplicación tiene acceso a **toda la infraestructura**; es efectivamente una llave maestra. Medidas obligatorias:

- **Sudo acotado con un ayudante de root**: el `sudoers` del usuario `inventory` permite **solo** `/usr/local/libexec/infraward/infraward-query` (sudoers v4, §7), nunca `ALL`. El ayudante es de root (0755, en un directorio que solo root puede tocar), admite una lista cerrada de consultas, valida cada argumento antes de ejecutar nada y ejecuta sin shell; las rutas de pvesh las compone él y `docker save` solo admite un id a la salida estándar. Vale igual con sudo clásico y con sudo-rs (Ubuntu ≥ 25.10). Un test ejecuta el ayudante con una batería de inyección, también a través de sudo y sudo-rs reales. **Aviso**: en nodos Proxmox y hosts Docker la lista es más documentación de intenciones que una barrera real: `pct-exec` implica root dentro de los CT (y un CT privilegiado no aísla del host), `docker inspect` expone la configuración de los contenedores (variables de entorno con secretos incluidas) y cualquier acceso al demonio de Docker equivale a root. En servidores sin Proxmox ni Docker sí limita. El aviso va también en el propio fichero de sudoers.
- **Qué versión del sudoers exige cada capacidad** (`SUDOERS_CAPABILITIES` en `shared-types`, única fuente de avisos, notas y comprobaciones; la cubre un test):

  | Capacidad | Versión | Roles | Si falta |
  |---|---|---|---|
  | `helper` (puertos, hardware y consultas de Docker, Proxmox y Plesk por el ayudante) | v4 | `*` (cualquier servidor) | aviso «sudoers desactualizado» |
  | `docker.save` (escanear imágenes) | v4 | `docker-host` | aviso «sudoers desactualizado» |
  | `plesk` (consultas del descubridor) | v4 | `plesk` | aviso «sudoers desactualizado» |
  | `proxies` (rutas de nginx, NPM, Traefik y Caddy: qué sirve cada dominio) | v5 | `*` | nota |
  | `processes` (paquetes de los procesos en marcha: prioridad de las vulnerabilidades) | v6 | `*` | nota |
  | `sshd` (si sshd admite el login de root o por contraseña, §19) | v7 | `*` | nota |

  `roles: ['*']` = cualquier servidor. Como el worker solo usa el ayudante, todas piden la v4 (las notas de volúmenes y redes de la v3 desaparecen: sin ayudante el servidor ya sale desactualizado). La versión exigida (`requiredSudoersVersion`) solo cuenta las capacidades que avisan; el mecanismo de notas (agrupadas por versión) se conserva para capacidades futuras. Los CT por `pct exec` lo pueden todo.
- **Consultas de Plesk acotadas**: el usuario de inventario solo puede ejecutar las consultas fijas `plesk-*` del ayudante (§8), no `plesk db` libre, que daría acceso de administrador a la base de datos de Plesk.
- **Ansible y sudo acotado**: `become` no funciona con un sudoers acotado (ejecuta `sudo /bin/sh -c …`, que equivaldría a `ALL`); los playbooks llaman a `sudo -n infraward-query <consulta>` explícitamente.
- **Solo lectura por defecto**: el descubrimiento nunca modifica nada. Cualquier acción futura (reiniciar, actualizar) será un permiso aparte y explícito.
- **Certificados SSH de vida corta** con la CA de OpenBao (modo CA, §7): sin claves privadas permanentes en los servidores, un principal fijo (`inventory`), key_id con el asset y el job en el log de sshd, pocos minutos de vida y una sola autenticación por job (ControlMaster). La clave privada de la CA no sale de OpenBao y la app no puede cambiarla (§6, rotación).
- **Verificación de host keys** (TOFU) y alerta si cambian.
- **Tokens de enrolamiento** de un solo uso y con caducidad corta.
- **Secretos solo en el worker**, nunca en logs (`no_log: true`) ni en respuestas de la API. La excepción explícita es «Revelar» de la caja fuerte (§19): solo admins, con reautenticación, auditado; y el worker no puede leer la caja fuerte.
- Rotación y revocación de claves desde la UI.
- **Acceso interactivo** (terminal web y gateway SSH) con identidad personal, permiso explícito (rol o AccessPolicy), MFA, cookie de la sesión ligada al ticket, cortes al momento, grabación y auditoría (§11, §12).

### Roles y permisos

Roles fijos con una **tabla única rol → permisos** (`ROLE_PERMISSIONS` en shared-types, cubierta por un test). La API la aplica con `@Can(permiso)` y `PermissionsGuard` (el rol se lee de la BD en cada petición) y la web la usa con `auth.can(permiso)` para enseñar solo lo que se puede hacer. Leer el inventario y las vulnerabilidades no exige permiso.

| Permiso | Qué permite | admin | editor | operator | auditor | viewer |
|---|---|:-:|:-:|:-:|:-:|:-:|
| `assets.operate` | recolectar, descubrir, escanear, re-escanear afectados, re-evaluar SBOMs, reconciliar | ✔ | ✔ | ✔ | | |
| `assets.write` | altas (script o a mano), comandos de alta, pasos a CA, editar, dar de baja, comprobar referencias; organizar: nombre visible, tags (y sus colores) y notas | ✔ | ✔ | | | |
| `assets.purge` | purgar (borrado físico) | ✔ | | | | |
| `projects.write` | crear, cambiar y borrar proyectos y decidir qué assets entran (y las excepciones) | ✔ | ✔ | | | |
| `policy.write` | política de inventario (también las reglas por proyecto) | ✔ | ✔ | | | |
| `secrets.status` | estado de los proveedores de secretos | ✔ | ✔ | | ✔ | |
| `audit.read` | registro de auditoría | ✔ | | | ✔ | |
| `users.read` | lista de usuarios (filtro de la auditoría) | ✔ | | | ✔ | |
| `users.manage` | gestionar usuarios | ✔ | | | | |
| `connectors.write` | conectores de dominios: alta con su token, probarlos, reemplazar el token y darlos de baja (sincronizar es `assets.operate`; «Marcar como esperado», `assets.write`; los umbrales de caducidad, `policy.write`) | ✔ | ✔ | | | |
| `vault.manage` | caja fuerte (§19): ver sus metadatos, crear y editar entradas, sustituir el secreto (sin leerlo), marcar rotadas, ver el historial, borrar y recuperar | ✔ | ✔ | | | |
| `vault.admin` | revelar una credencial, restaurar una versión anterior y los ajustes de la caja fuerte (además, con reautenticación reciente) | ✔ | | | | |
| `terminal.open` | abrir una terminal con la cuenta de administración (§11; con reautenticación reciente). A los demás roles o personas se les concede por asset, etiqueta o proyecto (AccessPolicy) | ✔ | | | | |

`DELETE /assets/:id` exige `assets.write` y, con `purge=true`, además `assets.purge`. Las **operaciones en lote** (QoL-6, §15) exigen el permiso de la acción de un asset: tags y baja `assets.write`, recolectar y escanear `assets.operate`, proyecto `projects.write` y política `policy.write`. Exportar no exige permiso (es leer). La regla del último admin sigue valiendo solo para `admin` (es el único que gestiona usuarios). El rol de un usuario enlazado al proveedor OIDC lo decide el proveedor (abajo): a mano, 409.

### Sesiones, CSRF y CSP (QoL-1)

- **Sesión opaca en servidor** (`user_sessions`, §5) en una cookie `__Host-iw_session` **httpOnly, Secure, SameSite=Strict, Path=/** y sin `Max-Age` (muere con el navegador): JavaScript no ve ningún token (`document.cookie` vacío) y no hay nada en `sessionStorage`/`localStorage`. Caducidad absoluta `SESSION_TTL` (12 h) y por inactividad `SESSION_IDLE_TTL` (2 h; `last_seen_at` se actualiza como mucho una vez por minuto). `SESSION_COOKIE_SECURE=false` (sin el prefijo) solo fuera de producción. Para scripts, tokens de API (abajo).
- **Guards globales**, por orden: `SessionGuard` (lee la cookie, busca la sesión por su sha256 con su usuario y rechaza caducadas, revocadas o de usuarios desactivados; el usuario y su **rol se leen de la BD en cada petición**, así que un cambio de rol surte efecto al momento; la sesión `password_change` solo vale en los endpoints `@AllowPasswordChange()` y si no, 403 `password_change_required`; la `mfa` y el admin sin TOTP, abajo), `CsrfGuard`, `PermissionsGuard` y `RecentAuthGuard` (acciones sensibles, abajo).
- **CSRF**: en POST/PUT/PATCH/DELETE con sesión, cabecera `X-CSRF-Token` igual al token de la sesión (comparación en tiempo constante). El token no va en ninguna cookie: la API lo devuelve en el cuerpo de `POST /auth/login` y `GET /auth/session` y la web lo guarda en memoria. Además, si el navegador manda `Origin`, tiene que ser la web (`WEB_ORIGIN`, por defecto el origen de `PUBLIC_URL` y, en desarrollo, `http://localhost:4200`) y `Sec-Fetch-Site` no puede ser `cross-site`; también en el login (CSRF de login). El script de alta (curl, sin Origin ni cookie) no se ve afectado.
- **Invalidación al momento**: desactivar, restablecer la contraseña o cambiar la propia borran las sesiones del usuario en la misma transacción (al cambiar la propia se abre una nueva); su siguiente petición recibe 401. Los flujos SSE abiertos se cortan con `SessionRegistry` (en memoria: con varias réplicas hará falta pub/sub de Redis). La web vuelve al login con «Tu sesión ha terminado» ante un 401 y comprueba la sesión al volver a la pestaña (`visibilitychange`), sin sondeo en reposo.
- **Contraseñas**: elegidas por el usuario, 12–1024 caracteres y distintas del email (y de la actual). Un admin nunca elige contraseñas ajenas: el alta y el restablecimiento generan una **temporal** de 20 caracteres sin ambiguos (≈ 117 bits) que se muestra una sola vez, se guarda como hash y caduca a las 24 h (`TEMP_PASSWORD_TTL`). El primer login correcto la **gasta** (actualización condicionada al hash: dos logins simultáneos no entran los dos) y abre una sesión `password_change`. El login responde siempre «Credenciales inválidas» (no revela si la cuenta existe, está desactivada o la temporal caducó; el motivo va a la auditoría), con hash de relleno y límite por IP.
- **Límites del login**: por IP (`ThrottlerGuard`, `LOGIN_THROTTLE_LIMIT` intentos cada `LOGIN_THROTTLE_TTL`, todos cuentan) y por cuenta (`LoginAccountLimiter`, `LOGIN_ACCOUNT_THROTTLE_LIMIT` **fallos** cada `LOGIN_ACCOUNT_THROTTLE_TTL` desde cualquier IP, 10/300 s; un login correcto pone el contador a cero). El bloqueo por cuenta **no se aplica a las redes desde las que la cuenta ya entró bien** en los últimos 30 días (la IP, o su /64 en IPv6): quien inunde una cuenta de contraseñas malas no deja fuera a su dueño (ni al admin de emergencia) desde donde suele entrar, y ahí sigue valiendo el límite por IP. Contadores en Redis (`THROTTLE_STORAGE=redis`, por defecto; claves con hash, sin emails ni IP en claro), compartidos por las réplicas; `memory` solo para tests. Con la cuenta bloqueada, 429 con `Retry-After` sin comprobar la contraseña.
- **`PUBLIC_URL` en producción**: tiene que ser `https://` (salvo loopback); si no, la API no arranca. El script de alta se descarga con `curl <PUBLIC_URL>/enroll/<token> | sudo bash`.
- **Último admin**: no se puede desactivar ni quitar el rol al último admin activo (409), ni desactivarse uno mismo. La comprobación bloquea primero las filas de los admins activos (`FOR UPDATE`, siempre en el mismo orden) y después la del usuario: dos cambios simultáneos se esperan.
- **IP real**: `TRUST_PROXY` (`false`, `true` o lista: `loopback`, CIDR) para `X-Forwarded-For`; el proxy de `ng serve` manda `xfwd`.
- **Referencia de la API**: `/docs` y `/openapi.json` solo se sirven fuera de producción, salvo `DOCS_PUBLIC=true` (o `false` para apagarlas también fuera).
- **Cabeceras de la API**: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` y, salvo en `/docs`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` y `X-Frame-Options: DENY`.
- **CSP de la web**: `angular.json` → `security.autoCsp` añade al `index.html` compilado una política con el hash del cargador y `'strict-dynamic'`; el `index.html` lleva otra de base (`default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'`). Un script inline solo corre si cumple las dos (es decir, con hash). El `'unsafe-inline'` de `script-src` solo queda en `ng serve`: tras `ng build`, `scripts/strict-csp.mjs` lo sustituye por los hashes de autoCsp (y la build falla si no los encuentra). `style-src 'unsafe-inline'` es una concesión: OptimusNG inyecta estilos en tiempo de ejecución y no hay servidor que genere nonces. `frame-ancestors 'none'` no vale en `<meta>`: el dev-server lo manda como cabecera y el nginx de la imagen `web` manda `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` y HSTS en todas sus rutas (en `/api/` quita las copias de la API y deja su CSP, más estricta). Con otro servidor web delante de los estáticos, tiene que mandarlas él.

### Tokens de API (QoL-6)

Para scripts y el futuro servidor MCP: `Authorization: Bearer iwt_<43 caracteres base64url>` (32 bytes aleatorios; el prefijo fijo los hace reconocibles en un log o un escáner de secretos).
- **Alta** solo con la sesión web (Ajustes › Tokens de API, `POST /auth/tokens`): nombre (único entre los vigentes del usuario), **caducidad obligatoria** (7, 30, 90 o 365 días, o una fecha; como mucho un año) y alcance: `read` (solo GET/HEAD, con lo que su rol pueda leer: un admin lee la auditoría, un lector no) o `role` (lo que permita su rol). Como mucho 25 vigentes por usuario. El token se devuelve **una sola vez**; en la BD, su sha256 y el prefijo (§5). Ninguna respuesta posterior lo lleva.
- **Autenticación** (`SessionGuard`): con `Authorization: Bearer iwt_…` manda el token aunque venga una cookie, y uno inválido, caducado, revocado o de un usuario desactivado es 401 (nunca se cae a la cookie). Cualquier otra cabecera `Authorization` (Basic que el navegador guarda para el host, el Bearer de un oauth2-proxy…) **se ignora** y vale la cookie. Deja `request.user` (rol leído de la BD en cada petición: bajarle el rol baja el token al momento) y `request.apiToken`, **sin** `authSession`: no hay CSRF (no hay cookie que un tercero pueda hacer viajar); el control de `Origin` sigue (curl no lo manda). `PermissionsGuard`: un `read` en otro método → 403 `api_token_read_only`.
- **Acciones sensibles**: con un token, siempre 403 `recent_auth_required` (§ MFA); crear uno de escritura pide reautenticación (y TOTP a los usuarios locales).
- **`@SessionOnly()`**: con un token, 403 `session_required` en gestionar tokens (`/auth/tokens`, `/api-tokens`), `GET /auth/session`, `POST /auth/logout`, `POST /auth/password` y el SSE del alta. Un token robado no puede crear otros ni perpetuarse.
- **Admin** (`users.manage`, sesión web): `GET /api-tokens?userId=` y `DELETE /api-tokens/:id` (nunca el valor). El dueño revoca los suyos con `DELETE /auth/tokens/:id` (uno ajeno, 404). Desactivar a un usuario revoca sus tokens en la misma transacción (no vuelven al reactivarlo).
- **Auditoría**: `api_token.created` y `api_token.revoked` (con prefijo, alcance, caducidad y si lo revocó el dueño o un admin); lo que se hace con un token lleva `viaApi: api:<prefijo>` en el detalle. Los intentos con un token malo solo dan 401 (no se auditan).
- **OpenAPI**: esquema `bearer` como alternativa a la cookie en cada operación.

### MFA y reautenticación reciente

- **TOTP** para usuarios locales (RFC 6238: HMAC-SHA1, 6 cifras, 30 s, ±1 paso; implementación propia con `node:crypto` y los vectores del RFC en su test), compatible con cualquier app de autenticación. El secreto (160 bits) se guarda **cifrado en el proveedor de secretos** (el primero escribible de `SECRETS_PROVIDERS`: con `local`, AES-256-GCM en `local_secrets`; con OpenBao, en KV) en `infraward/users/<id>/totp/<uuid>`; en `users` solo su referencia (§5). Cada alta usa una ruta nueva: confirmarla es cambiar la referencia (sin copiar el secreto) y la anterior se borra después. **Anti-replay**: `totp_last_step` guarda el último paso aceptado y solo valen los posteriores (actualización condicionada: dos peticiones con el mismo código, solo una entra).
- **Códigos de recuperación**: 10, de un solo uso (`xxxx-xxxx-xxxx-xxxx`, ≈ 79 bits), solo como sha256 (§5); se enseñan una vez al activar el TOTP o al generar otros (copiar o descargar `.txt`). Valen donde vale un código TOTP.
- **Obligatorio para los admins locales** (incluido el de emergencia y el inicial): una sesión abierta **con contraseña** de un usuario `admin` sin TOTP solo puede usar `@AllowMfaSetup()` (sesión, `GET /auth/me`, cierre, contraseña y alta del TOTP); el resto, 403 `mfa_setup_required`. Se comprueba en **cada petición** (`SessionGuard`): cubre también a quien asciendan a admin con la sesión abierta. Quien entra por OIDC no lo necesita (el MFA lo pone el proveedor), aunque su cuenta sea local enlazada. Los demás usuarios locales lo activan si quieren; un admin local no puede desactivarlo (409), solo cambiar de dispositivo.
- **Login en dos pasos**: con TOTP activo, la contraseña buena abre una sesión intermedia `mfa` (5 min) que solo vale en `@AllowMfaPending()` (verificar, ver la sesión y salir; el resto, 403 `mfa_pending`). `POST /auth/mfa/verify` con el código TOTP o de recuperación la **cambia por otra** (cookie y CSRF nuevos: sin fijación de sesión), ya reautenticada; con una temporal pendiente (gastada en el primer paso), la nueva es la de cambiarla. A los 5 códigos incorrectos se borra (401: hay que volver a entrar). El login solo se audita (`auth.login` con `mfa: totp|recovery`) al completarse; cada código, como `auth.mfa_challenge`.
- **Alta y baja desde el perfil** (`/auth/mfa`, solo con la sesión web): `GET` (estado y códigos que quedan), `POST setup` (secreto, URI `otpauth://` y QR en PNG, una vez; si ya tenía TOTP, es un **cambio de dispositivo** y pide reautenticación), `POST enable` (confirma con un código; devuelve los códigos de recuperación), `POST disable` y `POST recovery-codes` (las dos con reautenticación). Un usuario creado por OIDC no tiene TOTP propio (409).
- **Restablecerlo a otro** (`POST /users/:id/mfa/reset`, `users.manage` + reautenticación): borra su secreto y sus códigos y **cierra sus sesiones**; si es admin, al volver a entrar tendrá que configurarlo. A uno mismo no (400: desde el perfil). Auditado como `user.mfa_reset`.
- **Reautenticación reciente (step-up)**: las acciones sensibles exigen identidad confirmada hace menos de `REAUTH_MAX_AGE` (600 s), además de la sesión y el permiso. Un **único decorador** `@RecentAuth(acción, condición?)` y el guard global `RecentAuthGuard` (el último, tras sesión, CSRF y permisos). La lista vive en `SENSITIVE_ACTIONS` (shared-types) y un test recorre todos los controladores y exige que las rutas marcadas sean exactamente las de su tabla:

  | Acción | Ruta | Cuándo |
  |---|---|---|
  | `asset.purge` | `DELETE /assets/:id` | solo con `purge=true` (retirar no) |
  | `user.role_change` | `PATCH /users/:id` | si el cuerpo lleva `role` (la web solo lo manda si cambia) |
  | `user.deactivate` | `POST /users/:id/deactivate` | siempre |
  | `user.mfa_reset` | `POST /users/:id/mfa/reset` | siempre |
  | `api_token.create_write` | `POST /auth/tokens` | alcance `role` de un rol que escribe (admin, editor, operator) |
  | `mfa.replace` / `mfa.disable` / `mfa.recovery_regenerate` | `POST /auth/mfa/setup` (con TOTP ya activo) / `disable` / `recovery-codes` | siempre |
  | `vault.reveal` | `POST /vault/entries/:id/reveal` | siempre |
  | `vault.version_restore` | `POST /vault/entries/:id/versions/:version/restore` | siempre |
  | `vault.settings_change` | `PUT /vault/settings` | siempre |
  | `terminal.open` | `POST /terminal/sessions` | siempre (además del permiso `terminal.open`) |
  | `admin_access.enable` | `POST /assets/:id/enrollment/token` y `POST /assets/enroll` | si el cuerpo lleva `adminAccess: 'operator'` (retirarlo, no) |
  | `access.grant` | `POST /access-policies` | siempre (dar acceso a la terminal; retirarlo, no) |

  Respuestas (403, con la acción y su texto): `recent_auth_required` con `method: totp` (sesión local) u `oidc` (sesión del proveedor); `mfa_required_for_action` si un usuario local sin TOTP intenta una (debe activarlo: no hay alternativa con la contraseña); y **con un token de API, siempre** `recent_auth_required` con `method: null` (solo desde la web: un token robado no puede purgar ni cambiar roles).
- **Local**: `POST /auth/reauth` con un código TOTP o de recuperación (y la acción, para la auditoría) marca `reauthenticated_at` en la sesión. El login con TOTP y el alta del TOTP también la marcan.
- **OIDC**: `GET /auth/oidc/reauth?returnUrl=` (navegación con la cookie Strict de la sesión) empieza un flujo como el del login (§ siguiente) con `prompt=login` y `max_age=0`, que guarda en Redis además la sesión y el usuario que lo piden y cuándo empezó. En el callback (la cookie Strict no llega: por eso va en el flujo) exige `auth_time` en el ID token, **posterior al inicio** del flujo (5 s de margen), la misma identidad (`iss` + `sub`) que el usuario y la sesión aún viva; entonces marca `reauthenticated_at = auth_time` (no abre otra sesión) y vuelve a `returnUrl?reauth=ok`; si no, `?reauth=failed` y el motivo (`auth_time_missing`, `auth_time_stale`, `subject_mismatch`, `session_closed`, o los del login) a la auditoría. Un **login OIDC normal** cuenta como reautenticación según su `auth_time`: recién tecleadas las credenciales, sí; si el proveedor reutilizó una sesión SSO antigua, no.
- **Web**: el interceptor recibe el 403 de una acción sensible y abre un **diálogo único** (en el shell): código (o «usar un código de recuperación») y, si vale, **repite la petición** una vez (así purgar no exige otro clic); con OIDC, «Continuar con <proveedor>» y a la vuelta un aviso «Identidad confirmada: repite la acción»; sin TOTP, el aviso de activarlo con enlace al perfil.
- **Auditoría**: `auth.mfa_challenge` (segundo paso), `auth.mfa_enabled` (también los códigos incorrectos al confirmar, y `replaced` en un cambio de dispositivo), `auth.mfa_disabled`, `auth.mfa_recovery_regenerated`, `user.mfa_reset`, `auth.reauth` (éxito o fallo, método y acción) y `auth.reauth_required` (cada 403 del guard, con la acción y el motivo). Nunca el secreto ni los códigos.
- **Límite de intentos**: los códigos (`verify`, `enable`, `reauth`) usan `LOGIN_THROTTLE_LIMIT`/`TTL` como el login, pero **por usuario y compartido** entre esas rutas (`MfaThrottlerGuard`): repartir intentos entre IPs o rutas no permite adivinar un código de 6 cifras. Además, la sesión intermedia muere a los 5 fallos.

### Login con OIDC (QoL-2)

Proveedor OIDC **genérico** (Keycloak, Authentik, Google, Entra…) configurado por entorno: `OIDC_ISSUER` (lo activa; https en producción), `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET_REF` (**referencia** `secret://…#campo` resuelta con `SecretsService`; sin ella, cliente público con PKCE), `OIDC_REDIRECT_URI` (la ruta `/api/auth/oidc/callback` **de la web**: así la cookie de sesión queda en su origen, que es también el destino tras entrar y salir), `OIDC_PROVIDER_NAME` (el botón «Entrar con …»), `OIDC_SCOPES` (`openid email profile`), `OIDC_TOKEN_AUTH_METHOD`, `OIDC_GROUPS_CLAIM`, `OIDC_ROLE_MAPPING`, `OIDC_UNMAPPED` y `OIDC_ALLOW_UNVERIFIED_SIGNUP`. Librería `openid-client` (sobre `oauth4webapi`); discovery perezoso (la API arranca aunque el proveedor no responda) y rehecho cada 10 min (rotación del secreto).

- **Flujo**: authorization code con **PKCE S256**. `GET /auth/oidc/login?returnUrl=` genera `state`, `nonce` y `code_verifier`, los guarda en **Redis** (10 min, clave = sha256 del state) junto al sha256 de un token de enlace que va en la cookie `__Host-iw_oidc` (httpOnly, Secure, **SameSite=Lax** —el callback llega como navegación desde otro sitio—, 10 min) y redirige al proveedor. `GET /auth/oidc/callback` consume el estado con `GETDEL` (**un solo uso**: un state repetido falla) y exige la cookie del mismo navegador (sin ella, un `code` ajeno no sirve: CSRF de login); canjea el código con el verifier y valida el ID token: **firma contra el JWKS** del proveedor (`enableNonRepudiationChecks`: no basta con TLS; `alg: none` o una clave ajena fallan), `iss`, `aud`/`azp`, `exp`/`iat` y `nonce`. Abre la **misma sesión de QoL-1** (cookie `__Host-iw_session`, Strict) y redirige a `returnUrl` (solo rutas relativas). Cualquier fallo vuelve a `/login?oidcError=` con un código genérico (`failed`, `denied`, `disabled`, `email_conflict`, `unavailable`); el motivo concreto (`state_invalid`, `nonce_invalid`, `issuer_invalid`, `audience_invalid`, `token_expired`, `signature_invalid`, `provider_error`…) solo va a la auditoría.
- **Cuenta** (por orden): la enlazada a su `iss` + `sub`; si no, la local con su email **solo si el proveedor lo marca `email_verified: true`** (si falta el claim, como en Entra, no se enlaza), no está enlazada a otra identidad y no es el admin de emergencia (si no: `email_conflict`, la cuenta local queda intacta); si no hay ninguna, **alta automática** (`origin = oidc`, sin contraseña utilizable, nombre del claim `name`), también **solo con `email_verified: true`** (si no, `email_unverified` y no se crea nada: quien se registrara en el proveedor con el email de otra persona se quedaría con él). Para proveedores que no mandan el claim y verifican los emails por su cuenta (Entra), `OIDC_ALLOW_UNVERIFIED_SIGNUP=true` permite el alta; nunca el enlace. Sin email, no hay alta. Una cuenta desactivada en InfraWard no entra aunque el proveedor diga que sí. El nombre se actualiza en cada login; el email no (la identidad es `iss` + `sub`).
- **Rol**: los grupos salen del claim `OIDC_GROUPS_CLAIM` (lista o texto; primero por nombre literal y si no como ruta con puntos, p. ej. `realm_access.roles`) y `OIDC_ROLE_MAPPING` (`grupo=rol,…`) los traduce; con varios gana el de más permisos (`admin > editor > operator > auditor > viewer`). Sin ningún grupo con rol: **acceso denegado** (`OIDC_UNMAPPED=deny`, por defecto; no se crea la cuenta) o `viewer`. Se **reevalúa en cada login** con el bloqueo de admins de QoL-1; excepción: si quitaría el rol al **último admin activo**, lo conserva y lo audita (`roleKept: last_admin`). Entre logins manda la BD (desactivar sigue siendo inmediato).
- **Cierre de sesión**: `POST /auth/logout` devuelve `{ providerLogoutUrl }`; si la sesión vino del proveedor y este anuncia `end_session_endpoint`, la web navega a él con `id_token_hint`, `client_id` y `post_logout_redirect_uri` = `/login?loggedOut=1` (RP-Initiated Logout) y el proveedor cierra también la suya.
- **Login local desactivable**: `LOCAL_LOGIN=false` (exige OIDC) deja entrar con contraseña **solo al admin local de emergencia** `LOCAL_LOGIN_EMERGENCY_EMAIL`, y solo si es `admin`, `origin = local` y no está enlazado. Los demás reciben el «Credenciales inválidas» de siempre (motivo `local_login_disabled` en la auditoría). Sin login local no hay altas locales ni restablecimientos (409), salvo el de la cuenta de emergencia; la web enseña solo «Entrar con …» y un enlace discreto «Acceso de emergencia» que despliega el formulario (`GET /auth/providers`, público, le dice qué enseñar).
- **Admin de emergencia (recomendado si `LOCAL_LOGIN=false`)**: sirve para entrar si el proveedor cae o se configura mal (sin él, nadie entraría). Crearlo antes de desactivar el login local (alta normal en Ajustes con rol admin, o el admin inicial de `ADMIN_EMAIL`), poner su email en `LOCAL_LOGIN_EMERGENCY_EMAIL` y guardar su contraseña **fuera de línea** (caja fuerte, sobre lacrado), larga y única; el proveedor nunca puede enlazarla ni cambiarle el rol; su uso queda en la auditoría (conviene revisarlo). Se ve como «Emergencia» en Ajustes > Usuarios. Para quitarla, vaciar la variable.
- **Ajustes > Usuarios** muestra cómo entra cada uno (Local, OIDC, Local + OIDC, Emergencia); a los OIDC no se les restablece la contraseña ni se les cambia el rol a mano; el perfil de un usuario OIDC no ofrece cambio de contraseña.
- **Secretos y fugas**: el secreto del cliente solo vive en el proveedor de secretos (en desarrollo lo guarda `pnpm keycloak:bootstrap` con `secrets:put`, por stdin); ni él, ni el `code`, ni los tokens van a logs, respuestas (salvo la URL de logout, que lleva el ID token a propósito) o la auditoría (el saneador descarta además claves `code`/`nonce`/`verifier` y valores con forma de JWT).

### Registro de auditoría (QoL-1)

`AuditService.record(actor, acción, { target, outcome, details })`, con llamadas explícitas en los servicios (en la misma transacción que la acción cuando la hay) y el actor de `@AuditCtx()` (usuario e IP). Acciones: inicios de sesión locales y OIDC (también fallidos, con motivo; los OIDC con `method: oidc` y sus grupos), cierres (y si se cerró también en el proveedor) y cambios de contraseña; altas automáticas, enlaces (`user.oidc_linked`) y cambios de rol por OIDC; altas, cambios de nombre y de rol, desactivaciones, reactivaciones y restablecimientos de usuarios; altas (a mano y con script), cambios, bajas y purgas de assets (con cuántos del subárbol); renombrados (`asset.renamed`: antes → después, el descubierto y si vuelve a él), tags (`asset.tags_changed`: añadidos y quitados), notas (`asset.notes_changed`: **solo la longitud**, nunca el texto) y colores de tags (`tag.style_changed`); proyectos (`project.created|updated|deleted`) y pertenencia (`project.member_set` con el modo y el anterior, `project.member_removed`); comandos de alta y **pasos a CA**; cambios de política (global, reglas por etiqueta, por proyecto —objetivo el proyecto— y de assets, con antes → después de cada campo); reconciliaciones manuales y re-escaneos de afectados. **Nunca secretos**: el detalle es pequeño y plano, y un saneador quita las claves que parezcan llevarlos (`pass`, `secret`, `token`, `key`, `credential`, `hash`) y cualquier valor con `PRIVATE KEY` o `secret://`. `GET /audit` (admin) por cursor `(occurred_at, id)` con filtros de acción o categoría, actor, objetivo, resultado, texto (objetivo o email) y fechas. Sin purga: se conserva indefinidamente.

---

## 15. Interfaz (Angular + OptimusNG)

Iconos: Bootstrap Icons (`<i class="bi bi-…">`), CSS cargado desde `angular.json`. En desarrollo, `ng serve` sirve la API bajo `/api` (proxy a :3000): mismo origen, sin CORS. Sesión: cookie httpOnly (§14); al cargar, `GET /auth/session` (`provideAppInitializer`) recupera el perfil y el token CSRF, que viven solo en memoria. Un 401 devuelve al login con el aviso «Tu sesión ha terminado»; un 403 `password_change_required`, al cambio obligado.

Tema: preset Aura con primario **teal** (el del logo) en `apps/web/src/app/theme.ts`. El modo oscuro sigue al sistema (`darkModeSelector: 'system'`, igual que la variante `dark:` de Tailwind). Los fondos y colores de estado propios usan los tokens `--p-app-*` del preset (`background`, `code-background`, `danger/warn/success/info-color`), que cambian con el modo; no usar `--p-surface-*` para fondos, porque Aura no oscurece esa paleta. Tailwind CSS v4 (`src/tailwind.css`, fuera de Sass) con `@openng/optimus-ui-tailwindcss`; Optimus pinta en la capa CSS `optimus`, por debajo de `utilities`.

### Estructura

- **Login**: a dos columnas, con un panel de marca (el logo `logo.svg` —escudo con el árbol de inventario— y el color primario de la barra) y el formulario. Por debajo de 960 px, solo la marca encima. Errores por campo al tocarlo o al enviar (el botón no se deshabilita), aviso de Bloq. Mayús., aviso si la sesión anterior terminó y nota de que la sesión dura lo que el navegador (o hasta un rato sin actividad). Tras entrar con una contraseña temporal, la pantalla **Elige tu contraseña** (`/change-password`): nueva y repetida, sin volver a pedir la temporal; cualquier otra ruta lleva a ella. Con TOTP, tras la contraseña, **Verificación en dos pasos** (`/login/mfa`): código de 6 cifras o «He perdido el móvil: usar un código de recuperación» (a los 5 fallos, vuelta al login con el aviso). Un admin local sin TOTP va a **Configura la verificación en dos pasos** (`/mfa-setup`): QR, la clave para teclearla, el código de confirmación y los códigos de recuperación (copiar o descargar); cualquier otra ruta lleva a ella. Los pasos pendientes van por orden: código → contraseña nueva → alta del TOTP (`pendingStep` en los guards). La ruta `login` es exacta (`pathMatch: 'full'`): si no, su guard también se evaluaría para `/login/mfa`.
- **Barra superior**: botón de menú, marca (logo + nombre, lleva al panel), la **búsqueda global** de CVEs y paquetes (§9; en móvil, tras una lupa), la **campana de notificaciones** (§10: no leídas; se piden al entrar y al navegar, nunca en reposo; al abrirla, las últimas 15 con enlaces a los assets y «Marcar como leídas») y el usuario (nombre y rol; el email en el título) con un menú con «Tu perfil», la hora a la que caduca la sesión y «Cerrar sesión» (borra la sesión en la API). El mismo logo es el favicon (`favicon.svg` / `favicon.ico`) y el icono de Apple.
- **Menú lateral** con las secciones **Panel** (`/dashboard`, la página de inicio y a la que lleva el login), **Inventario** (`/inventory`), **Proyectos** (`/projects`), **Vulnerabilidades** (`/vulnerabilities`), **Actividad** (`/activity`), **Caja fuerte** (`/vault`, solo con `vault.manage`) y **Ajustes** (`/settings`). Se pliega a solo iconos (con tooltip) y la preferencia se recuerda en `localStorage`. Por debajo de 960 px el lateral desaparece y el botón de menú abre un **drawer** con las mismas secciones, que se cierra al navegar.
- Los filtros de cada sección viven en la URL, para que el panel enlace a la sección ya filtrada y se pueda volver atrás.
- Confirmaciones (`p-confirmdialog`) y avisos (`p-toast`) se proveen en el shell.
- Lo que está en curso se refresca solo (sondeo cada 3–5 s **solo mientras hay jobs pendientes**; en reposo no hay peticiones).

### Panel (QoL-8: paneles personalizables)

El panel de inicio es **un panel de widgets** que cada usuario personaliza y guarda (`dashboards`, §5); quien no lo ha tocado ve el **por defecto**, que es el panel de antes hecho con los mismos widgets: «Vulnerabilidades prioritarias», «Pendientes de alta» y «Tareas en curso» arriba; «Lo más prioritario», «Assets por tipo» y «Avisos» debajo; «Actividad reciente» a lo ancho. El selector de proyecto de la página (`?project=`) **sustituye** el proyecto de cada widget (así `/dashboard?project=` funciona como antes). Cada **proyecto** tiene además su panel en su página (sección «Panel del proyecto», `/projects/:id#panel`; a ella llevan el mosaico de la página y el botón «Panel» de la lista): sin panel propio se ve la **plantilla** (resumen de assets, vulnerabilidades con parche, vulnerabilidades prioritarias, lo más prioritario —10—, caducidades, evolución de los hallazgos abiertos, avisos y actividad; desde la revisión de QoL-8 la página ya no tiene mosaicos fijos: el resumen de assets y el de vulnerabilidades con parche son widgets que se pueden mover, cambiar o quitar), todos sus widgets están **fijados a ese proyecto** (la API lo fuerza al guardar) y lo cambia quien tiene `projects.write` (auditado como `project.dashboard_updated` / `_reset`); lo ve todo el mundo.

**Catálogo** (`DASHBOARD_WIDGETS` en shared-types: nombre, icono, tamaño por defecto y mínimo, filtros que admite, opciones con sus valores y caché; la misma fuente para la web, la validación y los DTO de la API):

| Widget | Qué enseña | Opciones |
|---|---|---|
| `asset-summary` | total de assets (sin retirados) y un chip por tipo, como la tarjeta de un proyecto → inventario | — |
| `fixable-vulnerabilities` | hallazgos críticos + altos con parche («31 C · 282 H»), CVE abiertos y la barra por severidad, con el criterio de la tarjeta de un proyecto (`ProjectsService.stats`: dueños no retirados que escanean, ruido incluido; tags y tipos sobre el dueño) → `/vulnerabilities` | — |
| `vulnerability-counts` | CVE de la vista principal por banda (urgentes + altos grande, KEV y el total ≥ media) → `/vulnerabilities` | — |
| `asset-counts` | assets por **tipo** (sin retirados; los que no salen en el árbol, sin enlace) o por **estado** → inventario filtrado | `groupBy` |
| `pending-enrollment` | pendientes de alta, con los primeros si se pide | `limit` (0 = solo el número) |
| `running-jobs` | tareas en cola o en curso → `/activity?state=running` | — |
| `top-vulnerabilities` | los N más prioritarios con puntuación, severidad, assets y porqué | `limit` 5/10/20, `minPriority` |
| `new-vulnerabilities` | CVE nuevos desde tu última visita (la de «Marcar como vistos») o en los últimos 7/30 días, con los en KEV | `since`, `limit` |
| `attention` | los 12 avisos de antes (duplicados, caducidades, DNS colgantes e informativos, clones, CA SSH, sshd, caja fuerte —solo con `vault.manage`—, sudoers, parcial, fallos 24 h) con los primeros assets | `kinds` |
| `expirations` | dominios y certificados caducados o que caducan antes de N días (por defecto el umbral mayor), los más próximos primero, con los días en rojo/ámbar según los umbrales | `kinds`, `horizonDays`, `limit` |
| `recent-activity` | las últimas ejecuciones | `limit`, `state` |
| `trend` | gráfico de evolución | `metric`, `range` 30 d/90 d/1 año |

**Filtros de cada widget**: proyecto, **tags** (alguno, O), **tipos** (alguno, O) —filtros distintos, Y— y **sitio**, que se acepta y se guarda pero aún no tiene efecto (no hay sitios, §18), como `sitio:` en la búsqueda. En los de vulnerabilidades, tags y tipos se aplican al **asset afectado** con la sintaxis de búsqueda (`tag:a tipo:server`, la de la lista de Vulnerabilidades); en los de assets, a `tags && …` (índice GIN) y `type`. Los enlaces de cada widget llevan a la sección con el mismo ámbito (`?project=` y los tags y tipos en `?q=`). Bajo el título, los filtros como chips (el proyecto, solo si es del widget; «Proyecto borrado» si ya no existe, y entonces no filtra).

**Evolución** (`trend`): `open-findings` (hallazgos abiertos por severidad, áreas apiladas) y `new-vs-fixed` (nuevos y corregidos por día o semana, líneas) se **reconstruyen** de `opened_at`/`fixed_at` (sin ruido y con la política de escaneo de hoy; recuento base + eventos por día, sin recorrer día × hallazgo) y admiten todos los filtros; van marcados **«aproximado»** con el porqué en un tooltip (un finding reabierto pierde sus ciclos anteriores y los de assets purgados ya no están). `cves-by-band` y `assets-by-status` (sin retirados) salen de `metric_samples`: exactos, pero **solo desde la primera muestra** y **solo por proyecto** (si el widget tiene tags o tipos, lo avisa). Todos dicen **desde cuándo hay datos** y antes de esa fecha no pintan nada (tampoco ceros); con un solo punto, marcadores y «crecerá cada día»; con un año, un punto por semana. Gráfico SVG propio (`widgets/trend-chart.ts`, sin dependencias): un eje, la rampa roja de un solo tono de la barra de proyectos para severidades y bandas, teal/rojo para corregidos/nuevos y teal/violeta/ámbar para los estados (validados con el comprobador de paletas en claro y oscuro), leyenda con el último valor, línea y valores al pasar por encima y una tabla para lectores de pantalla.

**Muestras** (`metrics.sample`, cola `system`, una fila en la Actividad): cada `METRICS_SAMPLE_INTERVAL` horas (24; 0 = nunca) y al arrancar el worker si aún no hay la de hoy; una **global y una por proyecto**; **idempotente por día** (upsert: repetir sustituye). **Retención**: diarias `METRICS_DAILY_RETENTION_DAYS` (365); después queda la del último día de cada semana ISO (contando las ya semanales, así una semana que cruza el plazo en varios días acaba con una), y las semanales se borran pasados `METRICS_RETENTION_DAYS` (0 = nunca). Todo en una transacción.

**API**: `GET|PUT|DELETE /dashboards/me` y `GET|PUT|DELETE /projects/:id/dashboard` (`DashboardDocument`: `layout`, `isDefault`, `version`, `updatedAt`, `updatedBy`; PUT `{ layout, version }`: 400 con el motivo si no es válido —tipo desconocido, solapes, fuera de la rejilla, opciones no permitidas, más de 24 widgets…—, 409 si otro guardó antes). **Datos**: `GET /dashboard/widgets/<tipo>?projectId=&tag=&type=&<opciones>` (listas repetidas, `tag=a&tag=b`), **uno por widget** y solo con lo suyo (agregados y `LIMIT` en SQL; nunca el inventario entero). **Caché corta** en memoria de la API (`TtlCache`: guarda la promesa, así dos peticiones iguales a la vez hacen una consulta; un fallo no se guarda; 1000 entradas) por tipo y parámetros normalizados más lo que depende del usuario (si ve la caja fuerte; su última visita en `new-vulnerabilities`): `DASHBOARD_CACHE_TTL` (30 s; 0 la desactiva), 5 s en `running-jobs` y `recent-activity`, con `Cache-Control: private, max-age=<ttl>`. `GET /dashboard` (el resumen de una vez) **se conserva** para los tokens de API, montado con las mismas funciones.

**Web** (`features/dashboard/`): `DashboardBoard` (el tablero, también en la página del proyecto) y `WidgetHost` (cada widget: su petición, que solo se repite si cambian tipo, filtros u opciones —no al moverlo—; esqueleto; error con «Reintentar»; los de tareas se refrescan cada 5 s **solo mientras haya jobs**). Los widgets fuera de la pantalla se crean al acercarse (`@defer (on viewport)`). En **lectura** la rejilla es CSS grid (12 columnas, filas de 80 px, el mismo margen que gridstack): no carga ninguna librería; por debajo de 768 px, una columna en orden de lectura y cada widget con su alto como máximo. **«Personalizar»** (el propio, siempre; el del proyecto, con `projects.write`): barra fija con «Añadir widget» (catálogo y después su configuración), «Restablecer» / «Volver a la plantilla» (con confirmación), «Cancelar» (confirma si hay cambios) y «Guardar». En pantallas anchas carga **gridstack.js** (MIT, 14.0.0, `import()` diferido; sin su wrapper de Angular) para **arrastrar** por el asa y **redimensionar** desde la esquina (gravedad arriba, sin huecos; con los mínimos del catálogo). Mientras está activo, gridstack es la fuente de verdad: tras cada evento, cada acción del menú y antes de guardar, el borrador copia las posiciones de todos sus widgets (gridstack no avisa de todo lo que recoloca al resolver colisiones); en cualquier anchura, el menú de cada widget configura, **mueve antes/después**, **cambia el tamaño** y quita (la alternativa con teclado y en móvil; recoloca con `packWidgets`). Configurar: título, proyecto (fijado en el de un proyecto), tags (los existentes), tipos, sitio (deshabilitado) y las opciones del tipo. Al salir de una página con cambios sin guardar, se pregunta (`unsavedChangesGuard`; al cerrar la pestaña, el aviso del navegador). Un 409 lo dice y ofrece «Recargar el panel».

### Inventario

`treeTable` con columnas **Nombre** (icono de tipo, enlace a la ficha y roles debajo), **Tipo**, **Dirección** (`address`), **Estado** (el de ejecución si existe —«En marcha», «Parado», «Pausado»— y el de inventario solo si no es «Activo» o no hay de ejecución) y **Vulnerabilidades**: la severidad máxima abierta y los CRITICAL/HIGH **con parche** («17 C · 98 H con parche»), el mismo criterio que el filtro por defecto de la ficha; el total por severidad va en un tooltip. **Búsqueda con sintaxis de filtros** (QoL-6b, `app-query-input`; abre las ramas que llevan a lo que coincide): `tag:prod nombre:"web prod" -estado:retirado ip:10.0.0.0/24`. Claves con alias en español e inglés: `tag` (exacto), `nombre/name` (parcial, visible o descubierto), `tipo/type` (código o etiqueta: `servidor`, `ct`, `imagen`…), `estado/status` (de inventario o de ejecución: `activo`, `parado`…), `rol/role` (exacto), `proyecto/project` (por nombre o id), `ip` (exacta, prefijo `10.0.` o red IPv4) y `sitio/site` (reconocida, aún sin efecto: no hay sitios, §18). El texto sin clave busca **solo en el nombre**, nunca en tags. Comillas para valores con espacios, `-` para negar, la misma clave repetida es O y claves distintas Y. **Un único parser** (`packages/shared-types/src/search-query.ts`, con tests): nunca lanza; lo que no entiende va como aviso (clave desconocida —se busca como texto, así `nginx:1.25` funciona—, comillas sin cerrar, valor no válido, clave de la otra vista, sin efecto, demasiado larga: 500 caracteres y 30 términos). Bajo el campo, los filtros activos como **chips** que se quitan (los negados, discontinuos; los avisos, en ámbar con su motivo) y «Quitar todos»; autocompletado de claves y, tras `clave:`, de valores existentes (tags y proyectos de `OrganizationStore`, tipos, estados y los roles del árbol cargado). La consulta va a la URL (`?q=`, sin apilar historial) para compartirla; la que se conserva al volver a la sección se reescribe en la URL. La API la acepta en `GET /assets/tree?q=` (lo que cumple y sus antepasados), `GET /assets/export?q=` y en vulnerabilidades (hasta 2000 caracteres; nunca 500). La búsqueda global manda una IP como `ip:`. Sin `[scrollable]`: en ese modo OptimusNG separa cabecera y cuerpo en dos tablas y las columnas dejan de coincidir; los anchos van en un `colgroup` (un test lo comprueba).

**Filtro rápido** desde la URL (`?type=`, `?status=`, `?attention=sudoers|partial`, `?project=` —también con el selector de proyecto de la barra—): deja los assets que cumplen y sus antepasados, con las ramas abiertas, y se muestra como un chip que se puede quitar.

**Topología** (QoL-4; conmutador **Árbol | Topología**, `?view=topology`, `?root=<id>` para un subárbol, con chip para quitarlo, y el `?project=` de siempre): grafo de Cytoscape (layout **fcose**, nodos compuestos) con el nivel host de `GET /assets/topology`: cada servidor es un grupo con sus CT/VM dentro y cada uno resume lo que tiene sin cargar («3 contenedores · 2 volúmenes · 5 redes · 3 imágenes · 51 críticas»). Tocar un host → tarjeta con «Expandir»/«Contraer» (doble clic también expande; en lo que no tiene nada más, abre la ficha); al expandir, sus contenedores, volúmenes, redes e imágenes aparecen **dentro** de él y fcose coloca solo lo nuevo (lo anterior conserva su posición). «Expandir un nivel» y «Contraer» para todos. Filtros en el cliente: **tipos** y **estados** (activo, parado, desaparecido, pendiente; «retirado» los pide a la API) y **Resaltar CVE críticos** (atenúa lo demás y deja los grupos que contienen algo crítico).

**Lienzo de grafos** (`shared/graph/`): `GraphCanvas` carga Cytoscape y fcose **bajo demanda** (chunks diferidos, ~150 kB transferidos; nada en el bundle inicial). Los iconos son los SVG de Bootstrap Icons de cada tipo como `data:` (el canvas no puede usar la fuente; la CSP ya permite `img-src data:`). El estilo sale de los tokens del tema (`--p-text-color`, `--p-content-*`, `--p-app-*`, `--p-<color>-500/400` por tipo) y se rehace al cambiar entre claro y oscuro; la leyenda usa los mismos colores con `light-dark()`. Zoom, «Encuadrar todo» (sin pasar de 1,2× con pocos nodos) y **pantalla completa** (la API del navegador; sin ella —Safari en iPhone— ocupa la ventana; Esc sale) y altura con `clamp()`/`dvh`. La tarjeta del nodo va **dentro** del lienzo (contenido proyectado), así también se ve a pantalla completa; por debajo de 640 px es una hoja en la parte de abajo. Seleccionar un nodo nunca vuelve a lanzar el layout (solo cambiar los elementos), así la vista no se mueve al pulsar. El lienzo es `role="img"` con un resumen; la vista Lista es la alternativa accesible.

**Selección y acciones en lote** (QoL-6; con algún permiso de lote): una casilla por fila y «Seleccionar todo lo visible» en la cabecera (lo que cumple el filtro rápido y el de texto, sin los antepasados que solo sitúan). Lo que se marca es lo que entra: no se propaga a los hijos (la selección `checkbox` del treeTable sí lo haría). Cambiar el filtro vacía la selección. Abajo, fija, la **barra de lote** (`shared/bulk-actions.ts`) con las acciones que permite el rol: **Etiquetar** (añadir y quitar, sin tocar los demás tags), **Mover a un proyecto** (`include`, `exclude` o volver a heredar), **Recolectar**, **Escanear**, **Aplicar una política** (el mismo `app-policy-form`; o quitar la regla propia) y **Dar de baja** (confirmación con cuántos y cuáles, más los descendientes que arrastra, de `POST /assets/bulk/preview`; nunca purga). Los diálogos dicen a qué assets llega. Al terminar, en el mismo bloque fijo: lo aplicado, lo omitido con su motivo (el 409 de la ficha, «Ya estaba así», «No existe»), los comandos de revocación de una baja y «Ver en Actividad» (`/activity?parentJobId=`).

API (`apps/api/src/bulk/`): `POST /assets/bulk/{preview,tags,project,collect,scan,policy,retire}` con `assetIds` (≤ 500) o `vulnerabilityIds` (≤ 200; sus afectados no retirados con findings abiertos o aceptados: servidores, CT e imágenes; con `projectId`, los de ese proyecto). Las que cambian datos van en **una transacción** con un solo recálculo de la política; recolectar y escanear reutilizan las reglas de cada asset (`CollectionService.collect`, `FindingsService.scan` con `force`) y sus jobs cuelgan de la operación. **Una** fila `assets.bulk` en la Actividad (§5) y **un** evento `asset.bulk_<acción>` en la auditoría (objetivo `bulk_operation` con el id de la operación; detalle con `count`, los nombres —hasta 50—, `skipped`, `jobs`, `alreadyRunning` y lo propio de la acción), en lugar de uno por asset.

**Columnas y exportación** (QoL-6): selector «Columnas» (Tipo, Dirección, Estado, Vulnerabilidades; el nombre siempre), recordado en el navegador. **Exportar ▾ CSV / JSON** descarga lo que se ve: `GET /assets/export?format=&columns=&q=&type=&status=&attention=&project=&includeRetired=`, con el **mismo filtro que el árbol** (`inventory-filter.ts` en shared-types: lo usan la web y la API) y las columnas visibles traducidas a las de una **lista blanca** (`INVENTORY_EXPORT_COLUMNS`: id, nombre, descubierto, ruta, tipo, estado, ejecución, dirección, roles, tags, proyectos, severidades, con parche y caducidad). Una fila por asset que cumple el filtro, en orden de árbol y con su ruta (`pve › ct › web`). Nunca conexión, credenciales, referencias ni facts.

**Organización en el árbol** (QoL-3; desde 2026-10-14, **solo lectura**: el nombre y los tags se cambian en la ficha, nunca en la lista): el nombre visible enlaza a la ficha (con «descubierto: …» debajo y en el tooltip si está renombrado); los **tags como chips de color**; un punto de color por proyecto. Tags y proyectos se piden una vez y se comparten (`OrganizationStore`). La caducidad de un certificado va en una línea en la columna Estado.

### Vulnerabilidades

- **Lista** (`GET /vulnerabilities`): una fila por CVE **de más a menos prioritaria** (sesión 19; `app-priority-score` con la puntuación y la banda, y bajo el CVE la línea de motivos `app-priority-reasons`, iconos y KEV/expuesto en rojo, sin repetir la base, que va en la columna de severidad con el CVSS), etiquetas **KEV** y **EPSS**, paquetes, a qué afecta (imágenes, contenedores, servidores o CT) y si hay parche; paginada por CVE. **Vista principal por defecto**: abiertas, prioridad ≥ media, sin ruido, sin imágenes sin uso ni escaneo desactivado; debajo, **«Fuera de esta vista: 21 840 kernel no en uso · 301 sin corrección prevista · 6 018 de prioridad baja (hallazgos)»**, cada uno enlazado a la lista de solo eso (`?hidden=`, con un chip para volver). Filtros: estado, prioridad mínima, severidad mínima, EPSS ≥ (1, 10 o 50 %), proyecto, orden (prioridad o severidad), «Solo en KEV», «Expuestas», «Solo con parche» e «Incluir lo oculto»; «Ver todas» / «Vista principal». En la cabecera, un **botón de fuentes** con el resumen («KEV del 22 oct · EPSS del 22 oct · Trivy del 22 oct»; en ámbar si una fuente falla o tiene más de 3 días, si la BD de Trivy tiene más de `TRIVY_STALE_DAYS` = 2 o si la última re-evaluación falló) que abre el panel **«Fuentes de datos»**: una sección por fuente (CISA KEV, EPSS y Trivy) con un punto de estado, qué aporta, la fecha de los datos y el resto en líneas separadas (versión, registros, última comprobación, antigüedad, último fallo; en Trivy, cuántos SBOMs, la última evaluación y el resumen de la última búsqueda). La de Trivy es la de la BD más reciente con la que se evaluó un SBOM (la API no toca la caché del worker; `GET /vulnerabilities/intel` → `trivy`, de `sboms` y `job_runs`). Con `assets.operate`, cada sección lleva su acción: «Descargar KEV y EPSS ahora» y, en Trivy, **«Buscar con la BD actual»** y **«Descargar la BD y buscar»** (antes, un icono suelto y un botón con menú): re-evalúa todos los SBOMs sin conectarse a las máquinas, espera al job y enseña su resumen («12 de 12 SBOMs evaluados: 3 findings nuevos y 1 corregidos») y recarga la lista y los nuevos. Búsqueda `q` con la **misma sintaxis** (QoL-6b; también en `/findings`, la exportación y la ficha): el texto suelto es un CVE por prefijo o un paquete por subcadena; además `cve:`, `paquete/package:`, `severidad/severity:` (`crítica`, `high`…) y `prioridad/priority:` (`urgente`, `alta`, `media`, `baja`), y las claves de asset (`tag`, `nombre`, `tipo`, `estado`, `rol`, `proyecto`, `ip`) sobre el **asset afectado**: el dueño del finding o, en una imagen, alguno de los contenedores y hosts no retirados que la usan. Todo en SQL parametrizado (`findings/finding-search.ts`). Como en el árbol, tags, roles, nombres y proyectos se comparan **sin mayúsculas ni tildes en los dos lados** (`foldSql`, el `foldText` de shared-types en SQL: NFD y fuera las marcas combinantes): `tag:produccion` encuentra el tag `Producción`. Filtros y búsqueda en la URL (`?q=&status=&min=&fixable=&prio=&kev=&epss=&exposed=&noise=&hidden=&sort=&new=&project=`, solo lo que difiere del defecto); con proyecto, solo los findings de sus assets (las imágenes, por quienes las usan) y los contenedores de ese proyecto.
- Arriba, el panel plegable **«CVE nuevos desde tu última visita»** (rediseñado en la sesión 19): resumen («4 037 nuevos · 3 en KEV · 22 141 hallazgos ocultos: kernel no en uso, sin corrección prevista») y una **tabla compacta** con los 10 más prioritarios sin ruido: puntuación, CVE y paquete, severidad y porqué (a 640 px o menos, el porqué pasa a su propia línea); «Ver los N en la lista» abre la lista con `?new=1` y todos sus filtros; «Marcar como vistos» (§9).
- **Detalle** (`/vulnerabilities/:id`): junto al CVE, su prioridad, KEV y el porqué completo; en el resumen, **Explotación** (en KEV desde cuándo, plazo de CISA y ransomware; EPSS con su percentil, o que no hay dato); en el árbol, la prioridad de cada afectado y el ruido marcado. «←» vuelve a la lista o, si se abrió desde la pestaña de un asset, a ese asset con su pestaña y su filtro (el origen va en el estado de la navegación; atrás en el historial, o a su URL tras recargar); resumen del CVE, árbol de afectados (`p-treetable` desplegado: asset, paquete con instalada → corregida o el estado de la distribución, estado de ejecución, puertos expuestos —5 y «+N más»— y acción sugerida), «Re-escanear afectados» (admin, con confirmación y el progreso de cada job) y los mensajes de «sin afectados», «desconocido» y «sin comprobar» (§9). Referencias solo http(s), 5 y «Ver las N».
- **Selección por CVE** (QoL-6): casillas que se conservan al paginar (cambiar el filtro las vacía) y la misma barra de lote con **Escanear** sus **afectados** (con el proyecto del filtro). Desde QoL-6b, nada más: un CVE no tiene tags, proyecto ni política propios (hereda el contexto del asset afectado, que se cambia en el inventario), y la API rechaza `vulnerabilityIds` en `tags`, `project`, `policy` y `retire` (400; `BULK_VULNERABILITY_ACTIONS`). Los afectados de un CVE son los mismos que enseña la lista (sin los de escaneo desactivado). «Aceptar el riesgo» llegará con la priorización.
- **Exportar ▾ Por CVE / Por asset · CSV / JSON** (`GET /vulnerabilities/export`, los mismos filtros que la lista sin paginar, hasta 20 000 filas): por CVE, una fila con severidad, título, parche, paquetes, imágenes, contenedores, servidores/CT, sin uso, dominios públicos y URL; por asset, una fila por servidor, CT o imagen afectado con proyectos, contenedores que la usan, CVE por severidad, con parche y la lista de CVE (en JSON, cada finding con paquete, instalada y corregida).
- **CSV** (`apps/api/src/common/csv.ts`): RFC 4180, BOM UTF-8 (Excel), listas con `; ` en una celda y **sin inyección de fórmulas** (una celda que empieza por `= + - @`, tabulador o CR lleva un `'` delante). `Content-Disposition: attachment; filename="infraward-<qué>-<fecha>.csv"`, `Cache-Control: no-store` y `X-Export-Rows`. La web descarga con un enlace (`<a download>`): la cookie va sola y un GET no lleva CSRF; con un token de API, igual por curl.
- **Barra de búsqueda global** en la barra superior (§9).

### Actividad

`GET /jobs` (historial `job_runs`, §5): tarea, asset (enlace; el nombre si se purgó), estado (con barra de progreso y último mensaje si está en curso, el motivo si espera turno —«Esperando turno en pve-pruebas (2 jobs en curso, máximo 2)»— y el error si falló), **worker** (la réplica que lo ejecuta o lo ejecutó por última vez), inicio y duración; en la cabecera, «3 workers conectados» con el detalle de cada réplica (`GET /jobs/workers`: máquina, colas y cuál es el líder); las encadenadas, marcadas con un enlace a las de la misma operación. Filtros por estado (todas, en curso, fallidas, terminadas), tipo, asset (`?assetId=`, desde la ficha) y operación (`?parentJobId=`, con chip). Una **operación en lote** sale como «Operación en lote» con su mensaje y «N tareas · M en curso · K fallidas» enlazado a sus tareas; mientras alguna siga en curso, la lista se refresca.

### Ajustes

Pestañas, con la abierta en `?tab=`:
- **Perfil** (por defecto; a ella lleva «Tu perfil» del menú del usuario): cabecera con un avatar con las iniciales, el nombre (editable en el sitio con el lápiz), el email, el rol, cómo entra y desde cuándo; debajo, dos tarjetas de filas de ajustes, **Cuenta** (email con «Cambiar», rol con su descripción, cómo entras) y **Seguridad** (contraseña con «Cambiar» y la verificación en dos pasos con su estado y acciones); cambiar el email o la contraseña se hace en un diálogo. Nombre con `PATCH /auth/me`; «Cambiar el email» con `POST /auth/email` (solo con la sesión web; pide la contraseña actual; único, normalizado y auditado como `user.email_changed`; no en cuentas OIDC o enlazadas, cuyo email da el proveedor, ni en la de emergencia, y **no mientras OIDC esté configurado**: el login OIDC enlaza por email verificado y aplica el rol de los grupos, así que un usuario que eligiera el email de otro aún sin enlazar heredaría su rol al entrar este). Un admin también lo cambia desde Usuarios (`PATCH /users/:id`, mismas reglas salvo la de OIDC); «Cambiar contraseña» con la actual, la nueva y su repetición, que cierra las demás sesiones. Debajo, **Verificación en dos pasos**: estado y códigos de recuperación que quedan (en ámbar con 3 o menos), «Activar» (diálogo con el mismo alta que `/mfa-setup`), «Cambiar de dispositivo», «Generar códigos nuevos» y, si no es obligatoria, «Desactivar»; a un usuario OIDC, que la aplica su proveedor. Cada pestaña restringida solo aparece con su permiso (aunque se pida en la URL); quien no tiene ninguna (lector, operador) ve aquí un aviso.
- **Tokens de API** (QoL-6, para todos): los propios (nombre, prefijo, alcance, caducidad, último uso con su IP, estado —vigente, caducado, revocado— y «Revocar» con confirmación) y «Nuevo token» (nombre, caducidad —7/30/90 días, un año u otra fecha— y alcance con su explicación). El token sale en un diálogo **una sola vez**, con copiar, el aviso de que no se guarda y un ejemplo de curl. Con `users.manage`, además «Tokens de todos los usuarios» con filtro por usuario y revocar.
- **Inventario**: los **avisos de caducidad** (umbrales en días, §13) y la **política de inventario** (§10: la global con sus tres desplegables y sus exclusiones del escaneo, las reglas por etiqueta (con la columna «Excluido») —con autocompletado— y por proyecto —crear, cambiar, borrar— y la lista de las reglas de assets con enlace a su ficha; «Reconciliar ahora»; un viewer la ve en solo lectura) y los **colores de los tags** (paleta fija de 12 tonos legibles en claro y oscuro, o sin color).
- **Conectores** (`connectors.write`, §13): un bloque por conector (proveedor, token válido o el error, dónde está el token —nunca el token—, dominios, registros y última sincronización, parcial o no) con **Probar**, **Sincronizar** (`assets.operate`), **Reemplazar token** y **Dar de baja** (con confirmación: retira sus dominios y registros y borra el token). «Nuevo conector»: proveedor (del catálogo `DOMAIN_PROVIDERS`), nombre y token en un campo de contraseña sin autocompletar, con dónde se crea y sus permisos de solo lectura; el campo se vacía al enviar, y al crear se prueba y, si vale, se sincroniza.
- **Usuarios** (`users.manage`): nombre, email, rol (con su descripción en el diálogo), estado (activo, «Temporal pendiente», desactivado), último acceso y acciones: **Nuevo usuario** (email, nombre y rol), **Editar** (nombre, email y rol), **Restablecer contraseña**, **Restablecer la verificación en dos pasos** (si la tiene y no es uno mismo; con confirmación) y **Desactivar**/**Reactivar** (con confirmación; uno mismo no se puede desactivar); en Acceso, la insignia «2FA» de quien tiene TOTP y «Ver su actividad» (Auditoría filtrada). La contraseña temporal sale en un diálogo **una sola vez**, con botón de copiar y su caducidad.
- **Acceso** (`users.manage`, sesión 22): reglas de acceso a la terminal (§11) con a quién (persona o rol), dónde (asset y lo que contiene, etiqueta o proyecto), quién y cuándo; alta en línea (persona o rol, ámbito y objetivo; pide reautenticación) y «Retirar» (corta al momento las terminales que dependían de ella).
- **Secretos** (`secrets.status`): estado de los proveedores (`GET /secrets/providers`).
- **Caja fuerte** (`vault.manage`; cambiar, `vault.admin` con reautenticación): estado del almacén (local u OpenBao, sano o no, versiones que conserva; si no está configurado, qué variables poner y dónde) y los ajustes: plazo de rotación por defecto, «Avisar a los demás admins de cada revelado» (activado por defecto) y días en la papelera.
- **Auditoría** (`audit.read`): cuándo, quién, acción (las fallidas en rojo), sobre qué (enlace a la ficha si es un asset que sigue existiendo, o a la del CVE), IP y detalle legible; filtros en la URL (categorías, usuario, resultado, texto y fechas) y «Cargar más» por cursor.

### Docker y Plesk en la interfaz (sesión 14)
- Ficha de un host Docker: bloque «Docker» con volúmenes, redes e imágenes, cuántos contenedores activos los usan y «sin uso».
- Fichas de volumen, red e imagen con «Uso» (o «Sin uso») y sus contenedores en Dependencias; de contenedor con «Montajes y redes».
- Fichas de suscripción, dominio y base de datos (Plesk) y de certificado (caducidad con etiqueta de color).
- Dominios (QoL-5): ficha del **conector** (proveedor, token, cuentas, última sincronización), del **dominio** (caducidad por RDAP o «sin RDAP», registrador, estados, nameservers, plan y cuenta; en «Contiene» los 25 que más piden atención —colgantes, caducidades— con «Ver todos en Relaciones») y del **registro DNS** (valor, TTL, proxy, lectura del 443 y la tarjeta **Comprobación**: nivel, motivo explicado, destino, servicio, «Marcar como esperado»/«Reabrir» y, en un informativo con más registros al mismo destino, «Marcar los N que apuntan a …»). Servidor, VM y CT: tarjeta lateral **«Dominios que le apuntan»** (directos y «vía» CNAME, con la caducidad del certificado). Árbol: etiquetas «Colgante» e «IP desconocida» y la caducidad de los dominios.
- Notas del sudoers como aviso informativo con «Generar el comando»; avisos de clones y de certificados en el panel.
- Los mosaicos del panel de tipos que no salen en el árbol no enlazan a un filtro vacío.

### Ficha de asset

- **Migas** con la ruta completa (`Inventario › pve-pruebas › pruebas › web1`).
- **Cabecera**: el nombre visible con «Renombrar» (en el sitio) y, si está renombrado, «Descubierto como … · Volver al nombre descubierto»; tipo, estado de ejecución y de inventario, dirección, roles y tags (editables, con color y autocompletado); debajo, bien visibles, el aviso de servidor duplicado (con «Purgar este» / «Purgar <otro>») o de «también aparece como…», el de alta pendiente, el de CA SSH desactualizada, el de sudoers desactualizado, el de **sshd** (QoL-7: «Root puede entrar por SSH con contraseña» en rojo, o en ámbar «sshd deja entrar a root» / «sshd admite contraseñas», con la configuración efectiva y la recomendada; solo se lee, nunca se aplica) y los avisos de recolección parcial (`facts.infraward.warnings`).
- **Acciones** (solo admin, según el tipo y el estado, con las mismas reglas que la API): **Recolectar de nuevo** (servidor dado de alta o CT activo y en marcha), **Escanear vulnerabilidades** (contenedor, imagen o host Docker; re-analiza con `force`), **Ver el comando de alta** y **Regenerar el comando** (servidor pendiente; regenerar también con el sudoers o la CA SSH desactualizados; pide confirmación porque invalida el anterior y abre el stepper), **Pasar a certificados (CA)** (servidor activo con clave estática dado de alta con el script; confirmación y stepper con el comando en modo CA), **Dar de baja** (confirmación; si había credenciales, muestra el comando para quitar el acceso del servidor) y **Purgar** (hay que escribir el nombre del asset). A un retirado solo le queda purgar. Mientras haya un job en cola o en curso para el asset (o la imagen de un contenedor) los botones se deshabilitan y se ve su progreso con enlace a la Actividad; al terminar, la ficha se recarga sin cambiar de pestaña.
- **Pestañas** (perezosas: cada una pide sus datos al abrirse; la abierta va en la URL, `?tab=`, y una que el asset no tiene abre el Resumen), en este orden:
  - **Resumen** (por defecto; dos columnas independientes —sin filas compartidas, sin huecos—: la **principal** con vulnerabilidades, lo propio del tipo —contenedor, imagen, uso, volumen, red de Docker, Plesk, certificado, montajes—, qué contiene, Docker, servicios, puertos y notas; la **lateral** con sistema, red y acceso, dependencias, proyectos, política e identificadores; una sola columna por debajo de 1100 px): vulnerabilidades (máxima y CRITICAL/HIGH con parche, con enlace a la pestaña), sistema (SO, kernel, CPU, RAM; en un CT/VM, lo que asigna Proxmox), red y acceso (dirección, conexión, hostname, interfaces, última recolección), contenedor o imagen, **servicios en marcha relevantes** (sin los del sistema base, que se cuentan aparte), **puertos en escucha con su proceso** (IPv4 e IPv6 juntos; primero los expuestos en todas las interfaces —`0.0.0.0`, `::`, `*`—, luego los de una IP concreta y al final los de loopback, marcados «solo local»; como máximo 8, con «Ver los N puertos» que abre la pestaña, como «Ver todos» de servicios), **qué contiene** (hijos con dirección, estado y vulnerabilidades), **dependencias** (padre, imagen y otras relaciones, en ambos sentidos), **notas** (Markdown con `marked`: GFM, el HTML en bruto sale como texto, enlaces solo http(s)/mailto en otra pestaña sin `opener`, imágenes como enlace; además pasa por el saneador de Angular; «Editar» con pestaña de vista previa) y **proyectos** (cada uno con su motivo —directo, heredado de…, por quienes la usan— y las excepciones; con `projects.write`: añadir a un proyecto, «Excluir» uno heredado y quitar filas propias). ID, clave natural, host key y credenciales (solo referencias) van plegados en «Identificadores».
  - **Vulnerabilidades** (contenedores e imágenes): **una fila por CVE** con su severidad, los paquetes afectados (desplegables) y si hay parche. Por defecto lo accionable —abiertos, **con parche** (`fixable=true`) y **HIGH o más** (`minSeverity`)—, con «Ver todas»; cada CVE enlaza a su ficha (`/vulnerabilities/:id`), donde están las referencias externas. El filtro también va en la URL (`?status=&min=&fixable=`, como la lista), así que al volver se ve lo mismo.
  - **Relaciones** (QoL-4), con tres vistas (`?view=`): **Mapa** (por defecto; grafo de Cytoscape centrado en el asset, anillos concéntricos por saltos, profundidad 1–3 en `?depth=`, icono y color por tipo, el tipo de relación en las aristas —con colores y trazos propios para imagen, volumen y red—, anillo rojo con CVE críticos, retirados y desaparecidos discontinuos, «+N más» en los nodos con vecinos sin cargar y aviso si se llegó al tope). Tocar un nodo abre su **tarjeta** (tipo, estado, dirección, críticas, lo que queda sin cargar) con «Abrir ficha» y «**Centrar aquí**», que recentra sin salir de la ficha (con «Volver a …»); doble clic abre su ficha. **Jerarquía**: organigrama de OptimusNG (`p-organization-chart`) solo con `contains`: antepasados, el asset resaltado, sus hijos y nietos (plegados), «y N más» pasados 12; cada nodo enlaza a su ficha; desplazamiento horizontal dentro del contenedor. **Lista**: las tablas de salientes y entrantes (la alternativa textual del mapa). Si tiene contenido, «Ver su topología».
  - **Credenciales** (QoL-7, con `vault.manage`, en servidores, VM, CT, contenedores, bases de datos y dominios): las entradas de la caja fuerte del asset (§19).
  - Paquetes, Servicios, Puertos, **Snapshots** (uno por cambio real: fecha, origen —recolección o descubrimiento— y resumen por sección; al elegir uno, su **diff** con el anterior agrupado por sección —añadido, quitado, cambiado con antes → después— y los facts completos plegados) y, al final, **Datos en bruto** (el visor de facts).
- **Terminal** (sesión 22): «Abrir terminal» en la cabecera para quien puede (otra pestaña, `/assets/:id/terminal`, §11); en «Red y acceso» de un servidor, el acceso de administración con «Activar»/«Retirar» (admins, §7); tarjeta lateral «Acceso a la terminal» (admins).
- **Política de inventario** en el Resumen (§10): valor efectivo de cada campo y su origen («propia», «heredada de pve-pruebas», «por la etiqueta lab», «global»); en un nodo raíz, el intervalo, la última y la siguiente reconciliación y «Reconciliar ahora»; en el resto, «con su nodo raíz». Admin: diálogo para fijar la regla propia (cada campo puede «Heredar») o quitarla.
- Avisos de **desaparecido** (desde cuándo y cuántas ejecuciones sin verlo) y de **retirado** (automáticamente: vuelve solo si reaparece; a mano: no). Un desaparecido o retirado no enseña el último estado de ejecución (ni en la ficha ni en el árbol).
- Con el **escaneo desactivado** por su política: «Escanear» deshabilitado con el motivo, aviso en la pestaña de vulnerabilidades y «sin escaneo» en el árbol.

### Proyectos (QoL-3)

Tarjeta de proyecto (y resumen de su página): tres cifras (assets, CVE abiertos y C/H con parche —el total grande y «27 C · 190 H» debajo—), una **barra apilada de hallazgos abiertos por severidad** (un solo tono rojo de más a menos grave —la severidad es un orden, no categorías—, oscuro en claro y vivo en oscuro; leyenda con nombre y número y tooltip por tramo, nunca solo el color) y los **tipos de asset como chips** con su icono y cuántos hay; accesos a Inventario, Vulnerabilidades y Panel con icono.
- **Lista** (`/projects`), en **cuadrícula** o **lista** (selector con iconos; la elección se recuerda en el navegador). Cuadrícula: tarjetas visuales con la inicial sobre el color del proyecto y un degradado suave de ese color, el nombre y la descripción en una línea, un **anillo** con los hallazgos abiertos por severidad (misma rampa que la barra; en el centro, los CRITICAL y HIGH con parche; el detalle en el tooltip y la etiqueta accesible), tres cifras (assets, CVE abiertos, críticas) y los tipos de asset solo con icono y número (cuatro y «+N» con el resto en el tooltip); toda la tarjeta lleva a su página y el pie tiene los accesos con icono a Inventario, Vulnerabilidades y Panel. Lista: una fila por proyecto (color, nombre y descripción, assets, CVE, barra de severidad sin leyenda, C/H con parche y los accesos); en móvil, cada fila se apila con sus etiquetas. «Nuevo proyecto» (nombre, descripción y color de la paleta) lleva a su página.
- **Detalle** (`/projects/:id`): el **panel del proyecto** (QoL-8, ver Panel; el resumen de assets y de vulnerabilidades con parche son widgets suyos), «Qué entra» (filas `include` y excepciones, quitar, «Añadir un asset» con autocompletado por nombre), la **regla de política del proyecto** (diálogo con «Heredar» por campo y «Quitar la regla»), editar y borrar (con confirmación).

### Otras vistas

- **Stepper de alta** de servidores con progreso en tiempo real (SSE, §7): comando por URL, script embebido con las huellas pegadas o clave manual. Antes, **«Añadir servidor»**: tres pasos numerados (**Servidor**: host, puerto y nombre; **Acceso**: el modo como tarjetas seleccionables con icono —certificados, «recomendado», o clave estática— y las opciones del script como filas con icono y casilla —instalar sudo y, para admins, el acceso de administración—; **Organización y política**, plegable) y, al lado (debajo en pantallas estrechas), «Qué va a pasar» (generar, ejecutar como root, verificar y recolectar) y lo que necesita el servidor (sudo, python3 y el aviso de Proxmox sin sudo). La sección plegable **«Organización y política»** (QoL-6b): tags, proyectos, plantilla y el formulario de política con sus exclusiones (cada parte con su permiso). Los comandos (llevan el token) solo viven en memoria de la pestaña que los generó; al recargar se genera otro.
- **Priorización** de vulnerabilidades y CVEs nuevos.
- **Selector de secretos** que lista el contenido del proveedor activo.
- **Gestión de conectores** (Proxmox por API, Plesk, proveedores de dominios, proveedores de secretos).
- **Terminal web** (xterm.js) desde la ficha de cada asset.
- **Reproductor de sesiones** grabadas y registro de auditoría.
- **Gestión de claves SSH personales** y comandos de conexión vía gateway.

---

## 16. Roadmap

### MVP
1. Monorepo con pnpm workspaces: `web`, `api`, `worker`, `shared-types`, `domain`, `secrets`.
2. Modelo `Asset` + `AssetRelation` + `Snapshot`.
3. Proveedor de secretos `local`.
4. Flujo de alta con generación de claves y script de enrolamiento.
5. Playbook de detección y facts básicos.
6. Descubridor de Proxmox con CT vía `pct exec`.
7. `trivy image` sobre los contenedores encontrados.
8. Vista en árbol en la web.

### Fase 2
- Proveedor OpenBao (AppRole, KV v2, CA SSH).
- Descubridor de Plesk y de Docker.
- SBOMs, tabla `Package` y re-evaluación periódica de CVEs (hecho en la sesión 15).
- Buscador de CVEs con árbol de afectados.
- Reconciliación con estados `missing` / `retired`.

### Fase 3
- Proveedor Vaultwarden (`bw serve`).
- Enriquecimiento KEV/EPSS y priorización con contexto de servicio (hecho en la sesión 19).
- Alertas (CVE críticos en KEV y expuestos: hecho en la sesión 19; puertos nuevos y canales externos, pendiente; certificados a punto de caducar: QoL-5).
- VMs vía qemu-guest-agent.
- Conector de **Cloudflare** e inventario de dominios: relación dominio → servidor, caducidades (RDAP, SSL) y registros colgantes (hecho en QoL-5).
- **Modo gateway del worker** (hecho en la sesión 21: WebSocket, PTY, saltos, certificados firmados por la API, cupos y parada ordenada, §11) + **terminal web** con xterm.js, `AccessPolicy` y cortes al momento (hecho en la sesión 22) y grabación de sesiones (sesión 23).
- **Caja fuerte de credenciales** con almacén separado, revelado con step-up y aviso de sshd (hecho en QoL-7, §19).
- **Paneles personalizables** por usuario y por proyecto, con widgets, rejilla editable y gráficos de evolución (hecho en QoL-8, §15).

### Futuro
- **Gateway SSH** completo: conexión con `ssh` nativo, generación de `~/.ssh/config`, SFTP y port forwarding.
- Más proveedores de dominios (OVH, Namecheap, Porkbun, GoDaddy…).
- **Workers remotos por sitio** con conexión saliente, terminal a través del túnel y autoactualización firmada (§18).
- Más conectores (Kubernetes, TrueNAS, Unraid, Cloudflare).
- Servidor MCP sobre la API para consultar el inventario en lenguaje natural (autenticado con un token de API de QoL-6).
- Turborepo para caché de builds si el CI crece.
- Collection de Ansible publicada en Galaxy (repositorio separado).

---

## 17. Decisiones tomadas (resumen)

| Decisión | Motivo |
|---|---|
| OptimusNG en lugar de PrimeNG | Licencia |
| pnpm workspaces en lugar de Nx | Problemas previos con Nx; CLIs nativos sin capas intermedias |
| Un único repositorio | Compartir tipos y lógica entre web, API y worker |
| La API no ejecuta trabajo pesado | Escalabilidad, reintentos y aislamiento vía BullMQ |
| Referencias a secretos, nunca valores | Gestor de secretos intercambiable y menor riesgo |
| Modelo genérico de Asset con JSONB | Inventariar cualquier tipo de recurso sin migraciones constantes |
| SBOMs guardados | Respuesta instantánea a nuevos CVEs sin tocar los servidores |
| Todo finding sale de `trivy sbom` sobre el SBOM guardado | Escaneo y re-evaluación dan los mismos fingerprints |
| SBOM de servidores con una copia de sus BDs de paquetes (sin sudo) | Trivy nunca en el servidor; pocos MB; a cambio, sin librerías de lenguajes sueltas |
| Job scheduler que solo dispara la re-evaluación | Que quede en la Actividad (ids UUID) y no se solapen dos |
| Detección de vulnerabilidades delegada en Trivy | Backports de distribuciones; evitar falsos positivos |
| No borrar assets desaparecidos | Robustez ante fallos y conservación del historial |
| `pct exec` para los CT | Sin SSH ni claves dentro de cada CT |
| Gateway como modo del worker (mismo código, proceso aparte) | Conexiones largas fuera de la API y de los jobs pesados, sin un segundo lenguaje ni duplicar el código de secretos |
| Gateway y workers remotos nunca acceden al gestor de secretos | La API firma certificados SSH de corta duración; la lógica sensible vive en un solo sitio |
| Acceso interactivo de administración opcional y solo con certificados | Administrar desde la terminal sin guardar contraseñas; quitar el acceso a una persona no exige tocar los servidores |
| Caja fuerte de credenciales separada y nunca usada por InfraWard | Custodiar contraseñas de emergencia y de servicios no SSH sin que el worker o el gateway puedan leerlas |
| Caja fuerte con su propio almacén (`VaultStore`), no un proveedor más de `SecretsService` | `SecretsService` lo comparten API y worker; con otra clave, otra AppRole y otro prefijo, el worker no puede leerla ni por error de configuración (la API se niega a arrancar si los comparte) |
| Purga de la papelera de la caja fuerte en la API, no en el worker | El worker no tiene acceso al almacén; es trabajo ligero (una llamada por entrada, con advisory lock) |
| Generar contraseñas en el navegador y comandos interactivos para aplicarlas | La generada no viaja hasta guardarla, y nunca va en la línea de órdenes ni en el historial del servidor; InfraWard no tiene escritura como root |
| Aviso de sshd por `sshd -T` filtrado en el servidor (sudoers v7, nota) | La configuración efectiva (Match, Include, valores por defecto) solo la da sshd y necesita root; solo salen tres opciones |
| Workers remotos solo con conexión saliente y actualizaciones firmadas | Redes cerradas sin abrir puertos; un worker con acceso a una red entera no puede aceptar código sin firmar |
| Terminal sin el usuario `inventory` | Mantener el descubrimiento de solo lectura e identificar a cada persona |
| Certificado de la terminal con un principal de rol (`infraward-operators`) y la persona en el key_id | Dar o quitar acceso no exige tocar los servidores; el auth.log sigue diciendo quién entró y en qué sesión |
| AppRole aparte para firmar los certificados de la terminal, solo en la API | Un worker comprometido (tiene la AppRole de la app) no puede emitir certificados de administración |
| Ticket de un solo uso entre la API y el gateway; el gateway pide la firma con un secreto compartido | El navegador o el cliente nunca ven el certificado; el gateway nunca toca el gestor de secretos |
| PTY con un puente en Python, no node-pty | Sin módulos nativos que compilar en la imagen (python3 ya está por Ansible); funciona igual en macOS y Linux |
| La terminal escanea solo la host key fijada (ED25519 primero) y la recuerda | OpenSSH ≥ 9.8 penaliza las conexiones sin autenticar (`PerSourcePenalties`) |
| WebSocket de la terminal por el mismo origen que la web, con la cookie de la sesión ligada al ticket | La CSP no cambia, el gateway no se publica y un ticket robado no sirve sin la cookie |
| AccessPolicy solo concede (persona o rol; asset con lo que contiene, etiqueta o proyecto) | Lo mismo que hereda la política de inventario, sin reglas que se contradigan |
| El permiso por asset se comprueba en `PermissionsGuard`, antes de la reautenticación | Quien no puede abrir terminal no ve el diálogo de reautenticación |
| Cortes por pub/sub de Redis y latido del gateway con barrido en la API | Al momento cuando hay aviso; en ≤ 15 s cuando el cambio es indirecto o el aviso se pierde; un gateway muerto no deja sesiones activas |
| La terminal en su propia ruta y pestaña | Varias a la vez, cada una su sesión; la ficha sigue usable |
| Dominios como assets relacionados con servidores | Priorizar CVEs expuestos y detectar registros colgantes |
| Imágenes de contenedor como assets (`image` + `instance_of`) | Findings, SBOM y paquetes una sola vez por imagen y con un único FK a `assets` (igual que los servidores) |
| Modo CA por servidor, conviviendo con la clave estática | Sin claves permanentes donde se pueda; migración gradual volviendo a ejecutar el script |
| Una sola conexión SSH por job (ControlMaster) | El certificado solo se comprueba al autenticar: vida corta sin renovar a mitad de Ansible; una línea en el log de sshd por job |
| Rotación de la CA manual y fuera de la app | La app solo firma; distribuir la CA nueva desde el worker exigiría sudo de escritura |
| Servidor duplicado (machine-id de otro asset vivo) no escribe nada | No mezclar el historial de dos assets; el admin decide cuál purgar |
| Clon (machine-id repetido con host keys distintas) con clave `<machine-id>+<huella>` | Las plantillas y los clones copian el machine-id; las host keys distinguen la misma máquina de otra |
| Volúmenes y redes de Docker como assets (fuera del árbol) | Las preguntas son recorrer relaciones (`mounts`, `attached_to`) y tienen ciclo de vida propio («sin uso», `missing`) |
| `stores` host → imagen | Una imagen sin contenedores sigue en el host: no es `missing` hasta que no la tiene nadie |
| Imágenes sin uso: escaneadas, pero fuera de lo accionable | Siguen pudiendo arrancarse; lo urgente es lo que corre |
| Plesk por consultas fijas a `psa` en el ayudante de root | `plesk bin` no da todo, la API exige credenciales y sudo-rs no admite argumentos con espacios |
| Sudoers v4: una regla con un ayudante de root de lista cerrada | sudo-rs (Ubuntu ≥ 25.10) no admite comodines, espacios ni regex; validar dentro del ayudante vale con los dos sudo y se puede probar con inyecciones |
| Corte limpio a v4 (el worker solo usa el ayudante) | Mantener también los comandos antiguos duplicaría playbook, conectores y tests; los v1–v3 salen «desactualizado» con su comando |
| Tabla única de capacidades del sudoers | Avisos y notas coherentes, sin condiciones repartidas por el código |
| Detalles de un CVE leyendo la BD de Trivy del worker (lector BoltDB propio, sin candados) | Distinguir «no afecta» de «desconocido» offline y sin dependencias; la API sigue sin tocar Trivy y Trivy nunca espera por nosotros |
| «CVEs nuevos» por `opened_at` y una marca por usuario que solo avanza a mano | Lo nuevo no deja de destacarse hasta que alguien lo confirma; un CVE que reaparece vuelve a avisar |
| Política de inventario por campo, heredada por `contains`, materializada en `assets.effective_policy` | Reglas parciales («solo sin escaneo»); las consultas filtran con una ruta de JSONB sin recorrer el árbol |
| Imagen: escanea si alguno de quienes la usan lo permite | Una imagen compartida se escanea una vez y sirve a todos sus hosts |
| Nodos raíz que fallan no pasan a `missing` | Un fallo de red no rompe el inventario; se avisa |
| `missing` → `retired` tras N descubrimientos completos de su ámbito, con su subárbol; reaparecer reactiva solo lo retirado automáticamente | Contar ejecuciones reales (no tiempo) y respetar las bajas a mano |
| Snapshot solo con cambios reales y diff guardado; lista de lo volátil centralizada y con test | Historial legible sin una foto por recolección; el ruido (uptime, PIDs, interfaces de Docker) se decide en un solo sitio |
| Notificaciones en la app, agrupadas por descubrimiento y padre | Sin canales externos aún (alertas, sesiones 19–20); un alta de un Plesk no genera decenas de avisos |
| Sesiones opacas en BD en una cookie httpOnly, en lugar de un JWT en `sessionStorage` | Revocar es borrar filas (desactivar o restablecer surten efecto al momento, «cerrar sesión» es real) y ningún token es accesible desde JavaScript; el mismo modelo servirá para OIDC y los tokens de API |
| Token CSRF en el cuerpo y en memoria, no en una cookie legible | `document.cookie` queda vacío; con SameSite=Strict y la comprobación de Origin es defensa en profundidad |
| El admin nunca elige contraseñas ajenas: temporal generada, de un solo uso | Nadie más conoce la contraseña final; el primer login la gasta y obliga a cambiarla |
| Login siempre «Credenciales inválidas»; el motivo, solo en la auditoría | No revelar qué cuentas existen o están desactivadas |
| Roles fijos con una tabla de permisos compartida (no roles personalizables) | Una sola fuente para la API y la web, cubierta por un test; ampliable sin tocar los endpoints |
| Auditoría con llamadas explícitas, no un interceptor genérico | Cada evento con un objetivo y un detalle con sentido, y en la misma transacción que la acción |
| Nombre visible como columna generada (`COALESCE(display_name, discovered_name)`) | La reconciliación sigue escribiendo solo el descubierto; todas las consultas leen el visible sin cambios y escribir `name` por error falla en vez de pisarlo |
| Un asset en varios proyectos; cada proyecto heredado por `contains` con la fila más cercana (`include`/`exclude`) | Un nodo entra con todo lo que contiene y las excepciones son locales a un proyecto; base para permisos por proyecto (unión) |
| Proyectos efectivos materializados (`effective_projects`) junto con la política | Filtros de inventario, vulnerabilidades y panel con un índice GIN, sin recorrer el árbol en cada consulta |
| Grafos con Cytoscape.js + fcose (MIT), no Sigma, vis-network ni ngx-graph | Nodos compuestos nativos (agrupar por host), canvas que aguanta miles de nodos, mantenida, sin atarse a una versión de Angular; se carga solo al abrir un mapa |
| Grafos por niveles en la API (vecinos por nodo, tope de nodos, nivel host + `expand`) | Con cientos de assets nunca se manda el grafo entero; lo oculto se resume (`hidden`, «+N») y se agrega entre grupos |
| Jerarquía `contains` con el organigrama de OptimusNG y el resto como grafo | El árbol es una jerarquía estricta; imágenes, redes y volúmenes compartidos son un grafo |
| Cuenta del proveedor DNS como asset raíz `dns_provider` (→ dominio → registros) | Reutiliza tal cual la reconciliación (ámbito de `missing`, intervalo por política, proyectos heredados, notificaciones agrupadas) y el token va en `credentials` como cualquier credencial |
| Conectores de dominios con `DomainApi` ya autenticado | El conector no ve el token; en Redis solo viaja el id del conector |
| Certificados del 443 como assets, uno por huella, adoptables por Plesk (alias `tls:<SHA-256>`) | Reutilizan la ficha, «caduca en N días» y los avisos; el Universal SSL de una zona es uno solo |
| Colgantes en dos niveles y «esperado» atado al valor del registro | Una IP pública desconocida puede ser un tercero legítimo; lo que de verdad es riesgo (IP privada ausente, destino retirado, NXDOMAIN) va aparte. Si el registro cambia, el aviso vuelve |
| NXDOMAIN solo con `ENOTFOUND` en todas las consultas; servicios con DNS comodín, informativos | Un DKIM sin A/AAAA existe (falso positivo real); Heroku resuelve cualquier nombre, así que el DNS no basta |
| Umbrales de caducidad en `app_settings` (y no una constante) | Se cambian desde Ajustes y valen para dominios y certificados de cualquier origen |
| En la política, la etiqueta gana al proyecto (y la regla de asset a ambos) | La etiqueta se pone en el propio asset; el proyecto suele llegar heredado |
| Notas en Markdown renderizadas en la web con `marked`, sin HTML en bruto y con el saneador de Angular | Sin dependencias de servidor; un `<script>` u `onerror` en las notas nunca llega al DOM |
| Operaciones en lote: una fila `assets.bulk` ya terminada en `job_runs` como padre de sus jobs, no un job real | Reutiliza `parent_job_id` y la Actividad sin otra tabla; los cambios de datos son rápidos y transaccionales en la API, y lo pesado sigue yendo al worker |
| Selección propia en el árbol (sin propagar a los hijos) | Lo que se marca es lo que entra; la baja ya arrastra el subárbol y lo confirma con la lista |
| Exportación en el servidor con el filtro del árbol en shared-types | La misma descarga sirve a la web y a un script con token; web y API filtran igual |
| Un parser de búsqueda en shared-types que nunca lanza (QoL-6b) | Web y API entienden igual la consulta; lo raro se ignora con aviso en vez de dar 400/500, y una clave desconocida se busca como texto (`nginx:1.25`) |
| El texto suelto busca solo en el nombre; tags y roles, con su clave | Resultados predecibles: `prueba` ya no saca todo lo etiquetado `prueba` |
| Exclusiones del escaneo como unión de las reglas y vía `scanEnabled` efectivo | Lo más restrictivo, como el resto de la política, y todo lo que ya respeta `scanEnabled` las respeta sin cambios |
| Lote de vulnerabilidades solo para escanear | Un CVE no tiene tags, proyecto ni política propios: se cambian en el asset afectado |
| Organización y política en la misma transacción del alta, con recálculo al verificar | La primera recolección y su escaneo ya respetan la política elegida |
| Tokens de API con caducidad obligatoria, alcance `read`/`role` y rol leído en cada petición | Nunca más que su dueño (ni después de bajarle el rol); un token olvidado acaba caducando; los de solo lectura no escriben aunque el rol pueda |
| Sin CSRF con Bearer, pero `@SessionOnly` para gestionar tokens, la sesión y la contraseña | El CSRF protege la cookie; un token robado no puede crear otros, cambiar la contraseña ni abrir flujos de larga vida |
| KEV y EPSS en una tabla por CVE, no en `findings` (sesión 19) | Son del CVE: una descarga diaria no reescribe miles de findings y un CVE nuevo ya tiene dato |
| Prioridad calculada en el worker y guardada en el finding, con motivos como códigos | Ordenar y paginar por prioridad en SQL; pesos en una función pura con tests; el texto, uno solo para web, API y exportación |
| «Kernel no en uso» por nombre de paquete (imagen/módulos frente a cabeceras y herramientas) y no solo por versión | Trivy cuelga cada CVE del kernel de todos los binarios de la fuente `linux`; en plesk-pruebas el kernel instalado era el que corría y el ruido eran sus paquetes auxiliares |
| Paquete de cada proceso calculado en el servidor (sudoers v6, nota) en lugar de adivinarlo por el nombre | Exacto también para librerías (openssl cargado por nginx); solo salen nombres de paquete; sin la v6 todo sigue y la prioridad lo dice |
| Aviso de KEV solo para CRITICAL expuesto, una vez por apertura | Lo inmediato es lo explotado y alcanzable; el resto va al panel sin ruido de notificaciones |
| Rejilla con gridstack.js (MIT) y no angular-gridster2 ni la CDK (QoL-8) | Sin dependencias ni atadura a la versión de Angular (su wrapper tampoco se usa); la CDK no redimensiona. Solo se carga al editar: en lectura basta CSS grid |
| Diseño del panel en jsonb, uno por usuario y uno por proyecto, y el por defecto en código | Se lee y se guarda entero; mejorar el por defecto llega a quien no lo personalizó; «Restablecer» es borrar la fila |
| Concurrencia optimista con `version` (409) | El panel de un proyecto lo pueden editar varias personas: nadie pisa sin saberlo el de otro |
| Una petición por widget con caché corta en la API (promesa compartida) | Cada widget pide solo lo suyo y la página no espera al más lento; varios usuarios o pestañas no multiplican las consultas |
| Evolución: reconstruida de los findings (aproximada, todos los filtros) y muestras diarias (exactas, solo por proyecto) | Historia desde el primer día para los hallazgos y exactitud para lo que no se puede reconstruir (prioridad, estados); cada gráfico dice cuál es y desde cuándo |
| `NOT_UNUSED_IMAGE` y `SCAN_ENABLED_OWNER` en `packages/domain` | La muestra del worker y la vista principal de la API cuentan con el mismo criterio |
| Una cola por tipo de job, cada una con su concurrencia (0 = no la consume) | BullMQ solo limita por cola; prepara los workers especializados y remotos (§18, §20) |
| Límite por host raíz con semáforo en Redis y concesiones con caducidad; sin hueco, el job vuelve a la cola retrasado | Un nodo Proxmox con sus CT no recibe N × réplicas conexiones; esperar no ocupa huecos del worker y una réplica muerta no bloquea el host |
| Fencing con `job_runs.attempt` en las escrituras finales | Una réplica lenta que perdió el lock no pisa el resultado de la que la retomó |
| Líder entre los workers (lease en Redis), no la API | Los intervalos son del worker, la API no hace trabajo de fondo y puede tener réplicas; los remotos no optan |
| BD de Trivy por generaciones con cambio atómico de `current`, bajo lock de Redis, en volumen compartido | Una descarga para todas las réplicas; ningún escaneo ni consulta lee una BD a medio escribir |

---

## 18. Workers remotos y sitios (futuro)

Se apoya en el paralelismo y las réplicas del worker (§20): colas por tipo, límites por host, locks, líder e identidad estable de cada réplica.

Objetivo: inventariar y acceder a redes que no se pueden o no se quieren exponer (infraestructura de un cliente, una red sin el 22 abierto al exterior) desplegando **dentro de esa red** un worker que se conecta hacia InfraWard.

### Sitios

- Entidad **Site** (sitio): un segmento de red atendido por uno o más workers. Siempre existe el sitio `local`, servido por los workers del propio despliegue.
- Cada asset pertenece a un sitio (heredado hacia abajo, como los proyectos). Sus jobs y sus sesiones de terminal solo los atiende un worker de ese sitio.
- Los sitios encajan con los proyectos y, en el futuro, con los permisos por proyecto o cliente.

### Conexión solo saliente

- El worker remoto abre una conexión **saliente** (HTTPS/WebSocket con TLS) hacia InfraWard. En su red no se abre ningún puerto.
- **Nunca usa Redis directamente**: exponer Redis fuera es inaceptable. InfraWard ofrece una API de jobs para workers remotos (recoger trabajo, informar progreso, entregar resultados), que hace de puente con BullMQ. El worker local sigue usando BullMQ como ahora.
- Por la misma conexión viaja el **túnel de terminal**: navegador → InfraWard → túnel del worker remoto → servidor. Por eso el modo `gateway` y el worker comparten código.

### Alta e identidad del worker

- Alta como la de un servidor: token de un solo uso y caducidad corta, generado en Ajustes > Sitios.
- Al darse de alta, el worker obtiene una **identidad propia** (certificado de cliente para mTLS o equivalente) de vida limitada y renovable. Se puede revocar desde la web, lo que corta su conexión al momento.
- Todo queda en la auditoría: alta, conexiones, versión, revocación.

### Mínimo privilegio

- Un worker remoto **nunca accede al gestor de secretos**. Para cada job pide a la API un **certificado SSH de pocos minutos**, y la API solo lo firma para **assets de su sitio**.
- Si roban un worker de un sitio, no sirve para llegar a la infraestructura de otros sitios.
- Los resultados que entrega se validan igual que los del worker local (mismos parsers y filtros de fugas).

### Versiones y autoactualización

Un worker con acceso a una red entera es un objetivo de ataque a la cadena de suministro, así que:

- **InfraWard dicta la versión** en el saludo inicial, por **digest** exacto de imagen, nunca por etiqueta.
- **Solo se aceptan imágenes firmadas** (por ejemplo con cosign) con la clave del proyecto; sin firma válida, no se actualiza.
- **Ventana de compatibilidad**: InfraWard acepta workers de la versión actual y la anterior, de modo que primero se actualiza el servidor y los workers se ponen al día de forma escalonada. Uno fuera de la ventana se marca como desactualizado y no recibe jobs.
- El worker no se reemplaza a sí mismo: un **supervisor** pequeño (sidecar) descarga, verifica la firma, cambia de versión, comprueba que arranca y conecta, y hace **rollback** si no.
- La autoactualización se puede **desactivar** por sitio para entornos que exigen actualizar a mano.

---

## 19. Caja fuerte de credenciales

Custodia de credenciales que **una persona** necesita y que InfraWard **nunca usa** para conectarse: la contraseña de root para la consola de emergencia (Proxmox, OVH), y credenciales de lo que no es SSH (interfaz web de Proxmox o Plesk, router, iDRAC/IPMI, paneles de proveedores). Hecho en QoL-7.

### Almacenamiento separado

`SecretsService` lo comparten la API y el worker (misma clave maestra, misma tabla `local_secrets`, misma AppRole). La caja fuerte **no es un proveedor más**: tiene su propio almacén, `VaultStore` (`packages/secrets/src/vault/`), que **solo crea la API** (`VaultModule`), con `put` (versión nueva), `get` (actual o una versión), `versions`, `destroy` y `healthCheck`. Se elige con `VAULT_PROVIDER` (`none` por defecto: la caja fuerte sale «sin configurar» y la API responde 409 `vault_not_configured`):

- **`openbao`**: el mismo `OPENBAO_ADDR` y montajes, pero **su propia AppRole** (`VAULT_OPENBAO_ROLE_ID` + `VAULT_OPENBAO_SECRET_ID_FILE`, rol y política `infraward-vault`) y **su prefijo** (`VAULT_OPENBAO_KV_PREFIX`, `infraward-vault`): la política de la app (`secret/…/infraward/*`) no lo alcanza y la de la caja fuerte solo da `secret/data/infraward-vault/*` (create, read, update) y `secret/metadata/infraward-vault/*` (create, read, update, delete; sin `list`). Versiones de KV v2, con `max_versions` en la metadata de cada ruta. `pnpm openbao:bootstrap` y `deploy/example/init.sh` crean la política, la AppRole y su secret_id (`vault-secret-id`), que **solo se monta en la API**.
- **`local`**: tabla `vault_local_secrets` (una fila por ruta y versión) cifrada con AES-256-GCM con **su propia clave** (`VAULT_LOCAL_MASTER_KEY_FILE`); AAD `infraward:vault:v1:<ruta>#<versión>` (una fila cambiada de ruta o de versión, o copiada de `local_secrets`, no descifra). Se podan las versiones por encima de `VAULT_MAX_VERSIONS` (10).
- **La API no arranca** si la caja fuerte comparte la clave local, la AppRole o el prefijo (o uno anidado en el otro) con los secretos de la app. El worker no declara ninguna variable `VAULT_*` ni registra sus tablas.
- Referencias `secret://vault-openbao/entries/<id>#password` o `secret://vault-local/…`: proveedores que `SecretsService` no conoce.
- **Comprobado**: test de integración contra OpenBao real (la AppRole de la app recibe 403 en datos, versiones, metadata y listado; la de la caja fuerte, 403 fuera de su prefijo), e2e (con la configuración del worker, `provider_not_configured`; su clave no descifra; el worker compilado no menciona la caja fuerte) y, en desarrollo, `bao` con cada AppRole.

### Modelo y operaciones

Entradas (§5) asociadas a un asset (`SET NULL` al purgarlo) o sueltas: tipo (consola, web, IPMI, otro), nombre, usuario, URL, notas, el secreto como referencia, la versión actual, la **última rotación** y un plazo propio opcional. API (`/vault/…`, todo con la sesión web —un token de API, 403— y `Cache-Control: no-store`):

| Ruta | Permiso | |
|---|---|---|
| `GET /vault/entries?assetId=&deleted=&q=` · `GET /vault/entries/:id` | `vault.manage` | solo metadatos y estado de la rotación (nunca la referencia) |
| `POST /vault/entries` · `PATCH /vault/entries/:id` | `vault.manage` | el secreto (opcional al crear) es de solo escritura; primero el almacén y luego la fila, con compensación |
| `PUT /vault/entries/:id/secret` | `vault.manage` | versión nueva sin leer la anterior; `rotated` actualiza la última rotación |
| `POST /vault/entries/:id/rotated` | `vault.manage` | marcar como rotada hoy |
| `DELETE /vault/entries/:id` · `POST …/restore` | `vault.manage` | papelera (recuperable) |
| `GET /vault/entries/:id/versions` | `vault.manage` | quién y cuándo, y si el almacén aún la conserva |
| `POST /vault/entries/:id/versions/:v/restore` | `vault.admin` + step-up | copia esa versión como una nueva |
| `POST /vault/entries/:id/reveal` | `vault.admin` + step-up + límite por usuario | la única respuesta con el valor |
| `GET /vault/status` · `GET /vault/settings` · `PUT /vault/settings` | `vault.manage` (cambiar: `vault.admin` + step-up) | ajustes en `app_settings` |

- **Rotación**: vencida si `última rotación + plazo ≤ ahora` (plazo propio o el de los ajustes, 180 días por defecto); «sin fecha» si no consta. Al crear con secreto cuenta como rotada hoy, salvo que se indique que no es nueva. El panel cuenta las vencidas (solo con `vault.manage`).
- **Papelera**: borrar es lógico; se recupera durante `deleteRetentionDays` (30 por defecto) y después se **destruye** en el almacén y en la BD (`vault.purged`). Lo hace un intervalo de la **API** (al arrancar y cada hora, con `pg_try_advisory_lock`): el worker no tiene acceso al almacén.
- **Versiones**: sustituir guarda otra versión y conserva las anteriores (las que el almacén mantiene); solo un admin con reautenticación restaura una (como versión nueva).

### Revelar

Excepción explícita a «los valores nunca salen del backend»: solo `POST /vault/entries/:id/reveal`, **solo admins**, con **reautenticación reciente** (`@RecentAuth('vault.reveal')`: código TOTP o login en el proveedor OIDC; el diálogo de la web repite la petición), motivo opcional (≤ 200 caracteres; si contiene la credencial, no se guarda) y un límite por usuario (`VAULT_REVEAL_THROTTLE_*`). La web lo **muestra 30 s** (cuenta atrás; después se borra de la vista y el diálogo se cierra) o lo **copia** al portapapeles y lo vacía a los 30 s si sigue ahí. Nunca en logs, en el estado de la web, en listados ni en exportaciones. Cada revelado (y cada fallo, con el motivo) va a la **auditoría** (`vault.revealed`: entrada, asset, versión, mostrar o copiar y motivo) y, con `notifyOnReveal` (activado por defecto), crea un aviso `vault_revealed` que solo ven **los demás admins**.

### Generación

«Generar» crea en el navegador (Web Crypto, `generatePassword` de shared-types: muestreo con rechazo, sin ambiguos, al menos un carácter de cada clase, 12–128) una contraseña robusta, y la web enseña el **comando para aplicarla** (`rotationCommand`): `sudo passwd <usuario>` en consola, `pveum passwd <usuario>@pam` en la web de Proxmox, `plesk bin admin --set-admin-password` con `read -s` en Plesk, `ipmitool user set password <id>` en IPMI. Todos **interactivos**: la contraseña nunca va en la línea de órdenes ni en el historial. **InfraWard no la aplica**: rotar exigiría escritura como root y queda fuera mientras no haya un permiso aparte y explícito. «Ya la he aplicado» la marca como rotada.

### Aviso de sshd (solo lectura)

La recolección lee `sshd -T` (sudoers v7, consulta `sshd-auth`, §7; en los CT por `pct exec`) y guarda en `facts.sshd` solo `permitRootLogin`, `passwordAuthentication` y `kbdInteractiveAuthentication`. Con `PermitRootLogin yes` o contraseñas admitidas (`PasswordAuthentication` o teclado interactivo), aviso en la ficha (en rojo si son las dos cosas: la contraseña de root de la caja fuerte serviría también por SSH), en el árbol (`?attention=ssh-password`) y en el panel, con la configuración recomendada (`PermitRootLogin prohibit-password`, `PasswordAuthentication no`). InfraWard no cambia nada. Sin la v7, la nota de siempre.

## 20. Paralelismo y réplicas del worker (sesión W-0)

Una o varias réplicas del worker (mismo Redis, misma BD, misma caché de Trivy) procesan los jobs en paralelo sin duplicar trabajo ni saturar un servidor. Paso previo a los workers remotos (§18).

### Colas por tipo y concurrencia

Una cola de BullMQ por tipo de trabajo, cada una con su concurrencia en cada réplica (0 = esa réplica no la consume: base de los workers especializados):

| Cola | Jobs | Concurrencia (defecto) |
|---|---|---|
| `system` | `ping`, `vulnerability.lookup`, `vulnerability.intel`, `findings.prioritize`, `metrics.sample` | `WORKER_CONCURRENCY` (5) |
| `enrollment` | `enrollment.verify` | `WORKER_CONCURRENCY` (5) |
| `collect` | `asset.collect` | `COLLECT_CONCURRENCY` (4) |
| `discovery` | `asset.discover` | `DISCOVERY_CONCURRENCY` (2) |
| `domains` | `domains.sync`, `domains.test`, `services.link` | `DOMAINS_SYNC_CONCURRENCY` (2) |
| `reconcile` | `inventory.reconcile` | `RECONCILE_CONCURRENCY` (1) |
| `image-scan` | `image.scan` | `IMAGE_SCAN_CONCURRENCY` (1; alias obsoleto `SCAN_CONCURRENCY`) |
| `host-scan` | `host.scan` | `HOST_SCAN_CONCURRENCY` (1) |
| `sbom` | `sbom.reevaluate` | `SBOM_CONCURRENCY` (1) |

`JOB_QUEUES` (shared-types) dice la cola de cada job; la API y el worker encolan a través de él. La cola `scan` de antes solo se drena (lo que quedara al actualizar) y el líder borra sus schedulers antiguos. Los `Worker` de BullMQ los crea `WorkerPool` (no `@Processor`), con el nombre de la réplica, `lockDuration` 60 s, *stalled* cada 30 s y `maxStalledCount` 1.

### Un job a la vez por operación y objeto

- **Deduplicación de BullMQ** (en Redis, compartida por API y réplicas): como mucho un job pendiente o en curso por asset y operación.
- **Lock de la operación** (`op:<job>:<asset|imagen|alta>`, Redis, renovado): cubre el caso en que BullMQ diera el mismo job a dos réplicas (una lenta que perdió el lock) o hubiera dos jobs iguales; el segundo vuelve a la cola retrasado.
- **Fencing token**: `job_runs.attempt`, que la réplica incrementa al empezar. Las escrituras finales (recolección y snapshot, listado del descubrimiento y de `domains.sync`, SBOM y findings de `host.scan`/`image.scan`/re-evaluación, verificación del alta) empiezan su transacción con `assertFence` (`SELECT attempt … FOR UPDATE`): si otra ejecución lo retomó, `SupersededError` y no se escribe nada. Los recálculos sin fila (`findings.prioritize`, `services.link`) son idempotentes.
- Si una réplica **no puede renovar el lock** de BullMQ (`lockRenewalFailed`), aborta esos jobs (con sus procesos hijos) sin tocarlos: ya son de otra.

### Límite por host raíz

`HostSlots`: semáforo en Redis por **host raíz** (el asset dueño de la conexión SSH, `AssetRoute.host`: un CT o un Docker dentro de un CT cuentan contra su nodo). ZSET por host (miembro = job, puntuación = caducidad) con un script Lua atómico: como mucho `HOST_MAX_JOBS` (2) a la vez en total y `HOST_MAX_SCAN_JOBS` (1) escaneos y rellenos (prioridad baja), entre todas las réplicas. La concesión vive 60 s y se renueva cada 20 s mientras el job corre; si la réplica muere, caduca sola. Lo piden `asset.collect`, `asset.discover`, `enrollment.verify`, `host.scan` e `image.scan` (el host elegido para `docker save`). **Sin hueco, el job no ocupa un hueco del worker esperando**: vuelve a la cola retrasado (5–10 s; escaneos 20–40 s) sin gastar intento ni soltar la deduplicación, y la Actividad dice «Esperando turno en … (N jobs en curso, máximo M)». El relleno de SBOMs lleva además un lock por host (`backfill:<host>`) que pasa de un escaneo al siguiente (y caduca si la cadena se corta).

### Locks distribuidos

`DistributedLock`: `SET NX PX` con token, renovación cada tercio de su vida y liberación con Lua comparando el token (nunca se suelta el de otro). Se usan para la descarga de la BD de Trivy (`trivy-db`, §9), la reconciliación (`reconcile:all`, `reconcile:<id>`, §10), la programación de los schedulers (`schedules`) y las operaciones. Las claves de coordinación llevan el prefijo `infraward:workers:`.

### Líder

Lease en Redis (`infraward:workers:leader` = nombre de la réplica, 30 s, renovado cada 10 s; `WORKER_LEADER_ELIGIBLE=false` no se presenta, para los workers remotos). **Elegido entre los workers y no la API**: los intervalos son variables del worker, la API también puede tener réplicas y no hace trabajo de fondo, y así los despliegues no cambian. El líder:
- programa los **job schedulers** (reconciliación, re-evaluación de SBOMs, KEV/EPSS, métricas; un disparo por intervalo para todas las réplicas) y pide el recálculo de prioridades al relevar;
- es el **único oyente de los eventos** de todas las colas (`JobEventsListener`) que lleva a `job_runs` lo que hacen todas las réplicas; guarda en Redis el último evento leído de cada cola, así que el siguiente líder sigue donde lo dejó;
- **barre los huérfanos** cada minuto (y al relevar) y poda el historial y las notificaciones.

### Identidad de la réplica

`WORKER_NAME` o `worker-<n>`, el menor libre, reservado en Redis con un lease de 30 s que se renueva: una réplica que reinicia o se recrea con `--scale` recupera su número. Es el nombre del `Worker` de BullMQ (`processedBy`), la columna `worker` de la Actividad y el subdirectorio de trabajo. Cada réplica publica su ficha (máquina, colas, arranque) con la misma caducidad; la API la lee para `GET /jobs/workers`.

### Arranque y parada

- **Arranque** (`WorkerLifecycle`): **esquema al día** (`SchemaGate`: comprueba con `SELECT <columnas> … LIMIT 0` que existen las tablas y columnas de todas sus entidades y, si falta algo —la API aún no ha migrado, p. ej. con `pnpm dev` o al desplegar las dos imágenes a la vez— o la BD no responde, espera y lo dice en el log) → nombre → limpieza de lo que dejó a medias (su `WORKER_SCAN_DIR/<nombre>/` entero; de réplicas muertas y del formato anterior, lo viejo; claves SSH viejas del tmpfs) → workers de BullMQ ya con nombre y concurrencia (hasta aquí no toma ningún job) → ficha → candidatura a líder.
- **Contexto por job** (`AsyncLocalStorage`, `JobRunner`): señal de aborto, token, fencing token, generación de Trivy y recursos con caducidad (concesiones, locks, lectores), que se renuevan mientras corre y se sueltan al terminar. Los procesos hijos (`execFileRunner`, `spawnStreamer`) van en su propio grupo y se matan enteros (ssh, ansible-playbook, trivy, un `docker save` remoto) al abortarse el job o agotarse el tiempo.
- **Parada** (SIGTERM): deja el liderazgo, deja de pedir jobs y espera a los que están en curso como mucho `WORKER_SHUTDOWN_GRACE` (90 s, menor que el `stop_grace_period` de 120 s del compose); los que no terminen se abortan, **vuelven a la cola** retrasados 0 s sin gastar intento («Devuelto a la cola al parar worker-2») y sus directorios se borran. Al final suelta su nombre.
- **Réplica muerta** (SIGKILL, máquina caída): BullMQ devuelve su job a la cola por *stalled* (≤ 90 s), las concesiones y locks caducan, el líder lo anota («Vuelve a la cola: worker-2 dejó de responder») y otra réplica lo retoma; si BullMQ ya no lo tiene, el barrido lo cierra como perdido.

### Despliegue

`deploy/example/compose.yml`: `docker compose up -d --scale worker=3` (o `WORKER_REPLICAS`), `stop_grace_period: 120s` y el volumen `./data/worker` (caché de Trivy y escaneos) **compartido por todas**.

