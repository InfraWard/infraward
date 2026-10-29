# syntax=docker/dockerfile:1
# Imágenes de InfraWard: un solo Dockerfile con un target por servicio.
#   docker build --target api    -t infraward-api .
#   docker build --target worker -t infraward-worker .
#   docker build --target web    -t infraward-web .
# Etiquetas OCI: cada target redefine todas las que traen las imágenes base (nginx-unprivileged y
# ubuntu traen title, description, version, created...; nginx además licenses, url, revision y
# maintainer), que si no se heredan. version, revision y created quedan vacías en un build local:
# el CI las rellena con --label (y source con la URL del proyecto en su registro).
# Las imágenes conservan la estructura del monorepo (/app/apps/<app>/dist, /app/ansible), así que
# las rutas por defecto de la API (plantilla de alta) y del worker (playbooks) funcionan sin
# configurar ENROLL_SCRIPT_TEMPLATE ni ANSIBLE_DIR.

ARG NODE_VERSION=24
# Debian 13: Python 3.13, que ansible-core >= 2.20 exige en el controlador.
ARG NODE_IMAGE=docker.io/library/node:${NODE_VERSION}-trixie-slim
# Base del worker: Ubuntu 26.04 trae el cliente OpenSSH con el arreglo de CVE-2026-60002, que
# Debian 13 aún no tiene (el worker y el gateway entran por SSH en todos los servidores). Node sale
# de NODE_IMAGE.
ARG WORKER_BASE_IMAGE=docker.io/library/ubuntu:26.04
ARG NGINX_IMAGE=docker.io/nginxinc/nginx-unprivileged:1.31-alpine3.24
ARG TRIVY_IMAGE=docker.io/aquasec/trivy:0.76.1

FROM ${TRIVY_IMAGE} AS trivy

# --- Base: Node con pnpm (la versión la fija packageManager) ---------------------------------
FROM ${NODE_IMAGE} AS base
ENV PNPM_HOME=/pnpm \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
WORKDIR /app

# --- Compilación de todo el monorepo ---------------------------------------------------------
FROM base AS build
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
COPY packages/shared-types/package.json packages/shared-types/
COPY packages/domain/package.json packages/domain/
COPY packages/secrets/package.json packages/secrets/
COPY packages/connectors/package.json packages/connectors/
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --frozen-lockfile
COPY . .
RUN pnpm -r build

# --- Dependencias de producción de cada app (sin devDependencies) ----------------------------
FROM base AS prod-deps
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY packages/shared-types/package.json packages/shared-types/
COPY packages/domain/package.json packages/domain/
COPY packages/secrets/package.json packages/secrets/
COPY packages/connectors/package.json packages/connectors/
# Los paquetes de packages/ declaran typeorm y Nest como peer (y dev) dependencies: con --prod no
# se instalan junto a ellos y Node los busca desde su ruta real (/app/packages/<p>). Con el
# hoisting (--shamefully-hoist) quedan también en /app/node_modules, que está en esa búsqueda.

FROM prod-deps AS api-deps
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --prod --frozen-lockfile --shamefully-hoist --filter "@infraward/api..."

FROM prod-deps AS worker-deps
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --prod --frozen-lockfile --shamefully-hoist --filter "@infraward/worker..."

# --- API ---------------------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS api
# Los arreglos de Debian publicados después de la imagen base. npm y corepack no se usan en
# ejecución (solo `node`): fuera, con las dependencias que traen.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
ENV NODE_ENV=production \
    PORT=3000
WORKDIR /app
COPY --from=api-deps --chown=root:root /app ./
COPY --from=build /app/packages/shared-types/dist packages/shared-types/dist
COPY --from=build /app/packages/domain/dist packages/domain/dist
COPY --from=build /app/packages/secrets/dist packages/secrets/dist
COPY --from=build /app/packages/connectors/dist packages/connectors/dist
COPY --from=build /app/apps/api/dist apps/api/dist
COPY ansible/enroll ansible/enroll
USER node
WORKDIR /app/apps/api
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
# Al final de la etapa (cambiarlas no invalida la caché de lo anterior); ver la cabecera.
LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.url="https://github.com/InfraWard/infraward" \
      org.opencontainers.image.source="https://github.com/InfraWard/infraward" \
      org.opencontainers.image.vendor="InfraWard" \
      org.opencontainers.image.title="infraward-api" \
      org.opencontainers.image.description="InfraWard API: REST (NestJS), autenticación y alta de servidores; aplica las migraciones al arrancar" \
      org.opencontainers.image.version="" \
      org.opencontainers.image.revision="" \
      org.opencontainers.image.created=""
# Aplica las migraciones pendientes al arrancar.
CMD ["node", "dist/main.js"]

# --- Worker ------------------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS node-runtime

FROM ${WORKER_BASE_IMAGE} AS worker
ARG ANSIBLE_CORE_VERSION=2.21.5
# Solo el binario de Node (sin npm ni corepack). El mismo usuario «node» con uid/gid 1000 que las
# imágenes de Node (data/worker es de 1000:1000); la de Ubuntu trae un usuario «ubuntu» con ese uid.
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
RUN (userdel --remove ubuntu 2>/dev/null || true) && \
    groupadd --gid 1000 node && \
    useradd --uid 1000 --gid node --create-home --shell /bin/sh node
# ssh/ssh-keyscan para conectar con los servidores; python3 + ansible-core para la recolección.
# /usr/bin/pebble: binario de Go que trae la imagen de Ubuntu sin usarse (Trivy marca su stdlib de Go).
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends openssh-client python3 python3-venv ca-certificates && \
    python3 -m venv /opt/ansible && \
    /opt/ansible/bin/pip install --no-cache-dir "ansible-core==${ANSIBLE_CORE_VERSION}" && \
    apt-get purge -y python3-venv && apt-get autoremove -y && \
    rm -f /usr/bin/pebble && \
    rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
ENV NODE_ENV=production \
    PATH=/opt/ansible/bin:$PATH \
    # Caché de Trivy (~3 GB) y directorio de trabajo de los escaneos: en un volumen.
    TRIVY_CACHE_DIR=/var/lib/infraward/trivy \
    WORKER_SCAN_DIR=/var/lib/infraward/scan
WORKDIR /app
COPY --from=worker-deps --chown=root:root /app ./
COPY --from=build /app/packages/shared-types/dist packages/shared-types/dist
COPY --from=build /app/packages/domain/dist packages/domain/dist
COPY --from=build /app/packages/secrets/dist packages/secrets/dist
COPY --from=build /app/packages/connectors/dist packages/connectors/dist
COPY --from=build /app/apps/worker/dist apps/worker/dist
COPY ansible/collect ansible/collect
RUN mkdir -p /var/lib/infraward && chown node:node /var/lib/infraward
USER node
VOLUME ["/var/lib/infraward"]
WORKDIR /app/apps/worker
# Al final de la etapa (cambiarlas no invalida la caché de lo anterior); ver la cabecera.
LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.url="https://github.com/InfraWard/infraward" \
      org.opencontainers.image.source="https://github.com/InfraWard/infraward" \
      org.opencontainers.image.vendor="InfraWard" \
      org.opencontainers.image.title="infraward-worker" \
      org.opencontainers.image.description="InfraWard worker: recolección con Ansible, descubrimiento, escaneos con Trivy y reconciliación; también el gateway de la terminal (modo gateway)" \
      org.opencontainers.image.version="" \
      org.opencontainers.image.revision="" \
      org.opencontainers.image.created=""
CMD ["node", "dist/main.js"]

# --- Web: estáticos de Angular servidos por nginx, con /api/ hacia la API ------------------------
FROM ${NGINX_IMAGE} AS web
# Los arreglos de Alpine publicados después de la imagen base.
USER root
RUN apk upgrade --no-cache
USER 101
# Destinos de /api/ y /gateway/ (sin barra final); envsubst los sustituye al arrancar. El
# resolver de /gateway/ sale de /etc/resolv.conf (NGINX_LOCAL_RESOLVERS).
ENV API_UPSTREAM=http://api:3000
ENV GATEWAY_UPSTREAM=http://gateway:3010
ENV NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1
COPY apps/web/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/apps/web/dist/web/browser /usr/share/nginx/html
EXPOSE 8080
# Al final de la etapa (cambiarlas no invalida la caché de lo anterior); ver la cabecera.
LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.url="https://github.com/InfraWard/infraward" \
      org.opencontainers.image.source="https://github.com/InfraWard/infraward" \
      org.opencontainers.image.vendor="InfraWard" \
      org.opencontainers.image.title="infraward-web" \
      org.opencontainers.image.description="InfraWard web: interfaz Angular servida por nginx, con /api/ hacia la API" \
      org.opencontainers.image.version="" \
      org.opencontainers.image.revision="" \
      org.opencontainers.image.created="" \
      maintainer="InfraWard"
