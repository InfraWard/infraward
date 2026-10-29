import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { PROXY_SELF_HOST } from '@infraward/shared-types';
import { parseContainer } from '../docker/docker.js';
import {
  nginxImageKind,
  parseProxyLabels,
  proxyLabelPairs,
} from './labels.js';
import { NGINX_ROUTES_SCRIPT, parseNginxRoutes } from './nginx-filter.js';

const NOW = new Date('2026-10-15T10:00:00Z');

/** Configuración con secretos que el filtro no puede dejar salir. */
const CONFIG = `# configuration file /etc/nginx/nginx.conf:
user www-data;
http {
  upstream backend { server 10.0.0.5:8080 weight=2; server app:3000; }
  server {
    listen 443 ssl default_server; listen [::]:443 ssl;
    server_name App.Example.com www.example.com;
    ssl_certificate_key /etc/ssl/private/centinela.key;
    auth_basic_user_file /etc/nginx/centinela.htpasswd;
    location / {
      proxy_set_header Authorization "Basic centinela";
      proxy_pass http://user:centinela@127.0.0.1:8080;
    }
    location /api { proxy_pass http://backend; }
  }
  include /data/nginx/proxy_host/*.conf;
  server { listen 80; server_name static.example.com; root /var/www; }
}
stream { server { listen 2222; proxy_pass 10.0.0.9:22; } }
# configuration file /data/nginx/proxy_host/1.conf:
  server {
    set $forward_scheme http;
    set $server         "192.168.1.20";
    set $port           8096;
    set $secret centinela;
    listen 80;
    listen 443 ssl;
    server_name jelly.example.com;
    location / {
      include conf.d/include/proxy.conf;
    }
  }
# configuration file /etc/nginx/conf.d/include/proxy.conf:
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_pass       $forward_scheme://$server:$port$request_uri;
`;

const dir = mkdtempSync(join(tmpdir(), 'infraward-nginx-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** El filtro tal cual lo ejecuta el ayudante: `sh -c <filtro> sh <nginx falso> -T`. */
function filter(config: string, code = 0): ReturnType<typeof spawnSync> {
  writeFileSync(join(dir, 'nginx.conf'), config);
  const fake = join(dir, 'nginx');
  writeFileSync(
    fake,
    `#!/bin/sh\ncat '${dir}/nginx.conf'\necho 'nginx: the configuration file test is successful' >&2\nexit ${code}\n`,
  );
  chmodSync(fake, 0o755);
  return spawnSync('sh', ['-c', NGINX_ROUTES_SCRIPT, 'sh', fake, '-T'], {
    encoding: 'utf8',
  });
}

describe('filtro de nginx -T (en el servidor)', () => {
  it('solo deja salir nombres, listen y destinos', () => {
    const r = filter(CONFIG);
    expect(r.status).toBe(0);
    const out = String(r.stdout);
    expect(out).not.toMatch(
      /centinela|Authorization|htpasswd|ssl_certificate|user:|include|\$secret|www-data/,
    );
    expect(out.split('\n')).toEqual(
      expect.arrayContaining([
        'U backend',
        'M 10.0.0.5:8080',
        'S http',
        'L 443 ssl default_server',
        'N App.Example.com www.example.com',
        'P proxy_pass http://127.0.0.1:8080',
        'V $server 192.168.1.20',
        'S stream',
      ]),
    );
  });

  it('si nginx -T falla, código 3 sin la configuración', () => {
    const r = filter(CONFIG, 1);
    expect(r.status).toBe(3);
    expect(r.stdout).toBe('');
    expect(String(r.stderr)).not.toContain('centinela');
  });

  it('el filtro no lleva comillas simples dentro del awk ni sintaxis de Jinja', () => {
    const awk = NGINX_ROUTES_SCRIPT.split("awk '")[1].replace(/'\n$/, '');
    expect(awk).not.toContain("'");
    expect(NGINX_ROUTES_SCRIPT).not.toMatch(/\{\{|\{%|\{#|\$\{/);
  });
});

describe('parseNginxRoutes', () => {
  const facts = parseNginxRoutes(String(filter(CONFIG).stdout), 'npm', NOW);

  it('una ruta por location con sus destinos (upstreams y variables de NPM resueltos)', () => {
    expect(facts.readAt).toBe(NOW.toISOString());
    expect(facts.routes).toEqual([
      {
        source: 'npm',
        hosts: ['app.example.com', 'www.example.com'],
        listen: [443],
        isDefault: true,
        path: '/',
        upstreams: [{ scheme: 'http', host: '127.0.0.1', port: 8080 }],
      },
      {
        source: 'npm',
        hosts: ['app.example.com', 'www.example.com'],
        listen: [443],
        isDefault: true,
        path: '/api',
        upstreams: [
          { scheme: 'http', host: '10.0.0.5', port: 8080 },
          { scheme: 'http', host: 'app', port: 3000 },
        ],
      },
      {
        source: 'npm',
        hosts: ['static.example.com'],
        listen: [80],
        isDefault: false,
        path: null,
        upstreams: [],
      },
      {
        source: 'npm',
        hosts: [],
        listen: [2222],
        isDefault: false,
        path: null,
        upstreams: [{ scheme: 'tcp', host: '10.0.0.9', port: 22 }],
      },
      {
        source: 'npm',
        hosts: ['jelly.example.com'],
        listen: [80, 443],
        isDefault: false,
        path: null,
        upstreams: [{ scheme: 'http', host: '192.168.1.20', port: 8096 }],
      },
    ]);
  });

  it('NPM: `$forward_scheme://$server:$port` con las variables del server', () => {
    const out = parseNginxRoutes(
      [
        'S http',
        'V $forward_scheme http',
        'V $server 192.168.1.20',
        'V $port 8096',
        'L 443 ssl',
        'N jelly.example.com',
        '@ /',
        'P proxy_pass $forward_scheme://$server:$port',
        'Q',
        'E',
      ].join('\n'),
      'npm',
      NOW,
    );
    expect(out.routes[0].upstreams).toEqual([
      { scheme: 'http', host: '192.168.1.20', port: 8096 },
    ]);
  });
});

describe('etiquetas de Traefik y Caddy', () => {
  const pairs: [string, string][] = [
    ['traefik.enable', 'true'],
    ['traefik.http.routers.app.rule', 'Host(`app.example.com`) || Host(`www.example.com`) && PathPrefix(`/x`)'],
    ['traefik.http.routers.app.service', 'app-svc'],
    ['traefik.http.services.app-svc.loadbalancer.server.port', '3000'],
    ['traefik.http.middlewares.auth.basicauth.users', 'admin:centinela'],
    ['caddy', 'files.example.com, http://other.example.com'],
    ['caddy.reverse_proxy', '{{upstreams 8080}}'],
    ['caddy.basic_auth', 'centinela'],
    ['caddy_1', 'api.example.com'],
    ['caddy_1.reverse_proxy', 'backend:9000'],
  ];

  it('proxyLabelPairs descarta lo que no es de la lista blanca', () => {
    const kept = proxyLabelPairs(pairs);
    expect(JSON.stringify(kept)).not.toContain('centinela');
    expect(kept.map(([k]) => k)).toEqual([
      'traefik.enable',
      'traefik.http.routers.app.rule',
      'traefik.http.routers.app.service',
      'traefik.http.services.app-svc.loadbalancer.server.port',
      'caddy',
      'caddy.reverse_proxy',
      'caddy_1',
      'caddy_1.reverse_proxy',
    ]);
  });

  it('rutas de Traefik y caddy-docker-proxy', () => {
    expect(parseProxyLabels(proxyLabelPairs(pairs))).toEqual([
      {
        source: 'traefik',
        hosts: ['app.example.com', 'www.example.com'],
        listen: [],
        isDefault: false,
        path: '/x',
        upstreams: [{ scheme: 'http', host: PROXY_SELF_HOST, port: 3000 }],
      },
      {
        source: 'caddy',
        hosts: ['files.example.com', 'other.example.com'],
        listen: [],
        isDefault: false,
        path: null,
        upstreams: [{ scheme: 'http', host: PROXY_SELF_HOST, port: 8080 }],
      },
      {
        source: 'caddy',
        hosts: ['api.example.com'],
        listen: [],
        isDefault: false,
        path: null,
        upstreams: [{ scheme: 'http', host: 'backend', port: 9000 }],
      },
    ]);
  });

  it('traefik.enable=false: sin rutas de Traefik', () => {
    expect(
      parseProxyLabels([
        ['traefik.enable', 'false'],
        ['traefik.http.routers.a.rule', 'Host(`a.example.com`)'],
      ]),
    ).toEqual([]);
  });

  it('un contenedor con etiquetas: rutas en sus facts, sin ningún secreto', () => {
    const line = JSON.stringify({
      id: 'a'.repeat(64),
      name: '/app',
      image: 'ghcr.io/x/app:1',
      imageId: `sha256:${'b'.repeat(64)}`,
      state: 'running',
      ports: { '3000/tcp': null },
      composeProject: 'web',
      composeService: 'app',
      proxyLabels: [...pairs, null],
      mounts: [null],
      networks: [{ name: 'web_default', ipv4: '172.18.0.3', ipv6: '', aliases: ['app', 'abc123'] }, null],
    });
    const c = parseContainer(line)!;
    expect(JSON.stringify(c)).not.toContain('centinela');
    expect(c.composeService).toBe('app');
    expect(c.networks[0].aliases).toEqual(['app', 'abc123']);
    expect(c.proxyRoutes?.map((r) => r.source)).toEqual(['traefik', 'caddy', 'caddy']);
  });

  it('imágenes de nginx y NPM', () => {
    expect(nginxImageKind('nginx:1.27')).toBe('nginx');
    expect(nginxImageKind('docker.io/library/nginx@sha256:abc')).toBe('nginx');
    expect(nginxImageKind('jc21/nginx-proxy-manager:latest')).toBe('npm');
    expect(nginxImageKind('openresty/openresty:alpine')).toBe('nginx');
    expect(nginxImageKind('lscr.io/linuxserver/swag')).toBe('nginx');
    expect(nginxImageKind('traefik:v3')).toBeNull();
    expect(nginxImageKind('myorg/nginx-exporter')).toBeNull();
  });
});
