import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  expandQuery,
  NGINX_ROUTES_SCRIPT,
  PRIVILEGED_QUERIES,
  PROCESS_PACKAGES_SCRIPT,
  SSHD_AUTH_SCRIPT,
  QUERY_REJECTED_EXIT,
  validateQuery,
  type PrivilegedQuery,
  type PrivilegedQueryName,
} from '@infraward/connectors';
import {
  ATTACKS,
  expectedCalls,
  HELPER_BINARIES,
  HELPER_REAL_TOOLS,
  NGINX_SECRET_CONFIG,
  NODE_ONLY_ATTACKS,
  PVE_FILES,
  SAMPLES,
} from '../../test/support/query-helper-cases.js';

/**
 * El ayudante de root del script de alta (sudoers v4) ejecutado de verdad con bash, con binarios
 * falsos que anotan su argv: hace exactamente lo que dice `PRIVILEGED_QUERIES` y rechaza (sin
 * ejecutar nada) cualquier otra cosa. Lo mismo, con sudo y sudo-rs reales, en la integración.
 */
const TEMPLATE = readFileSync(
  new URL('../../../../ansible/enroll/enroll.sh.tmpl', import.meta.url),
  'utf8',
);
describe('Ayudante de root (infraward-query)', () => {
  let dir: string;
  let helper: string;
  let log: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'infraward-query-'));
    const bin = join(dir, 'bin');
    const pve = join(dir, 'pve');
    log = join(dir, 'calls');
    mkdirSync(bin);
    // Binarios falsos: anotan su nombre y sus argumentos separados por NUL. nginx (y docker, por
    // `docker exec … nginx -T`) imprimen además la configuración de prueba si existe (sin cat:
    // el PATH solo tiene los falsos).
    for (const name of HELPER_BINARIES) {
      const path = join(bin, name);
      writeFileSync(
        path,
        `#!/bin/sh\nprintf '%s\\0' "${name}" "$@" > '${log}'\n[ -f '${dir}/nginx.conf' ] && while IFS= read -r l; do printf '%s\\n' "$l"; done < '${dir}/nginx.conf'\nexit 0\n`,
      );
      chmodSync(path, 0o755);
    }
    // Los scripts de nginx (v5) y de procesos (v6) usan las utilidades de verdad: corren en el
    // servidor.
    for (const real of HELPER_REAL_TOOLS) {
      const which = spawnSync('sh', ['-c', `command -v ${real}`], {
        encoding: 'utf8',
      }).stdout.trim();
      symlinkSync(which, join(bin, real));
    }
    for (const f of PVE_FILES) {
      mkdirSync(join(pve, f, '..'), { recursive: true });
      writeFileSync(join(pve, f), '');
    }
    const source = /^ {4}cat <<'HELPER'\n([\s\S]*?)\nHELPER$/m.exec(
      TEMPLATE,
    )?.[1];
    expect(source).toBeDefined();
    // Solo cambian el PATH y la raíz de /etc/pve; el resto es el ayudante tal cual.
    const path =
      'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
    expect(source).toContain(path);
    expect(source).toContain('\nPVE_DIR=/etc/pve\n');
    helper = join(dir, 'infraward-query');
    writeFileSync(
      helper,
      source!
        .replace(path, `export PATH=${bin}`)
        .replace('\nPVE_DIR=/etc/pve\n', `\nPVE_DIR=${pve}\n`),
    );
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  function call(args: string[]) {
    rmSync(log, { force: true });
    const r = spawnSync('bash', [helper, ...args], { encoding: 'utf8' });
    const argv = existsSync(log)
      ? readFileSync(log, 'utf8').split('\0').slice(0, -1)
      : null;
    return { code: r.status, stdout: r.stdout, stderr: r.stderr, argv };
  }

  it('cubre todas las consultas de PRIVILEGED_QUERIES', () => {
    expect(Object.keys(SAMPLES).sort()).toEqual(
      Object.keys(PRIVILEGED_QUERIES).sort(),
    );
  });

  it.each(
    Object.entries(SAMPLES).flatMap(([name, list]) =>
      list.map((args) => [name, args] as [PrivilegedQueryName, string[]]),
    ),
  )('%s %j: ejecuta exactamente el comando de expandQuery', (name, args) => {
    const query: PrivilegedQuery = { name, args };
    const r = call([name, ...args]);
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.argv).toEqual(expectedCalls(expandQuery(query)));
  });

  it.each([
    ['nginx-routes', []],
    ['docker-nginx-routes', ['d'.repeat(64)]],
  ])(
    '%s: solo salen nombres, listen y destinos; los secretos no salen del servidor',
    (name, args) => {
      writeFileSync(join(dir, 'nginx.conf'), NGINX_SECRET_CONFIG);
      try {
        const r = call([name, ...args]);
        expect(r.code, r.stderr).toBe(0);
        expect(r.stdout).not.toMatch(/centinela|Authorization|htpasswd|usuario|ssl_certificate|\$token/);
        expect(r.stdout.split('\n')).toEqual(
          expect.arrayContaining([
            'N app.example.com',
            'L 443 ssl default_server',
            'P proxy_pass http://127.0.0.1:8080',
            'M 10.0.0.5:8080',
            'V $server 192.168.1.20',
          ]),
        );
      } finally {
        rmSync(join(dir, 'nginx.conf'), { force: true });
      }
    },
  );

  it('nginx -T que falla: 3 y un mensaje sin la configuración', () => {
    writeFileSync(
      join(dir, 'bin', 'nginx'),
      `#!/bin/sh\necho 'nginx: [emerg] centinela-error' >&2\nexit 1\n`,
    );
    try {
      const r = call(['nginx-routes']);
      expect(r.code).toBe(3);
      expect(r.stdout).toBe('');
      expect(r.stderr).not.toContain('centinela');
    } finally {
      writeFileSync(
        join(dir, 'bin', 'nginx'),
        `#!/bin/sh\nprintf '%s\\0' "nginx" "$@" > '${log}'\n[ -f '${dir}/nginx.conf' ] && while IFS= read -r l; do printf '%s\\n' "$l"; done < '${dir}/nginx.conf'\nexit 0\n`,
      );
    }
  });

  it('lleva los scripts de la v5, la v6 y la v7 tal cual los de connectors', () => {
    const heredoc = (marker: string) =>
      new RegExp(`<<'${marker}' \\|\\| true\n([\\s\\S]*?)${marker}\n`).exec(
        TEMPLATE,
      )?.[1];
    expect(heredoc('NGINX')).toBe(NGINX_ROUTES_SCRIPT);
    expect(heredoc('PROCS')).toBe(PROCESS_PACKAGES_SCRIPT);
    expect(heredoc('SSHD')).toBe(SSHD_AUTH_SCRIPT);
  });

  it.each(ATTACKS)('rechaza %s (64, sin ejecutar nada)', (_name, args) => {
    const r = call(args);
    expect(r.code).toBe(QUERY_REJECTED_EXIT);
    expect(r.stderr).toMatch(/^infraward-query: rechazado: /);
    expect(r.argv).toBeNull();
  });

  it('la validación de TypeScript rechaza lo mismo (salvo lo que solo sabe el nodo)', () => {
    for (const [name, [query, ...args]] of ATTACKS) {
      if (NODE_ONLY_ATTACKS.has(name)) continue;
      expect(
        () => validateQuery({ name: query as PrivilegedQueryName, args }),
        name,
      ).toThrow();
    }
  });

  it('sin el binario, 127 con su nombre (Docker o Plesk pueden instalarse después)', () => {
    const r = spawnSync('bash', [helper, 'docker-ps'], {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
    });
    // El PATH del ayudante es fijo: no hereda el del llamante.
    expect(r.status).toBe(0);
    rmSync(join(dir, 'bin', 'docker'));
    const missing = call(['docker-ps']);
    expect(missing.code).toBe(127);
    expect(missing.stderr).toContain('infraward-query: falta docker');
  });
});
