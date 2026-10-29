import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  parseProcessPackages,
  PROCESS_PACKAGES_SCRIPT,
} from './process-packages.js';

const dir = mkdtempSync(join(tmpdir(), 'infraward-procs-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const LIBSSL = '/usr/lib/x86_64-linux-gnu/libssl.so.3';
const LIBC = '/usr/lib/x86_64-linux-gnu/libc.so.6';

/** Un /proc falso: ejecutable, nombre, cgroup, librerías y un entorno con un centinela. */
function proc(
  pid: number,
  p: { exe?: string; comm: string; cgroup: string; maps?: string[] },
) {
  const d = join(dir, 'proc', String(pid));
  mkdirSync(d, { recursive: true });
  if (p.exe) symlinkSync(p.exe, join(d, 'exe'));
  writeFileSync(join(d, 'comm'), `${p.comm}\n`);
  writeFileSync(join(d, 'cgroup'), `${p.cgroup}\n`);
  writeFileSync(
    join(d, 'maps'),
    (p.maps ?? [])
      .map((m) => `7f0000000000-7f0000001000 r-xp 00000000 08:01 1234    ${m}`)
      .join('\n') + '\n',
  );
  writeFileSync(join(d, 'environ'), 'PASSWORD=centinela-entorno\0');
  writeFileSync(join(d, 'cmdline'), 'nginx\0-g\0centinela-cmdline\0');
}

function setup() {
  proc(100, {
    exe: '/usr/sbin/nginx',
    comm: 'nginx',
    cgroup: '0::/system.slice/nginx.service',
    maps: [LIBSSL, LIBC, '/usr/sbin/nginx', '[heap]', '/memfd:x (deleted)'],
  });
  proc(200, {
    exe: '/usr/sbin/sshd (deleted)',
    comm: 'sshd',
    cgroup: '0::/system.slice/ssh.service',
    maps: [LIBC],
  });
  // Un proceso de un contenedor: su ejecutable no es del servidor.
  proc(300, {
    exe: '/usr/sbin/nginx',
    comm: 'nginx',
    cgroup: '0::/system.slice/docker-abc.scope',
  });
  // Un hilo del kernel: sin ejecutable.
  proc(400, { comm: 'kworker', cgroup: '0::/' });
  // Un servicio que no escucha (lo da su cgroup).
  proc(500, {
    exe: '/usr/sbin/cron',
    comm: 'cron',
    cgroup: '0::/system.slice/cron.service',
  });
  const svc = join(dir, 'cgroup', 'system.slice', 'cron.service');
  mkdirSync(svc, { recursive: true });
  writeFileSync(join(svc, 'cgroup.procs'), '500\n501\n');

  const bin = join(dir, 'bin');
  mkdirSync(bin);
  const fake = (name: string, body: string) => {
    writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  };
  fake(
    'ss',
    `echo 'tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=100,fd=6),("nginx",pid=100,fd=7))'
echo 'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=200,fd=3))'
echo 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=300,fd=3))'
echo 'tcp LISTEN 0 128 0.0.0.0:9 0.0.0.0:* users:(("kworker",pid=400,fd=3))'`,
  );
  // dpkg con usrmerge: libssl registrada en /lib, el resto en /usr; una desviación; lo que no
  // es de nadie, a stderr.
  fake(
    'dpkg',
    `shift
for p in "$@"; do
  case $p in
    /usr/sbin/nginx) echo "nginx-core: $p" ;;
    /lib/x86_64-linux-gnu/libssl.so.3) echo "diversion by foo from: $p"; echo "libssl3t64:amd64, otro: $p" ;;
    ${LIBC}) echo "libc6:amd64: $p" ;;
    /usr/sbin/sshd) echo "openssh-server: $p" ;;
    /usr/sbin/cron) echo "cron: $p" ;;
    *) echo "dpkg-query: no path found matching pattern $p" >&2 ;;
  esac
done
exit 1`,
  );
  return bin;
}

function run(bin: string) {
  return spawnSync(
    'sh',
    [
      '-c',
      PROCESS_PACKAGES_SCRIPT,
      'sh',
      join(dir, 'proc'),
      join(dir, 'cgroup'),
    ],
    { encoding: 'utf8', env: { PATH: `${bin}:${process.env.PATH}` } },
  );
}

describe('process-packages (en el servidor)', () => {
  const bin = setup();
  const r = run(bin);

  it('ejecutable y librerías de cada proceso con su paquete', () => {
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout.split('\n').filter(Boolean).sort()).toEqual(
      [
        'P\t100\tnginx\tnginx.service\tnginx-core\tlibc6,libssl3t64',
        'P\t200\tsshd\tssh.service\topenssh-server\tlibc6',
        'P\t500\tcron\tcron.service\tcron\t',
      ].sort(),
    );
  });

  it('nunca saca rutas, entorno ni línea de órdenes', () => {
    expect(r.stdout).not.toMatch(/centinela|\/usr|\/lib|docker-abc|PASSWORD/);
  });

  it('sin comillas simples dentro de los awk ni sintaxis de Jinja o plantillas', () => {
    expect(PROCESS_PACKAGES_SCRIPT).not.toMatch(/\{\{|\{%|\{#|\$\{/);
    for (const awk of PROCESS_PACKAGES_SCRIPT.split(
      /awk (?:-v p="\$pid" |-F '\\t' )?'/,
    ).slice(1))
      expect(awk.split("'")[0]).not.toContain('\\x27');
  });

  it('parseProcessPackages', () => {
    expect(parseProcessPackages(r.stdout)).toEqual(
      expect.arrayContaining([
        {
          pid: 100,
          name: 'nginx',
          unit: 'nginx.service',
          exePackage: 'nginx-core',
          libPackages: ['libc6', 'libssl3t64'],
        },
        {
          pid: 500,
          name: 'cron',
          unit: 'cron.service',
          exePackage: 'cron',
          libPackages: [],
        },
      ]),
    );
    expect(
      parseProcessPackages(
        'P\t0\tx\t\t\t\nP\t7\tbad name\t\t$(id)\ta,a,b;c\nbasura\nP\t7\tdup\t\t\t',
      ),
    ).toEqual([
      { pid: 7, name: '', unit: null, exePackage: null, libPackages: ['a'] },
    ]);
  });
});
