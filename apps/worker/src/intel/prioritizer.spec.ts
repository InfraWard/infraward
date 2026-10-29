import { describe, expect, it } from 'vitest';
import {
  prioritizeFinding,
  type AssetContext,
  type FindingRow,
} from './prioritizer.js';

const finding = (over: Partial<FindingRow> = {}): FindingRow => ({
  id: 'f1',
  vulnerabilityId: 'CVE-2026-0001',
  packageName: 'openssl',
  installedVersion: '3.0.11-1',
  fixedVersion: '3.0.11-2',
  fixStatus: 'fixed',
  severity: 'HIGH',
  cvss: 7.5,
  status: 'open',
  inKev: false,
  kevRansomware: false,
  epss: null,
  ...over,
});

// plesk-pruebas: Ubuntu 26.04 con el kernel 7.0.0-38-generic, nginx en 443 y sshd en 22.
const plesk: AssetContext = {
  id: 'a1',
  name: 'plesk-pruebas',
  type: 'server',
  kernel: '7.0.0-38-generic',
  processes: [
    {
      pid: 112914,
      name: 'nginx',
      unit: 'nginx.service',
      exePackage: 'nginx',
      libPackages: ['libssl3t64', 'libc6'],
    },
    {
      pid: 1092,
      name: 'mariadbd',
      unit: 'mariadb.service',
      exePackage: 'mariadb-server',
      libPackages: ['libssl3t64'],
    },
  ],
  ports: [
    {
      proto: 'tcp',
      address: '172.20.10.195',
      port: 443,
      process: 'nginx',
      pid: 112914,
    },
    {
      proto: 'tcp',
      address: '172.20.10.195',
      port: 80,
      process: 'nginx',
      pid: 112914,
    },
    {
      proto: 'tcp',
      address: '127.0.0.1',
      port: 3306,
      process: 'mariadbd',
      pid: 1092,
    },
  ],
  containers: [],
  publicDomains: null,
};

describe('prioritizeFinding', () => {
  it('kernel: solo los módulos del kernel en ejecución quedan en la vista', () => {
    const k = (packageName: string) =>
      prioritizeFinding(
        finding({
          packageName,
          installedVersion: '7.0.0-38.38',
          fixedVersion: null,
          fixStatus: 'affected',
        }),
        plesk,
      );
    expect(k('linux-modules-7.0.0-38-generic').noise).toBeNull();
    for (const name of [
      'linux-headers-7.0.0-38',
      'linux-tools-common',
      'linux-perf',
      'bpftool',
      'linux-libc-dev',
    ]) {
      const r = k(name);
      expect(r.noise, name).toBe('kernel_not_running');
      expect(r.reasons[0]).toEqual({ code: 'kernel_aux' });
    }
    expect(
      prioritizeFinding(
        finding({ packageName: 'linux-image-6.8.0-40-generic' }),
        plesk,
      ).reasons[0],
    ).toEqual({ code: 'kernel_other', running: '7.0.0-38-generic' });
  });

  it('will_not_fix y fix_deferred salen de la vista, salvo en KEV', () => {
    const wnf = prioritizeFinding(
      finding({ fixStatus: 'will_not_fix', fixedVersion: null }),
      plesk,
    );
    expect(wnf.noise).toBe('no_fix_planned');
    expect(wnf.reasons[0]).toEqual({
      code: 'no_fix_planned',
      fixStatus: 'will_not_fix',
    });
    expect(
      prioritizeFinding(finding({ fixStatus: 'fix_deferred' }), plesk).noise,
    ).toBe('no_fix_planned');
    expect(
      prioritizeFinding(
        finding({ fixStatus: 'affected', fixedVersion: null }),
        plesk,
      ).noise,
    ).toBeNull();
    expect(
      prioritizeFinding(
        finding({ fixStatus: 'will_not_fix', inKev: true }),
        plesk,
      ).noise,
    ).toBeNull();
  });

  it('una librería cargada por un servicio expuesto: expuesta en sus puertos', () => {
    const r = prioritizeFinding(finding({ packageName: 'libssl3t64' }), plesk);
    expect(r.reasons.slice(0, 3)).toEqual([
      { code: 'port', ports: [80, 443], process: 'nginx' },
      { code: 'service', process: 'nginx', unit: 'nginx.service', via: 'lib' },
      { code: 'fix' },
    ]);
    expect(r.priority).toBe(30 + 10 + 5 + 5);
  });

  it('un servicio que solo escucha en loopback: en marcha, pero no expuesto', () => {
    const r = prioritizeFinding(
      finding({ packageName: 'mariadb-server' }),
      plesk,
    );
    expect(r.reasons.map((x) => x.code)).toEqual(['service', 'fix', 'cvss']);
  });

  it('sin la v6: sin contexto de procesos y lo dice', () => {
    const r = prioritizeFinding(finding({ packageName: 'libssl3t64' }), {
      ...plesk,
      processes: null,
    });
    expect(r.reasons.map((x) => x.code)).toEqual([
      'fix',
      'cvss',
      'no_process_data',
    ]);
  });

  it('imagen: contenedores en marcha con puertos publicados (no los de 127.0.0.1)', () => {
    const image: AssetContext = {
      ...plesk,
      type: 'image',
      kernel: null,
      processes: null,
      ports: [],
      containers: [
        {
          status: 'active',
          state: 'running',
          ports: [
            {
              containerPort: 80,
              proto: 'tcp',
              hostIp: '0.0.0.0',
              hostPort: 8080,
            },
            {
              containerPort: 6379,
              proto: 'tcp',
              hostIp: '127.0.0.1',
              hostPort: 6379,
            },
            { containerPort: 9000, proto: 'tcp', hostIp: null, hostPort: null },
          ],
        },
        {
          status: 'active',
          state: 'exited',
          ports: [
            {
              containerPort: 80,
              proto: 'tcp',
              hostIp: '0.0.0.0',
              hostPort: 9090,
            },
          ],
        },
      ],
    };
    const r = prioritizeFinding(finding(), image);
    expect(r.reasons.slice(0, 2)).toEqual([
      { code: 'port', ports: [8080], process: null },
      { code: 'container', running: 1 },
    ]);
    // Sin contenedores activos: imagen sin uso, la mitad.
    const unused = prioritizeFinding(finding(), { ...image, containers: [] });
    expect(unused.priority).toBe(Math.round((30 + 5) * 0.5));
    expect(unused.reasons.at(-1)).toEqual({ code: 'unused_image' });
  });

  it('crítico en KEV y expuesto: aviso; sin exposición o corregido, no', () => {
    const kev = finding({
      packageName: 'nginx',
      severity: 'CRITICAL',
      cvss: 9.8,
      inKev: true,
      epss: 0.94,
    });
    const r = prioritizeFinding(kev, plesk);
    expect(r.kevExposed).toBe(true);
    expect(r.priority).toBe(100);
    expect(r.reasons.slice(0, 3).map((x) => x.code)).toEqual([
      'kev',
      'epss',
      'port',
    ]);
    expect(
      prioritizeFinding({ ...kev, packageName: 'mariadb-server' }, plesk)
        .kevExposed,
    ).toBe(false);
    expect(
      prioritizeFinding({ ...kev, severity: 'HIGH' }, plesk).kevExposed,
    ).toBe(false);
    // Un dominio público delante también es exposición.
    expect(
      prioritizeFinding(
        { ...kev, packageName: 'curl' },
        {
          ...plesk,
          publicDomains: { domains: ['ejemplo.com'], total: 1 },
        },
      ).kevExposed,
    ).toBe(true);
  });
});
