import type { CollectedPort, CollectedService } from '@infraward/shared-types';
import {
  certificateItems,
  collectionItems,
  collectionMeta,
  containerItems,
  containerMounts,
  dockerNetworkItems,
  pleskItems,
  volumeItems,
  factsPackages,
  listeningPorts,
  networkItems,
  runningServices,
  systemItems,
} from './facts-summary';

const labels = (items: { label: string; value: string }[]) =>
  Object.fromEntries(items.map((i) => [i.label, i.value]));

describe('resumen de los facts', () => {
  it('servidor recogido: SO, CPU, memoria, red y recolección', () => {
    const facts = {
      os: { family: 'Debian', distribution: 'Debian', version: '13.6', kernel: '6.1', arch: 'x86_64' },
      hardware: { processor: 'i7', vcpus: 8, memoryMb: 2048, vendor: 'QEMU', product: null },
      network: {
        hostname: 'pve',
        fqdn: null,
        defaultIpv4: '10.0.0.2',
        interfaces: [
          { name: 'lo', ipv4: ['127.0.0.1'] },
          { name: 'vmbr0', ipv4: ['10.0.0.2'] },
          { name: 'docker0', ipv4: ['172.17.0.1'] },
        ],
      },
      detected: { proxmox: 'pve-manager/9.0', plesk: null, docker: null },
      infraward: { via: 'pct', collectedAt: '2026-10-10T10:00:00Z', warnings: [] },
    };
    const system = labels(systemItems(facts));
    expect(system).toMatchObject({
      Sistema: 'Debian 13.6',
      Kernel: '6.1 · x86_64',
      CPU: '8 vCPU · i7',
      Memoria: '2.0 GiB',
      Fabricante: 'QEMU',
      'Software detectado': 'pve-manager/9.0',
    });
    expect(labels(networkItems(facts))).toEqual({
      Hostname: 'pve',
      'IPv4 por defecto': '10.0.0.2',
      Interfaces: 'vmbr0 10.0.0.2',
    });
    expect(labels(collectionItems(facts))).toMatchObject({ Vía: 'pct exec (desde el nodo)' });
  });

  it('CT de Proxmox: recursos asignados y nodo', () => {
    expect(
      labels(
        systemItems({
          proxmox: { kind: 'lxc', vmid: 101, node: 'pve', cpus: 2, maxMemBytes: 2 ** 31, maxDiskBytes: 8 * 2 ** 30, uptime: 90_000 },
        }),
      ),
    ).toEqual({
      Proxmox: 'CT 101 en pve',
      'Recursos asignados': '2 vCPU · 2.0 GiB RAM · 8.0 GiB disco',
      'En marcha desde hace': '1 d 1 h',
    });
  });

  it('contenedor: imagen, estado y puertos publicados una vez', () => {
    expect(
      labels(
        containerItems({
          docker: {
            image: 'nginx:1.25',
            state: 'running',
            ports: [
              { containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 },
              { containerPort: 80, proto: 'tcp', hostIp: '::', hostPort: 8080 },
              { containerPort: 443, proto: 'tcp', hostIp: null, hostPort: null },
            ],
          },
        }),
      ),
    ).toMatchObject({
      Imagen: 'nginx:1.25',
      'Estado en Docker': 'running',
      Puertos: '8080→80/tcp, 443/tcp',
    });
  });

  it('servicios: solo los relevantes en marcha, sin .service ni duplicados', () => {
    const svc = (name: string, state = 'running'): CollectedService => ({ name, state, status: null });
    expect(
      runningServices([
        svc('ssh'),
        svc('ssh.service'),
        svc('pveproxy.service'),
        svc('systemd-journald.service'),
        svc('getty@tty1.service'),
        svc('container-getty@1.service'),
        svc('user@999.service'),
        svc('pve-container@100.service'),
        svc('dbus'),
        svc('nginx.service', 'exited'),
      ]),
    ).toEqual({ relevant: ['pveproxy', 'ssh'], hidden: 6 });
  });

  it('puertos: IPv4 e IPv6 juntos, los públicos primero', () => {
    const port = (port: number, address: string, process: string, proto: 'tcp' | 'udp' = 'tcp'): CollectedPort => ({
      port,
      address,
      process,
      proto,
      pid: 1,
    });
    expect(
      listeningPorts([
        port(25, '127.0.0.1', 'master'),
        port(25, '::1', 'master'),
        port(22, '0.0.0.0', 'sshd'),
        port(22, '::', 'sshd'),
        port(8006, '*', 'pveproxy worker'),
      ]),
    ).toEqual([
      { port: 22, proto: 'tcp', process: 'sshd', addresses: ['0.0.0.0', '::'], exposure: 'all', localOnly: false },
      { port: 8006, proto: 'tcp', process: 'pveproxy worker', addresses: ['*'], exposure: 'all', localOnly: false },
      { port: 25, proto: 'tcp', process: 'master', addresses: ['127.0.0.1', '::1'], exposure: 'local', localOnly: true },
    ]);
  });

  it('puertos: todas las interfaces, después una IP concreta y al final los locales', () => {
    const port = (port: number, address: string): CollectedPort => ({
      port,
      address,
      process: 'p',
      proto: 'tcp',
      pid: 1,
    });
    const sorted = listeningPorts([
      port(5432, '127.0.0.1'),
      port(3306, '192.0.2.10'),
      port(9000, '::1'),
      port(443, '[::]'),
      port(80, '0.0.0.0'),
      // Local y en una IP a la vez: cuenta la más abierta.
      port(8080, '127.0.0.1'),
      port(8080, '10.0.0.5'),
    ]);
    expect(sorted.map((p) => [p.port, p.exposure])).toEqual([
      [80, 'all'],
      [443, 'all'],
      [3306, 'address'],
      [8080, 'address'],
      [5432, 'local'],
      [9000, 'local'],
    ]);
  });

  it('facts vacíos o con tipos inesperados no rompen', () => {
    expect(systemItems({})).toEqual([]);
    expect(systemItems({ os: 'linux', hardware: null, docker: [] })).toEqual([]);
    expect(networkItems({ network: { interfaces: 'x' } })).toEqual([]);
    expect(containerItems({ docker: 'x' })).toEqual([]);
    expect(factsPackages({ packages: 'x' })).toEqual([]);
    expect(factsPackages({ packages: [{ name: 'a' }, 3, null] })).toEqual([{ name: 'a' }]);
  });

  it('collectionMeta normaliza avisos y sudoers', () => {
    expect(collectionMeta({})).toBeNull();
    expect(
      collectionMeta({ infraward: { warnings: ['sin ss', 3], sudoersOutdated: 'sí' } }),
    ).toMatchObject({ warnings: ['sin ss'], sudoersOutdated: false });
  });

  it('volumen, red y montajes de Docker', () => {
    expect(
      labels(volumeItems({ docker: { name: 'datos', driver: 'local', scope: 'local', mountpoint: '/var/lib/docker/volumes/datos/_data' } })),
    ).toMatchObject({ Driver: 'local', 'Punto de montaje': '/var/lib/docker/volumes/datos/_data' });
    expect(
      labels(
        dockerNetworkItems({
          docker: { driver: 'bridge', internal: true, subnets: [{ subnet: '172.18.0.0/16', gateway: '172.18.0.1' }] },
        }),
      ),
    ).toMatchObject({ Subredes: '172.18.0.0/16 (gw 172.18.0.1)', Interna: 'sí (sin salida al exterior)' });
    expect(
      containerMounts({ docker: { mounts: [{ type: 'bind', name: null, source: '/srv', destination: '/srv', readOnly: true }, 'x'] } }),
    ).toEqual([{ type: 'bind', name: null, source: '/srv', destination: '/srv', readOnly: true }]);
    // Facts anteriores a la sesión 14: sin montajes.
    expect(containerMounts({ docker: { image: 'nginx' } })).toEqual([]);
  });

  it('Plesk y certificado: datos legibles, nunca más de lo que hay en los facts', () => {
    expect(
      labels(pleskItems({ plesk: { kind: 'subdomain', hostingType: 'vrt_hst', active: true, subscription: 'ejemplo.com', parent: 'ejemplo.com' } })),
    ).toEqual({
      Tipo: 'Subdominio',
      Hosting: 'Hosting web',
      'Estado en Plesk': 'Activo',
      Suscripción: 'ejemplo.com',
      'Dominio padre': 'ejemplo.com',
    });
    expect(
      labels(
        certificateItems({
          certificate: {
            subject: 'CN=ejemplo.com',
            subjectAltNames: ['DNS:ejemplo.com'],
            issuer: "O=Let's Encrypt, CN=R11",
            letsEncrypt: true,
            usedBy: ['ejemplo.com', 'otro.net'],
            repository: 'admin',
          },
        }),
      ),
    ).toMatchObject({ Tipo: "Let's Encrypt", 'Lo usan': 'ejemplo.com, otro.net', Repositorio: 'Del servidor' });
  });

  it('notas del sudoers en los metadatos', () => {
    expect(collectionMeta({ infraward: { sudoersNotes: ['Volúmenes…', 4] } })?.sudoersNotes).toEqual([
      'Volúmenes…',
    ]);
  });
});
