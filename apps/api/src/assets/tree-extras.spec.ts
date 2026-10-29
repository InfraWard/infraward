import { SSH_CA_CONFIG_VERSION } from '@infraward/shared-types';
import { runtimeState, treeExtras, type TreeExtrasRow } from './tree-extras.js';

const row = (extra: Partial<TreeExtrasRow>): TreeExtrasRow => ({
  type: 'server',
  scan_enabled: true,
  connection_host: null,
  connection_port: null,
  default_ipv4: null,
  docker_state: null,
  docker_ports: null,
  proxmox_status: null,
  proxmox_interfaces: null,
  proxmox_net0: null,
  duplicate_of_id: null,
  machine_id_clone: null,
  certificate_not_after: null,
  registration_expires_at: null,
  dns_warning: null,
  ssh_auth: 'static_key',
  ssh_ca: null,
  sshd: null,
  sudoers_outdated: null,
  collection_warnings: null,
  ...extra,
});

describe('treeExtras', () => {
  it('dominios: caducidad del registro (RDAP); registros DNS: aviso de colgante', () => {
    expect(
      treeExtras(row({ type: 'domain', registration_expires_at: '2027-03-01T00:00:00Z' }))
        .expiresAt,
    ).toBe('2027-03-01T00:00:00.000Z');
    expect(
      treeExtras(row({ type: 'server', registration_expires_at: '2027-03-01T00:00:00Z' }))
        .expiresAt,
    ).toBeNull();
    expect(treeExtras(row({ type: 'dns_record', dns_warning: 'high' })).dnsWarning).toBe('high');
    expect(treeExtras(row({ type: 'dns_record', dns_warning: 'x' })).dnsWarning).toBeNull();
  });

  it('servidor: host de conexión, con el puerto solo si no es el 22', () => {
    expect(
      treeExtras(
        row({
          connection_host: '10.0.0.5',
          connection_port: 22,
          default_ipv4: '10.0.0.5',
        }),
      ),
    ).toEqual({
      address: '10.0.0.5',
      ips: ['10.0.0.5'],
      runtimeState: null,
      runtimeDetail: null,
      sudoersOutdated: false,
      collectionWarnings: 0,
      duplicateOf: null,
      machineIdClone: false,
      expiresAt: null,
      dnsWarning: null,
      sshCaOutdated: false,
      sshdRisk: null,
      scanDisabled: false,
    });
    expect(treeExtras(row({ scan_enabled: false })).scanDisabled).toBe(true);
    // sshd -T (v7): login de root por contraseña; un JSON extraño no avisa.
    const sshd = {
      permitRootLogin: 'yes',
      passwordAuthentication: true,
      kbdInteractiveAuthentication: false,
    };
    expect(treeExtras(row({ sshd })).sshdRisk).toBe('root-password');
    expect(
      treeExtras(row({ sshd: { ...sshd, permitRootLogin: 'prohibit-password' } })).sshdRisk,
    ).toBe('password');
    expect(treeExtras(row({ sshd: { permitRootLogin: 'yes' } })).sshdRisk).toBeNull();
    expect(
      treeExtras(row({ connection_host: '127.0.0.1', connection_port: 2222 }))
        .address,
    ).toBe('127.0.0.1:2222');
    // Tras un NAT: dos servidores con la misma conexión se distinguen por su IP.
    expect(
      treeExtras(
        row({
          connection_host: '127.0.0.1',
          connection_port: 2232,
          default_ipv4: '10.88.0.18',
        }),
      ).address,
    ).toBe('127.0.0.1:2232 · 10.88.0.18');
    expect(treeExtras(row({ default_ipv4: '10.0.0.6' })).address).toBe(
      '10.0.0.6',
    );
  });

  it('CT: IPv4 de una interfaz real (no docker0 ni loopback) o la fija de net0', () => {
    const interfaces = [
      { name: 'lo', ipv4: ['127.0.0.1/8'] },
      { name: 'docker0', ipv4: ['172.17.0.1/16'] },
      { name: 'eth0', ipv4: ['172.20.1.193/16'] },
    ];
    expect(
      treeExtras(
        row({
          type: 'lxc',
          proxmox_status: 'running',
          proxmox_interfaces: interfaces,
        }),
      ),
    ).toMatchObject({
      address: '172.20.1.193',
      runtimeState: 'running',
      runtimeDetail: 'running',
    });
    const stopped = treeExtras(
      row({
        type: 'lxc',
        proxmox_status: 'stopped',
        proxmox_net0: 'name=eth0,bridge=vmbr0,ip=192.168.1.5/24,type=veth',
      }),
    );
    expect(stopped).toMatchObject({
      address: '192.168.1.5',
      runtimeState: 'stopped',
      runtimeDetail: 'stopped',
    });
    expect(
      treeExtras(row({ type: 'lxc', proxmox_net0: 'ip=dhcp' })).address,
    ).toBeNull();
  });

  it('contenedor: puertos publicados una vez (IPv4 e IPv6) y luego los expuestos', () => {
    const ports = [
      { proto: 'tcp', hostIp: null, hostPort: null, containerPort: 9000 },
      { proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080, containerPort: 80 },
      { proto: 'tcp', hostIp: '::', hostPort: 8080, containerPort: 80 },
    ];
    expect(
      treeExtras(
        row({
          type: 'container',
          docker_state: 'running',
          docker_ports: ports,
        }),
      ),
    ).toMatchObject({
      address: '8080→80/tcp, 9000/tcp',
      runtimeState: 'running',
      runtimeDetail: 'running',
    });
    expect(
      treeExtras(row({ type: 'container', docker_ports: [] })).address,
    ).toBeNull();
  });

  it('imagen: sin dirección; datos corruptos no rompen', () => {
    expect(
      treeExtras(row({ type: 'image', default_ipv4: '1.2.3.4' })).address,
    ).toBeNull();
    expect(
      treeExtras(
        row({ type: 'container', docker_ports: 'x', docker_state: 42 }),
      ),
    ).toMatchObject({ address: null, runtimeState: null, runtimeDetail: null });
  });

  it('estado de ejecución: created/exited cuentan como parado', () => {
    expect(runtimeState('created')).toBe('stopped');
    expect(runtimeState('exited')).toBe('stopped');
    expect(runtimeState('paused')).toBe('paused');
    expect(runtimeState('restarting')).toBe('other');
  });

  it('avisos de la recolección: sudoers desactualizado y número de avisos parciales', () => {
    expect(
      treeExtras(row({ sudoers_outdated: true, collection_warnings: 3 })),
    ).toMatchObject({
      sudoersOutdated: true,
      collectionWarnings: 3,
    });
    // JSON libre: solo `true` y enteros positivos cuentan.
    expect(
      treeExtras(row({ sudoers_outdated: 'true', collection_warnings: 'x' })),
    ).toMatchObject({
      sudoersOutdated: false,
      collectionWarnings: 0,
    });
  });
});

describe('sshCaOutdated en el árbol', () => {
  const CA1 = 'SHA256:' + 'a'.repeat(43);
  const CA2 = 'SHA256:' + 'b'.repeat(43);
  const ca = (trusted: string[], version = SSH_CA_CONFIG_VERSION) =>
    row({ ssh_auth: 'ca_certificate', ssh_ca: { version, trusted } });

  it('al día si confía exactamente en las CA vigentes', () => {
    expect(treeExtras(ca([CA1]), [CA1]).sshCaOutdated).toBe(false);
    expect(treeExtras(ca([CA2, CA1]), [CA1, CA2]).sshCaOutdated).toBe(false);
  });

  it('desactualizado si falta la nueva, sigue la retirada o la versión es antigua', () => {
    expect(treeExtras(ca([CA1]), [CA1, CA2]).sshCaOutdated).toBe(true);
    expect(treeExtras(ca([CA1, CA2]), [CA2]).sshCaOutdated).toBe(true);
    expect(treeExtras(ca([CA1], 0), [CA1]).sshCaOutdated).toBe(true);
  });

  it('sin referencia, sin datos o con clave estática no avisa', () => {
    expect(treeExtras(ca([CA1]), []).sshCaOutdated).toBe(false);
    expect(
      treeExtras(row({ ssh_auth: 'ca_certificate', ssh_ca: null }), [CA1])
        .sshCaOutdated,
    ).toBe(false);
    expect(
      treeExtras(
        row({ ssh_auth: 'static_key', ssh_ca: { version: 1, trusted: [] } }),
        [CA1],
      ).sshCaOutdated,
    ).toBe(false);
  });
});
