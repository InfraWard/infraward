import { readFileSync } from 'node:fs';
import {
  checkSudoers,
  detectRoles,
  mergeRoles,
  normalizeCollection,
  parseDmidecodeSystem,
  parseNetstat,
  parseProcNet,
  parseSs,
  type RawCollection,
  parseSshCaKeys,
} from './normalize.js';
import {
  generateSshKeyPair,
  sshPublicKeyFingerprint,
} from '@infraward/secrets';

const NOW = new Date('2026-10-09T12:00:00Z');

/** Salida real de `collect.yml` contra un Debian 13 (recortada; ver fixtures/). */
function debian(): RawCollection {
  return JSON.parse(
    readFileSync(new URL('./fixtures/debian.json', import.meta.url), 'utf8'),
  ) as RawCollection;
}

function withSudo(
  raw: RawCollection,
  results: Record<string, { rc: number; stdout?: string; stderr?: string }>,
): RawCollection {
  const which = new Set(raw.which.map((l) => l.split('=')[0]));
  for (const key of Object.keys(results)) which.add(key);
  return {
    ...raw,
    which: [...which].map((k) => `${k}=/usr/bin/${k}`),
    sudo: [
      ...raw.sudo.filter((r) => !(r.item.key in results)),
      ...Object.entries(results).map(([key, r]) => ({ item: { key }, ...r })),
    ],
  };
}

describe('normalizeCollection', () => {
  it('normaliza un Debian real', () => {
    const facts = normalizeCollection(debian(), NOW);
    expect(facts.machineId).toBe('eb57e19d4b83a685907fc4121c8af3a3');
    expect(facts.os).toEqual({
      family: 'Debian',
      distribution: 'Debian',
      version: '13.7',
      kernel: '7.1.10-200.fc44.aarch64',
      arch: 'aarch64',
    });
    expect(facts.hardware).toMatchObject({
      vendor: 'Libkrun',
      uuid: null, // «NA» sin root y dmidecode sin DMI
      cpus: 4,
      cores: 4,
      vcpus: 4,
      memoryMb: 3608,
    });
    expect(facts.network.defaultIpv4).toBe('10.88.0.3');
    expect(facts.network.interfaces).toEqual([
      {
        name: 'eth0',
        mac: 'f2:dd:9e:cb:d9:97',
        active: true,
        ipv4: ['10.88.0.3/16'],
        ipv6: ['fe80::f0dd:9eff:fecb:d997/64'],
      },
    ]);
    expect(facts.mounts).toEqual([
      {
        mount: '/',
        device: '/dev/vda1',
        fstype: 'ext4',
        sizeBytes: 21474836480,
        availableBytes: 10737418240,
      },
    ]);
    // dpkg-query como alternativa a package_facts; `rc` (desinstalado) fuera.
    expect(facts.packages.map((p) => p.name)).toEqual([
      'adduser',
      'apt',
      'base-files',
    ]);
    expect(facts.packages[1]).toEqual({
      name: 'apt',
      version: '3.0.3',
      arch: 'arm64',
      manager: 'dpkg',
    });
    expect(facts.services).toEqual([
      { name: 'cron.service', state: 'stopped', status: 'disabled' },
      { name: 'ssh.service', state: 'running', status: 'enabled' },
    ]);
    expect(facts.ports).toEqual([
      { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd', pid: 1 },
      { proto: 'tcp', address: '::', port: 22, process: 'sshd', pid: 1 },
    ]);
    expect(facts.detected).toEqual({
      proxmox: null,
      plesk: null,
      docker: null,
    });
    expect(facts.infraward).toEqual({
      collectedAt: NOW.toISOString(),
      via: 'ssh',
      sudoersVersion: 4,
      sudoersOutdated: false,
      sshCa: null,
      warnings: [],
    });
    expect(detectRoles(facts)).toEqual([]);
  });

  it('detecta Proxmox, Plesk y Docker', () => {
    const raw = withSudo(debian(), {
      pveversion: {
        rc: 0,
        stdout: 'pve-manager/9.0.3/abcdef (running kernel: 6.14)',
      },
      plesk: {
        rc: 0,
        stdout:
          'Product version: Plesk Obsidian 18.0.70\nOS version: Debian 12',
      },
      docker: { rc: 0, stdout: '28.3.1' },
    });
    const facts = normalizeCollection(raw, NOW);
    expect(facts.detected).toEqual({
      proxmox: 'pve-manager/9.0.3/abcdef (running kernel: 6.14)',
      plesk: 'Product version: Plesk Obsidian 18.0.70',
      docker: '28.3.1',
    });
    expect(detectRoles(facts)).toEqual([
      'proxmox-node',
      'plesk',
      'docker-host',
    ]);
    expect(facts.infraward.warnings).toEqual([]);
  });

  it('sudo denegado: recolección parcial con avisos, sin fallar', () => {
    const denied = { rc: 1, stderr: 'sudo: a password is required' };
    const raw = {
      ...withSudo(debian(), { pveversion: denied, ss: denied, docker: denied }),
      sudoersVersion: '',
    };
    const facts = normalizeCollection(raw, NOW);
    // pveversion existe: es un nodo Proxmox aunque no se pueda leer la versión.
    expect(facts.detected.proxmox).toBe('desconocida');
    expect(facts.detected.docker).toBeNull();
    expect(facts.ports).toEqual([]);
    expect(facts.infraward.sudoersVersion).toBeNull();
    expect(facts.infraward.warnings).toEqual([
      "sudo denegado para 'pveversion': alta manual o sudoers desactualizado",
      "sudo denegado para 'docker': alta manual o sudoers desactualizado",
      "sudo denegado para 'ss': alta manual o sudoers desactualizado",
      'docker está instalado pero el demonio no responde',
      'sin sudoers de InfraWard (alta manual): la recolección es parcial',
    ]);
    expect(detectRoles(facts)).toEqual(['proxmox-node']);
  });

  it('sudoers v4: al día con cualquier rol (la v5, la v6 y la v7 son solo notas)', () => {
    const facts = normalizeCollection(
      { ...debian(), sudoersVersion: '4\n' },
      NOW,
    );
    checkSudoers(facts, ['proxmox-node', 'docker-host', 'plesk']);
    expect(facts.infraward).toMatchObject({
      sudoersOutdated: false,
      sudoersNotes: [
        expect.stringContaining('requiere sudoers v5'),
        expect.stringContaining('requiere sudoers v6'),
        expect.stringContaining('requiere sudoers v7'),
      ],
      warnings: [],
    });
  });

  it('sudoers v5: rutas del nginx del sistema, filtradas en el servidor', () => {
    const raw = debian();
    raw.which = [...raw.which, 'nginx=/usr/sbin/nginx'];
    raw.sudo = [
      ...raw.sudo,
      {
        item: { key: 'nginx' },
        rc: 0,
        stdout: 'S http\nL 443 ssl\nN app.example.com\nP proxy_pass http://127.0.0.1:8080\nE\n',
        stderr: '',
      },
    ];
    const facts = normalizeCollection({ ...raw, sudoersVersion: '7\n' }, NOW);
    checkSudoers(facts, []);
    expect(facts.infraward.sudoersNotes).toEqual([]);
    expect(facts.infraward.warnings).toEqual([]);
    expect(facts.proxy).toEqual({
      source: 'nginx',
      readAt: NOW.toISOString(),
      routes: [
        {
          source: 'nginx',
          hosts: ['app.example.com'],
          listen: [443],
          isDefault: false,
          path: null,
          upstreams: [{ scheme: 'http', host: '127.0.0.1', port: 8080 }],
        },
      ],
    });
  });

  it('sudoers v6: paquetes de los procesos, calculados en el servidor', () => {
    const raw = debian();
    raw.sudo = [
      ...raw.sudo,
      {
        item: { key: 'processes' },
        rc: 0,
        stdout:
          'P\t812\tsshd\tssh.service\topenssh-server\tlibssl3t64,libc6\nP\t90\tcron\tcron.service\tcron\t\n',
        stderr: '',
      },
    ];
    const facts = normalizeCollection({ ...raw, sudoersVersion: '6\n' }, NOW);
    expect(facts.processes).toEqual([
      {
        pid: 812,
        name: 'sshd',
        unit: 'ssh.service',
        exePackage: 'openssh-server',
        libPackages: ['libssl3t64', 'libc6'],
      },
      { pid: 90, name: 'cron', unit: 'cron.service', exePackage: 'cron', libPackages: [] },
    ]);
    expect(facts.infraward.warnings).toEqual([]);
  });

  it('procesos denegados (sudoers v5): null, sin recolección parcial y con la nota', () => {
    const raw = debian();
    raw.sudo = [
      ...raw.sudo,
      { item: { key: 'processes' }, rc: 64, stdout: '', stderr: 'infraward-query: rechazado: consulta desconocida' },
    ];
    const facts = normalizeCollection({ ...raw, sudoersVersion: '5\n' }, NOW);
    checkSudoers(facts, []);
    expect(facts.processes).toBeNull();
    expect(facts.infraward.warnings).toEqual([]);
    expect(facts.infraward.sudoersNotes).toEqual([
      expect.stringContaining('requiere sudoers v6'),
      expect.stringContaining('requiere sudoers v7'),
    ]);
  });

  it('sudoers v7: autenticación de sshd, solo las tres opciones', () => {
    const raw = debian();
    raw.sudo = [
      ...raw.sudo,
      {
        item: { key: 'sshd' },
        rc: 0,
        stdout:
          'permitrootlogin\tyes\npasswordauthentication\tyes\nkbdinteractiveauthentication\tno\n',
        stderr: '',
      },
    ];
    const facts = normalizeCollection({ ...raw, sudoersVersion: '7\n' }, NOW);
    checkSudoers(facts, []);
    expect(facts.sshd).toEqual({
      permitRootLogin: 'yes',
      passwordAuthentication: true,
      kbdInteractiveAuthentication: false,
    });
    expect(facts.infraward.warnings).toEqual([]);
    expect(facts.infraward.sudoersNotes).toEqual([]);
  });

  it('sshd denegado (sudoers v6) o sin sshd: null, sin recolección parcial y con la nota', () => {
    const raw = debian();
    raw.sudo = [
      ...raw.sudo,
      { item: { key: 'sshd' }, rc: 64, stdout: '', stderr: 'infraward-query: rechazado: consulta desconocida' },
    ];
    const facts = normalizeCollection({ ...raw, sudoersVersion: '6\n' }, NOW);
    checkSudoers(facts, []);
    expect(facts.sshd).toBeNull();
    expect(facts.infraward.warnings).toEqual([]);
    expect(facts.infraward.sudoersNotes).toEqual([
      expect.stringContaining('requiere sudoers v7'),
    ]);
    raw.sudo[raw.sudo.length - 1] = { item: { key: 'sshd' }, rc: 3, stdout: '', stderr: '' };
    expect(normalizeCollection({ ...raw, sudoersVersion: '7\n' }, NOW).sshd).toBeNull();
  });

  it('nginx denegado (sudoers v4): sin rutas y sin recolección parcial', () => {
    const raw = debian();
    raw.sudo = [
      ...raw.sudo,
      { item: { key: 'nginx' }, rc: 64, stdout: '', stderr: 'infraward-query: rechazado: consulta desconocida' },
    ];
    const facts = normalizeCollection({ ...raw, sudoersVersion: '4\n' }, NOW);
    expect(facts.proxy).toBeNull();
    expect(facts.infraward.warnings).toEqual([]);
  });

  it('sudoers v1–v3 (sin el ayudante de root): desactualizado en cualquier servidor, sin repetir el aviso', () => {
    for (const v of ['1', '2', '3']) {
      const facts = normalizeCollection(
        { ...debian(), sudoersVersion: `${v}\n` },
        NOW,
      );
      expect(facts.infraward.sudoersOutdated).toBe(false);
      checkSudoers(facts, []);
      checkSudoers(facts, []);
      expect(facts.infraward.sudoersOutdated).toBe(true);
      expect(facts.infraward.warnings).toEqual([
        `sudoers desactualizado (v${v}, hace falta v4): genera un comando de actualización`,
      ]);
    }
  });

  it('CT por pct exec o alta manual: nunca desactualizado', () => {
    const pct = normalizeCollection(
      { ...debian(), sudoersVersion: '1\n', via: 'pct' },
      NOW,
    );
    checkSudoers(pct, ['docker-host']);
    expect(pct.infraward.sudoersOutdated).toBe(false);
    const manual = normalizeCollection(
      { ...debian(), sudoersVersion: '' },
      NOW,
    );
    checkSudoers(manual, ['docker-host']);
    expect(manual.infraward.sudoersOutdated).toBe(false);
  });

  it('CT recogido con pct exec: sin avisos de sudoers (no tiene) y via pct', () => {
    const facts = normalizeCollection(
      { ...debian(), sudoersVersion: '', via: 'pct' },
      NOW,
    );
    expect(facts.infraward).toMatchObject({
      via: 'pct',
      sudoersVersion: null,
      sudoersOutdated: false,
      warnings: [],
    });
  });

  it('sin paquetes ni servicios: listas vacías y avisos', () => {
    const facts = normalizeCollection(
      { ...debian(), nativePackages: null, services: null },
      NOW,
    );
    expect(facts.packages).toEqual([]);
    expect(facts.services).toEqual([]);
    expect(facts.infraward.warnings).toEqual([
      expect.stringMatching(
        /^no se pudo obtener la lista de paquetes: Could not detect/,
      ),
      'no se pudo obtener la lista de servicios (¿sin systemd?)',
    ]);
  });

  it('package_facts (rpm con epoch y release) tiene prioridad sobre el gestor nativo', () => {
    const facts = normalizeCollection(
      {
        ...debian(),
        packages: {
          openssl: [
            {
              name: 'openssl',
              version: '3.2.2',
              release: '5.el10',
              epoch: 1,
              arch: 'x86_64',
              source: 'rpm',
            },
          ],
          bash: [
            {
              name: 'bash',
              version: '5.2.26',
              release: '6.el10',
              epoch: null,
              arch: 'x86_64',
              source: 'rpm',
            },
          ],
        },
      },
      NOW,
    );
    expect(facts.packages).toEqual([
      {
        name: 'bash',
        version: '5.2.26-6.el10',
        arch: 'x86_64',
        manager: 'rpm',
      },
      {
        name: 'openssl',
        version: '1:3.2.2-5.el10',
        arch: 'x86_64',
        manager: 'rpm',
      },
    ]);
  });

  it('apk y rpm por el gestor nativo', () => {
    const apk = normalizeCollection(
      {
        ...debian(),
        nativePackages: ['apk', 'musl-1.2.5-r10', 'busybox-1.37.0-r18'],
      },
      NOW,
    );
    expect(apk.packages).toEqual([
      { name: 'busybox', version: '1.37.0-r18', arch: null, manager: 'apk' },
      { name: 'musl', version: '1.2.5-r10', arch: null, manager: 'apk' },
    ]);
    const rpm = normalizeCollection(
      {
        ...debian(),
        nativePackages: [
          'rpm',
          'bash\t0:5.2.26-6\tx86_64\tii',
          'openssl\t1:3.2.2-5\tx86_64\tii',
        ],
      },
      NOW,
    );
    expect(rpm.packages.map((p) => p.version)).toEqual([
      '5.2.26-6',
      '1:3.2.2-5',
    ]);
  });

  it('dmidecode con sudo completa el hardware', () => {
    const raw = withSudo(debian(), {
      dmidecode: {
        rc: 0,
        stdout: [
          '# dmidecode 3.6',
          'Handle 0x0001, DMI type 1, 27 bytes',
          'System Information',
          '\tManufacturer: Dell Inc.',
          '\tProduct Name: PowerEdge R650',
          '\tSerial Number: ABC1234',
          '\tUUID: 4c4c4544-0042-4310-8031-b4c04f333233',
          '\tSKU Number: Not Specified',
          '',
          'Handle 0x0002, DMI type 12, 5 bytes',
          'System Configuration Options',
          '\tOption 1: To Be Filled By O.E.M.',
        ].join('\n'),
      },
    });
    expect(normalizeCollection(raw, NOW).hardware).toMatchObject({
      vendor: 'Dell Inc.',
      product: 'PowerEdge R650',
      serial: 'ABC1234',
      uuid: '4c4c4544-0042-4310-8031-b4c04f333233',
    });
  });

  it('nunca incluye el entorno remoto ni facts no normalizados', () => {
    const raw = debian();
    raw.facts = {
      ...raw.facts,
      env: { AWS_SECRET_ACCESS_KEY: 'centinela' },
      cmdline: { x: 'centinela' },
    };
    expect(JSON.stringify(normalizeCollection(raw, NOW))).not.toContain(
      'centinela',
    );
  });
});

describe('parseSs', () => {
  it('interpreta IPv4, IPv6, comodines, zonas, udp y procesos', () => {
    const out = [
      'tcp   LISTEN 0      4096   127.0.0.53%lo:53      0.0.0.0:*    users:(("systemd-resolve",pid=512,fd=15))',
      'udp   UNCONN 0      0            0.0.0.0:68      0.0.0.0:*    users:(("dhclient",pid=700,fd=7))',
      'tcp   LISTEN 0      511                *:80            *:*    users:(("apache2",pid=900,fd=4),("apache2",pid=901,fd=4))',
      'udp   UNCONN 0      0     [fe80::1%eth0]:123        [::]:*',
      'tcp   LISTEN 0      511                *:80            *:*    users:(("apache2",pid=902,fd=4))',
      'basura',
      'tcp   LISTEN 0      10         [::1]:99999      [::]:*',
    ].join('\n');
    expect(parseSs(out)).toEqual([
      {
        proto: 'tcp',
        address: '127.0.0.53',
        port: 53,
        process: 'systemd-resolve',
        pid: 512,
      },
      {
        proto: 'udp',
        address: '0.0.0.0',
        port: 68,
        process: 'dhclient',
        pid: 700,
      },
      { proto: 'tcp', address: '*', port: 80, process: 'apache2', pid: 900 },
      { proto: 'udp', address: 'fe80::1', port: 123, process: null, pid: null },
    ]);
  });
});

// Salidas reales de un CT Alpine 3.24 (BusyBox) y de un Debian 13 en Proxmox (sesión 9).
const BUSYBOX_NETSTAT = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 :::9999                 :::*                    LISTEN      479/nc
tcp        0      0 ::1:9997                :::*                    LISTEN      481/nc
tcp        0      0 10.0.0.5:41000          10.0.0.1:443            ESTABLISHED 482/wget
udp        0      0 :::9998                 :::*                                480/nc
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
`;

const PROC_NET = `# tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 87943 1 00000000dd28f56a 100 0 0 10 0
   1: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29500 1 000000003faf631f 100 0 0 10 0
   2: 0500000A:A028 0100000A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 29501 1 000000003faf631f 100 0 0 10 0
# tcp6
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:270F 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107834 1 0000000002f05628 100 0 0 10 0
   1: 00000000000000000000000001000000:270D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107836 1 00000000b94cc8f8 100 0 0 10 0
# udp
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1283: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 34097 2 000000005d494b6b 0
 1284: 0500000A:D431 0100000A:0035 01 00000000:00000000 00:00000000 00000000     0        0 34098 2 000000005d494b6b 0
# udp6
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  254: 00000000000000000000000000000000:270E 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 107031 2 00000000d1a94932 0
`;

describe('parseNetstat', () => {
  it('lee netstat de BusyBox: solo LISTEN en TCP, UDP sin estado, IPv6 sin corchetes', () => {
    expect(parseNetstat(BUSYBOX_NETSTAT)).toEqual([
      { proto: 'udp', address: '0.0.0.0', port: 68, process: null, pid: null },
      { proto: 'tcp', address: '::1', port: 9997, process: 'nc', pid: 481 },
      { proto: 'udp', address: '::', port: 9998, process: 'nc', pid: 480 },
      { proto: 'tcp', address: '::', port: 9999, process: 'nc', pid: 479 },
    ]);
  });

  it('net-tools: el programa puede llevar espacios', () => {
    expect(
      parseNetstat(
        'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      712/sshd: /usr/sbin\n',
      ),
    ).toEqual([
      {
        proto: 'tcp',
        address: '0.0.0.0',
        port: 22,
        process: 'sshd: /usr/sbin',
        pid: 712,
      },
    ]);
  });
});

describe('parseProcNet', () => {
  it('decodifica las direcciones del kernel y solo coge sockets en escucha', () => {
    expect(parseProcNet(PROC_NET)).toEqual([
      {
        proto: 'tcp',
        address: '127.0.0.1',
        port: 25,
        process: null,
        pid: null,
      },
      { proto: 'udp', address: '0.0.0.0', port: 68, process: null, pid: null },
      {
        proto: 'tcp',
        address: '0.0.0.0',
        port: 8080,
        process: null,
        pid: null,
      },
      { proto: 'tcp', address: '::1', port: 9997, process: null, pid: null },
      { proto: 'udp', address: '::', port: 9998, process: null, pid: null },
      { proto: 'tcp', address: '::', port: 9999, process: null, pid: null },
    ]);
  });

  it('IPv6 no trivial', () => {
    // fe80::1:2 → palabras de 32 bits en little-endian.
    expect(
      parseProcNet(
        '# tcp6\n   0: 000080FE000000000000000002000100:0016 00000000000000000000000000000000:0000 0A 0\n',
      )[0].address,
    ).toBe('fe80::1:2');
  });
});

describe('puertos sin ss', () => {
  const withoutSs = (extra: Partial<RawCollection>): RawCollection => {
    const raw = debian();
    return {
      ...raw,
      which: raw.which.filter((l) => !l.startsWith('ss=')),
      sudo: raw.sudo.filter((r) => r.item.key !== 'ss'),
      ...extra,
    };
  };

  it('usa netstat y lo avisa', () => {
    const facts = normalizeCollection(
      withoutSs({
        netstat: { rc: 0, stdout: BUSYBOX_NETSTAT, stderr: '' },
        procNet: null,
      }),
      NOW,
    );
    expect(facts.ports).toHaveLength(4);
    expect(facts.infraward.warnings).toContain(
      "sin 'ss': puertos leídos con netstat",
    );
  });

  it('sin netstat (o si falla) usa /proc/net y lo avisa', () => {
    const facts = normalizeCollection(
      withoutSs({
        netstat: { rc: 1, stdout: '', stderr: 'netstat: applet not found' },
        procNet: PROC_NET,
      }),
      NOW,
    );
    expect(facts.ports.map((p) => p.port)).toEqual([
      25, 68, 8080, 9997, 9998, 9999,
    ]);
    expect(facts.infraward.warnings).toContain(
      "sin 'ss' ni 'netstat': puertos leídos de /proc/net, sin proceso",
    );
  });

  it('sin nada: aviso y sin puertos', () => {
    const facts = normalizeCollection(withoutSs({}), NOW);
    expect(facts.ports).toEqual([]);
    expect(facts.infraward.warnings).toContain(
      "sin 'ss' ni 'netstat': no se pueden listar los puertos en escucha",
    );
  });
});

describe('parseDmidecodeSystem', () => {
  it('ignora otras secciones y valores de relleno', () => {
    expect(
      parseDmidecodeSystem(
        'Base Board Information\n\tManufacturer: X\nSystem Information\n\tManufacturer: Y\n\tSerial Number: Not Specified\n',
      ),
    ).toEqual({ Manufacturer: 'Y' });
  });
});

describe('mergeRoles', () => {
  it('sustituye los detectados y conserva los manuales', () => {
    expect(
      mergeRoles(
        ['plesk', 'web', 'docker-host', 'backup'],
        ['proxmox-node', 'docker-host'],
      ),
    ).toEqual(['backup', 'docker-host', 'proxmox-node', 'web']);
  });
});

describe('parseSshCaKeys', () => {
  const ca1 = generateSshKeyPair('x')
    .publicKey.split(' ')
    .slice(0, 2)
    .join(' ');
  const ca2 = generateSshKeyPair('y')
    .publicKey.split(' ')
    .slice(0, 2)
    .join(' ');

  it('versión de la cabecera y huellas de las claves (ignora comentarios y basura)', () => {
    const text = [
      '# infraward-ssh-ca-version: 1',
      '# CA SSH de InfraWard. Generado por el script de alta: no editar.',
      ca1,
      '',
      ca2,
      'esto no es una clave',
    ].join('\n');
    expect(parseSshCaKeys(text)).toEqual({
      version: 1,
      trusted: [sshPublicKeyFingerprint(ca1), sshPublicKeyFingerprint(ca2)],
    });
  });

  it('sin fichero (modo estático) es null; sin cabecera, versión null', () => {
    expect(parseSshCaKeys('')).toBeNull();
    expect(parseSshCaKeys(ca1)).toEqual({
      version: null,
      trusted: [sshPublicKeyFingerprint(ca1)],
    });
  });
});
