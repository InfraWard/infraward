// Facts de ejemplo de cada tipo, tipados con los contratos: si cambia un tipo, el compilador
// obliga a actualizarlos (y con ellos el test de las rutas volátiles).
import type {
  CertificateFacts,
  CollectedFacts,
  ConnectorFacts,
  DnsRecordFacts,
  DnsTlsFacts,
  DockerContainerFacts,
  DockerNetworkFacts,
  DockerVolumeFacts,
  PleskDomainFacts,
  ProxmoxGuestFacts,
  RegistrationFacts,
  ZoneFacts,
} from '@infraward/shared-types';

export const collected: CollectedFacts = {
  machineId: '52d5aa',
  os: {
    family: 'Debian',
    distribution: 'Debian',
    version: '13.5',
    kernel: '7.0.2-6-pve',
    arch: 'x86_64',
  },
  hardware: {
    vendor: 'QEMU',
    product: 'Standard PC',
    uuid: null,
    serial: null,
    virtualization: 'kvm',
    processor: 'Intel',
    cpus: 1,
    cores: 4,
    vcpus: 4,
    memoryMb: 8192,
    swapMb: 1024,
  },
  mounts: [
    {
      mount: '/',
      device: '/dev/sda1',
      fstype: 'ext4',
      sizeBytes: 100,
      availableBytes: 40,
    },
  ],
  network: {
    hostname: 'pve',
    fqdn: 'pve.local',
    defaultIpv4: '172.20.10.190',
    interfaces: [
      {
        name: 'vmbr0',
        mac: 'aa:bb',
        active: true,
        ipv4: ['172.20.10.190'],
        ipv6: [],
      },
      { name: 'docker0', mac: '02:42:aa', active: true, ipv4: [], ipv6: [] },
    ],
  },
  packages: [
    { name: 'openssl', version: '3.0.11-1', arch: 'amd64', manager: 'dpkg' },
    { name: 'curl', version: '8.0-1', arch: 'amd64', manager: 'dpkg' },
  ],
  services: [
    { name: 'ssh.service', state: 'running', status: 'enabled' },
    { name: 'systemd-timedated.service', state: 'running', status: 'static' },
  ],
  ports: [
    { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd', pid: 812 },
  ],
  processes: [
    {
      pid: 812,
      name: 'sshd',
      unit: 'ssh.service',
      exePackage: 'openssh-server',
      libPackages: ['openssl', 'libc6'],
    },
  ],
  detected: { proxmox: 'pve-manager/9.2.2', plesk: null, docker: null },
  infraward: {
    collectedAt: '2026-10-12T10:00:00.000Z',
    via: 'ssh',
    sudoersVersion: 4,
    sudoersOutdated: false,
    sshCa: null,
    warnings: [],
  },
  proxy: {
    source: 'nginx',
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
    readAt: '2026-10-12T10:00:00.000Z',
  },
};

export const proxmox: ProxmoxGuestFacts = {
  vmid: 100,
  kind: 'lxc',
  node: 'pve',
  cluster: null,
  status: 'running',
  template: false,
  cpus: 2,
  maxMemBytes: 2048,
  maxDiskBytes: 8192,
  uptime: 3600,
  tags: [],
  config: { memory: 2048, cores: 2, hostname: 'pruebas', lock: 'backup' },
  interfaces: [
    { name: 'eth0', mac: 'bc:24', ipv4: ['10.0.0.5'], ipv6: [] },
    { name: 'veth021d6bd', mac: 'be:8f', ipv4: [], ipv6: ['fe80::1/64'] },
  ],
  discoveredAt: '2026-10-12T10:00:00.000Z',
};

export const container: DockerContainerFacts = {
  id: 'abc',
  name: 'web1',
  image: 'nginx:1.25',
  imageId: 'sha256:aaa',
  repoDigests: [],
  repoTags: ['nginx:1.25'],
  platform: 'linux/amd64',
  imageSizeBytes: 100,
  state: 'running',
  ports: [
    { containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 },
  ],
  composeProject: null,
  createdAt: '2026-10-01T00:00:00Z',
  startedAt: '2026-10-12T09:00:00Z',
  mounts: [
    {
      type: 'volume',
      name: 'data',
      source: null,
      destination: '/data',
      readOnly: false,
    },
  ],
  networks: [{ name: 'bridge', ipv4: '172.17.0.2', ipv6: null }],
  proxy: { source: 'nginx', routes: [], readAt: '2026-10-12T10:00:00.000Z' },
  discoveredAt: '2026-10-12T10:00:00.000Z',
};

export const volume: DockerVolumeFacts = {
  name: 'data',
  driver: 'local',
  scope: 'local',
  mountpoint: '/var/lib/docker/volumes/data/_data',
  createdAt: null,
  discoveredAt: '2026-10-12T10:00:00.000Z',
};

export const network: DockerNetworkFacts = {
  id: 'n1',
  name: 'bridge',
  driver: 'bridge',
  scope: 'local',
  internal: false,
  subnets: [{ subnet: '172.17.0.0/16', gateway: '172.17.0.1' }],
  createdAt: null,
  discoveredAt: '2026-10-12T10:00:00.000Z',
};

export const pleskDomain: PleskDomainFacts = {
  name: 'pruebas.local',
  kind: 'subscription',
  hostingType: 'vrt_hst',
  status: 0,
  active: true,
  subscription: 'pruebas.local',
  parent: null,
  createdAt: null,
  discoveredAt: '2026-10-12T10:00:00.000Z',
};

export const certificate: CertificateFacts = {
  name: 'default',
  subject: 'CN=pruebas.local',
  subjectAltNames: ['DNS:pruebas.local'],
  issuer: 'CN=R3',
  notBefore: null,
  notAfter: '2027-01-01T00:00:00Z',
  fingerprint256: 'AA:BB',
  selfSigned: false,
  letsEncrypt: true,
  usedBy: ['pruebas.local'],
  repository: 'admin',
  discoveredAt: '2026-10-12T10:00:00.000Z',
};

export const connector: ConnectorFacts = {
  kind: 'cloudflare',
  verify: {
    ok: true,
    checkedAt: '2026-10-14T10:00:00.000Z',
    error: null,
    tokenStatus: 'active',
    tokenExpiresAt: null,
    accounts: ['Pruebas'],
    zones: 1,
    warnings: [],
  },
  lastSync: {
    at: '2026-10-14T10:00:00.000Z',
    zones: 1,
    records: 2,
    complete: true,
    warnings: [],
  },
};

export const zone: ZoneFacts = {
  provider: 'cloudflare',
  id: '023e105f4ecef8ad9ca31a8372d0c353',
  name: 'ejemplo.dev',
  status: 'active',
  paused: false,
  nameServers: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
  plan: 'Free Website',
  account: 'Pruebas',
  discoveredAt: '2026-10-14T10:00:00.000Z',
};

export const registration: RegistrationFacts = {
  source: 'rdap',
  state: 'ok',
  expiresAt: '2027-03-01T00:00:00Z',
  registeredAt: '2020-03-01T00:00:00Z',
  registrar: 'Cloudflare, Inc.',
  statuses: ['client transfer prohibited'],
  error: null,
  checkedAt: '2026-10-14T10:00:00.000Z',
};

export const dnsRecord: DnsRecordFacts = {
  provider: 'cloudflare',
  id: '372e67954025e0ba6aaa6d586b9e0b59',
  zone: 'ejemplo.dev',
  name: 'www.ejemplo.dev',
  type: 'A',
  content: '203.0.113.10',
  truncated: false,
  ttl: 1,
  proxied: true,
  priority: null,
  discoveredAt: '2026-10-14T10:00:00.000Z',
};

export const dnsTls: DnsTlsFacts = {
  status: 'ok',
  error: null,
  authorized: true,
  authorizationError: null,
  hostnameMatch: true,
  fingerprint256: 'AA:BB',
  checkedAt: '2026-10-14T10:00:00.000Z',
};

/** Facts de cada tipo de asset tal como se guardan. */
export const SAMPLE_FACTS: Record<string, Record<string, unknown>> = {
  server: collected as unknown as Record<string, unknown>,
  lxc: { ...(collected as unknown as Record<string, unknown>), proxmox },
  container: { docker: container },
  volume: { docker: volume },
  network: { docker: network },
  domain: { plesk: pleskDomain },
  cloudflareDomain: { zone, registration },
  dns_record: { dns: dnsRecord, tls: dnsTls },
  dns_provider: { connector },
  certificate: { certificate },
};
