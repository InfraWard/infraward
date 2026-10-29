import { describe, expect, it } from 'vitest';
import {
  assetIps,
  externalCnameTargets,
  isPrivateIp,
  linkDnsRecords,
  normalizeIp,
  takeoverService,
  type LinkInput,
  type LinkRecord,
  type LinkTarget,
} from './link.js';

const srv = (id: string, status: LinkTarget['status'] = 'active'): LinkTarget => ({
  id,
  type: 'server',
  status,
});

function input(records: LinkRecord[], extra: Partial<LinkInput> = {}): LinkInput {
  return {
    records,
    ips: new Map([
      ['203.0.113.10', [srv('web')]],
      ['192.168.1.20', [srv('lab')]],
      ['10.0.0.5', [srv('viejo', 'retired')]],
      ['198.51.100.7', [srv('a'), srv('b')]],
      ['2001:db8::10', [srv('web')]],
      ['172.17.0.2', [{ id: 'c1', type: 'container', status: 'active' }]],
    ]),
    zones: new Map([['ejemplo.dev', 'dom']]),
    names: new Map([
      ['www.ejemplo.dev', ['r-www']],
      ['*.apps.ejemplo.dev', ['r-wild']],
      ['ejemplo.dev', ['r-apex']],
    ]),
    cnames: new Map([
      ['viejo-123.herokuapp.com', 'nxdomain'],
      ['quiza-mia.herokuapp.com', 'exists'],
      ['cdn.proveedor.net', 'exists'],
      ['lento.proveedor.net', 'error'],
    ]),
    ...extra,
  };
}

const rec = (id: string, type: LinkRecord['type'], content: string): LinkRecord => ({
  id,
  type,
  name: `${id}.ejemplo.dev`,
  content,
});

describe('linkDnsRecords', () => {
  it('A/AAAA a un asset activo: enlace sin aviso; varios, ambiguo', () => {
    const out = linkDnsRecords(
      input([
        rec('r1', 'A', '203.0.113.10'),
        rec('r2', 'AAAA', '2001:0db8:0:0::10'),
        rec('r3', 'A', '198.51.100.7'),
      ]),
    );
    expect(out.map((l) => [l.targets, l.level, l.reason, l.ambiguous])).toEqual([
      [['web'], null, 'linked', false],
      [['web'], null, 'linked', false],
      [['a', 'b'], null, 'linked', true],
    ]);
    expect(out[1].target).toBe('2001:db8::10');
  });

  it('niveles de los colgantes: retirado y privada desconocida (alto), pública desconocida (info)', () => {
    const out = linkDnsRecords(
      input([
        rec('r1', 'A', '10.0.0.5'),
        rec('r2', 'A', '10.99.99.99'),
        rec('r3', 'A', '100.64.1.1'),
        rec('r4', 'AAAA', 'fd00::1'),
        rec('r5', 'A', '8.8.8.8'),
        // Solo un contenedor tiene la IP (de su red de Docker): no cuenta.
        rec('r6', 'A', '172.17.0.2'),
      ]),
    );
    expect(out.map((l) => [l.targets, l.level, l.reason])).toEqual([
      [['viejo'], 'high', 'retired_target'],
      [[], 'high', 'private_unknown'],
      [[], 'high', 'private_unknown'],
      [[], 'high', 'private_unknown'],
      [[], 'info', 'public_unknown'],
      [[], 'high', 'private_unknown'],
    ]);
  });

  it('CNAME interno: a su registro, a un comodín o a la raíz; sin destino, alto', () => {
    const out = linkDnsRecords(
      input(
        [
          rec('r1', 'CNAME', 'WWW.ejemplo.dev.'),
          rec('r2', 'CNAME', 'x.apps.ejemplo.dev'),
          rec('r3', 'CNAME', 'ejemplo.dev'),
          rec('r4', 'CNAME', 'borrado.ejemplo.dev'),
        ],
        { names: new Map([['www.ejemplo.dev', ['r-www']], ['*.apps.ejemplo.dev', ['r-wild']]]) },
      ),
    );
    expect(out.map((l) => [l.targets, l.level, l.reason])).toEqual([
      [['r-www'], null, 'cname_internal'],
      [['r-wild'], null, 'cname_internal'],
      [['dom'], null, 'cname_internal'],
      [[], 'high', 'cname_internal_missing'],
    ]);
  });

  it('CNAME externo: NXDOMAIN (takeover, con el servicio), existe, túnel y sin comprobar', () => {
    const out = linkDnsRecords(
      input([
        rec('r1', 'CNAME', 'viejo-123.herokuapp.com'),
        rec('r2', 'CNAME', 'cdn.proveedor.net'),
        rec('r3', 'CNAME', 'f00.cfargotunnel.com'),
        rec('r4', 'CNAME', 'lento.proveedor.net'),
        rec('r5', 'CNAME', 'nunca-resuelto.net'),
        // Heroku resuelve cualquier nombre: que exista no prueba que la app sea tuya.
        rec('r6', 'CNAME', 'quiza-mia.herokuapp.com'),
      ]),
    );
    expect(out.map((l) => [l.level, l.reason, l.takeoverService])).toEqual([
      ['high', 'cname_nxdomain', 'Heroku'],
      [null, 'cname_external', null],
      [null, 'cname_tunnel', null],
      [null, 'unchecked', null],
      [null, 'unchecked', null],
      ['info', 'cname_takeover_service', 'Heroku'],
    ]);
  });

  it('un CNAME no se enlaza a sí mismo', () => {
    const [l] = linkDnsRecords(
      input([{ id: 'r-www', type: 'CNAME', name: 'www.ejemplo.dev', content: 'www.ejemplo.dev' }]),
    );
    expect(l.reason).toBe('cname_internal_missing');
  });

  it('destinos externos a resolver: sin internos, túneles ni repetidos', () => {
    expect(
      externalCnameTargets(
        [
          rec('r1', 'CNAME', 'a.herokuapp.com.'),
          rec('r2', 'CNAME', 'A.herokuapp.com'),
          rec('r3', 'CNAME', 'www.ejemplo.dev'),
          rec('r4', 'CNAME', 'x.cfargotunnel.com'),
          rec('r5', 'A', '1.2.3.4'),
        ],
        ['ejemplo.dev'],
      ),
    ).toEqual(['a.herokuapp.com']);
  });
});

describe('IPs de los assets', () => {
  it('interfaces reales, net0 de Proxmox y host de conexión; sin loopback ni Docker', () => {
    expect(
      assetIps(
        {
          network: {
            defaultIpv4: '192.168.1.20',
            interfaces: [
              { name: 'lo', ipv4: ['127.0.0.1'], ipv6: ['::1'] },
              { name: 'eth0', ipv4: ['192.168.1.20/24'], ipv6: ['fe80::1', '2001:db8::20'] },
              { name: 'docker0', ipv4: ['172.17.0.1'], ipv6: [] },
              { name: 'vmbr0', ipv4: ['192.168.1.2'], ipv6: [] },
            ],
          },
          proxmox: {
            interfaces: [{ name: 'eth0', ipv4: ['192.168.1.30'], ipv6: [] }],
            config: { net0: 'name=eth0,bridge=vmbr0,ip=192.168.1.31/24,ip6=2001:db8::31/64' },
          },
        },
        { host: '203.0.113.10', port: 22, user: 'inventory' },
      ).sort(),
    ).toEqual(
      ['192.168.1.20', '2001:db8::20', '192.168.1.2', '192.168.1.30', '192.168.1.31', '2001:db8::31', '203.0.113.10'].sort(),
    );
    expect(assetIps({}, { host: 'servidor.ejemplo.dev' })).toEqual([]);
  });

  it('normaliza y clasifica', () => {
    expect(normalizeIp('2001:0DB8::0010')).toBe('2001:db8::10');
    expect(normalizeIp('nope')).toBeNull();
    expect(['10.1.1.1', '172.31.0.1', '192.168.0.1', '100.100.0.1', 'fd12::1'].every(isPrivateIp)).toBe(true);
    expect(['172.32.0.1', '8.8.8.8', '2001:db8::1'].some(isPrivateIp)).toBe(false);
    expect(takeoverService('foo.github.io')).toBe('GitHub Pages');
    expect(takeoverService('foo.ejemplo.dev')).toBeNull();
  });
});
