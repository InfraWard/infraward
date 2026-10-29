import {
  matchesInventoryText,
  type AssetTreeSummaryNode,
  type Severity,
} from '@infraward/shared-types';
import {
  certificateExpiring,
  certificateExpiryLabel,
  expiryTag,
  filterTree,
  matchesQuickFilter,
  branchKeys,
  fixableLabel,
  prefilter,
  quickFilter,
  quickFilterLabel,
  toRow,
  toTreeNodes,
} from './tree-nodes';

const none: Record<Severity, number> = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

function node(
  id: string,
  children: AssetTreeSummaryNode[] = [],
  extra: Partial<AssetTreeSummaryNode> = {},
): AssetTreeSummaryNode {
  return {
    id,
    name: id,
    type: 'server',
    status: 'active',
    discoveredName: null,
    roles: [],
    tags: [],
    projects: [],
    address: null,
    ips: [],
    runtimeState: null,
    runtimeDetail: null,
    openFindings: none,
    fixableFindings: { CRITICAL: 0, HIGH: 0 },
    sudoersOutdated: false,
    collectionWarnings: 0,
    duplicateOf: null,
  machineIdClone: false,
  expiresAt: null,
    dnsWarning: null,
    sshCaOutdated: false,
    sshdRisk: null,
    scanDisabled: false,
    children,
    ...extra,
  };
}

describe('toTreeNodes', () => {
  const forest = [
    node('pve', [
      node('ct', [
        node('web1', [], {
          type: 'container',
          openFindings: { ...none, CRITICAL: 2, HIGH: 5, LOW: 1 },
          fixableFindings: { CRITICAL: 1, HIGH: 3 },
        }),
      ], { roles: ['docker-host'], tags: ['prod'], address: '10.0.0.7' }),
    ]),
    node('suelto'),
  ];

  it('conserva la jerarquía y usa el id como clave', () => {
    const [pve, suelto] = toTreeNodes(forest);
    expect(pve.key).toBe('pve');
    expect(pve.leaf).toBe(false);
    expect(pve.children![0].children![0].key).toBe('web1');
    expect(suelto.leaf).toBe(true);
  });

  it('abre solo las ramas recordadas', () => {
    const [pve] = toTreeNodes(forest, new Set(['pve']));
    expect(pve.expanded).toBe(true);
    expect(pve.children![0].expanded).toBe(false);
  });

  it('resume los findings: peor severidad, CRITICAL/HIGH con parche y el total para el tooltip', () => {
    const web1 = toTreeNodes(forest)[0].children![0].children![0].data!;
    expect(web1).toMatchObject({
      worst: 'CRITICAL',
      fixableCritical: 1,
      fixableHigh: 3,
      findingsSummary: '8 abiertas: 2 CRITICAL · 5 HIGH · 1 LOW',
    });
    expect(fixableLabel(web1)).toBe('1 C · 3 H');
    const pve = toTreeNodes(forest)[0].data!;
    expect(pve).toMatchObject({ worst: null, findingsSummary: '' });
    expect(fixableLabel(pve)).toBeNull();
  });

  it('desaparecido o retirado: sin el último estado de ejecución; escaneo desactivado, marcado', () => {
    const running = { runtimeState: 'running' as const, runtimeDetail: 'running' };
    expect(toRow(node('a', [], running)).runtimeState).toBe('running');
    expect(toRow(node('a', [], { ...running, status: 'missing' })).runtimeState).toBeNull();
    expect(toRow(node('a', [], { ...running, status: 'retired' })).runtimeDetail).toBeNull();
    expect(toRow(node('a', [], { scanDisabled: true })).scanDisabled).toBe(true);
  });

  it('branchKeys devuelve solo los nodos con hijos', () => {
    expect(branchKeys(forest)).toEqual(['pve', 'ct']);
  });
});

describe('filtro rápido (URL)', () => {
  const forest = [
    node('pve', [
      node('ct', [node('web1', [], { type: 'container' }), node('cache', [], { type: 'container' })], {
        type: 'lxc',
        collectionWarnings: 2,
      }),
    ]),
    node('nuevo', [], { status: 'pending_enrollment' }),
    node('viejo', [], { sudoersOutdated: true }),
    node('copia', [], { duplicateOf: 'pve' }),
    node('clon', [], { machineIdClone: true }),
  ];

  it('valida los parámetros: lo desconocido se ignora', () => {
    expect(quickFilter({})).toBeNull();
    expect(quickFilter({ type: 'nave', status: 'x', attention: 'y' })).toBeNull();
    expect(quickFilter({ type: 'container', attention: 'sudoers' })).toEqual({
      type: 'container',
      attention: 'sudoers',
    });
  });

  it('deja los que cumplen y sus antepasados, con las ramas abiertas', () => {
    const { nodes, expand, matches } = prefilter(forest, { type: 'container' });
    expect(matches).toBe(2);
    expect(nodes.map((n) => n.id)).toEqual(['pve']);
    expect(nodes[0]!.children[0]!.children.map((n) => n.id)).toEqual(['web1', 'cache']);
    expect(expand.sort()).toEqual(['ct', 'pve']);
  });

  it('pendientes de alta, sudoers desactualizado, duplicados, clones y recolección parcial', () => {
    const ids = (f: Parameters<typeof prefilter>[1]) =>
      prefilter(forest, f).nodes.map((n) => n.id);
    expect(ids({ status: 'pending_enrollment' })).toEqual(['nuevo']);
    expect(ids({ attention: 'sudoers' })).toEqual(['viejo']);
    expect(ids({ attention: 'duplicate' })).toEqual(['copia']);
    expect(ids({ attention: 'clone' })).toEqual(['clon']);
    const partial = prefilter(forest, { attention: 'partial' });
    expect(partial.nodes.map((n) => n.id)).toEqual(['pve']);
    // El CT que cumple no arrastra a sus hijos que no cumplen.
    expect(partial.nodes[0]!.children[0]!.children).toEqual([]);
  });

  it('etiqueta legible para el chip', () => {
    expect(quickFilterLabel({ type: 'server', status: 'pending_enrollment' })).toBe(
      'Tipo: Servidor · Estado: Pendiente de alta',
    );
    expect(quickFilterLabel({ attention: 'partial' })).toBe('Recolección parcial');
    expect(quickFilterLabel({ attention: 'duplicate' })).toBe('Duplicados');
    expect(quickFilterLabel({ attention: 'clone' })).toBe('machine-id clonado');
    expect(quickFilterLabel({ attention: 'dns-dangling' })).toBe('Registros DNS colgantes');
  });

  it('filtros de dominios: caducan, colgantes y a IPs desconocidas', () => {
    const soon = new Date(Date.now() + 5 * 86_400_000).toISOString();
    const domain = node('ejemplo.dev', [], { type: 'domain', expiresAt: soon });
    const cert = node('cert', [], { type: 'certificate', expiresAt: soon });
    const high = node('roto · CNAME', [], { type: 'dns_record', dnsWarning: 'high' });
    const info = node('saas · A', [], { type: 'dns_record', dnsWarning: 'info' });
    const all = [domain, cert, high, info];
    const pick = (attention: string) =>
      all.filter((n) => matchesQuickFilter(n, quickFilter({ attention })!)).map((n) => n.id);
    expect(pick('domain-expiring')).toEqual(['ejemplo.dev']);
    expect(pick('cert-expiring')).toEqual(['cert']);
    expect(pick('dns-dangling')).toEqual(['roto · CNAME']);
    expect(pick('dns-unknown')).toEqual(['saas · A']);
    // Un registro retirado no enseña su aviso en la fila.
    expect(toRow({ ...high, status: 'retired' }).dnsWarning).toBeNull();
  });

  it('caducidad: aviso por debajo del umbral mayor, nivel por umbral y etiqueta legible', () => {
    const now = Date.parse('2026-10-11T12:00:00Z');
    const inDays = (d: number) => new Date(now + d * 86_400_000).toISOString();
    const days = [30, 7];
    expect(certificateExpiring(null, days, now)).toBe(false);
    expect(certificateExpiring(inDays(90), days, now)).toBe(false);
    expect(certificateExpiring(inDays(10), days, now)).toBe(true);
    expect(certificateExpiring(inDays(-1), days, now)).toBe(true);
    // Con otros umbrales (Ajustes > Inventario).
    expect(certificateExpiring(inDays(50), [60], now)).toBe(true);
    expect(expiryTag(inDays(90), days, now).severity).toBe('success');
    expect(expiryTag(inDays(20), days, now).severity).toBe('warn');
    expect(expiryTag(inDays(3), days, now).severity).toBe('danger');
    expect(expiryTag(inDays(-1), days, now).severity).toBe('danger');
    expect(certificateExpiryLabel(inDays(12.5), now)).toBe('caduca en 12 días');
    expect(certificateExpiryLabel(inDays(1.2), now)).toBe('caduca mañana');
    expect(certificateExpiryLabel(inDays(0.2), now)).toBe('caduca hoy');
    expect(certificateExpiryLabel(inDays(-0.2), now)).toBe('caducó hoy');
    expect(certificateExpiryLabel(inDays(-3.5), now)).toBe('caducó hace 3 días');
  });
});

describe('filterTree con la búsqueda', () => {
  it('abre los antepasados de cada coincidencia; el texto suelto solo busca en el nombre', () => {
    const forest = [
      node('pve', [
        node('ct', [node('web1'), node('cache')]),
        node('db', [], { address: '10.0.0.5', ips: ['10.0.0.5'] }),
      ]),
      node('otro', [], { roles: ['docker-host'] }),
    ];
    const open = (q: string) =>
      filterTree(forest, (n) => matchesInventoryText(n, q)).expand.sort();
    expect(open(' WEB ')).toEqual(['ct', 'pve']);
    expect(open('ip:10.0.0.')).toEqual(['pve']);
    expect(filterTree(forest, (n) => matchesInventoryText(n, '10.0.0')).matches).toBe(0);
    expect(filterTree(forest, (n) => matchesInventoryText(n, 'docker-host')).matches).toBe(0);
    expect(filterTree(forest, (n) => matchesInventoryText(n, 'rol:docker-host')).matches).toBe(1);
  });
});

