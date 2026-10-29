import {
  findingWhere as where_,
  likeLiteral,
  SCAN_ENABLED_OWNER,
} from './finding-where.js';
import { foldSql } from './finding-search.js';

// Los de siempre, sin los filtros de escaneo desactivado ni de ruido (se prueban aparte).
const findingWhere = (
  query: Parameters<typeof where_>[0],
  base?: Parameters<typeof where_>[1],
) => where_({ includeScanDisabled: true, includeNoise: true, ...query }, base);

describe('findingWhere', () => {
  it('sin filtros, sin condiciones', () => {
    expect(findingWhere({})).toEqual({ where: [], params: [] });
  });

  it('numera los parámetros a continuación de los que ya hay', () => {
    const { where, params } = findingWhere(
      { status: 'open', minSeverity: 'HIGH', fixable: true },
      { where: ['f.asset_id = $1'], params: ['a1'] },
    );
    expect(where).toEqual([
      'f.asset_id = $1',
      'f.status = $2',
      'f.severity::text = ANY($3::text[])',
      'f.fixed_version IS NOT NULL',
    ]);
    expect(params).toEqual(['a1', 'open', ['HIGH', 'CRITICAL']]);
  });

  it('q busca un CVE por prefijo o un paquete por subcadena, con un solo parámetro', () => {
    const { where, params } = findingWhere({ q: '  krb5 ' });
    expect(where).toEqual([
      `((upper(f.vulnerability_id) LIKE upper($1) || '%' OR f.package_name ILIKE '%' || $1 || '%'))`,
    ]);
    expect(params).toEqual(['krb5']);
    expect(findingWhere({ q: '   ' }).where).toEqual([]);
  });

  it('q con la sintaxis de filtros: claves del CVE y del asset afectado, todo parametrizado', () => {
    const { where, params } = findingWhere({
      q: 'cve:CVE-2024 paquete:open_ssl severidad:crítica severidad:high tag:prod -tag:legacy ip:10.0.0.0/24',
    });
    expect(where).toHaveLength(6);
    expect(where[0]).toBe(`(upper(f.vulnerability_id) LIKE upper($1) || '%')`);
    expect(where[1]).toBe(`(f.package_name ILIKE '%' || $2 || '%')`);
    expect(where[2]).toBe(`(f.severity::text = ANY($3::text[]))`);
    // tag: el dueño o, en una imagen, quien la usa.
    expect(where[3]).toContain(`qr.type IN ('instance_of', 'stores')`);
    // Plegado (minúsculas y sin tildes) en los dos lados: el valor ya llega plegado.
    expect(where[3]).toContain(`${foldSql('t')} = ANY($4::text[])`);
    expect(where[4]).toMatch(/^NOT \(/);
    expect(where[5]).toContain('::inet <<= $6::inet');
    expect(params).toEqual([
      'CVE-2024',
      'open\\_ssl',
      ['CRITICAL', 'HIGH'],
      ['prod'],
      ['legacy'],
      '10.0.0.0/24',
    ]);
  });

  it('q: tags, roles, nombres y proyectos con tildes se comparan sin tildes en los dos lados', () => {
    const { where, params } = findingWhere({
      q: 'tag:Producción rol:Señal nombre:Cañón proyecto:Ñandú',
    });
    expect(params).toEqual([['produccion'], ['senal'], 'canon', ['nandu']]);
    expect(where[0]).toContain(`${foldSql('t')} = ANY($1::text[])`);
    expect(where[1]).toContain(`${foldSql('r')} = ANY($2::text[])`);
    expect(where[2]).toContain(`${foldSql('qa.name')} LIKE '%' || $3 || '%'`);
    expect(where[3]).toContain(`${foldSql('pr.name')} = ANY($4::text[])`);
  });

  it('q: lo que no entiende no filtra y nunca mete texto en el SQL', () => {
    const { where, params } = findingWhere({
      q: `tipo:foo sitio:x prioridad:x "'; DROP TABLE findings; --`,
    });
    expect(where).toHaveLength(1);
    expect(where.join(' ')).not.toContain('DROP');
    expect(params).toEqual([`'; DROP TABLE findings; --`]);
  });

  it('los comodines de LIKE se buscan tal cual', () => {
    expect(likeLiteral('lib%_x\\')).toBe('lib\\%\\_x\\\\');
  });

  it('por defecto, sin los de assets con el escaneo desactivado (§10)', () => {
    expect(where_({ includeNoise: true })).toEqual({
      where: [SCAN_ENABLED_OWNER],
      params: [],
    });
    expect(SCAN_ENABLED_OWNER).toContain(
      "effective_policy->'values'->>'scanEnabled'",
    );
  });

  it('openedSince: abiertos (aparecidos o reabiertos) después de la fecha', () => {
    expect(findingWhere({ openedSince: '2026-10-11T16:40:00.000Z' })).toEqual({
      where: [`f.status = 'open' AND f.opened_at > $1::timestamptz`],
      params: ['2026-10-11T16:40:00.000Z'],
    });
  });

  it('por defecto, sin el ruido (kernel no en uso, sin corrección prevista)', () => {
    expect(where_({ includeScanDisabled: true }).where).toEqual([
      'f.noise_reason IS NULL',
    ]);
  });

  it('prioridad mínima, KEV, EPSS y expuestas', () => {
    const { where, params } = findingWhere({
      minPriority: 'high',
      kev: true,
      minEpss: 0.1,
      exposure: 'any',
    });
    expect(where).toEqual([
      expect.stringContaining('"code":"port"'),
      expect.stringContaining('ki.in_kev'),
      expect.stringContaining('ei.epss >= $1'),
      'f.priority >= 50',
    ]);
    expect(params).toEqual([0.1]);
  });

  it('hidden: solo lo que la vista oculta por ese motivo (y sin los demás filtros de ocultar)', () => {
    const q = { inUse: true, minPriority: 'medium' as const };
    expect(where_({ ...q, hidden: 'kernel_not_running' })).toEqual({
      where: ['f.noise_reason = $1', SCAN_ENABLED_OWNER],
      params: ['kernel_not_running'],
    });
    expect(where_({ ...q, hidden: 'unused_image' }).where[0]).toMatch(
      /^NOT NOT EXISTS/,
    );
    expect(where_({ ...q, hidden: 'scan_disabled' }).where).toEqual([
      `NOT ${SCAN_ENABLED_OWNER}`,
    ]);
    expect(where_({ ...q, hidden: 'low_priority' }).where).toEqual([
      'f.priority < 30',
      'f.noise_reason IS NULL',
      SCAN_ENABLED_OWNER,
    ]);
  });

  it('q con prioridad: por banda', () => {
    const { where, params } = findingWhere({ q: 'prioridad:urgente' });
    expect(where[0]).toContain("WHEN f.priority >= 70 THEN 'urgent'");
    expect(params).toEqual([['urgent']]);
  });
});
