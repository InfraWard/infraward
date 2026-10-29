import { describe, expect, it } from 'vitest';
import type { AssetTreeSummaryNode } from './assets.js';
import { filterTree, matchesInventoryText } from './inventory-filter.js';
import {
  formatSearchTerm,
  ipMatcher,
  ipMatches,
  matchesInventoryQuery,
  parseSearchQuery,
  removeSearchToken,
  searchGroups,
} from './search-query.js';

function node(
  name: string,
  extra: Partial<AssetTreeSummaryNode> = {},
): AssetTreeSummaryNode {
  return {
    id: name,
    name,
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
    openFindings: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    fixableFindings: { CRITICAL: 0, HIGH: 0 },
    sudoersOutdated: false,
    collectionWarnings: 0,
    duplicateOf: null,
    machineIdClone: false,
    expiresAt: null,
    dnsWarning: null,
    sshCaOutdated: false,
    scanDisabled: false,
    children: [],
    ...extra,
  };
}

const inv = (q: string) => parseSearchQuery(q, 'inventory');

describe('parseSearchQuery', () => {
  it('separa claves (con alias es/en) y texto libre', () => {
    const p = inv('tag:prueba nombre:hola web');
    expect(p.issues).toEqual([]);
    expect(p.terms.map((t) => [t.key, t.value, t.negated])).toEqual([
      ['tag', 'prueba', false],
      ['name', 'hola', false],
      [null, 'web', false],
    ]);
    expect(
      inv('name:hola Type:Server').terms.map((t) => [t.key, t.value]),
    ).toEqual([
      ['name', 'hola'],
      ['type', 'server'],
    ]);
  });

  it('comillas, negación y posiciones', () => {
    const p = inv('nombre:"web prod" -tag:legacy "dos palabras"');
    expect(p.terms).toEqual([
      {
        key: 'name',
        value: 'web prod',
        negated: false,
        raw: 'nombre:"web prod"',
        start: 0,
        end: 17,
      },
      {
        key: 'tag',
        value: 'legacy',
        negated: true,
        raw: '-tag:legacy',
        start: 18,
        end: 29,
      },
      {
        key: null,
        value: 'dos palabras',
        negated: false,
        raw: '"dos palabras"',
        start: 30,
        end: 44,
      },
    ]);
  });

  it('normaliza tipos, estados y severidades en español e inglés', () => {
    expect(
      inv('tipo:servidor tipo:CT tipo:imagen').terms.map((t) => t.value),
    ).toEqual(['server', 'lxc', 'image']);
    expect(
      inv('estado:activo estado:"en marcha" status:stopped').terms.map(
        (t) => t.value,
      ),
    ).toEqual(['active', 'running', 'stopped']);
    const v = parseSearchQuery(
      'severidad:crítica severity:high',
      'vulnerabilities',
    );
    expect(v.terms.map((t) => t.value)).toEqual(['CRITICAL', 'HIGH']);
  });

  it('agrupa: la misma clave es O, claves distintas Y', () => {
    const groups = searchGroups(
      inv('tag:prod tag:staging nombre:web -tag:legacy a b'),
    );
    expect(groups).toEqual([
      { key: 'tag', negated: false, values: ['prod', 'staging'] },
      { key: 'name', negated: false, values: ['web'] },
      { key: 'tag', negated: true, values: ['legacy'] },
      { key: null, negated: false, values: ['a'] },
      { key: null, negated: false, values: ['b'] },
    ]);
  });

  it('clave desconocida: aviso y se busca como texto (nginx:1.25)', () => {
    const p = inv('nginx:1.25');
    expect(p.issues.map((i) => i.kind)).toEqual(['unknown_key']);
    expect(p.terms).toMatchObject([{ key: null, value: 'nginx:1.25' }]);
  });

  it('comillas sin cerrar: hasta el final, con aviso', () => {
    const p = inv('tag:prod nombre:"web pr');
    expect(p.issues.map((i) => i.kind)).toEqual(['unclosed_quote']);
    expect(p.terms.map((t) => t.value)).toEqual(['prod', 'web pr']);
    expect(inv('"').terms).toEqual([]);
  });

  it('valores no válidos, vacíos, de la otra vista o sin datos: se ignoran con aviso', () => {
    const p = inv('tipo:foo tag: cve:CVE-2024 sitio:madrid ip:abc estado:x');
    expect(p.terms).toEqual([]);
    expect(p.issues.map((i) => i.kind)).toEqual([
      'invalid_value',
      'empty_value',
      'wrong_scope',
      'unsupported',
      'invalid_value',
      'invalid_value',
    ]);
    const v = parseSearchQuery(
      'prioridad:alta -prioridad:Urgente cve:CVE-2024 prioridad:x',
      'vulnerabilities',
    );
    expect(v.issues.map((i) => i.kind)).toEqual(['invalid_value']);
    expect(v.terms).toMatchObject([
      { key: 'priority', value: 'high', negated: false },
      { key: 'priority', value: 'urgent', negated: true },
      { key: 'cve' },
    ]);
  });

  it('casos raros sin lanzar', () => {
    for (const q of [
      '',
      '   ',
      ':',
      '::1',
      '-',
      '- -',
      'a:',
      ':b',
      '-"',
      'tag:"',
      '"a" "b',
      'ñandú:x',
      '\u0000',
      '\t\n',
    ]) {
      expect(() => inv(q)).not.toThrow();
    }
    expect(inv('::1').terms).toMatchObject([{ key: null, value: '::1' }]);
    expect(inv('-').terms).toEqual([]);
    expect(parseSearchQuery(null, 'inventory')).toEqual({
      terms: [],
      issues: [],
    });
  });

  it('corta lo demasiado largo', () => {
    const long = inv('a'.repeat(600));
    expect(long.issues.map((i) => i.kind)).toEqual(['too_long']);
    expect(long.terms[0]!.value).toHaveLength(500);
    const many = inv(Array.from({ length: 40 }, (_, i) => `w${i}`).join(' '));
    expect(many.terms).toHaveLength(30);
    expect(many.issues).toHaveLength(10);
  });

  it('nunca lanza con entradas aleatorias', () => {
    const alphabet = [
      'a',
      'é',
      ':',
      '"',
      '-',
      ' ',
      'tag',
      'ip',
      '/',
      '.',
      '1',
      '\\',
      '\n',
    ];
    let seed = 42;
    const rand = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
    for (let i = 0; i < 2000; i++) {
      const q = Array.from(
        { length: Math.floor(rand() * 30) },
        () => alphabet[Math.floor(rand() * alphabet.length)],
      ).join('');
      for (const scope of ['inventory', 'vulnerabilities'] as const) {
        const p = parseSearchQuery(q, scope);
        expect(() => matchesInventoryQuery(node('x'), p)).not.toThrow();
        for (const t of [...p.terms, ...p.issues])
          expect(q.slice(t.start, t.end)).toBe(t.raw);
      }
    }
  });
});

describe('matchesInventoryQuery', () => {
  const web = node('hola-web', { tags: ['prueba'], roles: ['docker-host'] });
  const other = node('hola-db', { tags: ['prueba-2'] });
  const tagged = node('adios', {
    tags: ['prueba'],
    discoveredName: 'hola-old',
  });

  it('tag:prueba nombre:hola: tag exacto y nombre parcial', () => {
    const q = inv('tag:prueba nombre:hola');
    expect(
      [web, other, tagged]
        .filter((n) => matchesInventoryQuery(n, q))
        .map((n) => n.id),
    ).toEqual([
      'hola-web',
      'adios', // por el nombre descubierto
    ]);
  });

  it('el texto libre busca solo en el nombre, nunca en tags ni roles', () => {
    expect(matchesInventoryText(web, 'prueba')).toBe(false);
    expect(matchesInventoryText(web, 'docker')).toBe(false);
    expect(matchesInventoryText(web, 'WEB')).toBe(true);
    expect(matchesInventoryText(tagged, 'old')).toBe(true);
    expect(matchesInventoryText(web, '')).toBe(true);
  });

  it('negación, O y roles', () => {
    expect(matchesInventoryText(web, '-tag:prueba')).toBe(false);
    expect(matchesInventoryText(other, '-tag:prueba')).toBe(true);
    expect(matchesInventoryText(other, 'tag:prueba tag:prueba-2')).toBe(true);
    expect(matchesInventoryText(web, 'rol:Docker-Host')).toBe(true);
    expect(matchesInventoryText(web, 'rol:docker')).toBe(false);
  });

  it('tipo, estado de inventario y de ejecución', () => {
    const ct = node('ct', { type: 'lxc', runtimeState: 'stopped' });
    expect(matchesInventoryText(ct, 'tipo:ct estado:parado')).toBe(true);
    expect(matchesInventoryText(ct, 'tipo:servidor')).toBe(false);
    expect(matchesInventoryText(ct, 'estado:activo')).toBe(true);
    expect(matchesInventoryText(ct, '-estado:retirado')).toBe(true);
  });

  it('proyecto por nombre o id', () => {
    const projects = [{ id: 'p1', name: 'Clientes Web' }];
    const n = node('n', { projects: ['p1'] });
    expect(
      matchesInventoryText(n, 'proyecto:"clientes web"', { projects }),
    ).toBe(true);
    expect(matchesInventoryText(n, 'project:p1', { projects })).toBe(true);
    expect(matchesInventoryText(n, 'proyecto:otro', { projects })).toBe(false);
  });

  it('ip exacta, prefijo y red', () => {
    const n = node('n', { ips: ['10.0.0.12', 'fd00::1'] });
    expect(matchesInventoryText(n, 'ip:10.0.0.12')).toBe(true);
    expect(matchesInventoryText(n, 'ip:10.0.0.1')).toBe(false);
    expect(matchesInventoryText(n, 'ip:10.0.')).toBe(true);
    expect(matchesInventoryText(n, 'ip:10.0.0.0/24')).toBe(true);
    expect(matchesInventoryText(n, 'ip:10.0.1.0/24')).toBe(false);
    expect(matchesInventoryText(n, 'ip:fd00::1')).toBe(true);
    expect(matchesInventoryText(n, 'ip:fd00:')).toBe(true);
  });

  it('las claves ignoradas no filtran', () => {
    expect(matchesInventoryText(web, 'sitio:madrid tipo:foo')).toBe(true);
  });

  it('filterTree conserva los antepasados y abre sus ramas', () => {
    const tree = [
      node('pve', {
        children: [
          node('ct', { children: [node('hola', { tags: ['prueba'] })] }),
          node('x'),
        ],
      }),
    ];
    const r = filterTree(tree, (n) =>
      matchesInventoryText(n, 'tag:prueba nombre:hola'),
    );
    expect(r.matches).toBe(1);
    expect(r.expand).toEqual(['ct', 'pve']);
    expect(r.nodes[0]!.children.map((c) => c.id)).toEqual(['ct']);
  });
});

describe('utilidades', () => {
  it('removeSearchToken quita un término sin tocar el resto', () => {
    const q = 'tag:a  nombre:"x y"  -tag:b';
    const term = inv(q).terms[1]!;
    expect(removeSearchToken(q, term)).toBe('tag:a -tag:b');
  });

  it('formatSearchTerm pone comillas cuando hace falta', () => {
    expect(formatSearchTerm('tag', 'prod')).toBe('tag:prod');
    expect(formatSearchTerm('proyecto', 'Clientes Web', true)).toBe(
      '-proyecto:"Clientes Web"',
    );
  });

  it('ipMatcher rechaza lo que no es una IP', () => {
    expect(ipMatcher('300.1.1.1')).toBeNull();
    expect(ipMatcher('10.0.0.0/40')).toBeNull();
    expect(ipMatcher('abc')).toBeNull();
    expect(ipMatches(ipMatcher('0.0.0.0/0')!, '8.8.8.8')).toBe(true);
  });
});
