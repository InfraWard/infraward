import { exportFilename, toCsv } from './csv.js';

describe('toCsv', () => {
  it('cabecera, BOM, CRLF y listas en una celda', () => {
    const out = toCsv(
      ['name', 'tags', 'n'],
      [{ name: 'web1', tags: ['a', 'b'], n: 3 }],
    );
    expect(out.startsWith('\uFEFF')).toBe(true);
    expect(out.slice(1)).toBe('name,tags,n\r\nweb1,a; b,3\r\n');
  });

  it('comillas, comas y saltos de línea', () => {
    const out = toCsv(['v'], [{ v: 'a,"b"\nc' }]);
    expect(out.slice(1)).toBe('v\r\n"a,""b""\nc"\r\n');
  });

  it('neutraliza fórmulas (= + - @ tab CR) sin tocar los números', () => {
    const rows = ['=HYPERLINK("x")', '+1', '-2', '@SUM(A1)', '\tx', '\rx'].map(
      (v) => ({ v }),
    );
    const cells = toCsv(['v'], rows).slice(1).split('\r\n').slice(1, -1);
    expect(cells[0]).toBe(`"'=HYPERLINK(""x"")"`);
    expect(cells[1]).toBe("'+1");
    expect(cells[2]).toBe("'-2");
    expect(cells[3]).toBe("'@SUM(A1)");
    expect(cells.every((c) => c.replace(/^"/, '').startsWith("'"))).toBe(true);
    expect(toCsv(['n'], [{ n: -5 }]).slice(1)).toBe('n\r\n-5\r\n');
  });

  it('vacíos para null y undefined', () => {
    expect(toCsv(['a', 'b'], [{ a: null, b: undefined }]).slice(1)).toBe(
      'a,b\r\n,\r\n',
    );
  });
});

describe('exportFilename', () => {
  it('fecha y extensión, sin caracteres raros', () => {
    expect(
      exportFilename(
        'vulnerabilidades"; x',
        'csv',
        new Date(2026, 9, 18, 0, 30),
      ),
    ).toBe('infraward-vulnerabilidadesx-2026-10-18.csv');
  });
});
