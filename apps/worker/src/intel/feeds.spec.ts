import { gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';
import {
  fetchConditional,
  IntelFeedError,
  parseEpss,
  parseKev,
  type FetchFn,
} from './feeds.js';

const KEV = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2026.10.18',
  count: 3,
  vulnerabilities: [
    {
      cveID: 'CVE-2024-3094',
      vulnerabilityName: 'XZ Utils Embedded Malicious Code',
      dateAdded: '2024-03-29',
      dueDate: '2024-04-19',
      knownRansomwareCampaignUse: 'Unknown',
    },
    {
      cveID: 'cve-2023-4966',
      vulnerabilityName: 'Citrix Bleed',
      dateAdded: '2023-10-18',
      dueDate: 'mañana',
      knownRansomwareCampaignUse: 'Known',
    },
    { cveID: 'no es un CVE' },
    { cveID: 'CVE-2024-3094' },
  ],
};

describe('parseKev', () => {
  it('normaliza, valida y quita duplicados', () => {
    expect(parseKev(Buffer.from(JSON.stringify(KEV)))).toEqual({
      version: '2026.10.18',
      entries: [
        {
          vulnerabilityId: 'CVE-2024-3094',
          added: '2024-03-29',
          due: '2024-04-19',
          ransomware: false,
          name: 'XZ Utils Embedded Malicious Code',
        },
        {
          vulnerabilityId: 'CVE-2023-4966',
          added: '2023-10-18',
          due: null,
          ransomware: true,
          name: 'Citrix Bleed',
        },
      ],
    });
  });

  it('lo que no es el catálogo, error sin el cuerpo', () => {
    for (const body of [
      '<html>centinela</html>',
      '{"vulnerabilities":[]}',
      '{"x":1}',
    ]) {
      const fn = () => parseKev(Buffer.from(body));
      expect(fn).toThrow(IntelFeedError);
      expect(fn).not.toThrow(/centinela/);
    }
  });
});

const EPSS_CSV = `#model_version:v2025.03.14,score_date:2026-10-18T12:55:00Z
cve,epss,percentile
CVE-2024-3094,0.85012,0.99321
CVE-2023-4966,0.94,
CVE-1999-0001,7,0.5
basura
`;

describe('parseEpss', () => {
  it('con gzip y sin él', () => {
    const expected = {
      version: '2026-10-18',
      rows: [
        {
          vulnerabilityId: 'CVE-2024-3094',
          epss: 0.85012,
          percentile: 0.99321,
        },
        { vulnerabilityId: 'CVE-2023-4966', epss: 0.94, percentile: null },
      ],
    };
    expect(parseEpss(gzipSync(EPSS_CSV))).toEqual(expected);
    expect(parseEpss(Buffer.from(EPSS_CSV))).toEqual(expected);
  });

  it('gzip roto o sin cabecera: error', () => {
    const broken = gzipSync(EPSS_CSV).subarray(0, 20);
    expect(() => parseEpss(broken)).toThrow('no se pudo descomprimir');
    expect(() => parseEpss(Buffer.from('a,b\n1,2\n'))).toThrow('no reconocido');
  });
});

function response(
  status: number,
  body = '',
  headers: Record<string, string> = {},
) {
  return new Response(status === 304 ? null : body, { status, headers });
}

describe('fetchConditional', () => {
  it('manda la caché y un 304 no descarga', async () => {
    const fetchFn = vi.fn<FetchFn>().mockResolvedValue(response(304));
    await expect(
      fetchConditional(
        'https://x/kev.json',
        { etag: '"abc"', lastModified: 'Sat, 18 Oct 2026 10:00:00 GMT' },
        1000,
        fetchFn,
      ),
    ).resolves.toEqual({ status: 'not_modified' });
    expect(fetchFn.mock.calls[0][1]?.headers).toMatchObject({
      'if-none-match': '"abc"',
      'if-modified-since': 'Sat, 18 Oct 2026 10:00:00 GMT',
    });
  });

  it('200: cuerpo con su ETag y Last-Modified', async () => {
    const fetchFn = vi
      .fn<FetchFn>()
      .mockResolvedValue(
        response(200, 'hola', { etag: '"v2"', 'last-modified': 'x' }),
      );
    const r = await fetchConditional(
      'https://x',
      { etag: null, lastModified: null },
      1000,
      fetchFn,
    );
    expect(r).toMatchObject({ status: 'ok', etag: '"v2"', lastModified: 'x' });
    expect(r.status === 'ok' && r.body.toString()).toBe('hola');
  });

  it('errores: estado HTTP, red, tiempo y tamaño, sin el cuerpo', async () => {
    const call = (fetchFn: FetchFn, max?: number) =>
      fetchConditional(
        'https://x',
        { etag: null, lastModified: null },
        1000,
        fetchFn,
        max,
      );
    await expect(
      call(vi.fn<FetchFn>().mockResolvedValue(response(503, 'centinela'))),
    ).rejects.toThrow(/^HTTP 503$/);
    await expect(
      call(vi.fn<FetchFn>().mockRejectedValue(new TypeError('fetch failed'))),
    ).rejects.toThrow('no se pudo conectar');
    const timeout = Object.assign(new Error('t'), { name: 'TimeoutError' });
    await expect(
      call(vi.fn<FetchFn>().mockRejectedValue(timeout)),
    ).rejects.toThrow('sin respuesta en 1 s');
    await expect(
      call(
        vi.fn<FetchFn>().mockResolvedValue(response(200, 'x'.repeat(100))),
        10,
      ),
    ).rejects.toThrow('demasiado grande');
  });
});
