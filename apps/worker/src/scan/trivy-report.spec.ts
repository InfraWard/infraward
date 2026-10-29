import { readFileSync } from 'node:fs';
import {
  cvssScore,
  findingFingerprint,
  parseTrivyReport,
  TrivyError,
} from './trivy-report.js';

/** Informe real de Trivy 0.75 sobre nginx:1.25 (recortado a 3 vulnerabilidades). */
const NGINX = readFileSync(
  new URL('./fixtures/nginx-1.25.json', import.meta.url),
  'utf8',
);

describe('parseTrivyReport', () => {
  it('normaliza las vulnerabilidades de un informe real', () => {
    const scan = parseTrivyReport(NGINX);
    expect(scan.configDigest).toBe(
      'sha256:e784f4560448b14a66f55c26e1b4dad2c2877cc73d001b7cd0b18e24a700a070',
    );
    expect(scan.trivyVersion).toBe('0.75.0');
    expect(scan.vulnerabilities).toHaveLength(3);
    expect(scan.vulnerabilities[1]).toEqual({
      vulnerabilityId: 'CVE-2025-0838',
      packageName: 'libabsl20220623',
      installedVersion: '20220623.1-1',
      fixedVersion: '20220623.1-1+deb12u1',
      severity: 'CRITICAL',
      title: expect.any(String) as string,
      fixStatus: 'fixed',
      class: 'os-pkgs',
      pkgType: 'debian',
      pkgPath: null,
      purl: expect.stringContaining('pkg:deb/debian/libabsl20220623') as string,
      primaryUrl: expect.stringContaining('cve-2025-0838') as string,
      cvss: null,
      fingerprint: findingFingerprint([
        'CVE-2025-0838',
        'libabsl20220623',
        '20220623.1-1',
        'os-pkgs',
        'debian',
        '',
      ]),
    });
    // Sin versión corregida.
    expect(scan.vulnerabilities[0].fixedVersion).toBeNull();
  });

  it('el fingerprint no depende de la ruta temporal del tar (Target)', () => {
    const moved = NGINX.replaceAll('scan-XXXX', 'scan-YYYY');
    expect(
      parseTrivyReport(moved).vulnerabilities.map((v) => v.fingerprint),
    ).toEqual(
      parseTrivyReport(NGINX).vulnerabilities.map((v) => v.fingerprint),
    );
  });

  it('quita duplicados y normaliza severidades desconocidas', () => {
    const report = JSON.parse(NGINX) as {
      Results: { Vulnerabilities: Record<string, unknown>[] }[];
    };
    const vulns = report.Results[0].Vulnerabilities;
    vulns.push(
      { ...vulns[0] },
      { ...vulns[1], Severity: 'rarísima', VulnerabilityID: 'CVE-1' },
    );
    const scan = parseTrivyReport(JSON.stringify(report));
    expect(scan.vulnerabilities).toHaveLength(4);
    expect(scan.vulnerabilities[3].severity).toBe('UNKNOWN');
  });

  it('sin vulnerabilidades o sin resultados: lista vacía', () => {
    expect(
      parseTrivyReport(JSON.stringify({ SchemaVersion: 2 })).vulnerabilities,
    ).toEqual([]);
    expect(
      parseTrivyReport(
        JSON.stringify({ SchemaVersion: 2, Results: [{ Target: 'x' }] }),
      ).vulnerabilities,
    ).toEqual([]);
  });

  it('rechaza lo que no es un informe de Trivy', () => {
    expect(() => parseTrivyReport('no json')).toThrow(TrivyError);
    expect(() => parseTrivyReport('{"SchemaVersion":1}')).toThrow(TrivyError);
  });
});

describe('cvssScore', () => {
  it('NVD primero; en cada fuente, V3, si no V4.0 o V2', () => {
    expect(
      cvssScore({
        ghsa: { V3Score: 5.3 },
        nvd: { V2Score: 5, V3Score: 9.8 },
        redhat: { V3Score: 7.5 },
      }),
    ).toBe(9.8);
    expect(
      cvssScore({ redhat: { V3Score: 7.5 }, ghsa: { V40Score: 8.7 } }),
    ).toBe(8.7);
    expect(cvssScore({ nvd: { V2Score: 4.3 } })).toBe(4.3);
  });

  it('sin puntuación válida, null', () => {
    expect(cvssScore(undefined)).toBeNull();
    expect(cvssScore({ nvd: { V3Vector: 'CVSS:3.1/AV:N' } })).toBeNull();
    expect(cvssScore({ nvd: { V3Score: 11 } })).toBeNull();
    expect(cvssScore([1, 2])).toBeNull();
  });

  it('se lee del informe', () => {
    const report = JSON.parse(NGINX) as {
      Results: { Vulnerabilities: Record<string, unknown>[] }[];
    };
    report.Results[0].Vulnerabilities[0].CVSS = { nvd: { V3Score: 7.5 } };
    expect(
      parseTrivyReport(JSON.stringify(report)).vulnerabilities[0].cvss,
    ).toBe(7.5);
  });
});
