import { readFileSync } from 'node:fs';
import { parseCycloneDx } from './sbom.js';
import { TrivyError } from './trivy-report.js';

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

/** `trivy image --format cyclonedx` de nginx:1.25 (recortado a 8 paquetes). */
const IMAGE = fixture('sbom-image.cdx.json');
/** `trivy rootfs --format cyclonedx` de una copia de dpkg (Debian 13) con dos paquetes npm. */
const ROOTFS = fixture('sbom-rootfs.cdx.json');

describe('parseCycloneDx', () => {
  it('SBOM de una imagen: SO, ImageID, paquetes con purl y sin las etiquetas de la imagen', () => {
    const sbom = parseCycloneDx(IMAGE);
    expect(sbom.specVersion).toBe('1.7');
    expect(sbom.trivyVersion).toBe('0.75.0');
    expect(sbom.os).toEqual({ family: 'debian', name: '12.5' });
    expect(sbom.imageId).toBe(
      'sha256:8dd77ef2d82eade8dcf2c08ea032bd9cba04c9d28ace2ccf08ad6804c27bf14f',
    );
    expect(sbom.packages).toHaveLength(8);
    expect(sbom.packages).toContainEqual({
      name: 'adduser',
      version: '3.134',
      ecosystem: 'deb',
      purl: 'pkg:deb/debian/adduser@3.134?arch=all&distro=debian-12.5',
      pkgPath: null,
    });
    // Lo guardado no lleva etiquetas (pueden llevar secretos) ni vulnerabilidades.
    expect(IMAGE).toContain('aquasecurity:trivy:Labels:maintainer');
    expect(IMAGE).toContain('"vulnerabilities"');
    expect(sbom.json).not.toContain('Labels');
    expect(JSON.parse(sbom.json)).not.toHaveProperty('vulnerabilities');
    // El resto del documento se conserva para que `trivy sbom` lo entienda igual.
    expect(sbom.json).toContain('aquasecurity:trivy:DiffID');
    expect(JSON.parse(sbom.json).components).toHaveLength(9);
  });

  it('SBOM de un rootfs: paquetes del SO y de lenguajes con su ruta y su grupo', () => {
    const sbom = parseCycloneDx(ROOTFS);
    expect(sbom.os).toEqual({ family: 'debian', name: '13.7' });
    expect(sbom.imageId).toBeNull();
    expect(sbom.packages.filter((p) => p.ecosystem === 'deb')).toHaveLength(5);
    expect(sbom.packages).toContainEqual({
      name: '@acme/util',
      version: '1.2.3',
      ecosystem: 'npm',
      purl: 'pkg:npm/%40acme/util@1.2.3',
      pkgPath: 'app/node_modules/@acme/util/package.json',
    });
  });

  it('Maven: grupo:artefacto, como en los findings de Trivy', () => {
    const sbom = parseCycloneDx(
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        components: [
          {
            type: 'library',
            group: 'org.apache.logging.log4j',
            name: 'log4j-core',
            version: '2.14.1',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            components: [
              {
                type: 'library',
                name: 'anidado',
                version: '1',
                purl: 'pkg:pypi/anidado@1',
              },
            ],
          },
          { type: 'application', name: 'app/pom.xml' },
        ],
      }),
    );
    expect(sbom.packages.map((p) => [p.name, p.ecosystem]).sort()).toEqual([
      ['anidado', 'pypi'],
      ['org.apache.logging.log4j:log4j-core', 'maven'],
    ]);
    expect(sbom.os).toBeNull();
  });

  it('la huella de paquetes no depende del orden, de la fecha ni de los bom-ref aleatorios', () => {
    const a = parseCycloneDx(ROOTFS);
    const doc = JSON.parse(ROOTFS) as {
      serialNumber: string;
      metadata: { timestamp: string };
      components: { 'bom-ref': string }[];
    };
    doc.serialNumber = 'urn:uuid:otro';
    doc.metadata.timestamp = '2030-01-01T00:00:00Z';
    doc.components.reverse();
    doc.components[0]['bom-ref'] = 'otro';
    const b = parseCycloneDx(JSON.stringify(doc));
    expect(b.packagesSha256).toBe(a.packagesSha256);

    // Otra versión de un paquete ⇒ otra huella.
    const changed = ROOTFS.replace(
      '"version": "4.17.20"',
      '"version": "4.17.21"',
    );
    expect(parseCycloneDx(changed).packagesSha256).not.toBe(a.packagesSha256);
  });

  it.each([
    ['no es JSON', 'no json', /no es JSON/],
    ['no es CycloneDX', '{"bomFormat":"SPDX"}', /no reconocido/],
    ['sin specVersion', '{"bomFormat":"CycloneDX"}', /no reconocido/],
  ])('rechaza un SBOM que %s', (_name, json, error) => {
    expect(() => parseCycloneDx(json)).toThrow(TrivyError);
    expect(() => parseCycloneDx(json)).toThrow(error);
  });
});
