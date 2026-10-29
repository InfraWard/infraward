import {
  enrollmentPhase,
  parseHostKeyFingerprints,
  severitiesAtLeast,
  type EnrollmentJobProgress,
} from '@infraward/shared-types';

// Reglas puras de shared-types que comparten la API y la web.

const FP1 = `SHA256:${'a'.repeat(43)}`;
const FP2 = `SHA256:${'B/+9'.repeat(10)}xyz`;

describe('parseHostKeyFingerprints', () => {
  it('lee la salida del script embebido con sus marcas', () => {
    const text = [
      '[infraward] Hecho. Pega en InfraWard las huellas…',
      '',
      '----- infraward host keys -----',
      `ED25519 ${FP1}`,
      `RSA ${FP2}`,
      '----- fin -----',
    ].join('\n');
    expect(parseHostKeyFingerprints(text)).toEqual([
      { type: 'ED25519', fingerprint: FP1 },
      { type: 'RSA', fingerprint: FP2 },
    ]);
  });

  it('lee la salida de ssh-keygen -lf (y CRLF) y quita duplicados', () => {
    const text = `256 ${FP1} root@pve (ED25519)\r\n3072 ${FP2} root@pve (RSA)\r\ned25519 ${FP1}\r\n`;
    expect(parseHostKeyFingerprints(text)).toEqual([
      { type: 'ED25519', fingerprint: FP1 },
      { type: 'RSA', fingerprint: FP2 },
    ]);
  });

  it('ignora huellas sin tipo, tipos desconocidos, MD5 y longitudes erróneas', () => {
    expect(
      parseHostKeyFingerprints(
        [
          FP1,
          `DSA ${FP1}`,
          'ED25519 MD5:aa:bb:cc',
          `ED25519 SHA256:${'a'.repeat(42)}`,
          `ED25519 SHA256:${'a'.repeat(44)}`,
          'texto cualquiera',
        ].join('\n'),
      ),
    ).toEqual([]);
  });
});

describe('enrollmentPhase', () => {
  const job = (
    name: EnrollmentJobProgress['name'],
    state: EnrollmentJobProgress['state'],
  ) => ({ name, state });

  it('pendiente, confirmado, fallido y cancelado', () => {
    expect(enrollmentPhase('pending', [])).toBe('waiting');
    expect(enrollmentPhase('confirmed', [])).toBe('connecting');
    expect(
      enrollmentPhase('failed', [job('enrollment.verify', 'failed')]),
    ).toBe('failed');
    expect(enrollmentPhase('cancelled', [])).toBe('cancelled');
  });

  it('verificado: conectando mientras el verify no termina (aún no encoló nada)', () => {
    expect(
      enrollmentPhase('verified', [job('enrollment.verify', 'active')]),
    ).toBe('connecting');
  });

  it('verificado: escaneando con jobs encadenados en marcha y listo al acabar', () => {
    const verify = job('enrollment.verify', 'completed');
    expect(
      enrollmentPhase('verified', [verify, job('asset.collect', 'waiting')]),
    ).toBe('scanning');
    expect(
      enrollmentPhase('verified', [
        verify,
        job('asset.collect', 'completed'),
        job('asset.discover', 'completed'),
        job('image.scan', 'active'),
      ]),
    ).toBe('scanning');
    // Un fallo de la cadena no impide terminar; los jobs caducados cuentan como terminados.
    expect(
      enrollmentPhase('verified', [
        verify,
        job('asset.collect', 'failed'),
        job('image.scan', 'unknown'),
      ]),
    ).toBe('ready');
    expect(enrollmentPhase('verified', [])).toBe('ready');
  });
});

describe('severitiesAtLeast', () => {
  it('incluye la mínima y las más graves', () => {
    expect(severitiesAtLeast('MEDIUM')).toEqual(['MEDIUM', 'HIGH', 'CRITICAL']);
    expect(severitiesAtLeast('UNKNOWN')).toHaveLength(5);
    expect(severitiesAtLeast('CRITICAL')).toEqual(['CRITICAL']);
  });
});
