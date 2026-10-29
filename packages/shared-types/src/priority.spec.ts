import { describe, expect, it } from 'vitest';
import {
  bandsAtLeast,
  PRIORITY_WEIGHTS,
  priorityBand,
  priorityExplanation,
  priorityReasonText,
  scoreFinding,
  type PriorityInput,
} from './priority.js';

const base: PriorityInput = {
  severity: 'HIGH',
  cvss: null,
  kev: null,
  epss: null,
  fixable: false,
  service: null,
  exposedPorts: [],
  runningContainers: 0,
  publicDomains: null,
  unusedImage: false,
  processData: true,
};
const score = (over: Partial<PriorityInput>) =>
  scoreFinding({ ...base, ...over }).score;

describe('pesos', () => {
  // Fijan los pesos: cambiar uno es una decisión (DESIGN §9), no un efecto colateral.
  it('son los acordados', () => {
    expect(PRIORITY_WEIGHTS).toMatchObject({
      cvss: 4,
      kev: 30,
      fixAvailable: 5,
      running: 5,
      exposedPort: 10,
      publicDomain: 10,
      unusedImageFactor: 0.5,
    });
    expect(PRIORITY_WEIGHTS.severityCvss).toEqual({
      CRITICAL: 9.5,
      HIGH: 7.5,
      MEDIUM: 5,
      LOW: 2.5,
      UNKNOWN: 4,
    });
    expect(PRIORITY_WEIGHTS.epss).toEqual([
      { min: 0.5, points: 15 },
      { min: 0.1, points: 10 },
      { min: 0.01, points: 4 },
    ]);
  });

  it('base: CVSS × 4 o la severidad si no hay CVSS', () => {
    expect(score({ cvss: 9.8 })).toBe(39);
    expect(score({ severity: 'CRITICAL' })).toBe(38);
    expect(score({ severity: 'MEDIUM' })).toBe(20);
    expect(score({ severity: 'LOW', cvss: 0 })).toBe(0);
  });

  it('cada factor suma su peso', () => {
    const b = score({});
    expect(score({ kev: { ransomware: false } }) - b).toBe(30);
    expect(score({ fixable: true }) - b).toBe(5);
    expect(
      score({ service: { process: 'nginx', unit: null, via: 'exe' } }) - b,
    ).toBe(5);
    expect(score({ runningContainers: 2 }) - b).toBe(5);
    expect(score({ exposedPorts: [443] }) - b).toBe(10);
    expect(score({ publicDomains: { domains: ['a.es'], total: 1 } }) - b).toBe(
      10,
    );
    expect(score({ epss: 0.6 }) - b).toBe(15);
    expect(score({ epss: 0.1 }) - b).toBe(10);
    expect(score({ epss: 0.02 }) - b).toBe(4);
    expect(score({ epss: 0.001 }) - b).toBe(0);
  });

  it('servicio y contenedor en marcha no se suman dos veces', () => {
    expect(
      score({
        service: { process: 'nginx', unit: null, via: 'exe' },
        runningContainers: 3,
      }),
    ).toBe(score({ runningContainers: 1 }));
  });

  it('una imagen sin uso vale la mitad y todo se acota a 0–100', () => {
    expect(score({ cvss: 8, fixable: true, unusedImage: true })).toBe(19);
    expect(
      score({
        cvss: 10,
        kev: { ransomware: true },
        epss: 0.9,
        fixable: true,
        exposedPorts: [22],
        publicDomains: { domains: ['x.es'], total: 1 },
        service: { process: 'sshd', unit: 'ssh.service', via: 'exe' },
      }),
    ).toBe(100);
  });
});

describe('bandas', () => {
  it('urgente ≥ 70, alta ≥ 50, media ≥ 30', () => {
    expect([0, 29, 30, 49, 50, 69, 70, 100].map(priorityBand)).toEqual([
      'low',
      'low',
      'medium',
      'medium',
      'high',
      'high',
      'urgent',
      'urgent',
    ]);
    expect(bandsAtLeast('high')).toEqual(['high', 'urgent']);
  });

  it('casos del diseño', () => {
    // OpenSSH en KEV, servicio activo y el 22 expuesto: máxima.
    expect(
      scoreFinding({
        ...base,
        severity: 'CRITICAL',
        cvss: 9.8,
        kev: { ransomware: false },
        fixable: true,
        service: { process: 'sshd', unit: 'ssh.service', via: 'exe' },
        exposedPorts: [22],
      }).band,
    ).toBe('urgent');
    // Librería en una imagen sin uso: mínima.
    expect(
      scoreFinding({ ...base, cvss: 7.5, fixable: true, unusedImage: true })
        .band,
    ).toBe('low');
    // Kernel en uso, MEDIUM sin parche: baja.
    expect(scoreFinding({ ...base, severity: 'MEDIUM', cvss: 5.5 }).band).toBe(
      'low',
    );
  });
});

describe('motivos', () => {
  it('van por peso, con el ruido delante y la base al final', () => {
    const r = scoreFinding({
      ...base,
      cvss: 8.1,
      kev: { ransomware: false },
      fixable: true,
      exposedPorts: [443, 80, 443],
      service: { process: 'nginx', unit: 'nginx.service', via: 'lib' },
      noise: [{ code: 'no_fix_planned', fixStatus: 'fix_deferred' }],
    });
    expect(r.reasons.map((x) => x.code)).toEqual([
      'no_fix_planned',
      'kev',
      'port',
      'service',
      'fix',
      'cvss',
    ]);
    expect(priorityExplanation(r.reasons.slice(1))).toBe(
      'en KEV · expuesto en 80, 443 (nginx) · cargado por nginx · parche disponible',
    );
  });

  it('dice cuándo faltan datos de procesos y si no hay parche', () => {
    const r = scoreFinding({ ...base, processData: false });
    expect(r.reasons.map(priorityReasonText)).toEqual([
      'sin parche aún',
      'severidad HIGH (sin CVSS)',
      'sin datos de procesos (sudoers v6)',
    ]);
  });

  it('textos', () => {
    expect(priorityReasonText({ code: 'epss', epss: 0.3412 })).toBe(
      'EPSS 34 %',
    );
    expect(priorityReasonText({ code: 'epss', epss: 0.004 })).toBe('EPSS <1 %');
    expect(priorityReasonText({ code: 'cvss', score: 9.8 })).toBe('CVSS 9,8');
    expect(
      priorityReasonText({
        code: 'public',
        domains: ['a.es', 'b.es'],
        total: 5,
      }),
    ).toBe('dominio público: a.es, b.es y 3 más');
    expect(
      priorityReasonText({
        code: 'port',
        ports: [1, 2, 3, 4, 5, 6],
        process: null,
      }),
    ).toBe('expuesto en 1, 2, 3, 4 y 2 más');
    expect(priorityReasonText({ code: 'container', running: 1 })).toBe(
      '1 contenedor en marcha',
    );
    expect(
      priorityReasonText({ code: 'kernel_other', running: '7.0.0-38-generic' }),
    ).toBe('kernel no en uso (en ejecución: 7.0.0-38-generic)');
    expect(priorityReasonText({ code: 'kev', ransomware: true })).toBe(
      'en KEV (usado por ransomware)',
    );
  });
});
