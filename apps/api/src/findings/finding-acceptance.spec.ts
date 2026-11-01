import { BadRequestException } from '@nestjs/common';
import { FINDING_ACCEPT_MAX_DAYS } from '@infraward/shared-types';
import { describe, expect, it } from 'vitest';
import { acceptanceOf, acceptExpiry } from './finding-acceptance.service.js';

const NOW = new Date('2026-10-29T12:00:00Z');
const DAY = 86_400_000;

describe('acceptExpiry', () => {
  it('sin fecha, no caduca', () => {
    expect(acceptExpiry(undefined, NOW)).toBeNull();
    expect(acceptExpiry(null, NOW)).toBeNull();
  });

  it('una fecha futura dentro del plazo', () => {
    const at = new Date(NOW.getTime() + 90 * DAY).toISOString();
    expect(acceptExpiry(at, NOW)?.toISOString()).toBe(at);
  });

  it('rechaza el pasado, el ahora y más allá del máximo', () => {
    expect(() => acceptExpiry(NOW.toISOString(), NOW)).toThrow(BadRequestException);
    expect(() => acceptExpiry('2026-01-01T00:00:00Z', NOW)).toThrow(BadRequestException);
    const tooFar = new Date(NOW.getTime() + (FINDING_ACCEPT_MAX_DAYS + 1) * DAY);
    expect(() => acceptExpiry(tooFar.toISOString(), NOW)).toThrow(/365 días/);
  });
});

describe('acceptanceOf', () => {
  it('null si nunca se aceptó', () => {
    expect(
      acceptanceOf({
        accepted_at: null,
        accepted_by: null,
        accept_reason: null,
        accept_expires_at: null,
      }),
    ).toBeNull();
  });

  it('quién, cuándo, por qué y hasta cuándo', () => {
    expect(
      acceptanceOf({
        accepted_at: NOW,
        accepted_by: 'a@b.c',
        accept_reason: 'no explotable aquí',
        accept_expires_at: new Date(NOW.getTime() + DAY),
      }),
    ).toEqual({
      by: 'a@b.c',
      at: NOW.toISOString(),
      reason: 'no explotable aquí',
      expiresAt: '2026-10-30T12:00:00.000Z',
    });
  });
});
