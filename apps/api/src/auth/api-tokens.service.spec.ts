import { BadRequestException, ConflictException } from '@nestjs/common';
import type { Repository } from 'typeorm';
import type { AuditService } from '../audit/audit.service.js';
import type { ApiToken } from './api-token.entity.js';
import { ApiTokensService, isApiTokenActive } from './api-tokens.service.js';
import { hashSessionToken } from './session.service.js';

const DAY = 24 * 60 * 60 * 1000;
const actor = { actorId: 'u1', actorEmail: 'a@b.c', ip: '10.0.0.1' };

function token(overrides: Partial<ApiToken> = {}): ApiToken {
  return {
    id: 't1',
    userId: 'u1',
    name: 'script',
    prefix: 'iwt_abcdefgh',
    tokenHash: Buffer.alloc(32),
    scope: 'read',
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + DAY),
    lastUsedAt: null,
    lastUsedIp: null,
    revokedAt: null,
    revokedById: null,
    user: { id: 'u1', disabledAt: null } as ApiToken['user'],
    ...overrides,
  } as ApiToken;
}

function setup(existing: ApiToken[] = [], found: ApiToken | null = null) {
  const saved: ApiToken[] = [];
  const repo = {
    find: vi.fn(async () => existing),
    findOne: vi.fn(async () => found),
    update: vi.fn(async () => ({ affected: 1 })),
    create: (v: Partial<ApiToken>) => v as ApiToken,
    save: vi.fn(async (v: ApiToken) => {
      const row = { ...v, id: 'new', createdAt: new Date() } as ApiToken;
      saved.push(row);
      return row;
    }),
  };
  const manager = {
    query: vi.fn(async () => []),
    getRepository: () => repo,
    transaction: async (fn: (m: unknown) => unknown) => fn(manager),
  };
  const audit = { record: vi.fn(async () => undefined) };
  const service = new ApiTokensService(
    { ...repo, manager } as unknown as Repository<ApiToken>,
    audit as unknown as AuditService,
  );
  return { service, repo, audit, saved };
}

describe('ApiTokensService', () => {
  it('crea un token iwt_ y solo guarda su sha256 y el prefijo', async () => {
    const { service, saved, audit } = setup();
    const res = await service.create(
      'u1',
      {
        name: ' ci ',
        scope: 'read',
        expiresAt: new Date(Date.now() + 30 * DAY).toISOString(),
      },
      actor,
    );
    expect(res.secret).toMatch(/^iwt_[A-Za-z0-9_-]{43}$/);
    expect(saved[0].tokenHash.equals(hashSessionToken(res.secret))).toBe(true);
    expect(saved[0].prefix).toBe(res.secret.slice(0, 12));
    expect(saved[0].name).toBe('ci');
    expect(JSON.stringify(saved[0])).not.toContain(res.secret);
    expect(JSON.stringify(res.token)).not.toContain(res.secret);
    expect(JSON.stringify(audit.record.mock.calls)).not.toContain(res.secret);
  });

  it('caducidad obligatoria: futura y como mucho a un año', async () => {
    const { service } = setup();
    const create = (ms: number) =>
      service.create(
        'u1',
        {
          name: 'x',
          scope: 'role',
          expiresAt: new Date(Date.now() + ms).toISOString(),
        },
        actor,
      );
    await expect(create(-1000)).rejects.toBeInstanceOf(BadRequestException);
    await expect(create(366 * DAY)).rejects.toBeInstanceOf(BadRequestException);
    await expect(create(365 * DAY)).resolves.toBeDefined();
  });

  it('nombre único entre los vigentes y tope de 25', async () => {
    const future = new Date(Date.now() + 30 * DAY).toISOString();
    await expect(
      setup([token({ name: 'CI' })]).service.create(
        'u1',
        { name: 'ci', scope: 'read', expiresAt: future },
        actor,
      ),
    ).rejects.toBeInstanceOf(ConflictException);
    // Uno revocado con el mismo nombre no cuenta.
    await expect(
      setup([token({ name: 'ci', revokedAt: new Date() })]).service.create(
        'u1',
        { name: 'ci', scope: 'read', expiresAt: future },
        actor,
      ),
    ).resolves.toBeDefined();
    const many = Array.from({ length: 25 }, (_, i) =>
      token({ id: `t${i}`, name: `n${i}` }),
    );
    await expect(
      setup(many).service.create(
        'u1',
        { name: 'otro', scope: 'read', expiresAt: future },
        actor,
      ),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('resolve: rechaza lo que no es un token nuestro sin ir a la BD', async () => {
    const { service, repo } = setup();
    await expect(service.resolve('abc', null)).resolves.toBeNull();
    await expect(
      service.resolve('iwt_' + 'x'.repeat(100), null),
    ).resolves.toBeNull();
    expect(repo.findOne).not.toHaveBeenCalled();
  });

  it('resolve: caducado, revocado o usuario desactivado → null', async () => {
    for (const t of [
      token({ expiresAt: new Date(Date.now() - 1) }),
      token({ revokedAt: new Date() }),
      token({ user: { id: 'u1', disabledAt: new Date() } as ApiToken['user'] }),
    ]) {
      await expect(
        setup([], t).service.resolve('iwt_x', null),
      ).resolves.toBeNull();
    }
  });

  it('resolve: anota el último uso como mucho una vez por minuto (o si cambia la IP)', async () => {
    const fresh = token({ lastUsedAt: new Date(), lastUsedIp: '10.0.0.1' });
    const a = setup([], fresh);
    await expect(
      a.service.resolve('iwt_x', '10.0.0.1'),
    ).resolves.not.toBeNull();
    expect(a.repo.update).not.toHaveBeenCalled();
    const b = setup(
      [],
      token({ lastUsedAt: new Date(), lastUsedIp: '10.0.0.1' }),
    );
    await b.service.resolve('iwt_x', '10.0.0.2');
    expect(b.repo.update).toHaveBeenCalledWith(
      { id: 't1' },
      expect.objectContaining({ lastUsedIp: '10.0.0.2' }),
    );
    const c = setup(
      [],
      token({
        lastUsedAt: new Date(Date.now() - 2 * 60_000),
        lastUsedIp: '10.0.0.1',
      }),
    );
    await c.service.resolve('iwt_x', '10.0.0.1');
    expect(c.repo.update).toHaveBeenCalled();
  });

  it('isApiTokenActive', () => {
    expect(isApiTokenActive(token())).toBe(true);
    expect(isApiTokenActive(token({ revokedAt: new Date() }))).toBe(false);
    expect(
      isApiTokenActive(token({ expiresAt: new Date(Date.now() - 1) })),
    ).toBe(false);
  });
});
