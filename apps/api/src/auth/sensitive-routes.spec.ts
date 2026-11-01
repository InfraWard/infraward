import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants.js';
import { RequestMethod } from '@nestjs/common';
import { SENSITIVE_ACTIONS } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RECENT_AUTH, type RecentAuthRule } from './recent-auth.decorator.js';

/**
 * La lista de acciones sensibles vive en un único sitio (DESIGN §14): `SENSITIVE_ACTIONS` y
 * `@RecentAuth()` en cada ruta. Este test recorre todos los controladores y exige que las rutas
 * marcadas sean exactamente estas (añadir o quitar una obliga a cambiar la tabla).
 */
const EXPECTED: Record<string, string> = {
  'DELETE /assets/:id': 'asset.purge',
  'PATCH /users/:id': 'user.role_change',
  'POST /users/:id/deactivate': 'user.deactivate',
  'POST /users/:id/mfa/reset': 'user.mfa_reset',
  'POST /auth/tokens': 'api_token.create_write',
  'POST /auth/mfa/setup': 'mfa.replace',
  'POST /auth/mfa/disable': 'mfa.disable',
  'POST /auth/mfa/recovery-codes': 'mfa.recovery_regenerate',
  'POST /vault/entries/:id/reveal': 'vault.reveal',
  'POST /vault/entries/:id/versions/:version/restore': 'vault.version_restore',
  'PUT /vault/settings': 'vault.settings_change',
  'POST /terminal/sessions': 'terminal.open',
  'POST /assets/:id/enrollment/token': 'admin_access.enable',
  'POST /assets/enroll': 'admin_access.enable',
  'POST /access-policies': 'access.grant',
  'POST /alerts/channels': 'alerts.channel_change',
  'PATCH /alerts/channels/:id': 'alerts.channel_change',
  'DELETE /alerts/channels/:id': 'alerts.channel_change',
};
/** Acciones sin endpoint todavía. */
const NOT_YET: string[] = [];

const SRC = fileURLToPath(new URL('..', import.meta.url));
let controllers: Record<string, unknown>[] = [];

beforeAll(async () => {
  const files = readdirSync(SRC, { recursive: true, encoding: 'utf8' }).filter((f) =>
    f.endsWith('.controller.ts'),
  );
  expect(files.length).toBeGreaterThan(20);
  controllers = await Promise.all(
    files.map((f) => import(join(SRC, f)) as Promise<Record<string, unknown>>),
  );
});

function routes(): Map<string, RecentAuthRule> {
  const found = new Map<string, RecentAuthRule>();
  for (const mod of controllers) {
    for (const exported of Object.values(mod)) {
      if (typeof exported !== 'function') continue;
      const base = Reflect.getMetadata(PATH_METADATA, exported) as string | undefined;
      if (base === undefined) continue;
      const proto = (exported as { prototype: object }).prototype;
      for (const name of Object.getOwnPropertyNames(proto)) {
        const handler = (proto as Record<string, unknown>)[name];
        if (typeof handler !== 'function') continue;
        const rule = Reflect.getMetadata(RECENT_AUTH, handler) as RecentAuthRule | undefined;
        if (!rule) continue;
        const method = RequestMethod[Reflect.getMetadata(METHOD_METADATA, handler) as number];
        const path = Reflect.getMetadata(PATH_METADATA, handler) as string;
        const full = `/${[base, path].filter((p) => p && p !== '/').join('/')}`;
        found.set(`${method} ${full}`, rule);
      }
    }
  }
  return found;
}

const request = (fields: Partial<FastifyRequest>) => fields as FastifyRequest;

describe('rutas que exigen reautenticación reciente', () => {
  it('son exactamente las de la tabla', () => {
    const actual = Object.fromEntries(
      [...routes()].map(([route, rule]) => [route, rule.action]),
    );
    expect(actual).toEqual(EXPECTED);
  });

  it('toda acción de SENSITIVE_ACTIONS tiene ruta o está pendiente', () => {
    const used = new Set(Object.values(EXPECTED));
    for (const action of Object.keys(SENSITIVE_ACTIONS))
      expect(used.has(action) || NOT_YET.includes(action), action).toBe(true);
  });

  it('las condiciones: purgar sí, retirar no; rol sí, nombre no; token de escritura sí', () => {
    const all = routes();
    const purge = all.get('DELETE /assets/:id')!.when!;
    expect(purge(request({ query: { purge: 'true' } }))).toBe(true);
    expect(purge(request({ query: {} }))).toBe(false);
    expect(purge(request({ query: { purge: 'false' } }))).toBe(false);

    const role = all.get('PATCH /users/:id')!.when!;
    expect(role(request({ body: { role: 'viewer' } }))).toBe(true);
    expect(role(request({ body: { name: 'Ana' } }))).toBe(false);

    const token = all.get('POST /auth/tokens')!.when!;
    const as = (r: string) => ({ id: 'u', email: 'e', name: 'n', role: r, mfaEnabled: true });
    expect(token(request({ body: { scope: 'role' }, user: as('editor') } as never))).toBe(true);
    expect(token(request({ body: { scope: 'role' }, user: as('operator') } as never))).toBe(true);
    expect(token(request({ body: { scope: 'role' }, user: as('auditor') } as never))).toBe(false);
    expect(token(request({ body: { scope: 'role' }, user: as('viewer') } as never))).toBe(false);
    expect(token(request({ body: { scope: 'read' }, user: as('admin') } as never))).toBe(false);

    // Activar el acceso de administración sí; retirarlo o no tocarlo, no.
    const admin = all.get('POST /assets/:id/enrollment/token')!.when!;
    expect(admin(request({ body: { adminAccess: 'operator' } }))).toBe(true);
    expect(admin(request({ body: { adminAccess: 'none' } }))).toBe(false);
    expect(admin(request({ body: {} }))).toBe(false);
    const enroll = all.get('POST /assets/enroll')!.when!;
    expect(enroll(request({ body: { host: 'h', adminAccess: 'operator' } }))).toBe(true);
    expect(enroll(request({ body: { host: 'h' } }))).toBe(false);

    const replace = all.get('POST /auth/mfa/setup')!.when!;
    expect(replace(request({ user: as('admin') } as never))).toBe(true);
    expect(
      replace(request({ user: { ...as('admin'), mfaEnabled: false } } as never)),
    ).toBe(false);
  });
});
