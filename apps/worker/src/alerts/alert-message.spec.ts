import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  alertLink,
  channelAccepts,
  emailContent,
  webhookPayload,
  webhookSignature,
  type AlertSource,
} from './alert-message.js';

const kev: AlertSource = {
  id: 'n1',
  kind: 'vulnerability_kev',
  assetId: 'a1',
  assetName: 'web1',
  message: 'web1: 1 CVE crítico explotado activamente (KEV) y expuesto — CVE-2026-1 (openssl)',
  items: [{ id: 'CVE-2026-1', name: 'CVE-2026-1 (openssl)', type: 'vulnerability' }],
  total: 1,
  createdAt: new Date('2026-10-29T10:00:00Z'),
};

describe('alertLink', () => {
  it('el CVE si es uno, si no el asset; sin URL pública, nada', () => {
    expect(alertLink(kev, 'https://iw.example/')).toBe('https://iw.example/vulnerabilities/CVE-2026-1');
    expect(alertLink({ ...kev, items: [] }, 'https://iw.example')).toBe('https://iw.example/assets/a1');
    expect(alertLink(kev, undefined)).toBeNull();
  });
});

describe('webhookPayload', () => {
  it('lo mismo que la campana, sin más', () => {
    expect(webhookPayload(kev, undefined)).toEqual({
      event: 'notification',
      id: 'n1',
      kind: 'vulnerability_kev',
      message: kev.message,
      asset: { id: 'a1', name: 'web1' },
      items: kev.items,
      total: 1,
      createdAt: '2026-10-29T10:00:00.000Z',
      url: null,
    });
  });
});

describe('webhookSignature', () => {
  it('HMAC-SHA256 de `<fecha>.<cuerpo>`', () => {
    const expected = createHmac('sha256', 'secreto').update('1700000000.{"a":1}').digest('hex');
    expect(webhookSignature('secreto', 1_700_000_000, '{"a":1}')).toBe(`sha256=${expected}`);
  });
});

describe('channelAccepts', () => {
  const channel = { enabled: true, kinds: null, includeAdminOnly: false };
  it('activo y sin filtro: todas menos las de solo admins', () => {
    expect(channelAccepts(channel, { kind: 'asset_created', audienceRoles: null })).toBe(true);
    expect(channelAccepts(channel, { kind: 'vault_revealed', audienceRoles: ['admin'] })).toBe(false);
    expect(
      channelAccepts(
        { ...channel, includeAdminOnly: true },
        { kind: 'vault_revealed', audienceRoles: ['admin'] },
      ),
    ).toBe(true);
  });

  it('filtro de tipos y desactivado', () => {
    const only = { ...channel, kinds: ['vulnerability_kev' as const] };
    expect(channelAccepts(only, { kind: 'vulnerability_kev' })).toBe(true);
    expect(channelAccepts(only, { kind: 'asset_created' })).toBe(false);
    expect(channelAccepts({ ...channel, enabled: false }, { kind: 'asset_created' })).toBe(false);
  });
});

describe('emailContent', () => {
  it('asunto en una línea y HTML escapado', () => {
    const n = { ...kev, message: 'a\r\nb <script>', items: [{ id: 'x', name: '<b>x</b>', type: 'server' as const }] };
    const mail = emailContent(n, 'https://iw.example');
    expect(mail.subject).toBe('[InfraWard] a b <script>');
    expect(mail.html).not.toContain('<script>');
    expect(mail.html).toContain('&#60;b&#62;x&#60;/b&#62;');
    expect(mail.text).toContain('- <b>x</b>');
    expect(mail.text).toContain('https://iw.example/assets/a1');
  });
});
