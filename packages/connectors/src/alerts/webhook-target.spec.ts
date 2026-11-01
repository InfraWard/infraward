import { describe, expect, it } from 'vitest';
import {
  ipv6Groups,
  isForbiddenWebhookIp,
  parseWebhookUrl,
  resolveWebhookTarget,
  WebhookTargetError,
} from './webhook-target.js';

const resolvesTo =
  (...addresses: string[]) =>
  async () =>
    addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));

describe('parseWebhookUrl', () => {
  it('solo https salvo que se permita http', () => {
    expect(parseWebhookUrl('https://hooks.example.com/x').hostname).toBe('hooks.example.com');
    expect(() => parseWebhookUrl('http://hooks.example.com/x')).toThrow(/https/);
    expect(parseWebhookUrl('http://ntfy.lan/x', { allowHttp: true }).protocol).toBe('http:');
    expect(() => parseWebhookUrl('ftp://x/y', { allowHttp: true })).toThrow(WebhookTargetError);
    expect(() => parseWebhookUrl('no es una url')).toThrow(/no válida/);
  });

  it('sin credenciales en la URL', () => {
    expect(() => parseWebhookUrl('https://u:p@hooks.example.com/')).toThrow(/usuario/);
  });
});

describe('isForbiddenWebhookIp', () => {
  it.each([
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254',
    '224.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    'fe80::1',
    'ff02::1',
    '::ffff:7f00:1',
    // IPv4 compatible (como la normaliza la URL y con puntos), NAT64, 6to4 y Teredo: llevan una
    // IPv4 dentro.
    '::7f00:1',
    '::127.0.0.1',
    '::a9fe:a9fe',
    '::ffff:0:7f00:1',
    '64:ff9b::a9fe:a9fe',
    '64:ff9b:1::1',
    '2002:7f00:1::1',
    '2001:0:4136:e378::1',
    // Descarte, site-local, enlace local con zona y lo que no es una IP.
    '100::1',
    'fec0::1',
    'fe80::1%eth0',
    'febf::1',
    'no-es-ip',
  ])('%s no se admite nunca', (ip) => expect(isForbiddenWebhookIp(ip)).toBe(true));

  it.each(['8.8.8.8', '10.0.0.5', '2001:db8::1', 'fd00::1', '2606:4700::1111', '2001:4860::8888', '64:ff9b:2::1'])(
    '%s no está prohibida',
    (ip) => expect(isForbiddenWebhookIp(ip)).toBe(false),
  );

  it('una URL con una IPv6 que esconde 127.0.0.1 no pasa', async () => {
    const url = parseWebhookUrl('https://[::127.0.0.1]/x');
    expect(url.hostname).toBe('[::7f00:1]');
    await expect(resolveWebhookTarget(url)).rejects.toThrow(/no permitida/);
  });
});

describe('ipv6Groups', () => {
  it('expande `::`, la IPv4 del final y la zona', () => {
    expect(ipv6Groups('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups('::ffff:10.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
    expect(ipv6Groups('fe80::1%eth0')).toEqual([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups('2001:db8:0:0:0:0:0:1')).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups('10.0.0.1')).toBeNull();
  });
});

describe('resolveWebhookTarget', () => {
  it('devuelve la dirección pública con la que conectar', async () => {
    const url = new URL('https://hooks.example.com/x');
    await expect(resolveWebhookTarget(url, {}, resolvesTo('203.0.113.7'))).resolves.toEqual({
      address: '203.0.113.7',
      family: 4,
    });
  });

  it('privadas solo si se permiten', async () => {
    const url = new URL('https://ntfy.lan/x');
    await expect(resolveWebhookTarget(url, {}, resolvesTo('192.168.1.10'))).rejects.toThrow(
      /privada/,
    );
    await expect(
      resolveWebhookTarget(url, { allowPrivate: true }, resolvesTo('192.168.1.10')),
    ).resolves.toMatchObject({ address: '192.168.1.10' });
  });

  it('loopback y metadatos nunca, ni con privadas permitidas', async () => {
    for (const ip of ['127.0.0.1', '169.254.169.254', '::1'])
      await expect(
        resolveWebhookTarget(new URL('https://x.example/'), { allowPrivate: true }, resolvesTo(ip)),
      ).rejects.toThrow(/no permitida/);
  });

  it('basta una dirección prohibida entre varias', async () => {
    await expect(
      resolveWebhookTarget(
        new URL('https://x.example/'),
        {},
        resolvesTo('203.0.113.7', '10.0.0.1'),
      ),
    ).rejects.toThrow(/privada/);
  });

  it('IPs literales sin resolver', async () => {
    const never = async () => {
      throw new Error('no debería resolver');
    };
    await expect(
      resolveWebhookTarget(new URL('https://[::ffff:127.0.0.1]/'), {}, never),
    ).rejects.toThrow(/no permitida/);
    await expect(
      resolveWebhookTarget(new URL('https://203.0.113.9/'), {}, never),
    ).resolves.toEqual({ address: '203.0.113.9', family: 4 });
  });

  it('host que no resuelve', async () => {
    const fail = async () => {
      throw new Error('ENOTFOUND');
    };
    await expect(resolveWebhookTarget(new URL('https://nope.example/'), {}, fail)).rejects.toThrow(
      /resolver/,
    );
  });
});
