import { describe, expect, it } from 'vitest';
import { DomainApiError } from './domain-provider.js';
import { parseBootstrap, RdapClient } from './rdap.js';

const BOOTSTRAP = {
  services: [
    [['com', 'net'], ['http://inseguro/', 'https://rdap.verisign.com/com/v1/']],
    [['dev'], ['https://pubapi.registry.google/rdap']],
    [['co.uk'], ['https://rdap.nominet.uk/uk/']],
  ],
};

const DOMAIN = {
  objectClassName: 'domain',
  ldhName: 'ejemplo.dev',
  status: ['client transfer prohibited'],
  events: [
    { eventAction: 'registration', eventDate: '2020-03-01T10:00:00Z' },
    { eventAction: 'expiration', eventDate: '2027-03-01T10:00:00Z' },
    { eventAction: 'last changed', eventDate: '2026-03-01T10:00:00Z' },
  ],
  entities: [
    { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Privado']]] },
    {
      roles: ['registrar'],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Cloudflare, Inc.']]],
    },
  ],
};

describe('RDAP', () => {
  it('bootstrap: solo servidores https y con barra final', () => {
    const map = parseBootstrap(BOOTSTRAP);
    expect(map.get('com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(map.get('dev')).toBe('https://pubapi.registry.google/rdap/');
  });

  it('caducidad, alta, registrador y estados del TLD que toca (y el bootstrap en caché)', async () => {
    const urls: string[] = [];
    const rdap = new RdapClient((url) => {
      urls.push(url);
      return Promise.resolve(url.endsWith('dns.json') ? BOOTSTRAP : DOMAIN);
    }, 'https://iana/dns.json');
    expect(await rdap.lookup('ejemplo.dev')).toEqual({
      source: 'rdap',
      state: 'ok',
      expiresAt: '2027-03-01T10:00:00.000Z',
      registeredAt: '2020-03-01T10:00:00.000Z',
      registrar: 'Cloudflare, Inc.',
      statuses: ['client transfer prohibited'],
      error: null,
    });
    await rdap.lookup('ejemplo.co.uk');
    expect(urls).toEqual([
      'https://iana/dns.json',
      'https://pubapi.registry.google/rdap/domain/ejemplo.dev',
      'https://rdap.nominet.uk/uk/domain/ejemplo.co.uk',
    ]);
  });

  it('TLD sin RDAP (.es), dominio que no existe y bootstrap caído', async () => {
    const rdap = new RdapClient((url) => {
      if (url.endsWith('dns.json')) return Promise.resolve(BOOTSTRAP);
      return Promise.reject(new DomainApiError('HTTP 404', 404));
    });
    expect(await rdap.lookup('ejemplo.es')).toMatchObject({ state: 'unsupported', expiresAt: null });
    expect(await rdap.lookup('nadie.com')).toMatchObject({
      state: 'error',
      error: 'el registro no encuentra el dominio',
    });
    const down = new RdapClient(() => Promise.reject(new DomainApiError('sin respuesta en 5000 ms', null)));
    expect(await down.lookup('ejemplo.com')).toMatchObject({
      state: 'error',
      error: 'no se pudo leer el bootstrap de IANA (sin respuesta en 5000 ms)',
    });
  });
});
