import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { SecretProviderError } from '../errors.js';
import { OpenBaoHttp, type FetchFn } from './openbao-client.js';
import { loadOpenBaoConfig } from './openbao-config.js';

function listen(handler: Parameters<typeof createServer>[1]): Promise<Server> {
  const server = createServer(handler);
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve(server)),
  );
}
const url = (s: Server) =>
  `http://127.0.0.1:${(s.address() as AddressInfo).port}`;

describe('OpenBaoHttp: redirecciones (revisión #3, M8)', () => {
  const servers: Server[] = [];
  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map((s) => new Promise((r) => s.close(r))),
    );
  });

  it('pide siempre redirect: error', async () => {
    let init: Parameters<FetchFn>[1] | undefined;
    const fetchFn: FetchFn = async (_input, i) => {
      init = i;
      return { status: 204, json: async () => null };
    };
    const http = new OpenBaoHttp(
      loadOpenBaoConfig({
        addr: 'https://bao.example:8200',
        roleId: 'r',
        secretId: 's',
      }),
      fetchFn,
    );
    await http.request('GET', 'sys/health');
    expect(init?.redirect).toBe('error');
  });

  it('un 307 del login no reenvía el secret_id ni el token a otro sitio', async () => {
    const seen: { headers: Record<string, unknown>; body: string }[] = [];
    const attacker = await listen((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c));
      req.on('end', () => {
        seen.push({ headers: req.headers, body });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"auth":{"client_token":"robado"}}');
      });
    });
    servers.push(attacker);
    const bao = await listen((req, res) => {
      res.writeHead(307, { location: `${url(attacker)}${req.url}` });
      res.end();
    });
    servers.push(bao);
    const http = new OpenBaoHttp(
      loadOpenBaoConfig({ addr: url(bao), roleId: 'r', secretId: 's' }),
    );
    const login = http.request('POST', 'auth/approle/login', {
      token: 'tok-de-la-app',
      body: { role_id: 'r', secret_id: 'secreto' },
    });
    await expect(login).rejects.toBeInstanceOf(SecretProviderError);
    await expect(login).rejects.toThrow(/redirección/);
    expect(seen).toEqual([]);
  });
});
