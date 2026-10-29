import { execFileSync } from 'node:child_process';
import { createSocket, type Socket } from 'node:dgram';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createTlsServer, type Server as TlsServer } from 'node:tls';

// Simulados de los e2e de dominios (QoL-5): la API de Cloudflare y RDAP por HTTP, un DNS por
// UDP (los CNAME y los nombres del 443) y un servidor TLS con un certificado autofirmado.

export interface FakeZone {
  id: string;
  name: string;
}

export interface FakeRecord {
  id: string;
  zoneId: string;
  name: string;
  type: string;
  content: string;
  proxied?: boolean;
}

export interface FakeDomainsState {
  /** El único token que acepta (Bearer). */
  token: string;
  zones: FakeZone[];
  records: FakeRecord[];
  /** Dominio → caducidad (RDAP); sin entrada, 404. */
  rdap: Record<string, string>;
  /** Túneles de la cuenta (QoL-5b): `config` es lo que devuelve `…/configurations`. */
  tunnels?: { id: string; name: string; status: string; remote_config: boolean; config?: unknown }[];
}

/** Cloudflare (`/client/v4`) y RDAP (`/rdap/dns.json`, `/rdap/domain/<nombre>`). */
export class FakeDomainsApi {
  private server?: Server;
  url = '';
  state: FakeDomainsState = { token: '', zones: [], records: [], rdap: {} };
  /** Peticiones recibidas (ruta y si traía el token bueno), para comprobarlas. */
  readonly requests: { path: string; authorized: boolean }[] = [];

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      const reply = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      const url = new URL(req.url ?? '/', 'http://x');
      const authorized = this.authorized(req);
      this.requests.push({ path: url.pathname, authorized });
      if (url.pathname === '/rdap/dns.json')
        return reply(200, { services: [[['test', 'dev'], [`${this.url}/rdap/`]]] });
      const rdap = /^\/rdap\/domain\/(.+)$/.exec(url.pathname);
      if (rdap) {
        const expires = this.state.rdap[rdap[1]];
        if (!expires) return reply(404, { errorCode: 404 });
        return reply(200, {
          objectClassName: 'domain',
          ldhName: rdap[1],
          status: ['client transfer prohibited'],
          events: [
            { eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' },
            { eventAction: 'expiration', eventDate: expires },
          ],
          entities: [
            {
              roles: ['registrar'],
              vcardArray: ['vcard', [['fn', {}, 'text', 'Registrador de Pruebas']]],
            },
          ],
        });
      }
      if (!authorized)
        return reply(401, {
          success: false,
          errors: [{ code: 1000, message: 'Invalid API Token' }],
        });
      const page = Number(url.searchParams.get('page') ?? 1);
      const perPage = Number(url.searchParams.get('per_page') ?? 20);
      const paged = (all: unknown[]) =>
        reply(200, {
          success: true,
          errors: [],
          result: all.slice((page - 1) * perPage, page * perPage),
          result_info: {
            page,
            per_page: perPage,
            total_pages: Math.max(1, Math.ceil(all.length / perPage)),
          },
        });
      if (url.pathname === '/client/v4/user/tokens/verify')
        return reply(200, { success: true, result: { id: 't', status: 'active' } });
      if (url.pathname === '/client/v4/zones')
        return paged(
          this.state.zones.map((z) => ({
            ...z,
            status: 'active',
            paused: false,
            name_servers: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
            plan: { name: 'Free Website' },
            account: { id: 'a'.repeat(32), name: 'Cuenta de pruebas' },
          })),
        );
      const records = /^\/client\/v4\/zones\/([0-9a-f]{32})\/dns_records$/.exec(url.pathname);
      if (records)
        return paged(
          this.state.records
            .filter((r) => r.zoneId === records[1])
            .map((r) => ({ ttl: 1, proxied: false, comment: 'nota', ...r })),
        );
      if (url.pathname === `/client/v4/accounts/${'a'.repeat(32)}/cfd_tunnel`)
        return paged(this.state.tunnels ?? []);
      const tunnel = /^\/client\/v4\/accounts\/[0-9a-f]{32}\/cfd_tunnel\/([0-9a-f-]{36})\/configurations$/.exec(url.pathname);
      if (tunnel) {
        const t = (this.state.tunnels ?? []).find((x) => x.id === tunnel[1]);
        if (t?.config) return reply(200, { success: true, errors: [], result: { tunnel_id: t.id, config: t.config } });
      }
      reply(404, { success: false, errors: [{ code: 7003, message: 'no route' }] });
    });
    await new Promise<void>((done) => this.server!.listen(0, '127.0.0.1', done));
    this.url = `http://127.0.0.1:${(this.server.address() as { port: number }).port}`;
  }

  private authorized(req: IncomingMessage): boolean {
    return (
      !!this.state.token &&
      req.headers.authorization === `Bearer ${this.state.token}`
    );
  }

  async stop(): Promise<void> {
    await new Promise((done) => this.server?.close(done));
  }
}

/**
 * DNS mínimo por UDP: responde A con la IP de `names` (y NOERROR sin datos a AAAA/CNAME de esos
 * nombres) y NXDOMAIN a todo lo demás.
 */
export class FakeDns {
  private socket?: Socket;
  port = 0;
  names = new Map<string, string>();
  readonly queries: string[] = [];

  async start(): Promise<void> {
    this.socket = createSocket('udp4');
    this.socket.on('message', (msg, rinfo) => {
      const reply = this.answer(msg);
      if (reply) this.socket!.send(reply, rinfo.port, rinfo.address);
    });
    await new Promise<void>((done) => this.socket!.bind(0, '127.0.0.1', done));
    this.port = this.socket.address().port;
  }

  get server(): string {
    return `127.0.0.1:${this.port}`;
  }

  private answer(msg: Buffer): Buffer | null {
    if (msg.length < 17) return null;
    let offset = 12;
    const labels: string[] = [];
    while (offset < msg.length && msg[offset] !== 0) {
      const len = msg[offset];
      labels.push(msg.subarray(offset + 1, offset + 1 + len).toString('ascii'));
      offset += len + 1;
    }
    const qEnd = offset + 5;
    const qtype = msg.readUInt16BE(offset + 1);
    const name = labels.join('.').toLowerCase();
    this.queries.push(`${name}/${qtype}`);
    const ip = this.names.get(name);
    const header = Buffer.alloc(12);
    msg.copy(header, 0, 0, 2);
    const answers = ip && qtype === 1 ? 1 : 0;
    header.writeUInt16BE(ip ? 0x8180 : 0x8183, 2); // respuesta, RD, RA; 3 = NXDOMAIN
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answers, 6);
    const question = msg.subarray(12, qEnd);
    if (!answers) return Buffer.concat([header, question]);
    const rr = Buffer.alloc(16);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(1, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(60, 6);
    rr.writeUInt16BE(4, 10);
    ip!.split('.').forEach((o, i) => rr.writeUInt8(Number(o), 12 + i));
    return Buffer.concat([header, question, rr]);
  }

  async stop(): Promise<void> {
    await new Promise<void>((done) => (this.socket ? this.socket.close(() => done()) : done()));
  }
}

/** TLS en 127.0.0.1 con un certificado autofirmado para `names` (generado con openssl). */
export class FakeTls {
  private server?: TlsServer;
  private dir = '';
  port = 0;
  /** Huella SHA-256 del certificado (como la de `X509Certificate.fingerprint256`). */
  fingerprint = '';

  async start(names: string[], days = 20): Promise<void> {
    this.dir = mkdtempSync(join(tmpdir(), 'infraward-fake-tls-'));
    const key = join(this.dir, 'key.pem');
    const cert = join(this.dir, 'cert.pem');
    execFileSync(
      'openssl',
      [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
        '-keyout', key, '-out', cert, '-days', String(days), '-subj', `/CN=${names[0]}`,
        '-addext', `subjectAltName=${names.map((n) => `DNS:${n}`).join(',')}`,
      ],
      { stdio: 'ignore' },
    );
    const { X509Certificate } = await import('node:crypto');
    this.fingerprint = new X509Certificate(readFileSync(cert)).fingerprint256;
    this.server = createTlsServer({ key: readFileSync(key), cert: readFileSync(cert) }, (s) =>
      s.end(),
    );
    await new Promise<void>((done) => this.server!.listen(0, '127.0.0.1', done));
    this.port = (this.server.address() as { port: number }).port;
  }

  async stop(): Promise<void> {
    await new Promise((done) => (this.server ? this.server.close(done) : done(undefined)));
    if (this.dir) rmSync(this.dir, { recursive: true, force: true });
  }
}
