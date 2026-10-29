import { createHash, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
} from 'jose';

/** Usuario que «se autentica» en el proveedor falso. */
export interface FakeOidcUser {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  groups?: string[];
}

/** Manipulaciones del ID token para probar los rechazos. */
export interface IdTokenTamper {
  iss?: string;
  aud?: string;
  nonce?: string;
  /** Segundos desde ahora (negativo = caducado). */
  expiresIn?: number;
  /** Firma con una clave que no está en el JWKS, o sin firma (`alg: none`). */
  signWith?: 'rogue' | 'none';
  /**
   * `auth_time` en segundos respecto a ahora (por defecto 0: acaba de teclear las credenciales;
   * negativo = sesión SSO anterior). null = sin el claim.
   */
  authTime?: number | null;
  /** `sub` distinto del del usuario (otra identidad). */
  sub?: string;
}

interface PendingCode {
  user: FakeOidcUser;
  nonce: string;
  codeChallenge: string;
  redirectUri: string;
  tamper: IdTokenTamper;
}

/**
 * Proveedor OIDC mínimo para los e2e: discovery, JWKS y token endpoint (comprueba la
 * autenticación del cliente, la redirect_uri y el code_verifier S256). La página de login no
 * existe: `authorize()` toma la URL de autorización que dio la API y devuelve el `code` y el
 * `state` con los que «vuelve» el navegador.
 */
export class FakeOidcProvider {
  readonly clientId = 'infraward-e2e';
  readonly clientSecret = randomBytes(24).toString('base64url');
  issuer = '';
  /** ID tokens emitidos (para comprobar que no se filtran). */
  readonly issuedIdTokens: string[] = [];
  readonly issuedCodes: string[] = [];
  /** Parámetros de la última petición de autorización (prompt, max_age…). */
  lastAuthorization: URLSearchParams | null = null;
  private server!: Server;
  private key!: CryptoKey;
  private rogue!: CryptoKey;
  private jwk!: JWK;
  private readonly codes = new Map<string, PendingCode>();

  async start(): Promise<void> {
    const pair = await generateKeyPair('RS256');
    this.key = pair.privateKey;
    this.jwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'k1',
      alg: 'RS256',
      use: 'sig',
    };
    this.rogue = (await generateKeyPair('RS256')).privateKey;
    this.server = createServer((req, res) => {
      void this.handle(req).then(
        ({ status, body }) => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(body));
        },
        () => {
          res.writeHead(500);
          res.end();
        },
      );
    });
    await new Promise<void>((resolve) =>
      this.server.listen(0, '127.0.0.1', resolve),
    );
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}/realms/e2e`;
  }

  async stop(): Promise<void> {
    await new Promise((resolve) => this.server?.close(resolve));
  }

  /** «Login» en el proveedor: registra un code para la petición de autorización dada. */
  authorize(
    authorizationUrl: string,
    user: FakeOidcUser,
    tamper: IdTokenTamper = {},
  ): { code: string; state: string; redirectUri: string } {
    const url = new URL(authorizationUrl);
    const p = url.searchParams;
    if (
      `${url.origin}${url.pathname}` !==
      `${this.issuer}/protocol/openid-connect/auth`
    )
      throw new Error(
        `URL de autorización inesperada: ${url.origin}${url.pathname}`,
      );
    if (p.get('client_id') !== this.clientId)
      throw new Error('client_id inesperado');
    if (p.get('response_type') !== 'code')
      throw new Error('response_type inesperado');
    if (p.get('code_challenge_method') !== 'S256')
      throw new Error('sin PKCE S256');
    if (!p.get('scope')?.split(' ').includes('openid'))
      throw new Error('sin scope openid');
    this.lastAuthorization = p;
    const code = randomBytes(16).toString('base64url');
    this.issuedCodes.push(code);
    this.codes.set(code, {
      user,
      nonce: p.get('nonce')!,
      codeChallenge: p.get('code_challenge')!,
      redirectUri: p.get('redirect_uri')!,
      tamper,
    });
    return {
      code,
      state: p.get('state')!,
      redirectUri: p.get('redirect_uri')!,
    };
  }

  private async handle(
    req: IncomingMessage,
  ): Promise<{ status: number; body: unknown }> {
    const path = new URL(req.url ?? '/', this.issuer).pathname.replace(
      new URL(this.issuer).pathname,
      '',
    );
    if (req.method === 'GET' && path === '/.well-known/openid-configuration')
      return {
        status: 200,
        body: {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/protocol/openid-connect/auth`,
          token_endpoint: `${this.issuer}/protocol/openid-connect/token`,
          jwks_uri: `${this.issuer}/protocol/openid-connect/certs`,
          end_session_endpoint: `${this.issuer}/protocol/openid-connect/logout`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic'],
        },
      };
    if (req.method === 'GET' && path === '/protocol/openid-connect/certs')
      return { status: 200, body: { keys: [this.jwk] } };
    if (req.method === 'POST' && path === '/protocol/openid-connect/token')
      return this.token(req);
    return { status: 404, body: {} };
  }

  private async token(
    req: IncomingMessage,
  ): Promise<{ status: number; body: unknown }> {
    // RFC 6749 §2.3.1: id y secreto codificados como formulario antes de base64.
    const basic =
      /^Basic (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
    const [id, secret] = Buffer.from(basic, 'base64')
      .toString('utf8')
      .split(':')
      .map((v) => decodeURIComponent(v.replace(/\+/g, ' ')));
    if (id !== this.clientId || secret !== this.clientSecret)
      return { status: 401, body: { error: 'invalid_client' } };
    const form = new URLSearchParams(await readBody(req));
    const code = form.get('code') ?? '';
    const pending = this.codes.get(code);
    this.codes.delete(code);
    const verifier = form.get('code_verifier') ?? '';
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    if (
      form.get('grant_type') !== 'authorization_code' ||
      !pending ||
      form.get('redirect_uri') !== pending.redirectUri ||
      challenge !== pending.codeChallenge
    )
      return { status: 400, body: { error: 'invalid_grant' } };
    const idToken = await this.idToken(pending);
    this.issuedIdTokens.push(idToken);
    return {
      status: 200,
      body: {
        access_token: randomBytes(16).toString('base64url'),
        token_type: 'Bearer',
        expires_in: 300,
        id_token: idToken,
      },
    };
  }

  private async idToken({ user, nonce, tamper }: PendingCode): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      ...user,
      nonce: tamper.nonce ?? nonce,
      azp: this.clientId,
      ...(tamper.authTime === null
        ? {}
        : { auth_time: now + (tamper.authTime ?? 0) }),
    };
    const exp = now + (tamper.expiresIn ?? 300);
    if (tamper.signWith === 'none') {
      const b64 = (v: object) =>
        Buffer.from(JSON.stringify(v)).toString('base64url');
      return `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
        ...claims,
        iss: tamper.iss ?? this.issuer,
        aud: tamper.aud ?? this.clientId,
        iat: Math.min(now, exp - 60),
        exp,
      })}.`;
    }
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT' })
      .setIssuer(tamper.iss ?? this.issuer)
      .setAudience(tamper.aud ?? this.clientId)
      .setSubject(tamper.sub ?? user.sub)
      .setIssuedAt(Math.min(now, exp - 60))
      .setExpirationTime(exp)
      .sign(tamper.signWith === 'rogue' ? this.rogue : this.key);
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
