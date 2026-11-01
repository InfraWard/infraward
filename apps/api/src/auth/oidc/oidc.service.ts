import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { SecretsService } from '@infraward/secrets';
import type {
  LoginFailureReason,
  OidcLoginError,
  UserRole,
} from '@infraward/shared-types';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import * as client from 'openid-client';
import { DataSource, type EntityManager } from 'typeorm';
import type { AuditActor } from '../../audit/audit-context.decorator.js';
import { AuditService } from '../../audit/audit.service.js';
import type { EnvironmentVariables } from '../../config/env.validation.js';
import { isUniqueViolation } from '../../database/pg-errors.js';
import { UNUSABLE_PASSWORD_HASH } from '../../users/temporary-password.js';
import { User } from '../../users/user.entity.js';
import {
  defaultName,
  lockActiveAdmins,
  normalizeEmail,
  userTarget,
} from '../../users/users.service.js';
import { SessionService, type ClientContext } from '../session.service.js';
import { decideAccount, type OidcIdentity } from './oidc-account.js';
import {
  claimValues,
  oidcSettings,
  resolveRole,
  safeReturnPath,
  type OidcSettings,
} from './oidc-settings.js';
import {
  OidcStateStore,
  sha256Hex,
  type OidcFlowState,
} from './oidc-state.store.js';

/** La configuración descubierta se rehace cada cierto tiempo (rotación del secreto del cliente). */
const CONFIGURATION_TTL_MS = 10 * 60 * 1000;

export interface OidcBegin {
  authorizationUrl: string;
  /** Token de la cookie que ata el flujo a este navegador. */
  bindingToken: string;
}

export type OidcCallbackResult =
  | { ok: true; sessionToken: string | null; redirectUrl: string }
  | { ok: false; redirectUrl: string };

/** Margen para `auth_time` frente al inicio del flujo de reautenticación (relojes). */
const AUTH_TIME_SKEW_MS = 5_000;

/**
 * `max_age` de la reautenticación (step-up). No 0: Authentik ignora `max_age=0` (lo trata como
 * ausente) y su `prompt=login` solo vuelve a pedir las credenciales la primera vez en cada sesión
 * del navegador (goauthentik/authentik#18507); a partir de la segunda devolvía el `auth_time` del
 * login anterior y la reautenticación fallaba (`auth_time_stale`). Con un `max_age` positivo
 * Authentik sí obliga a entrar de nuevo si el último login es más antiguo. Pequeño, pero con margen
 * para que la vuelta del login al endpoint de autorización no lo supere (y vuelva a pedirlo). Lo que
 * decide sigue siendo `auth_time`, posterior al inicio del flujo.
 */
export const OIDC_REAUTH_MAX_AGE_SECONDS = 30;

/** Sesión que pide reautenticarse con el proveedor (GET /auth/oidc/reauth). */
export interface OidcReauthRequest {
  sessionId: string;
  userId: string;
}

/** Fallo del login OIDC con su motivo (auditoría) y el código que ve la web. */
class OidcLoginFailure extends Error {
  constructor(
    readonly reason: LoginFailureReason,
    readonly error: OidcLoginError,
    readonly user?: Pick<User, 'id' | 'email'>,
    readonly details: Record<string, unknown> = {},
  ) {
    super(reason);
  }
}

/** Fallo después de consumir el state: conserva el flujo (¿era una reautenticación?). */
class OidcFailureWithFlow extends Error {
  constructor(
    readonly flow: OidcFlowState,
    readonly failure: OidcLoginFailure,
  ) {
    super(failure.reason);
  }
}

/** `auth_time` del ID token (nunca en el futuro), o null si no lo trae. */
function authTimeOf(claims: client.IDToken): Date | null {
  return typeof claims.auth_time === 'number'
    ? new Date(Math.min(claims.auth_time * 1000, Date.now()))
    : null;
}

/** Ruta de vuelta con `reauth=ok|failed` (la web avisa y lo quita de la URL). */
export function withReauthResult(path: string, result: 'ok' | 'failed'): string {
  const url = new URL(path, 'https://web.invalid');
  url.searchParams.set('reauth', result);
  return url.pathname + url.search + url.hash;
}

/**
 * Login con un proveedor OIDC genérico (DESIGN §14): authorization code con PKCE (S256), state
 * de un solo uso atado al navegador por una cookie, nonce, y validación del ID token (firma por
 * JWKS, issuer, audiencia, azp, caducidad) con openid-client. La sesión resultante es la misma
 * de siempre (SessionService).
 */
@Injectable()
export class OidcService {
  private readonly logger = new Logger(OidcService.name);
  readonly settings: OidcSettings | null;
  private configuration: {
    value: Promise<client.Configuration>;
    expiresAt: number;
  } | null = null;
  private readonly insecure: boolean;
  private readonly emergencyEmail: string | null;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    private readonly secrets: SecretsService,
    private readonly store: OidcStateStore,
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
    @InjectDataSource() private readonly db: DataSource,
  ) {
    this.settings = oidcSettings({
      OIDC_ISSUER: config.get('OIDC_ISSUER', { infer: true }),
      OIDC_CLIENT_ID: config.get('OIDC_CLIENT_ID', { infer: true }),
      OIDC_CLIENT_SECRET_REF: config.get('OIDC_CLIENT_SECRET_REF', {
        infer: true,
      }),
      OIDC_TOKEN_AUTH_METHOD: config.get('OIDC_TOKEN_AUTH_METHOD', {
        infer: true,
      }),
      OIDC_REDIRECT_URI: config.get('OIDC_REDIRECT_URI', { infer: true }),
      OIDC_PROVIDER_NAME: config.get('OIDC_PROVIDER_NAME', { infer: true }),
      OIDC_SCOPES: config.get('OIDC_SCOPES', { infer: true }),
      OIDC_GROUPS_CLAIM: config.get('OIDC_GROUPS_CLAIM', { infer: true }),
      OIDC_ROLE_MAPPING: config.get('OIDC_ROLE_MAPPING', { infer: true }),
      OIDC_UNMAPPED: config.get('OIDC_UNMAPPED', { infer: true }),
      OIDC_ALLOW_UNVERIFIED_SIGNUP: config.get('OIDC_ALLOW_UNVERIFIED_SIGNUP', {
        infer: true,
      }),
    });
    // http solo fuera de producción (lo garantiza la validación del entorno).
    this.insecure = this.settings?.issuer.protocol === 'http:';
    const emergency = config.get('LOCAL_LOGIN_EMERGENCY_EMAIL', {
      infer: true,
    });
    this.emergencyEmail = emergency ? normalizeEmail(emergency) : null;
  }

  /**
   * Empieza el flujo: guarda state, nonce y verifier y devuelve adónde mandar al navegador. Con
   * `reauth`, es una reautenticación (step-up) de esa sesión: el proveedor debe pedir otra vez
   * las credenciales (`prompt=login` y `max_age`) y a la vuelta se comprueba `auth_time`.
   */
  async begin(
    returnUrl: unknown,
    reauth?: OidcReauthRequest,
  ): Promise<OidcBegin> {
    const settings = this.required();
    const config = await this.config();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const codeVerifier = client.randomPKCECodeVerifier();
    const bindingToken = randomBytes(32).toString('base64url');
    await this.store.save(state, {
      bindingHash: sha256Hex(bindingToken),
      codeVerifier,
      nonce,
      returnUrl: safeReturnPath(returnUrl),
      ...(reauth ? { reauth: { ...reauth, startedAt: Date.now() } } : {}),
    });
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: settings.redirectUri.href,
      scope: settings.scopes,
      state,
      nonce,
      code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
      ...(reauth
        ? { prompt: 'login', max_age: String(OIDC_REAUTH_MAX_AGE_SECONDS) }
        : {}),
    });
    return { authorizationUrl: url.href, bindingToken };
  }

  /**
   * Completa el flujo en el callback. Nunca lanza: cualquier fallo se audita con su motivo y
   * devuelve la redirección a /login con un código genérico.
   */
  async complete(
    query: Record<string, string | undefined>,
    bindingToken: string | undefined,
    clientCtx: ClientContext,
  ): Promise<OidcCallbackResult> {
    const settings = this.required();
    let flow: OidcFlowState | null = null;
    try {
      const exchanged = await this.exchange(settings, query, bindingToken);
      flow = exchanged.flow;
      if (flow.reauth)
        return await this.completeReauth(
          settings,
          flow,
          flow.reauth,
          exchanged.claims,
          clientCtx,
        );
      const { user, idToken, role, matched, returnUrl } =
        await this.authenticate(settings, exchanged, clientCtx);
      // `auth_time` dice cuándo tecleó las credenciales en el proveedor: si el proveedor reutilizó
      // una sesión SSO antigua, la sesión nueva no cuenta como reautenticación reciente.
      const { token } = await this.sessions.create(user.id, 'full', clientCtx, {
        oidcIdToken: idToken,
        authMethod: 'oidc',
        reauthenticatedAt: authTimeOf(exchanged.claims),
      });
      await this.audit.record(actorOf(user, clientCtx), 'auth.login', {
        target: userTarget(user),
        details: { method: 'oidc', role, groups: matched },
      });
      return {
        ok: true,
        sessionToken: token,
        redirectUrl: settings.webOrigin + returnUrl,
      };
    } catch (error_) {
      let error = error_;
      if (error instanceof OidcFailureWithFlow) {
        flow = error.flow;
        error = error.failure;
      }
      const failure =
        error instanceof OidcLoginFailure
          ? error
          : new OidcLoginFailure('token_invalid', 'failed');
      if (!(error instanceof OidcLoginFailure))
        this.logger.warn(`Login OIDC fallido: ${errorSummary(error)}`);
      const reauth = flow?.reauth;
      await this.audit.record(
        {
          actorId: failure.user?.id ?? reauth?.userId ?? null,
          actorEmail:
            failure.user?.email ?? (failure.details.email as string) ?? null,
          ip: clientCtx.ip,
        },
        reauth ? 'auth.reauth' : 'auth.login_failed',
        {
          outcome: 'failure',
          target: failure.user ? userTarget(failure.user) : undefined,
          details: {
            method: 'oidc',
            reason: failure.reason,
            ...failure.details,
          },
        },
      );
      if (flow?.reauth)
        return {
          ok: false,
          redirectUrl: settings.webOrigin + withReauthResult(flow.returnUrl, 'failed'),
        };
      return {
        ok: false,
        redirectUrl: `${settings.webOrigin}/login?oidcError=${failure.error}`,
      };
    }
  }

  /**
   * URL para cerrar también la sesión del proveedor (RP-Initiated Logout), o null si el
   * proveedor no la anuncia o no hay ID token.
   */
  async endSessionUrl(idToken: string | null): Promise<string | null> {
    const settings = this.settings;
    if (!settings || !idToken) return null;
    try {
      const config = await this.config();
      if (!config.serverMetadata().end_session_endpoint) return null;
      return client.buildEndSessionUrl(config, {
        id_token_hint: idToken,
        client_id: settings.clientId,
        post_logout_redirect_uri: `${settings.webOrigin}/login?loggedOut=1`,
      }).href;
    } catch (error) {
      this.logger.warn(`Sin logout del proveedor: ${errorSummary(error)}`);
      return null;
    }
  }

  /**
   * Pasos comunes al login y a la reautenticación: el state (existe, no se ha usado y lo empezó
   * este navegador), el canje del código y la validación del ID token.
   */
  private async exchange(
    settings: OidcSettings,
    query: Record<string, string | undefined>,
    bindingToken: string | undefined,
  ): Promise<{
    flow: OidcFlowState;
    claims: client.IDToken;
    idToken: string;
  }> {
    // 1. El state: existe, no se ha usado y lo empezó este navegador (cookie de enlace).
    const state = query.state;
    const flow = state ? await this.store.take(state) : null;
    if (query.error) {
      throw new OidcLoginFailure('provider_error', 'failed', undefined, {
        providerError: query.error.slice(0, 64),
      });
    }
    if (
      !state ||
      !flow ||
      !bindingToken ||
      !sameHash(sha256Hex(bindingToken), flow.bindingHash)
    )
      throw new OidcLoginFailure('state_invalid', 'failed');

    // 2. Canje del código y validación del ID token.
    let config: client.Configuration;
    try {
      config = await this.config();
    } catch (error) {
      this.logger.warn(`Proveedor OIDC inaccesible: ${errorSummary(error)}`);
      throw new OidcFailureWithFlow(
        flow,
        new OidcLoginFailure('provider_unavailable', 'unavailable'),
      );
    }
    const callbackUrl = new URL(settings.redirectUri.href);
    for (const [key, value] of Object.entries(query))
      if (value !== undefined) callbackUrl.searchParams.set(key, value);
    let tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
    try {
      tokens = await client.authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: flow.codeVerifier,
        expectedState: state,
        expectedNonce: flow.nonce,
        idTokenExpected: true,
      });
    } catch (error) {
      const reason = classifyOidcError(error);
      this.logger.warn(
        `ID token o canje rechazados (${reason}): ${errorSummary(error)}`,
      );
      throw new OidcFailureWithFlow(
        flow,
        new OidcLoginFailure(
          reason,
          reason === 'provider_unavailable' ? 'unavailable' : 'failed',
        ),
      );
    }
    const claims = tokens.claims();
    if (!claims || !tokens.id_token)
      throw new OidcFailureWithFlow(
        flow,
        new OidcLoginFailure('token_invalid', 'failed'),
      );
    return { flow, claims, idToken: tokens.id_token };
  }

  private async authenticate(
    settings: OidcSettings,
    exchanged: { flow: OidcFlowState; claims: client.IDToken; idToken: string },
    clientCtx: ClientContext,
  ): Promise<{
    user: User;
    idToken: string;
    role: UserRole;
    matched: string[];
    returnUrl: string;
  }> {
    const { flow, claims } = exchanged;
    const identity: OidcIdentity = {
      issuer: claims.iss,
      subject: claims.sub,
      email:
        typeof claims.email === 'string' ? normalizeEmail(claims.email) : null,
      emailVerified: claims.email_verified === true,
      name:
        typeof claims.name === 'string'
          ? claims.name.trim().slice(0, 120) || null
          : null,
      groups: claimValues(claims, settings.groupsClaim),
    };
    const { role, matched } = resolveRole(
      identity.groups,
      settings.roleMapping,
      settings.unmapped,
    );

    // 3. Cuenta y rol, en una transacción con los admins bloqueados (regla del último admin).
    const user = await this.db
      .transaction((m) =>
        this.applyIdentity(m, identity, role, matched, clientCtx),
      )
      .catch((error: unknown) => {
        if (error instanceof OidcLoginFailure) throw error;
        // Otro login simultáneo creó la misma cuenta: que vuelva a intentarlo.
        if (isUniqueViolation(error))
          throw new OidcLoginFailure('token_invalid', 'failed', undefined, {
            email: identity.email,
            conflict: true,
          });
        throw error;
      });
    // Si el proveedor le cambió el rol, sus terminales abiertas se vuelven a comprobar.
    this.sessions.userChanged(user.id);
    return {
      user,
      idToken: exchanged.idToken,
      role: user.role,
      matched,
      returnUrl: flow.returnUrl,
    };
  }

  /**
   * Vuelta de una reautenticación: el proveedor tiene que haber pedido las credenciales después
   * de empezar el flujo (`auth_time`), la identidad tiene que ser la del usuario de la sesión y
   * la sesión tiene que seguir viva. Entonces se marca `reauthenticated_at = auth_time` (no se
   * abre otra sesión) y se vuelve a la página con `?reauth=ok`.
   */
  private async completeReauth(
    settings: OidcSettings,
    flow: OidcFlowState,
    reauth: NonNullable<OidcFlowState['reauth']>,
    claims: client.IDToken,
    clientCtx: ClientContext,
  ): Promise<OidcCallbackResult> {
    const user = await this.db
      .getRepository(User)
      .findOneBy({ id: reauth.userId });
    if (!user || user.disabledAt)
      throw new OidcLoginFailure('disabled', 'disabled');
    if (user.oidcIssuer !== claims.iss || user.oidcSubject !== claims.sub)
      throw new OidcLoginFailure('subject_mismatch', 'failed', user);
    if (typeof claims.auth_time !== 'number')
      throw new OidcLoginFailure('auth_time_missing', 'failed', user);
    const authTime = claims.auth_time * 1000;
    if (authTime < reauth.startedAt - AUTH_TIME_SKEW_MS)
      throw new OidcLoginFailure('auth_time_stale', 'failed', user, {
        authAgeSeconds: Math.round((Date.now() - authTime) / 1000),
      });
    const session = await this.sessions.findActive(reauth.sessionId, user.id);
    if (!session) throw new OidcLoginFailure('session_closed', 'failed', user);
    // Nunca en el futuro: un reloj del proveedor adelantado no alarga la ventana.
    await this.sessions.markReauthenticated(session.id, authTimeOf(claims)!);
    await this.audit.record(actorOf(user, clientCtx), 'auth.reauth', {
      target: userTarget(user),
      details: { method: 'oidc' },
    });
    return {
      ok: true,
      sessionToken: null,
      redirectUrl: settings.webOrigin + withReauthResult(flow.returnUrl, 'ok'),
    };
  }

  private async applyIdentity(
    m: EntityManager,
    identity: OidcIdentity,
    role: UserRole | null,
    matched: string[],
    clientCtx: ClientContext,
  ): Promise<User> {
    const repo = m.getRepository(User);
    const admins = await lockActiveAdmins(m);
    const bySubject = await repo.findOne({
      where: { oidcIssuer: identity.issuer, oidcSubject: identity.subject },
      lock: { mode: 'pessimistic_write' },
    });
    const byEmail =
      bySubject || !identity.email
        ? null
        : await repo.findOne({
            where: { email: identity.email },
            lock: { mode: 'pessimistic_write' },
          });
    const decision = decideAccount(
      identity,
      bySubject,
      byEmail,
      this.emergencyEmail,
      { allowUnverifiedSignup: this.settings?.allowUnverifiedSignup ?? false },
    );
    const groups = { groups: identity.groups.slice(0, 50) };
    if (decision.kind === 'reject')
      throw new OidcLoginFailure(
        decision.reason,
        decision.error,
        decision.user,
        {
          email: identity.email,
          ...groups,
        },
      );
    if (!role)
      throw new OidcLoginFailure(
        'no_role_mapping',
        'denied',
        decision.kind === 'create' ? undefined : decision.user,
        { email: identity.email, ...groups },
      );

    const now = new Date();
    if (decision.kind === 'create') {
      const user = await repo.save(
        repo.create({
          email: identity.email!,
          name: identity.name ?? defaultName(identity.email!),
          passwordHash: UNUSABLE_PASSWORD_HASH,
          role,
          origin: 'oidc',
          oidcIssuer: identity.issuer,
          oidcSubject: identity.subject,
          lastLoginAt: now,
        }),
      );
      await this.audit.record(actorOf(user, clientCtx), 'user.created', {
        target: userTarget(user),
        details: { method: 'oidc', role, name: user.name, groups: matched },
        manager: m,
      });
      return user;
    }

    const user = decision.user;
    const actor = actorOf(user, clientCtx);
    if (decision.kind === 'link') {
      user.oidcIssuer = identity.issuer;
      user.oidcSubject = identity.subject;
      await repo.update(
        { id: user.id },
        { oidcIssuer: identity.issuer, oidcSubject: identity.subject },
      );
      await this.audit.record(actor, 'user.oidc_linked', {
        target: userTarget(user),
        details: { method: 'oidc' },
        manager: m,
      });
    }
    if (role !== user.role) {
      const lastAdmin =
        user.role === 'admin' && !admins.some((id) => id !== user.id);
      if (lastAdmin) {
        // El proveedor le quita el admin, pero es el último activo: se conserva y se avisa.
        await this.audit.record(actor, 'user.role_changed', {
          outcome: 'failure',
          target: userTarget(user),
          details: {
            method: 'oidc',
            from: user.role,
            to: role,
            roleKept: 'last_admin',
          },
          manager: m,
        });
      } else {
        const from = user.role;
        user.role = role;
        await repo.update({ id: user.id }, { role });
        await this.audit.record(actor, 'user.role_changed', {
          target: userTarget(user),
          details: { method: 'oidc', from, to: role, groups: matched },
          manager: m,
        });
      }
    }
    if (identity.name && identity.name !== user.name) {
      const from = user.name;
      user.name = identity.name;
      await repo.update({ id: user.id }, { name: identity.name });
      await this.audit.record(actor, 'user.updated', {
        target: userTarget(user),
        details: { method: 'oidc', nameFrom: from, nameTo: identity.name },
        manager: m,
      });
    }
    user.lastLoginAt = now;
    await repo.update({ id: user.id }, { lastLoginAt: now });
    return user;
  }

  private required(): OidcSettings {
    if (!this.settings) throw new Error('OIDC no está configurado');
    return this.settings;
  }

  /** Discovery perezoso y cacheado; si falla, se reintenta en la siguiente petición. */
  private config(): Promise<client.Configuration> {
    const now = Date.now();
    if (this.configuration && this.configuration.expiresAt > now)
      return this.configuration.value;
    const value = this.discover();
    this.configuration = { value, expiresAt: now + CONFIGURATION_TTL_MS };
    value.catch(() => {
      if (this.configuration?.value === value) this.configuration = null;
    });
    return value;
  }

  private async discover(): Promise<client.Configuration> {
    const settings = this.required();
    const secret = settings.clientSecretRef
      ? await this.secrets.resolve(settings.clientSecretRef)
      : null;
    const auth = !secret
      ? client.None()
      : settings.tokenAuthMethod === 'client_secret_post'
        ? client.ClientSecretPost(secret)
        : client.ClientSecretBasic(secret);
    const execute: Array<(config: client.Configuration) => void> = [
      // Firma del ID token comprobada contra el JWKS del proveedor (no solo TLS).
      client.enableNonRepudiationChecks,
    ];
    if (this.insecure) execute.push(client.allowInsecureRequests);
    return client.discovery(
      settings.issuer,
      settings.clientId,
      { redirect_uris: [settings.redirectUri.href] },
      auth,
      { execute, timeout: 10 },
    );
  }
}

function actorOf(
  user: Pick<User, 'id' | 'email'>,
  clientCtx: ClientContext,
): AuditActor {
  return { actorId: user.id, actorEmail: user.email, ip: clientCtx.ip };
}

function sameHash(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Recorre la cadena de causas de un error de openid-client/oauth4webapi. */
function errorChain(
  error: unknown,
): Array<{ code?: string; message: string; claim?: string }> {
  const chain: Array<{ code?: string; message: string; claim?: string }> = [];
  let current: unknown = error;
  for (let depth = 0; current && depth < 5; depth++) {
    const e = current as {
      code?: unknown;
      message?: unknown;
      claim?: unknown;
      cause?: unknown;
    };
    chain.push({
      code: typeof e.code === 'string' ? e.code : undefined,
      message: typeof e.message === 'string' ? e.message : '',
      claim: typeof e.claim === 'string' ? e.claim : undefined,
    });
    current = e.cause;
  }
  return chain;
}

/** Motivo (para la auditoría) de un fallo del canje o de la validación del ID token. */
export function classifyOidcError(error: unknown): LoginFailureReason {
  const chain = errorChain(error);
  const codes = new Set(chain.map((c) => c.code));
  const claim = chain.find((c) => c.claim)?.claim;
  const messages = chain.map((c) => c.message).join(' | ');
  if (
    codes.has('OAUTH_RESPONSE_BODY_ERROR') ||
    codes.has('OAUTH_AUTHORIZATION_RESPONSE_ERROR') ||
    codes.has('OAUTH_WWW_AUTHENTICATE_CHALLENGE')
  )
    return 'provider_error';
  if (codes.has('OAUTH_JWT_TIMESTAMP_CHECK_FAILED')) return 'token_expired';
  if (codes.has('OAUTH_JWT_CLAIM_COMPARISON_FAILED')) {
    if (claim === 'nonce') return 'nonce_invalid';
    if (claim === 'iss') return 'issuer_invalid';
    if (claim === 'aud' || claim === 'azp') return 'audience_invalid';
    return 'token_invalid';
  }
  if (
    codes.has('OAUTH_KEY_SELECTION_FAILED') ||
    /signature verification failed|"alg"/i.test(messages)
  )
    return 'signature_invalid';
  if (/fetch failed|ECONNREFUSED|timed? ?out|aborted/i.test(messages))
    return 'provider_unavailable';
  return 'token_invalid';
}

/** Resumen de un error para el log: solo tipo, código y mensaje (nunca tokens ni el code). */
function errorSummary(error: unknown): string {
  return errorChain(error)
    .filter((c) => c.code || c.message)
    .map((c) => `${c.code ?? 'error'}: ${c.message.slice(0, 160)}`)
    .join(' <- ');
}
