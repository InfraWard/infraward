import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  isForbiddenWebhookIp,
  parseWebhookUrl,
  WebhookTargetError,
} from '@infraward/connectors';
import { AlertChannel as AlertChannelEntity } from '@infraward/domain';
import {
  formatSecretRef,
  parseSecretRef,
  SecretsService,
} from '@infraward/secrets';
import {
  ALERT_CHANNELS_MAX,
  ALERTS_STATUS_KEY,
  JOB_NAMES,
  type AlertChannel,
  type AlertsStatus,
  type AlertTestResult,
} from '@infraward/shared-types';
import { Redis } from 'ioredis';
import { isIP } from 'node:net';
import { randomUUID } from 'node:crypto';
import { DataSource, type EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { JobsService } from '../jobs/jobs.service.js';
import { writableSecretsProvider } from '../secrets/writable-provider.js';
import type { CreateAlertChannelDto, UpdateAlertChannelDto } from './alerts.dto.js';

/** Dónde van en el gestor de secretos la URL del webhook y su secreto de firma. */
const URL_SECRET = { path: 'webhook-url', field: 'url' } as const;
const SIGNING_SECRET = { path: 'webhook-signing', field: 'signing_secret' } as const;
type StoredSecret = typeof URL_SECRET | typeof SIGNING_SECRET;
/** Lo que espera la API a la prueba de un canal (un webhook lento o un SMTP con greylisting). */
const TEST_TIMEOUT_MS = 30_000;

/**
 * Canales de alertas fuera de la app (DESIGN §10). La API solo los guarda (el secreto de firma
 * en el gestor de secretos, como referencia) y encola la prueba: el envío, la resolución DNS y la
 * protección SSRF completa son del worker. Aquí se valida la forma de la URL para avisar pronto.
 */
@Injectable()
export class AlertsService implements OnApplicationShutdown {
  private readonly logger = new Logger(AlertsService.name);
  private client?: Redis;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly jobs: JobsService,
    private readonly audit: AuditService,
  ) {}

  async onApplicationShutdown(): Promise<void> {
    await this.client?.quit().catch(() => undefined);
  }

  /** Lo que publica el worker al arrancar (SMTP configurado, webhooks http/privados). */
  async status(): Promise<AlertsStatus> {
    try {
      const raw = await this.redis().get(ALERTS_STATUS_KEY);
      const parsed = raw ? (JSON.parse(raw) as Partial<AlertsStatus>) : {};
      return {
        smtpConfigured: parsed.smtpConfigured ?? null,
        allowPrivate: parsed.allowPrivate ?? null,
        allowHttp: parsed.allowHttp ?? null,
      };
    } catch (error) {
      this.logger.warn(`Estado de las alertas: ${(error as Error).name}`);
      return { smtpConfigured: null, allowPrivate: null, allowHttp: null };
    }
  }

  async list(): Promise<AlertChannel[]> {
    const rows = await this.db
      .getRepository(AlertChannelEntity)
      .find({ order: { name: 'ASC', createdAt: 'ASC' } });
    return rows.map(toChannel);
  }

  async get(id: string): Promise<AlertChannel> {
    return toChannel(await this.find(this.db.manager, id));
  }

  async create(body: CreateAlertChannelDto, actor: AuditActor): Promise<AlertChannel> {
    const target = await this.target(body.type, body);
    if (body.type === 'email' && body.secret)
      throw new BadRequestException('El correo no lleva secreto de firma');
    const count = await this.db.getRepository(AlertChannelEntity).count();
    if (count >= ALERT_CHANNELS_MAX)
      throw new ConflictException(`Como mucho ${ALERT_CHANNELS_MAX} canales`);
    const id = randomUUID();
    const stored: string[] = [];
    try {
      const config: AlertChannelEntity['config'] =
        'url' in target
          ? { host: target.host, urlRef: await this.storeSecret(id, URL_SECRET, target.url, null, stored) }
          : target;
      const secretRef = body.secret
        ? await this.storeSecret(id, SIGNING_SECRET, body.secret, null, stored)
        : null;
      await this.db.transaction(async (m) => {
        await m.insert(AlertChannelEntity, {
          id,
          name: body.name.trim(),
          type: body.type,
          enabled: body.enabled ?? true,
          kinds: body.kinds ?? null,
          includeAdminOnly: body.includeAdminOnly ?? false,
          config,
          secretRef,
        });
        await this.audit.record(actor, 'alerts.channel_created', {
          target: { type: 'alert_channel', id, label: body.name.trim() },
          details: {
            ...destination(config),
            type: body.type,
            enabled: body.enabled ?? true,
            ...('urlRef' in config ? { storedIn: parseSecretRef(config.urlRef).provider } : {}),
          },
          manager: m,
        });
      });
    } catch (error) {
      for (const ref of stored) await this.secrets.remove(baseOf(ref)).catch(() => undefined);
      throw error;
    }
    return this.get(id);
  }

  async update(
    id: string,
    body: UpdateAlertChannelDto,
    actor: AuditActor,
  ): Promise<AlertChannel> {
    const current = await this.find(this.db.manager, id);
    if (current.type === 'email' && body.secret)
      throw new BadRequestException('El correo no lleva secreto de firma');
    if (current.type === 'webhook' && body.recipients)
      throw new BadRequestException('Un webhook no tiene destinatarios');
    if (current.type === 'email' && body.url)
      throw new BadRequestException('Un canal de correo no tiene URL');
    let config = current.config;
    if (body.url !== undefined || body.recipients !== undefined) {
      const target = await this.target(current.type, body);
      config =
        'url' in target
          ? {
              host: target.host,
              urlRef: await this.storeSecret(
                id,
                URL_SECRET,
                target.url,
                'urlRef' in current.config ? current.config.urlRef : null,
              ),
            }
          : target;
    }
    // Secreto de firma: uno nuevo se guarda (en su sitio si se puede); null lo quita al terminar.
    let secretRef = current.secretRef;
    let removeAfter: string | null = null;
    if (typeof body.secret === 'string')
      secretRef = await this.storeSecret(id, SIGNING_SECRET, body.secret, current.secretRef);
    else if (body.secret === null && current.secretRef) {
      secretRef = null;
      removeAfter = current.secretRef;
    }
    // La URL anterior, si estaba en otro sitio (otro proveedor), sobra.
    const oldUrl = 'urlRef' in current.config ? current.config.urlRef : null;
    const newUrl = 'urlRef' in config ? config.urlRef : null;
    const removeUrl = oldUrl && newUrl && baseOf(oldUrl) !== baseOf(newUrl) ? oldUrl : null;
    const changes: Partial<AlertChannelEntity> = {
      ...(body.name !== undefined ? { name: body.name.trim() } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.kinds !== undefined ? { kinds: body.kinds } : {}),
      ...(body.includeAdminOnly !== undefined ? { includeAdminOnly: body.includeAdminOnly } : {}),
      config,
      secretRef,
    };
    const fields = Object.keys(body).filter((k) => k !== 'secret');
    await this.db.transaction(async (m) => {
      await m.update(AlertChannelEntity, { id }, changes);
      await this.audit.record(actor, 'alerts.channel_updated', {
        target: { type: 'alert_channel', id, label: changes.name ?? current.name },
        details: {
          ...destination(config),
          type: current.type,
          fields,
          ...(body.secret !== undefined ? { secretChanged: true } : {}),
          ...(body.enabled === false ? { enabled: false } : {}),
        },
        manager: m,
      });
    });
    for (const ref of [removeAfter, removeUrl])
      if (ref) await this.secrets.remove(baseOf(ref)).catch(() => undefined);
    return this.get(id);
  }

  async remove(id: string, actor: AuditActor): Promise<void> {
    const current = await this.find(this.db.manager, id);
    await this.db.transaction(async (m) => {
      await m.delete(AlertChannelEntity, { id });
      await this.audit.record(actor, 'alerts.channel_deleted', {
        target: { type: 'alert_channel', id, label: current.name },
        details: { ...destination(current.config), type: current.type },
        manager: m,
      });
    });
    const refs = [
      current.secretRef,
      'urlRef' in current.config ? current.config.urlRef : null,
    ];
    for (const ref of refs)
      if (ref)
        await this.secrets.remove(baseOf(ref)).catch((error: unknown) =>
          this.logger.warn(`No se pudo borrar un secreto del canal: ${(error as Error).name}`),
        );
  }

  /** Mensaje de prueba: lo envía el worker y la API espera el resultado. */
  async test(id: string, actor: AuditActor): Promise<AlertTestResult> {
    const channel = await this.find(this.db.manager, id);
    const result = (await this.jobs.runQuick(
      JOB_NAMES.alertTest,
      { channelId: id },
      { idPrefix: 'alert-test-', timeoutMs: TEST_TIMEOUT_MS },
    )) ?? { ok: false, error: 'El worker no respondió a tiempo' };
    await this.audit.tryRecord(actor, 'alerts.channel_tested', {
      target: { type: 'alert_channel', id, label: channel.name },
      outcome: result.ok ? 'success' : 'failure',
      details: {
        ...destination(channel.config),
        type: channel.type,
        ...(result.error ? { error: result.error } : {}),
      },
    });
    return result;
  }

  private async find(m: EntityManager, id: string): Promise<AlertChannelEntity> {
    const row = await m.findOneBy(AlertChannelEntity, { id });
    if (!row) throw new NotFoundException('Canal no encontrado');
    return row;
  }

  /** Destino del canal según su tipo (la URL, validada, aún sin guardar); 400 si falta o no vale. */
  private async target(
    type: AlertChannelEntity['type'],
    body: { url?: string; recipients?: string[] },
  ): Promise<{ url: string; host: string } | { recipients: string[] }> {
    if (type === 'email') {
      if (!body.recipients?.length) throw new BadRequestException('Faltan los destinatarios');
      if (body.url) throw new BadRequestException('Un canal de correo no tiene URL');
      return { recipients: [...new Set(body.recipients.map((r) => r.trim().toLowerCase()))] };
    }
    if (!body.url) throw new BadRequestException('Falta la URL del webhook');
    if (body.recipients) throw new BadRequestException('Un webhook no tiene destinatarios');
    const status = await this.status();
    try {
      const url = parseWebhookUrl(body.url.trim(), { allowHttp: status.allowHttp === true });
      // Una IP literal se puede comprobar ya; los nombres los resuelve el worker al enviar.
      const host = url.hostname.replace(/^\[|\]$/g, '');
      if (isIP(host) && isForbiddenWebhookIp(host))
        throw new WebhookTargetError(
          'La dirección no está permitida (loopback, enlace local o reservada)',
        );
      return { url: url.toString(), host: url.host };
    } catch (error) {
      if (error instanceof WebhookTargetError) throw new BadRequestException(error.message);
      throw error;
    }
  }

  /**
   * Guarda un secreto del canal (la URL o el de firma) y devuelve su referencia (`…#campo`): en su
   * sitio si su proveedor admite escritura; si no, en el primero que la admita. `stored` recoge lo
   * guardado para deshacerlo si falla el alta.
   */
  private async storeSecret(
    id: string,
    kind: StoredSecret,
    value: string,
    current: string | null,
    stored?: string[],
  ): Promise<string> {
    const same = current ? parseSecretRef(current) : null;
    const target =
      same && this.secrets.provider(same.provider).set
        ? formatSecretRef({ provider: same.provider, path: same.path })
        : formatSecretRef({
            provider: writableSecretsProvider(this.secrets, this.config),
            path: `alerts/${id}/${kind.path}`,
          });
    const base = await this.secrets.store(target, { [kind.field]: value });
    const ref = `${base}#${kind.field}`;
    stored?.push(ref);
    return ref;
  }

  private redis(): Redis {
    this.client ??= new Redis({
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
      maxRetriesPerRequest: 2,
    });
    return this.client;
  }
}

/** Referencia sin `#campo` (la que se borra en el gestor). */
function baseOf(ref: string): string {
  const { provider, path } = parseSecretRef(ref);
  return formatSecretRef({ provider, path });
}

/** Destino para la auditoría: el host del webhook o cuántos destinatarios (nunca la ruta). */
function destination(config: AlertChannelEntity['config']): Record<string, string | number> {
  if ('host' in config) return { host: config.host };
  return { recipients: config.recipients.length };
}

function toChannel(row: AlertChannelEntity): AlertChannel {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    enabled: row.enabled,
    kinds: row.kinds,
    includeAdminOnly: row.includeAdminOnly,
    host: 'host' in row.config ? row.config.host : null,
    recipients: 'recipients' in row.config ? row.config.recipients : null,
    hasSecret: !!row.secretRef,
    secretProvider:
      'urlRef' in row.config ? parseSecretRef(row.config.urlRef).provider : null,
    lastSuccessAt: row.lastSuccessAt?.toISOString() ?? null,
    lastErrorAt: row.lastErrorAt?.toISOString() ?? null,
    lastError: row.lastError,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}
