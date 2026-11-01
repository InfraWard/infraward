import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { AlertChannel, Notification } from '@infraward/domain';
import { SecretsService } from '@infraward/secrets';
import {
  ALERTS_STATUS_KEY,
  JOB_NAMES,
  type AlertDeliverJobData,
  type AlertDeliverJobResult,
  type AlertsStatus,
  type AlertTestJobData,
  type AlertTestResult,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { JobQueues } from '../jobs/job-queues.js';
import { WorkerRedis } from '../redis/redis.js';
import {
  channelAccepts,
  emailContent,
  webhookPayload,
  type AlertSource,
} from './alert-message.js';
import { EmailSender } from './email-sender.js';
import { AlertSendError, sendWebhook } from './webhook-sender.js';

/** Notificaciones que se reparten por pasada. */
const DISPATCH_BATCH = 100;
/** Reintentos de un envío (con espera exponencial desde 30 s: hasta ~15 min). */
const DELIVER_ATTEMPTS = 5;
const DELIVER_BACKOFF_MS = 30_000;

/**
 * Alertas fuera de la app (DESIGN §10). El líder reparte cada pocos segundos las notificaciones
 * nuevas (`dispatched_at IS NULL`, las inserte quien las inserte: worker o API) entre los canales
 * que las admiten, con un job `alert.deliver` por notificación y canal; el envío lo hace cualquier
 * réplica, con reintentos. La API nunca envía: la prueba de un canal también es un job.
 */
@Injectable()
export class AlertDelivery {
  private readonly logger = new Logger(AlertDelivery.name);

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly queues: JobQueues,
    private readonly secrets: SecretsService,
    private readonly email: EmailSender,
    @Optional() private readonly redis?: WorkerRedis,
  ) {}

  /** Publica para la API si hay SMTP y si se admiten webhooks privados (sin datos de config). */
  async publishStatus(): Promise<void> {
    const status: AlertsStatus = {
      smtpConfigured: this.email.configured,
      allowPrivate: this.config.get('ALERTS_WEBHOOK_ALLOW_PRIVATE', { infer: true }),
      allowHttp: this.config.get('ALERTS_WEBHOOK_ALLOW_HTTP', { infer: true }),
    };
    await this.redis?.client.set(ALERTS_STATUS_KEY, JSON.stringify(status));
  }

  /**
   * Reparte las notificaciones pendientes; devuelve cuántos envíos encoló. Cada tanda se bloquea
   * (`FOR UPDATE SKIP LOCKED`: con dos líderes un instante, cada una la reparte uno), se encolan
   * sus envíos y solo entonces se marca `dispatched_at`, en la misma transacción. Si Redis falla
   * (o el proceso cae) a medias, no se marca nada y la siguiente pasada lo vuelve a intentar: los
   * envíos ya encolados no se repiten (mismo `jobId`). Así ninguna alerta se pierde sin avisar.
   */
  async dispatch(): Promise<number> {
    const channels = await this.db
      .getRepository(AlertChannel)
      .find({ where: { enabled: true } });
    let queued = 0;
    for (;;) {
      const claimed = await this.db.transaction(async (m) => {
        const rows: NotificationRow[] = await m.query(
          `SELECT id, kind, audience_roles FROM notifications WHERE dispatched_at IS NULL
            ORDER BY created_at LIMIT ${DISPATCH_BATCH} FOR UPDATE SKIP LOCKED`,
        );
        for (const n of rows)
          for (const channel of channels) {
            if (!channelAccepts(channel, { kind: n.kind, audienceRoles: n.audience_roles }))
              continue;
            await this.queues.add(
              JOB_NAMES.alertDeliver,
              { notificationId: n.id, channelId: channel.id } satisfies AlertDeliverJobData,
              {
                // Sin UUID: no sale en la Actividad. Con el mismo id, BullMQ no lo duplica.
                jobId: `alert-${n.id}-${channel.id}`,
                attempts: DELIVER_ATTEMPTS,
                backoff: { type: 'exponential', delay: DELIVER_BACKOFF_MS },
                removeOnComplete: { age: 86_400, count: 1000 },
                removeOnFail: { age: 7 * 86_400, count: 1000 },
              },
            );
            queued++;
          }
        if (rows.length)
          await m.query(
            `UPDATE notifications SET dispatched_at = now() WHERE id = ANY($1::uuid[])`,
            [rows.map((n) => n.id)],
          );
        return rows;
      });
      if (claimed.length < DISPATCH_BATCH) break;
    }
    return queued;
  }

  /** `alert.deliver`: un fallo lanza (BullMQ reintenta) y queda en el canal. */
  async deliver(data: AlertDeliverJobData): Promise<AlertDeliverJobResult> {
    const channel = await this.db
      .getRepository(AlertChannel)
      .findOneBy({ id: data.channelId });
    const notification = await this.db
      .getRepository(Notification)
      .findOneBy({ id: data.notificationId });
    // Borrado o desactivado entretanto (o la notificación se podó): nada que enviar.
    if (!channel?.enabled || !notification) return { ok: false, skipped: true };
    await this.send(channel, notification, 'notification');
    return { ok: true };
  }

  /** `alert.test`: un mensaje de prueba; nunca lanza (la API espera el resultado). */
  async test(data: AlertTestJobData): Promise<AlertTestResult> {
    const channel = await this.db
      .getRepository(AlertChannel)
      .findOneBy({ id: data.channelId });
    if (!channel) return { ok: false, error: 'El canal no existe' };
    try {
      await this.send(
        channel,
        {
          id: `test-${Date.now()}`,
          kind: 'asset_created',
          assetId: null,
          assetName: null,
          message: `Prueba del canal «${channel.name}» de InfraWard`,
          items: [],
          total: 0,
          createdAt: new Date(),
        },
        'test',
      );
      return { ok: true, error: null };
    } catch (error) {
      return { ok: false, error: (error as Error).message };
    }
  }

  private async send(
    channel: AlertChannel,
    n: AlertSource,
    event: 'notification' | 'test',
  ): Promise<void> {
    const publicUrl = this.config.get('ALERTS_PUBLIC_URL', { infer: true });
    try {
      if (channel.type === 'webhook') {
        if (!('urlRef' in channel.config)) throw new AlertSendError('Canal sin URL');
        let url: string;
        try {
          url = await this.secrets.resolve(channel.config.urlRef, { fresh: true });
        } catch (error) {
          throw new AlertSendError(`No se pudo leer la URL (${(error as Error).name})`);
        }
        let secret: string | null = null;
        if (channel.secretRef)
          try {
            secret = await this.secrets.resolve(channel.secretRef, { fresh: true });
          } catch (error) {
            throw new AlertSendError(
              `No se pudo leer el secreto de firma (${(error as Error).name})`,
            );
          }
        await sendWebhook(url, webhookPayload(n, publicUrl, event), {
          timeoutMs: this.config.get('ALERTS_TIMEOUT_MS', { infer: true }),
          allowHttp: this.config.get('ALERTS_WEBHOOK_ALLOW_HTTP', { infer: true }),
          allowPrivate: this.config.get('ALERTS_WEBHOOK_ALLOW_PRIVATE', { infer: true }),
          secret,
        });
      } else {
        if (!('recipients' in channel.config)) throw new AlertSendError('Canal sin destinatarios');
        await this.email.send({
          to: channel.config.recipients,
          ...emailContent(n, publicUrl),
        });
      }
    } catch (error) {
      const message =
        error instanceof AlertSendError ? error.message : `Error (${(error as Error).name})`;
      // Sin tocar updated_at (es la fecha del último cambio del canal, no del último envío).
      await this.db.query(
        `UPDATE alert_channels SET last_error_at = now(), last_error = $2 WHERE id = $1`,
        [channel.id, message.slice(0, 255)],
      );
      this.logger.warn(`Alerta por «${channel.name}» (${channel.type}): ${message}`);
      throw new AlertSendError(message);
    }
    await this.db.query(`UPDATE alert_channels SET last_success_at = now() WHERE id = $1`, [
      channel.id,
    ]);
  }
}

interface NotificationRow {
  id: string;
  kind: Notification['kind'];
  audience_roles: string[] | null;
}
