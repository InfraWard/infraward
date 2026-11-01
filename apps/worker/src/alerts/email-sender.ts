import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecretsService } from '@infraward/secrets';
import { createTransport } from 'nodemailer';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { AlertSendError } from './webhook-sender.js';

export interface EmailMessage {
  to: string[];
  subject: string;
  text: string;
  html: string;
}

/**
 * Correo de las alertas por el SMTP del worker (DESIGN §10). La contraseña es una referencia
 * `secret://` (SMTP_PASSWORD_REF) que se resuelve en cada envío; nunca va al log. TLS obligatorio
 * (directo o STARTTLS) salvo SMTP_REQUIRE_TLS=false.
 */
@Injectable()
export class EmailSender {
  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly secrets: SecretsService,
  ) {}

  get configured(): boolean {
    return !!this.config.get('SMTP_HOST', { infer: true });
  }

  async send(message: EmailMessage): Promise<void> {
    const host = this.config.get('SMTP_HOST', { infer: true });
    if (!host) throw new AlertSendError('El worker no tiene SMTP configurado (SMTP_HOST)');
    const user = this.config.get('SMTP_USER', { infer: true });
    const ref = this.config.get('SMTP_PASSWORD_REF', { infer: true });
    let pass: string | undefined;
    if (user && ref) {
      try {
        pass = await this.secrets.resolve(ref, { fresh: true });
      } catch (error) {
        throw new AlertSendError(
          `No se pudo leer la contraseña SMTP (${(error as Error).name})`,
        );
      }
    }
    const secure = this.config.get('SMTP_SECURE', { infer: true });
    const timeout = this.config.get('ALERTS_TIMEOUT_MS', { infer: true });
    const transport = createTransport({
      host,
      port: this.config.get('SMTP_PORT', { infer: true }),
      secure,
      requireTLS: !secure && this.config.get('SMTP_REQUIRE_TLS', { infer: true }),
      ...(user ? { auth: { user, pass } } : {}),
      connectionTimeout: timeout,
      greetingTimeout: timeout,
      socketTimeout: timeout,
      logger: false,
      debug: false,
    });
    try {
      await transport.sendMail({
        from: this.config.get('SMTP_FROM', { infer: true }),
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
      });
    } catch (error) {
      const e = error as { code?: string; responseCode?: number };
      throw new AlertSendError(
        `SMTP: ${e.responseCode ? `${e.responseCode}` : (e.code ?? 'error')}`,
      );
    } finally {
      transport.close();
    }
  }
}
