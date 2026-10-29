import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecretsService } from '@infraward/secrets';
import { SSH_CERT_PRINCIPAL, type SshAuthMode } from '@infraward/shared-types';
import { CollectionError } from '../collect/ansible-runner.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { SshIdentity } from './ssh-client.js';

/** Cómo entra el worker en un servidor (el propio asset o el nodo por el que se llega a él). */
export interface SshAccess {
  auth: SshAuthMode;
  /** Referencia de la clave estática; null si no hay (modo CA). */
  keyRef: string | null;
}

/** Para el key_id del certificado: qué asset y qué job (queda en el log de sshd del servidor). */
export interface SshTrace {
  assetId: string;
  jobId: string | undefined;
}

/**
 * Identidad SSH de cada job (DESIGN §6, §14):
 * - modo CA con un proveedor con CA SSH: par efímero firmado en el momento, con el principal
 *   `inventory`, key_id `infraward:asset=<id>:job=<id>` y vida `SSH_CERT_TTL`;
 * - si no (modo estático, o CA sin proveedor capaz pero con clave estática): la clave estática,
 *   resuelta sin caché para que un borrado en la API se vea al instante.
 */
@Injectable()
export class SshIdentities {
  private readonly logger = new Logger(SshIdentities.name);
  private readonly ttlSeconds: number;
  private readonly renewMarginSeconds: number;

  constructor(
    private readonly secrets: SecretsService,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.ttlSeconds = config.get('SSH_CERT_TTL', { infer: true });
    this.renewMarginSeconds = config.get('SSH_CERT_RENEW_MARGIN', {
      infer: true,
    });
  }

  /**
   * `strict`: en modo CA, sin proveedor con CA SSH falla en lugar de usar la clave estática (la
   * verificación de un alta en modo CA tiene que probar el certificado, no otra cosa).
   */
  async resolve(
    access: SshAccess,
    trace: SshTrace,
    options: { strict?: boolean } = {},
  ): Promise<SshIdentity> {
    if (access.auth === 'ca_certificate') {
      const ca = this.secrets.sshCertificates();
      if (ca) {
        const keyId = `infraward:asset=${trace.assetId}:job=${trace.jobId ?? 'ninguno'}`;
        return {
          kind: 'certificate',
          ttlSeconds: this.ttlSeconds,
          renewMarginSeconds: this.renewMarginSeconds,
          sign: async (publicKey) => {
            const certificate = await ca.signSshKey({
              publicKey,
              principal: SSH_CERT_PRINCIPAL,
              keyId,
              ttlSeconds: this.ttlSeconds,
            });
            this.logger.log(`Certificado SSH firmado por ${ca.id}: ${keyId}`);
            return certificate;
          },
        };
      }
      if (!access.keyRef || options.strict)
        throw new CollectionError(
          'El servidor está en modo CA y ningún proveedor de secretos activo tiene CA SSH',
        );
      this.logger.warn(
        `Asset ${trace.assetId} en modo CA sin proveedor con CA SSH: se usa su clave estática`,
      );
    }
    if (!access.keyRef)
      throw new CollectionError('El servidor no tiene clave SSH');
    return {
      kind: 'key',
      privateKey: await this.secrets.resolve(access.keyRef, { fresh: true }),
    };
  }
}
