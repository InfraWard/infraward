import { Injectable, Logger } from '@nestjs/common';
import { SecretsService } from '@infraward/secrets';
import { sshCaOutdated, type SshCaTrust } from '@infraward/shared-types';

/** Las claves de la CA cambian solo al rotar: unos segundos de caché bastan. */
const CACHE_MS = 30_000;

/**
 * Huellas de las CA SSH vigentes en el proveedor (para el aviso «CA SSH desactualizada»). Si no
 * hay proveedor con CA o no responde, no hay referencia con la que comparar: no se avisa.
 */
@Injectable()
export class SshCaTrustService {
  private readonly logger = new Logger(SshCaTrustService.name);
  private cached: { at: number; fingerprints: Promise<string[]> } | null = null;

  constructor(private readonly secrets: SecretsService) {}

  /** Huellas `SHA256:…` de las CA vigentes (vacío si no hay CA). */
  currentFingerprints(): Promise<string[]> {
    const now = Date.now();
    if (this.cached && now - this.cached.at < CACHE_MS)
      return this.cached.fingerprints;
    const fingerprints = this.load();
    this.cached = { at: now, fingerprints };
    return fingerprints;
  }

  /** ¿El servidor confía en un conjunto de CA distinto del vigente? */
  async outdated(installed: SshCaTrust | null | undefined): Promise<boolean> {
    return sshCaOutdated(installed, await this.currentFingerprints());
  }

  private async load(): Promise<string[]> {
    const ca = this.secrets.sshCertificates();
    if (!ca) return [];
    try {
      return (await ca.sshCaPublicKeys()).map((k) => k.fingerprint);
    } catch (error) {
      this.logger.warn(
        `No se pudieron leer las CA SSH de ${ca.id}: ${(error as Error).message}`,
      );
      // Sin caché de un fallo: el siguiente uso lo vuelve a intentar.
      this.cached = null;
      return [];
    }
  }
}
