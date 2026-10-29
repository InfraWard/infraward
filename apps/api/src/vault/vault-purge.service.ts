import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { VaultService } from './vault.service.js';

const HOUR = 3_600_000;
/** Clave del advisory lock: con varias réplicas de la API, solo una purga a la vez. */
const PURGE_LOCK = 0x1a17_0007;

/**
 * Destruye cada hora (y al arrancar) las entradas de la caja fuerte borradas hace más del plazo.
 * Va en la API y no en el worker a propósito: el worker no tiene acceso al almacén de la caja
 * fuerte. Es trabajo ligero (pocas filas, una llamada al almacén por entrada).
 */
@Injectable()
export class VaultPurgeService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(VaultPurgeService.name);
  private timer: NodeJS.Timeout | undefined;
  private first: NodeJS.Timeout | undefined;

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly vault: VaultService,
  ) {}

  onApplicationBootstrap(): void {
    this.first = setTimeout(() => void this.run(), 30_000);
    this.timer = setInterval(() => void this.run(), HOUR);
    this.first.unref();
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    clearTimeout(this.first);
    clearInterval(this.timer);
  }

  /** Una pasada, si ninguna otra réplica la está haciendo. */
  async run(): Promise<number> {
    const runner = this.db.createQueryRunner();
    try {
      await runner.connect();
      const [{ locked }] = (await runner.query('SELECT pg_try_advisory_lock($1) AS locked', [
        PURGE_LOCK,
      ])) as { locked: boolean }[];
      if (!locked) return 0;
      try {
        const purged = await this.vault.purgeExpired();
        if (purged > 0) this.logger.log(`Caja fuerte: ${purged} entradas destruidas tras el plazo`);
        return purged;
      } finally {
        await runner.query('SELECT pg_advisory_unlock($1)', [PURGE_LOCK]);
      }
    } catch (error) {
      this.logger.warn(`No se pudo purgar la caja fuerte: ${(error as Error).name}`);
      return 0;
    } finally {
      await runner.release();
    }
  }
}
