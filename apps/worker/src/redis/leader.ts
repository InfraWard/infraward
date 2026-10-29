import { Injectable, Logger } from '@nestjs/common';
import { WORKER_LEADER_KEY } from '@infraward/shared-types';
import { EXTEND_IF_OWNER, RELEASE_IF_OWNER, WorkerRedis } from './redis.js';

/** Vida del lease de líder: si el líder muere, otro lo toma como mucho en este tiempo. */
export const LEADER_TTL_MS = 30_000;
const LEADER_RENEW_MS = 10_000;

export interface LeaderHooks {
  /** Esta réplica acaba de ser elegida. */
  elected(): Promise<void>;
  /** Ha dejado de ser líder (perdió el lease o se para). */
  demoted(): Promise<void>;
}

/**
 * Elección de líder entre las réplicas (DESIGN §20): lease en Redis (`WORKER_LEADER_KEY` = nombre
 * de la réplica) que el líder renueva cada 10 s y que las demás intentan tomar con `SET NX`. El
 * líder programa los jobs periódicos, poda el historial, escucha los eventos de las colas y
 * recupera los huérfanos.
 */
@Injectable()
export class LeaderElection {
  private readonly logger = new Logger(LeaderElection.name);
  private timer?: NodeJS.Timeout;
  private name: string | null = null;
  private hooks: LeaderHooks | null = null;
  private leading = false;
  /** Las transiciones van en serie (una elección no se pisa con una destitución). */
  private chain: Promise<void> = Promise.resolve();

  constructor(private readonly redis: WorkerRedis) {}

  get isLeader(): boolean {
    return this.leading;
  }

  start(name: string, hooks: LeaderHooks): void {
    this.name = name;
    this.hooks = hooks;
    this.timer = setInterval(() => void this.tick(), LEADER_RENEW_MS);
    this.timer.unref();
    void this.tick();
  }

  /** Deja de optar y suelta el lease (parada): otra réplica toma el relevo al momento. */
  async stop(): Promise<void> {
    clearInterval(this.timer);
    this.timer = undefined;
    await this.enqueue(async () => {
      if (!this.leading || !this.name) return;
      await this.setLeading(false);
      await this.redis.client
        .eval(RELEASE_IF_OWNER, 1, WORKER_LEADER_KEY, this.name)
        .catch(() => undefined);
    });
  }

  private tick(): Promise<void> {
    return this.enqueue(async () => {
      if (!this.name || !this.timer) return;
      try {
        const held = this.leading
          ? (await this.redis.client.eval(
              EXTEND_IF_OWNER,
              1,
              WORKER_LEADER_KEY,
              this.name,
              LEADER_TTL_MS,
            )) === 1
          : (await this.redis.client.set(
              WORKER_LEADER_KEY,
              this.name,
              'PX',
              LEADER_TTL_MS,
              'NX',
            )) === 'OK';
        if (held !== this.leading) await this.setLeading(held);
      } catch (error) {
        // Sin Redis no se sabe si el lease sigue: el líder deja de serlo hasta poder renovarlo.
        this.logger.warn(`Elección de líder: ${(error as Error).name}`);
        if (this.leading) await this.setLeading(false);
      }
    });
  }

  private async setLeading(leading: boolean): Promise<void> {
    this.leading = leading;
    this.logger.log(
      leading
        ? `${this.name} es ahora el líder`
        : `${this.name} deja de ser el líder`,
    );
    try {
      await (leading ? this.hooks?.elected() : this.hooks?.demoted());
    } catch (error) {
      this.logger.warn(
        `Tareas del líder al ${leading ? 'empezar' : 'terminar'}: ${(error as Error).name}`,
      );
    }
  }

  private enqueue(fn: () => Promise<void>): Promise<void> {
    this.chain = this.chain.then(fn, fn);
    return this.chain;
  }
}
