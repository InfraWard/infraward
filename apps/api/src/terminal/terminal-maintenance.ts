import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AccessService } from '../access/access.service.js';
import { SessionRegistry } from '../auth/session-registry.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { TerminalService } from './terminal.service.js';

/**
 * Cortes y barrido de las terminales (sesión 22, DESIGN §11):
 * - al cerrarse sesiones web (logout, desactivar, contraseña, MFA…), cambiar el rol de alguien o
 *   las reglas de acceso, vuelve a comprobar las terminales abiertas y corta las que ya no pueden
 *   seguir (aviso al gateway por Redis);
 * - cada `TERMINAL_SWEEP_INTERVAL`, cierra las que perdieron el latido de su gateway.
 */
@Injectable()
export class TerminalMaintenance implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(TerminalMaintenance.name);
  private readonly unsubscribe: (() => void)[] = [];
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly terminal: TerminalService,
    private readonly registry: SessionRegistry,
    private readonly access: AccessService,
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  onApplicationBootstrap(): void {
    this.unsubscribe.push(
      // Las sesiones borradas ya no se pueden buscar (la FK pone `auth_session_id` a null):
      // se revisan todas las abiertas, que son pocas.
      this.registry.onSessionsClosed(() => this.run(() => this.terminal.recheck())),
      this.registry.onUserChanged((userId) =>
        this.run(() => this.terminal.recheck({ userIds: [userId] })),
      ),
      this.access.onChange(() => this.run(() => this.terminal.recheck())),
    );
    const every = this.config.get('TERMINAL_SWEEP_INTERVAL', { infer: true }) * 1000;
    this.timer = setInterval(() => this.run(() => this.terminal.sweep()), every);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    clearInterval(this.timer);
    for (const off of this.unsubscribe) off();
  }

  private run(task: () => Promise<unknown>): void {
    task().catch((error: unknown) =>
      this.logger.error(`Mantenimiento de terminales: ${(error as Error).message}`),
    );
  }
}
