import {
  Inject,
  Injectable,
  Module,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createTerminalSigner,
  openBaoSourceFromEnv,
  type TerminalCertSigner,
} from '@infraward/secrets';
import { readFileSync } from 'node:fs';
import { AccessModule } from '../access/access.module.js';
import { SessionsModule } from '../auth/sessions.module.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { gatewaySecretHash, GatewayAuthGuard } from './gateway-auth.guard.js';
import { TerminalControl } from './terminal-control.js';
import { TerminalMaintenance } from './terminal-maintenance.js';
import {
  AssetTerminalController,
  GatewayInternalController,
  TerminalController,
} from './terminal.controller.js';
import { TerminalService } from './terminal.service.js';
import { GATEWAY_SECRET_HASH, TERMINAL_SIGNER } from './terminal.tokens.js';

/**
 * Firmante de la terminal a partir del entorno (TERMINAL_OPENBAO_*). Se niega a arrancar si
 * comparte la AppRole o el rol de firma con la app (los que también tiene el worker).
 */
export function terminalSignerFromConfig(
  config: ConfigService<EnvironmentVariables, true>,
): TerminalCertSigner | null {
  const get = <K extends keyof EnvironmentVariables>(k: K) => config.get(k, { infer: true });
  const app = openBaoSourceFromEnv((name) =>
    config.get(name as keyof EnvironmentVariables, { infer: true }),
  );
  return createTerminalSigner({
    openbao: {
      addr: app.addr,
      kvMount: app.kvMount,
      approleMount: app.approleMount,
      sshMount: app.sshMount,
      timeoutMs: app.timeoutMs,
      roleId: get('TERMINAL_OPENBAO_ROLE_ID'),
      secretId: get('TERMINAL_OPENBAO_SECRET_ID'),
      secretIdFile: get('TERMINAL_OPENBAO_SECRET_ID_FILE'),
      sshRole: get('TERMINAL_OPENBAO_SSH_ROLE'),
    },
    appOpenbao: { roleId: app.roleId, sshRole: app.sshRole },
  });
}

/** sha256 del secreto del gateway (null sin GATEWAY_API_SECRET_FILE). El error no lleva el valor. */
export function gatewaySecretFromConfig(
  config: ConfigService<EnvironmentVariables, true>,
): Buffer | null {
  const file = config.get('GATEWAY_API_SECRET_FILE', { infer: true });
  if (!file) return null;
  let secret: string;
  try {
    secret = readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(
      `GATEWAY_API_SECRET_FILE: no se puede leer el fichero (${(error as NodeJS.ErrnoException).code ?? 'error'})`,
      { cause: error },
    );
  }
  return gatewaySecretHash(secret);
}

/** Revoca el token de OpenBao del firmante al parar la API. */
@Injectable()
class TerminalSignerCloser implements OnApplicationShutdown {
  constructor(@Inject(TERMINAL_SIGNER) private readonly signer: TerminalCertSigner | null) {}

  async onApplicationShutdown(): Promise<void> {
    await this.signer?.close();
  }
}

/**
 * Terminal interactiva (sesiones 21 y 22, DESIGN §11). El firmante solo existe en la API. Las
 * políticas de acceso (AccessModule) deciden quién, además del rol.
 */
@Module({
  imports: [SessionsModule, AccessModule],
  controllers: [TerminalController, AssetTerminalController, GatewayInternalController],
  providers: [
    {
      provide: TERMINAL_SIGNER,
      inject: [ConfigService],
      useFactory: terminalSignerFromConfig,
    },
    {
      provide: GATEWAY_SECRET_HASH,
      inject: [ConfigService],
      useFactory: gatewaySecretFromConfig,
    },
    TerminalSignerCloser,
    GatewayAuthGuard,
    TerminalService,
    TerminalControl,
    TerminalMaintenance,
  ],
})
export class TerminalModule {}
