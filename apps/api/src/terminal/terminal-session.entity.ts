import { Asset } from '@infraward/domain';
import {
  TERMINAL_CLOSE_REASONS,
  TERMINAL_SESSION_STATES,
  type TerminalAction,
  type TerminalCloseReason,
  type TerminalSessionState,
} from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UserSession } from '../auth/user-session.entity.js';
import { User } from '../users/user.entity.js';

/**
 * Sesión interactiva a través del gateway (sesión 21, DESIGN §5 y §11): quién, en qué asset,
 * con qué cuenta, cuándo y por qué terminó. El ticket que el cliente presenta al gateway solo
 * se guarda como sha256 y se gasta al canjearlo (`pending` → `starting`).
 */
@Entity({ name: 'terminal_sessions' })
// Las vivas (latido y barrido, sesión 22).
@Index('IDX_terminal_sessions_live', ['state'], { where: `"state" IN ('starting', 'active')` })
export class TerminalSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('IDX_terminal_sessions_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user?: User;

  /**
   * Sesión web que la pidió: al canjear el ticket tiene que seguir viva (y ser la de la cookie
   * del WebSocket); al cerrarla se corta la terminal.
   */
  @Index('IDX_terminal_sessions_auth_session_id')
  @Column({ name: 'auth_session_id', type: 'uuid', nullable: true })
  authSessionId: string | null;

  @ManyToOne(() => UserSession, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'auth_session_id' })
  authSession?: UserSession | null;

  /** Asset en el que se abre la terminal (servidor, CT o contenedor). */
  @Index('IDX_terminal_sessions_asset_id')
  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset | null;

  /** Servidor por el que se entra por SSH (el propio asset o su host raíz). */
  @Column({ name: 'host_asset_id', type: 'uuid', nullable: true })
  hostAssetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'host_asset_id' })
  hostAsset?: Asset | null;

  /** Nombre del asset al abrirla (se conserva si el asset se purga). */
  @Column({ name: 'asset_name', type: 'varchar', length: 255 })
  assetName: string;

  /** Cuenta del servidor con la que se entra. */
  @Column({ type: 'varchar', length: 32 })
  account: string;

  @Column({
    type: 'enum',
    enum: TERMINAL_SESSION_STATES,
    enumName: 'terminal_session_state',
    default: 'pending',
  })
  state: TerminalSessionState;

  /** sha256 del ticket (null una vez gastado). */
  @Index('UQ_terminal_sessions_ticket_hash', { unique: true })
  @Column({ name: 'ticket_hash', type: 'bytea', nullable: true })
  ticketHash: Buffer | null;

  @Column({ name: 'ticket_expires_at', type: 'timestamptz' })
  ticketExpiresAt: Date;

  /** Cuándo se canjeó el ticket: el certificado solo se firma poco después. */
  @Column({ name: 'redeemed_at', type: 'timestamptz', nullable: true })
  redeemedAt: Date | null;

  /** Certificados firmados para esta sesión (tope: no se firma indefinidamente). */
  @Column({ name: 'certificates_issued', type: 'int', default: 0 })
  certificatesIssued: number;

  /** Réplica del gateway que la atiende (`gateway-1`). */
  @Column({ type: 'varchar', length: 64, nullable: true })
  gateway: string | null;

  /** IP desde la que se pidió (la de la API) y desde la que se conectó al gateway. */
  @Column({ name: 'request_ip', type: 'inet', nullable: true })
  requestIp: string | null;

  @Column({ name: 'client_ip', type: 'inet', nullable: true })
  clientIp: string | null;

  /** Último latido del gateway que la atiende; sin latido, el barrido la cierra (`gateway_lost`). */
  @Column({ name: 'heartbeat_at', type: 'timestamptz', nullable: true })
  heartbeatAt: Date | null;

  /** Cuándo pidió la API al gateway que la cortara (`revoked`); una vez por sesión. */
  @Column({ name: 'revoke_requested_at', type: 'timestamptz', nullable: true })
  revokeRequestedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'started_at', type: 'timestamptz', nullable: true })
  startedAt: Date | null;

  @Column({ name: 'ended_at', type: 'timestamptz', nullable: true })
  endedAt: Date | null;

  @Column({
    name: 'close_reason',
    type: 'enum',
    enum: TERMINAL_CLOSE_REASONS,
    enumName: 'terminal_close_reason',
    nullable: true,
  })
  closeReason: TerminalCloseReason | null;

  @Column({ name: 'exit_code', type: 'int', nullable: true })
  exitCode: number | null;

  /** Motivo apto para mostrarse (p. ej. el fallo de conexión). */
  @Column({ name: 'close_message', type: 'varchar', length: 500, nullable: true })
  closeMessage: string | null;

  /** Acción de solo lectura (comando fijo); null = shell interactiva. */
  @Column({ type: 'jsonb', nullable: true })
  action: TerminalAction | null;
}
