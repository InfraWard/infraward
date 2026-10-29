import { API_TOKEN_SCOPES, type ApiTokenScope } from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from '../users/user.entity.js';

/**
 * Token de API personal (QoL-6, DESIGN §14). El valor solo se enseña al crearlo; aquí se guarda
 * su sha256 y los primeros caracteres para reconocerlo. Revocar = marcar `revoked_at` (la fila se
 * conserva para ver qué hubo y cuándo se usó).
 */
@Entity({ name: 'api_tokens' })
export class ApiToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('IDX_api_tokens_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user?: User;

  @Column({ type: 'varchar', length: 100 })
  name: string;

  /** Primeros caracteres del token (`iwt_ab12cd34`): no bastan para usarlo. */
  @Column({ type: 'varchar', length: 16 })
  prefix: string;

  /** sha256 del token. */
  @Index('UQ_api_tokens_token_hash', { unique: true })
  @Column({ name: 'token_hash', type: 'bytea' })
  tokenHash: Buffer;

  @Column({
    type: 'enum',
    enum: API_TOKEN_SCOPES,
    enumName: 'api_token_scope',
  })
  scope: ApiTokenScope;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  /** Último uso (se actualiza como mucho una vez por minuto). */
  @Column({ name: 'last_used_at', type: 'timestamptz', nullable: true })
  lastUsedAt: Date | null;

  @Column({ name: 'last_used_ip', type: 'inet', nullable: true })
  lastUsedIp: string | null;

  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  /** Quién lo revocó (el dueño o un admin); null si sigue vigente o se borró ese usuario. */
  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'revoked_by_id' })
  revokedBy?: User | null;

  @Column({ name: 'revoked_by_id', type: 'uuid', nullable: true })
  revokedById: string | null;
}
