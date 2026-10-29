import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from '../../users/user.entity.js';

/**
 * Código de recuperación de la verificación en dos pasos (DESIGN §14): un solo uso, y aquí solo
 * su sha256 (80 bits aleatorios: no hace falta un hash lento). Usarlo = marcar `used_at` con una
 * actualización condicionada (de dos usos simultáneos, solo gana uno).
 */
@Entity({ name: 'user_recovery_codes' })
export class UserRecoveryCode {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('IDX_user_recovery_codes_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user?: User;

  @Index('UQ_user_recovery_codes_code_hash', { unique: true })
  @Column({ name: 'code_hash', type: 'bytea' })
  codeHash: Buffer;

  @Column({ name: 'used_at', type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
