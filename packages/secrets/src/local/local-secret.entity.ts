import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Secreto del proveedor local: solo texto cifrado (AES-256-GCM). La clave maestra vive
 * fuera de la BD; sin ella estas filas son irrecuperables.
 */
@Entity({ name: 'local_secrets' })
export class LocalSecret {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', unique: true })
  path: string;

  /** Huella de la clave maestra con la que se cifró (ver masterKeyId). */
  @Column({ name: 'key_id', type: 'varchar', length: 16 })
  keyId: string;

  @Column({ type: 'bytea' })
  iv: Buffer;

  @Column({ type: 'bytea' })
  ciphertext: Buffer;

  @Column({ name: 'auth_tag', type: 'bytea' })
  authTag: Buffer;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}

/** Entidades de este paquete, para registrarlas en el DataSource. */
export const SECRETS_ENTITIES = [LocalSecret];
