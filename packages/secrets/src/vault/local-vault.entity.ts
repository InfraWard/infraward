import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';

/**
 * Versión de un secreto de la caja fuerte con el almacén local: solo texto cifrado
 * (AES-256-GCM) con la clave **de la caja fuerte** (VAULT_LOCAL_MASTER_KEY), distinta de la de
 * `local_secrets`, que también tiene el worker. Una fila por ruta y versión.
 *
 * No está en `SECRETS_ENTITIES`: solo la registra la API (`VAULT_ENTITIES`).
 */
@Entity({ name: 'vault_local_secrets' })
@Unique('UQ_vault_local_secrets_path_version', ['path', 'version'])
export class VaultLocalSecret {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' })
  path: string;

  @Column({ type: 'integer' })
  version: number;

  /** Huella de la clave con la que se cifró (ver masterKeyId). */
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
}

/** Entidades de la caja fuerte: solo para el DataSource de la API (nunca el del worker). */
export const VAULT_ENTITIES = [VaultLocalSecret];
