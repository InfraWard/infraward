import {
  ASSET_NOTES_MAX,
  ASSET_STATUSES,
  ASSET_TYPES,
  SSH_AUTH_MODES,
  type AdminAccess,
  type AssetConnection,
  type AssetCredentials,
  type AssetFacts,
  type AssetStatus,
  type AssetType,
  type EffectiveInventoryPolicy,
  type SshAuthMode,
} from '@infraward/shared-types';
import {
  Check,
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Entidad base de todo el inventario (DESIGN §5): servidores, CT, contenedores, dominios…
 * Los datos variables van en `facts` (JSONB); nunca secretos, solo referencias.
 */
@Entity({ name: 'assets' })
@Index('UQ_assets_type_natural_key', ['type', 'naturalKey'], {
  unique: true,
  where: '"natural_key" IS NOT NULL',
})
// Índices GIN: TypeORM no sabe declararlos, se crean en la migración (synchronize: false
// evita que migration:check intente recrearlos).
@Index('IDX_assets_facts', { synchronize: false })
@Index('IDX_assets_tags', { synchronize: false })
@Index('IDX_assets_roles', { synchronize: false })
@Index('IDX_assets_effective_projects', { synchronize: false })
@Check('CHK_assets_notes_length', `char_length("notes") <= ${ASSET_NOTES_MAX}`)
export class Asset {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'enum', enum: ASSET_TYPES, enumName: 'asset_type' })
  type: AssetType;

  /**
   * Nombre que pone el descubridor (o el del alta a mano). La reconciliación lo mantiene al día;
   * nunca se escribe `name`.
   */
  @Column({ name: 'discovered_name', type: 'varchar', length: 255 })
  discoveredName: string;

  /** Nombre puesto a mano (null = se ve el descubierto). */
  @Column({ name: 'display_name', type: 'varchar', length: 255, nullable: true })
  displayName: string | null;

  /**
   * Nombre visible: columna generada por PostgreSQL (`display_name` o, si no, el descubierto).
   * TypeORM la ignora al guardar, así que es de solo lectura también aquí.
   */
  @Column({
    type: 'varchar',
    length: 255,
    generatedType: 'STORED',
    asExpression: 'COALESCE("display_name", "discovered_name")',
    insert: false,
    update: false,
  })
  readonly name: string;

  /** Notas en Markdown, escritas a mano. */
  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @Index('IDX_assets_status')
  @Column({
    type: 'enum',
    enum: ASSET_STATUSES,
    enumName: 'asset_status',
    default: 'pending_enrollment',
  })
  status: AssetStatus;

  /** Identificador estable entre ejecuciones (DESIGN §8). Único por tipo. */
  @Column({ name: 'natural_key', type: 'varchar', length: 512, nullable: true })
  naturalKey: string | null;

  /** Roles detectados (`proxmox-node`, `plesk`, `docker-host`…). */
  @Column({ type: 'text', array: true, default: () => "'{}'" })
  roles: string[];

  @Column({ type: 'text', array: true, default: () => "'{}'" })
  tags: string[];

  @Column({ type: 'jsonb', default: () => "'{}'" })
  facts: AssetFacts;

  /** Cómo se conecta el worker (host, puerto, usuario). No contiene secretos. */
  @Column({ type: 'jsonb', nullable: true })
  connection: AssetConnection | null;

  /** Solo referencias `secret://…` (DESIGN §6), nunca valores. */
  @Column({ type: 'jsonb', default: () => "'{}'" })
  credentials: AssetCredentials;

  /** Clave estática o certificados de vida corta de la CA SSH (DESIGN §6). */
  @Column({
    name: 'ssh_auth',
    type: 'enum',
    enum: SSH_AUTH_MODES,
    enumName: 'ssh_auth_mode',
    default: 'static_key',
  })
  sshAuth: SshAuthMode;

  /** Huella `SHA256:…` de la host key fijada en el primer contacto (TOFU). */
  @Column({
    name: 'host_key_fingerprint',
    type: 'varchar',
    length: 128,
    nullable: true,
  })
  hostKeyFingerprint: string | null;

  /**
   * Acceso interactivo de administración que instaló el script (DESIGN §7): lo escribe el worker
   * al verificar un alta que lo pedía. null = sin acceso: la terminal no está disponible en este
   * servidor ni en sus CT y contenedores.
   */
  @Column({ name: 'admin_access', type: 'jsonb', nullable: true })
  adminAccess: AdminAccess | null;

  /**
   * Otro asset (no retirado) que ya tiene el machine-id que reporta este servidor: es la misma
   * máquina dada de alta dos veces. Mientras esté puesto, la recolección no escribe nada.
   */
  @Column({ name: 'duplicate_of_id', type: 'uuid', nullable: true })
  duplicateOfId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'duplicate_of_id' })
  duplicateOf?: Asset | null;

  /**
   * Política de inventario efectiva (DESIGN §10), calculada con `recomputePolicies` al cambiar
   * reglas, etiquetas o el árbol. `{}` = aún sin calcular (valores por defecto).
   */
  @Column({ name: 'effective_policy', type: 'jsonb', default: () => "'{}'" })
  effectivePolicy: EffectiveInventoryPolicy | Record<string, never>;

  /**
   * Proyectos a los que pertenece, heredados incluidos (DESIGN §5), calculados con
   * `recomputePolicies` junto con la política.
   */
  @Column({
    name: 'effective_projects',
    type: 'uuid',
    array: true,
    default: () => "'{}'",
  })
  effectiveProjects: string[];

  /** Descubrimientos completos de su ámbito sin verlo; a `RECONCILE_RETIRE_AFTER`, `retired`. */
  @Column({ name: 'missing_runs', type: 'int', default: 0 })
  missingRuns: number;

  @Column({ name: 'missing_since', type: 'timestamptz', nullable: true })
  missingSince: Date | null;

  /**
   * Asset cuyos descubrimientos completos cuentan las ausencias: su padre o, en una imagen, el
   * último host que la tenía.
   */
  @Column({ name: 'missing_scope_id', type: 'uuid', nullable: true })
  missingScopeId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'missing_scope_id' })
  missingScope?: Asset | null;

  /** Retirado por la reconciliación (no a mano): vuelve a `active` si reaparece. */
  @Column({ name: 'retired_auto', type: 'boolean', default: false })
  retiredAuto: boolean;

  /** Nodos raíz: cuándo se encoló su última reconciliación. */
  @Column({ name: 'reconciled_at', type: 'timestamptz', nullable: true })
  reconciledAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
