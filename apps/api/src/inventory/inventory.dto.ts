import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  INVENTORY_POLICY_SCOPES,
  SCAN_EXCLUDABLE_TYPES,
  SCAN_EXCLUSION_ASSETS_MAX,
  SCAN_EXCLUSION_PATTERN,
  SCAN_EXCLUSION_PATTERN_MAX,
  SCAN_EXCLUSION_PATTERNS_MAX,
  type ScanExcludableType,
  type ScanExclusions,
  NOTIFICATION_KINDS,
  RECONCILE_INTERVAL_MAX,
  RECONCILE_INTERVAL_MIN,
  SNAPSHOT_SOURCES,
  type AssetPolicy,
  type AssetType,
  type CreateInventoryPolicyRequest,
  type EffectiveInventoryPolicy,
  type InventoryPolicyList,
  type InventoryPolicyRule,
  type InventoryPolicyScope,
  type InventoryPolicySource,
  type InventoryPolicyValues,
  type Notification,
  type NotificationItem,
  type NotificationKind,
  type NotificationPage,
  type NotificationUnreadCount,
  type ReconcileRequest,
  type SnapshotChange,
  type SnapshotChangeKind,
  type SnapshotChangeSummary,
  type SnapshotDiff,
  type UpdateInventoryPolicyRequest,
} from '@infraward/shared-types';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  ValidateIf,
  ValidateNested,
  ValidationArguments,
  ValidatorConstraint,
  type ValidatorConstraintInterface,
  Validate,
} from 'class-validator';
import { LABEL } from '../assets/labels.js';

/** 0 (nunca) o entre `RECONCILE_INTERVAL_MIN` y `RECONCILE_INTERVAL_MAX` minutos. */
@ValidatorConstraint({ name: 'reconcileInterval' })
class ReconcileIntervalConstraint implements ValidatorConstraintInterface {
  validate(value: unknown): boolean {
    return (
      value === null ||
      value === undefined ||
      (Number.isInteger(value) &&
        ((value as number) === 0 ||
          ((value as number) >= RECONCILE_INTERVAL_MIN &&
            (value as number) <= RECONCILE_INTERVAL_MAX)))
    );
  }
  defaultMessage(args: ValidationArguments): string {
    return `${args.property} debe ser 0 (nunca) o estar entre ${RECONCILE_INTERVAL_MIN} y ${RECONCILE_INTERVAL_MAX} minutos`;
  }
}

const INTERVAL_DOC = {
  type: Number,
  nullable: true,
  description: `Minutos entre reconciliaciones de un nodo raíz: 0 = nunca, ${RECONCILE_INTERVAL_MIN}–${RECONCILE_INTERVAL_MAX}; null = no lo fija (se hereda)`,
} as const;

export class InventoryPolicyValuesDto implements InventoryPolicyValues {
  @ApiProperty({ description: 'Minutos entre reconciliaciones (0 = nunca)' })
  reconcileIntervalMinutes: number;

  @ApiProperty({ description: 'Escanear vulnerabilidades (SBOM y Trivy)' })
  scanEnabled: boolean;

  @ApiProperty({
    description: 'Escaneos automáticos; desactivado = solo bajo demanda',
  })
  scanPeriodic: boolean;
}

/** Lo que una regla excluye del escaneo (QoL-6b). */
export class ScanExclusionsDto implements ScanExclusions {
  @ApiPropertyOptional({
    enum: SCAN_EXCLUDABLE_TYPES,
    isArray: true,
    description:
      'Tipos que no se escanean (los únicos que se escanean: imágenes, servidores y CT)',
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(SCAN_EXCLUDABLE_TYPES.length)
  @IsIn(SCAN_EXCLUDABLE_TYPES, { each: true })
  types?: ScanExcludableType[];

  @ApiPropertyOptional({
    type: [String],
    maxItems: SCAN_EXCLUSION_PATTERNS_MAX,
    description:
      'Patrones glob (`*`, `?`) sobre el nombre visible o el descubierto, sin mayúsculas',
    example: ['bitnami/*', '*-test'],
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(SCAN_EXCLUSION_PATTERNS_MAX)
  @IsString({ each: true })
  @MaxLength(SCAN_EXCLUSION_PATTERN_MAX, { each: true })
  @Matches(SCAN_EXCLUSION_PATTERN, { each: true })
  namePatterns?: string[];

  @ApiPropertyOptional({
    type: [String],
    format: 'uuid',
    maxItems: SCAN_EXCLUSION_ASSETS_MAX,
    description: 'Assets concretos',
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(SCAN_EXCLUSION_ASSETS_MAX)
  @IsUUID('all', { each: true })
  assetIds?: string[];
}

export class InventoryPolicySourceDto {
  @ApiProperty({
    enum: ['own', 'inherited', 'tag', 'project', 'holders', 'global', 'excluded'],
  })
  kind: InventoryPolicySource['kind'];

  @ApiPropertyOptional({
    description:
      'excluded: regla que lo excluye (`kind` own, inherited, tag, project o global, con su id)',
  })
  by?: Record<string, string>;

  @ApiPropertyOptional({
    description:
      'excluded: por qué (`kind` type, pattern o asset, con el tipo, el patrón o el asset)',
  })
  match?: Record<string, string>;

  @ApiPropertyOptional({
    format: 'uuid',
    description:
      'excluded, en una imagen: el host o contenedor que la usa por cuya regla queda fuera',
  })
  holderId?: string;

  @ApiPropertyOptional({ description: 'excluded: nombre de ese holder' })
  holderName?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'inherited: antepasado con la regla',
  })
  assetId?: string;

  @ApiPropertyOptional({ description: 'inherited: nombre del antepasado' })
  assetName?: string;

  @ApiPropertyOptional({ description: 'tag: etiqueta con la regla' })
  tag?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'project: proyecto con la regla',
  })
  projectId?: string;

  @ApiPropertyOptional({ description: 'project: nombre del proyecto' })
  projectName?: string;
}

export class InventoryPolicySourcesDto {
  @ApiProperty({ type: InventoryPolicySourceDto })
  reconcileIntervalMinutes: InventoryPolicySourceDto;

  @ApiProperty({ type: InventoryPolicySourceDto })
  scanEnabled: InventoryPolicySourceDto;

  @ApiProperty({ type: InventoryPolicySourceDto })
  scanPeriodic: InventoryPolicySourceDto;
}

export class EffectiveInventoryPolicyDto implements EffectiveInventoryPolicy {
  @ApiProperty({ type: InventoryPolicyValuesDto })
  values: InventoryPolicyValuesDto;

  @ApiProperty({ type: InventoryPolicySourcesDto })
  sources: Record<keyof InventoryPolicyValues, InventoryPolicySource>;
}

export class InventoryPolicyRuleDto implements InventoryPolicyRule {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: INVENTORY_POLICY_SCOPES })
  scope: InventoryPolicyScope;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  assetId: string | null;

  @ApiPropertyOptional({ type: String, nullable: true })
  assetName?: string | null;

  @ApiProperty({ type: String, nullable: true })
  tag: string | null;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  projectId: string | null;

  @ApiPropertyOptional({ type: String, nullable: true })
  projectName?: string | null;

  @ApiProperty(INTERVAL_DOC)
  reconcileIntervalMinutes: number | null;

  @ApiProperty({ type: Boolean, nullable: true })
  scanEnabled: boolean | null;

  @ApiProperty({ type: Boolean, nullable: true })
  scanPeriodic: boolean | null;

  @ApiProperty({ type: ScanExclusionsDto, nullable: true })
  scanExclusions: ScanExclusions | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ format: 'date-time' })
  updatedAt: string;
}

export class InventoryPolicyListDto implements InventoryPolicyList {
  @ApiProperty({ type: InventoryPolicyRuleDto })
  global: InventoryPolicyRuleDto;

  @ApiProperty({ type: [InventoryPolicyRuleDto] })
  rules: InventoryPolicyRuleDto[];
}

/** Campos de una regla de asset, etiqueta o proyecto: null = no lo fija; ausente = no se cambia. */
export class InventoryPolicyFieldsDto implements UpdateInventoryPolicyRequest {
  @ApiPropertyOptional({
    type: ScanExclusionsDto,
    nullable: true,
    description: 'Lo que excluye del escaneo (null o vacío = nada)',
  })
  @ValidateIf((_o, v) => v !== null)
  @IsOptional()
  @ValidateNested()
  @Type(() => ScanExclusionsDto)
  scanExclusions?: ScanExclusionsDto | null;

  @ApiPropertyOptional(INTERVAL_DOC)
  @IsOptional()
  @Validate(ReconcileIntervalConstraint)
  reconcileIntervalMinutes?: number | null;

  @ApiPropertyOptional({ type: Boolean, nullable: true })
  @ValidateIf((_o, v) => v !== null)
  @IsOptional()
  @IsBoolean()
  scanEnabled?: boolean | null;

  @ApiPropertyOptional({ type: Boolean, nullable: true })
  @ValidateIf((_o, v) => v !== null)
  @IsOptional()
  @IsBoolean()
  scanPeriodic?: boolean | null;
}

export class CreateInventoryPolicyDto
  extends InventoryPolicyFieldsDto
  implements CreateInventoryPolicyRequest
{
  @ApiProperty({ enum: ['asset', 'tag', 'project'] })
  @IsIn(['asset', 'tag', 'project'])
  scope: 'asset' | 'tag' | 'project';

  @ApiPropertyOptional({ format: 'uuid', description: 'Solo scope=asset' })
  @ValidateIf((o: CreateInventoryPolicyDto) => o.scope === 'asset')
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({ description: 'Solo scope=tag' })
  @ValidateIf((o: CreateInventoryPolicyDto) => o.scope === 'tag')
  @IsString()
  @MaxLength(64)
  @Matches(LABEL)
  tag?: string;

  @ApiPropertyOptional({ format: 'uuid', description: 'Solo scope=project' })
  @ValidateIf((o: CreateInventoryPolicyDto) => o.scope === 'project')
  @IsUUID()
  projectId?: string;
}

/** La global fija siempre los tres campos. */
export class UpdateGlobalPolicyDto implements Partial<InventoryPolicyValues> {
  @ApiPropertyOptional({
    description: `0 (nunca) o ${RECONCILE_INTERVAL_MIN}–${RECONCILE_INTERVAL_MAX} minutos`,
  })
  @IsOptional()
  @IsInt()
  @Validate(ReconcileIntervalConstraint)
  reconcileIntervalMinutes?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  scanEnabled?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  scanPeriodic?: boolean;

  @ApiPropertyOptional({
    type: ScanExclusionsDto,
    nullable: true,
    description: 'Lo que se excluye del escaneo en todo el inventario',
  })
  @ValidateIf((_o, v) => v !== null)
  @IsOptional()
  @ValidateNested()
  @Type(() => ScanExclusionsDto)
  scanExclusions?: ScanExclusionsDto | null;
}

export class AssetRefDto {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;
}

export class AssetPolicyDto implements AssetPolicy {
  @ApiProperty({ type: EffectiveInventoryPolicyDto })
  effective: EffectiveInventoryPolicyDto;

  @ApiProperty({ type: InventoryPolicyRuleDto, nullable: true })
  rule: InventoryPolicyRuleDto | null;

  @ApiProperty({
    type: AssetRefDto,
    nullable: true,
    description: 'Nodo raíz que lo reconcilia (él mismo si es raíz)',
  })
  reconcileRoot: AssetRefDto | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  reconciledAt: string | null;

  @ApiProperty({
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'Solo raíces con intervalo: la siguiente prevista',
  })
  nextReconcileAt: string | null;
}

export class ReconcileRequestDto implements ReconcileRequest {
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Solo este nodo raíz (sin mirar el intervalo)',
  })
  @IsOptional()
  @IsUUID()
  assetId?: string;
}

// --- Diff de snapshots ---

export class SnapshotChangeDto implements SnapshotChange {
  @ApiProperty({ example: 'packages[openssl:amd64].version' })
  path: string;

  @ApiProperty({ enum: ['added', 'removed', 'changed'] })
  kind: SnapshotChangeKind;

  @ApiPropertyOptional({ description: 'Valor anterior (JSON)' })
  before?: unknown;

  @ApiPropertyOptional({ description: 'Valor nuevo (JSON)' })
  after?: unknown;
}

export class SnapshotChangeSummaryDto implements SnapshotChangeSummary {
  @ApiProperty({ example: 'packages' })
  section: string;

  @ApiProperty()
  added: number;

  @ApiProperty()
  removed: number;

  @ApiProperty()
  changed: number;
}

export class SnapshotDiffDto implements SnapshotDiff {
  @ApiProperty({ type: [SnapshotChangeDto] })
  changes: SnapshotChangeDto[];

  @ApiProperty({ type: [SnapshotChangeSummaryDto] })
  summary: SnapshotChangeSummaryDto[];

  @ApiProperty({ description: 'La lista de cambios se cortó' })
  truncated: boolean;
}

export const SNAPSHOT_SOURCE_DOC = {
  enum: SNAPSHOT_SOURCES,
  description: 'Recolección (Ansible) o descubrimiento',
} as const;

// --- Notificaciones ---

export class NotificationItemDto implements NotificationItem {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  type: AssetType;
}

export class NotificationDto implements Notification {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: NOTIFICATION_KINDS })
  kind: NotificationKind;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  assetId: string | null;

  @ApiProperty({ type: String, nullable: true })
  assetName: string | null;

  @ApiProperty()
  message: string;

  @ApiProperty({ type: [NotificationItemDto] })
  items: NotificationItemDto[];

  @ApiProperty({ description: 'Assets afectados en total' })
  total: number;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ description: 'Posterior al último «Marcar como leídas»' })
  unread: boolean;
}

export class NotificationPageDto implements NotificationPage {
  @ApiProperty({ type: [NotificationDto] })
  items: NotificationDto[];

  @ApiProperty()
  total: number;

  @ApiProperty()
  unread: number;
}

export class NotificationUnreadCountDto implements NotificationUnreadCount {
  @ApiProperty()
  unread: number;
}
