import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_RELATION_TYPES,
  ASSET_STATUSES,
  ASSET_RUNTIME_STATES,
  ASSET_TYPES,
  SSH_AUTH_MODES,
  ADMIN_ACCESS_MODES,
  MANUAL_ASSET_RELATION_TYPES,
  MANUAL_ASSET_STATUSES,
  MANUAL_ASSET_TYPES,
  ASSET_NOTES_MAX,
  SEVERITIES,
  type AdminAccess,
  type AdminAccessMode,
  type Asset,
  type AssetConnection,
  type AssetCredentials,
  type AssetFacts,
  type CredentialRevocation,
  type SshdRiskLevel,
  type AssetListQuery,
  type AssetRelation,
  type AssetRelationType,
  type AssetRelationWithPeer,
  type AssetRelations,
  type AssetStatus,
  type AssetSummary,
  type AssetTreeSummaryNode,
  type AssetType,
  type DnsCheckLevel,
  type SshAuthMode,
  type ManualAssetRelationType,
  type ManualAssetStatus,
  type ManualAssetType,
  type CreateAssetRelationRequest,
  type CreateAssetRequest,
  type DeleteAssetResponse,
  type DockerHostResources,
  type DockerResource,
  type Page,
  type AssetRuntimeState,
  type Severity,
  type Snapshot,
  type SnapshotSource,
  type SnapshotSummary,
  type UpdateAssetRequest,
  DNS_CHECK_LEVELS,
  SEARCH_QUERY_INPUT_MAX,
} from '@infraward/shared-types';
import { Transform, Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsBoolean,
  IsIn,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';
import {
  EffectiveInventoryPolicyDto,
  SNAPSHOT_SOURCE_DOC,
  SnapshotChangeSummaryDto,
  SnapshotDiffDto,
} from '../inventory/inventory.dto.js';
import { LABEL, LABEL_MAX, LABELS_MAX } from './labels.js';

/** Query string → boolean; cualquier otro valor llega tal cual y lo rechaza @IsBoolean. */
export const toBoolean = ({ value }: { value: unknown }) =>
  value === 'true' ? true : value === 'false' ? false : value;

const FACTS_SCHEMA = {
  type: 'object',
  additionalProperties: true,
} as const;

// --- Peticiones ---

export class CreateAssetDto implements CreateAssetRequest {
  @ApiProperty({ enum: MANUAL_ASSET_TYPES })
  @IsIn(MANUAL_ASSET_TYPES)
  type: ManualAssetType;

  @ApiProperty({ maxLength: 255, example: 'pve01' })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  name: string;

  @ApiPropertyOptional({
    enum: MANUAL_ASSET_STATUSES,
    default: 'pending_enrollment',
  })
  @IsOptional()
  @IsIn(MANUAL_ASSET_STATUSES)
  status?: ManualAssetStatus;

  @ApiPropertyOptional({ type: String, nullable: true, maxLength: 512 })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  naturalKey?: string | null;

  @ApiPropertyOptional({ type: [String], example: ['proxmox-node'] })
  @IsOptional()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  roles?: string[];

  @ApiPropertyOptional({ type: [String], example: ['env:prod'] })
  @IsOptional()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  tags?: string[];

  @ApiPropertyOptional(FACTS_SCHEMA)
  @IsOptional()
  @IsObject()
  facts?: AssetFacts;
}

export class UpdateAssetDto implements UpdateAssetRequest {
  @ApiPropertyOptional({
    type: String,
    nullable: true,
    maxLength: 255,
    description:
      'Nombre visible puesto a mano; null para volver al descubierto (que nunca se edita)',
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  displayName?: string | null;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    maxLength: ASSET_NOTES_MAX,
    description: 'Notas en Markdown; null o vacío para quitarlas',
  })
  @IsOptional()
  @IsString()
  @MaxLength(ASSET_NOTES_MAX)
  notes?: string | null;

  @ApiPropertyOptional({
    enum: MANUAL_ASSET_STATUSES,
    description: 'Para retirar, DELETE /assets/:id',
  })
  @IsOptional()
  @IsIn(MANUAL_ASSET_STATUSES)
  status?: ManualAssetStatus;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    maxLength: 512,
    description: 'null para quitarla',
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  naturalKey?: string | null;

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  roles?: string[];

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  tags?: string[];

  @ApiPropertyOptional({ ...FACTS_SCHEMA, description: 'Sustituye los facts' })
  @IsOptional()
  @IsObject()
  facts?: AssetFacts;
}

export class PageQueryDto {
  @ApiPropertyOptional({ minimum: 1, maximum: 200, default: 50 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number;

  @ApiPropertyOptional({ minimum: 0, default: 0 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  offset?: number;
}

export class AssetListQueryDto extends PageQueryDto implements AssetListQuery {
  @ApiPropertyOptional({ enum: ASSET_TYPES })
  @IsOptional()
  @IsIn(ASSET_TYPES)
  type?: AssetType;

  @ApiPropertyOptional({ enum: ASSET_STATUSES })
  @IsOptional()
  @IsIn(ASSET_STATUSES)
  status?: AssetStatus;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(LABEL_MAX)
  tag?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(LABEL_MAX)
  role?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Solo los del proyecto (heredados incluidos)',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;

  @ApiPropertyOptional({
    description:
      'Nombre visible o descubierto que lo contenga, sin distinguir mayúsculas',
  })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  q?: string;

  @ApiPropertyOptional({
    description: 'Objeto JSON que deben contener los facts (`@>`)',
    example: '{"os":{"family":"Debian"}}',
  })
  @IsOptional()
  @IsString()
  @MaxLength(4096)
  facts?: string;
}

export class TreeQueryDto {
  @ApiPropertyOptional({
    description:
      'Búsqueda con la sintaxis de filtros (`tag:prod nombre:web -estado:retirado ip:10.0.0.0/24`); lo que no se entiende se ignora',
    maxLength: SEARCH_QUERY_INPUT_MAX,
  })
  @IsOptional()
  @IsString()
  @MaxLength(SEARCH_QUERY_INPUT_MAX)
  q?: string;

  @ApiPropertyOptional({
    default: false,
    description: 'Incluir los assets retirados (y lo que cuelga de ellos)',
  })
  @IsOptional()
  @Transform(toBoolean)
  @IsBoolean()
  includeRetired?: boolean;
}

export class DeleteAssetQueryDto {
  @ApiPropertyOptional({
    default: false,
    description:
      'Borrado físico del asset y su subárbol (relaciones y snapshots). Solo admin.',
  })
  @IsOptional()
  @Transform(toBoolean)
  @IsBoolean()
  purge?: boolean;
}

export class CreateAssetRelationDto implements CreateAssetRelationRequest {
  @ApiProperty({ format: 'uuid' })
  @IsUUID()
  parentId: string;

  @ApiProperty({ format: 'uuid' })
  @IsUUID()
  childId: string;

  @ApiProperty({ enum: MANUAL_ASSET_RELATION_TYPES })
  @IsIn(MANUAL_ASSET_RELATION_TYPES)
  type: ManualAssetRelationType;
}

// --- Respuestas ---

export class AssetConnectionDto implements AssetConnection {
  @ApiProperty({ example: '192.0.2.10' })
  host: string;

  @ApiProperty({ example: 22 })
  port: number;

  @ApiProperty({ example: 'inventory' })
  user: string;
}

export class AdminAccessDto implements AdminAccess {
  @ApiProperty({ enum: ADMIN_ACCESS_MODES })
  mode: AdminAccessMode;

  @ApiProperty({ example: 'infraward-admin' })
  account: string;

  @ApiProperty({ example: 1 })
  version: number;

  @ApiProperty({ format: 'date-time' })
  enabledAt: string;
}

export class AssetCredentialsDto implements AssetCredentials {
  @ApiPropertyOptional({
    description: 'Referencia a la clave privada SSH (nunca el valor)',
    example: 'secret://local/assets/<id>/ssh#privateKey',
  })
  sshPrivateKey?: string;
}

export class AssetDto implements Asset {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: ASSET_TYPES })
  type: AssetType;

  @ApiProperty({
    description: 'Nombre visible: displayName o, si no, el descubierto',
  })
  name: string;

  @ApiProperty({
    description:
      'Nombre que pone el descubridor (o el del alta a mano); lo mantiene la reconciliación',
  })
  discoveredName: string;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Nombre puesto a mano (null = se ve el descubierto)',
  })
  displayName: string | null;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    description: 'Notas en Markdown (solo en GET /assets/:id)',
  })
  notes?: string | null;

  @ApiProperty({
    type: [String],
    format: 'uuid',
    description: 'Proyectos a los que pertenece, heredados incluidos',
  })
  projects: string[];

  @ApiProperty({ enum: ASSET_STATUSES })
  status: AssetStatus;

  @ApiProperty({ type: String, nullable: true })
  naturalKey: string | null;

  @ApiProperty({ type: [String] })
  roles: string[];

  @ApiProperty({ type: [String] })
  tags: string[];

  @ApiProperty(FACTS_SCHEMA)
  facts: AssetFacts;

  @ApiProperty({ type: AssetConnectionDto, nullable: true })
  connection: AssetConnectionDto | null;

  @ApiProperty({ type: AssetCredentialsDto })
  credentials: AssetCredentialsDto;

  @ApiProperty({
    enum: SSH_AUTH_MODES,
    description:
      'Clave estática o certificados de vida corta de la CA SSH (DESIGN §6)',
  })
  sshAuth: SshAuthMode;

  @ApiProperty({ type: String, nullable: true, example: 'SHA256:…' })
  hostKeyFingerprint: string | null;

  @ApiProperty({
    type: AdminAccessDto,
    nullable: true,
    description:
      'Acceso interactivo de administración instalado por el script (terminal); null si no lo tiene',
  })
  adminAccess: AdminAccess | null;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description:
      'Asset no retirado que ya tiene el machine-id de este servidor; mientras esté puesto, la recolección no guarda nada',
  })
  duplicateOfId: string | null;

  @ApiPropertyOptional({
    type: () => AssetSummaryDto,
    nullable: true,
    description: 'Solo en GET /assets/:id',
  })
  duplicateOf?: AssetSummaryDto | null;

  @ApiPropertyOptional({
    type: () => [AssetSummaryDto],
    description:
      'Solo en GET /assets/:id: assets marcados como duplicados de este',
  })
  duplicates?: AssetSummaryDto[];

  @ApiProperty({ type: EffectiveInventoryPolicyDto })
  effectivePolicy: EffectiveInventoryPolicyDto;

  @ApiProperty({
    description:
      'Descubrimientos completos sin verlo (missing); a RECONCILE_RETIRE_AFTER pasa a retired',
  })
  missingRuns: number;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  missingSince: string | null;

  @ApiProperty({
    description:
      'Retirado por la reconciliación (no a mano): vuelve a active si reaparece',
  })
  retiredAuto: boolean;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ format: 'date-time' })
  updatedAt: string;
}

export class AssetPageDto implements Page<Asset> {
  @ApiProperty({ type: [AssetDto] })
  items: AssetDto[];

  @ApiProperty()
  total: number;
}

export class AssetSummaryDto implements AssetSummary {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty({ enum: ASSET_TYPES })
  type: AssetType;

  @ApiProperty({ enum: ASSET_STATUSES })
  status: AssetStatus;
}

export class DockerResourceDto extends AssetSummaryDto implements DockerResource {
  @ApiProperty({
    type: 'integer',
    description:
      'Contenedores activos que lo usan (en las imágenes, de cualquier host)',
  })
  containers: number;

  @ApiProperty({ description: 'false = sin uso (ningún contenedor activo)' })
  inUse: boolean;
}

export class DockerHostResourcesDto implements DockerHostResources {
  @ApiProperty({ type: [DockerResourceDto] })
  volumes: DockerResourceDto[];

  @ApiProperty({ type: [DockerResourceDto] })
  networks: DockerResourceDto[];

  @ApiProperty({
    type: [DockerResourceDto],
    description: 'Imágenes del host (stores), las use o no algún contenedor',
  })
  images: DockerResourceDto[];
}

export class AssetTreeSummaryNodeDto
  extends AssetSummaryDto
  implements AssetTreeSummaryNode
{
  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Nombre descubierto, solo si está renombrado',
  })
  discoveredName: string | null;

  @ApiProperty({ type: [String] })
  roles: string[];

  @ApiProperty({ type: [String] })
  tags: string[];

  @ApiProperty({
    type: [String],
    format: 'uuid',
    description: 'Proyectos (heredados incluidos)',
  })
  projects: string[];

  @ApiProperty({
    type: String,
    nullable: true,
    description:
      'Host de conexión (o IPv4) de un servidor, IPv4 de un CT/VM o puertos publicados de un contenedor',
    example: '8080→80/tcp',
  })
  address: string | null;

  @ApiProperty({
    type: [String],
    description:
      'IPs para la búsqueda `ip:`: host de conexión si es una IP, IPv4 por defecto e IPs de sus interfaces',
    example: ['10.0.0.12'],
  })
  ips: string[];

  @ApiProperty({
    enum: ASSET_RUNTIME_STATES,
    nullable: true,
    description:
      'Estado de ejecución (Docker o Proxmox), aparte del de inventario',
  })
  runtimeState: AssetRuntimeState | null;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Estado tal como lo da la fuente (`exited`, `created`…)',
  })
  runtimeDetail: string | null;

  @ApiProperty({
    description:
      'Findings `open` por severidad (los de un contenedor son los de su imagen)',
    type: 'object',
    properties: Object.fromEntries(
      SEVERITIES.map((s) => [s, { type: 'integer' }]),
    ),
    required: [...SEVERITIES],
  })
  openFindings: Record<Severity, number>;

  @ApiProperty({
    description: 'Findings `open` CRITICAL y HIGH con versión corregida',
    type: 'object',
    properties: { CRITICAL: { type: 'integer' }, HIGH: { type: 'integer' } },
    required: ['CRITICAL', 'HIGH'],
  })
  fixableFindings: Record<'CRITICAL' | 'HIGH', number>;

  @ApiProperty({
    description:
      'La última recolección vio el sudoers por debajo de la versión que necesitan sus roles',
  })
  sudoersOutdated: boolean;

  @ApiProperty({
    type: 'integer',
    description: 'Avisos de recolección parcial de la última recolección',
  })
  collectionWarnings: number;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'Asset del que este es duplicado (mismo machine-id)',
  })
  duplicateOf: string | null;

  @ApiProperty({
    description:
      'Comparte machine-id con otros assets con host keys distintas (clon sin regenerar)',
  })
  machineIdClone: boolean;

  @ApiProperty({
    type: String,
    format: 'date-time',
    nullable: true,
    description:
      'Certificados: fin de validez (notAfter); dominios: caducidad del registro (RDAP); null en el resto',
  })
  expiresAt: string | null;

  @ApiProperty({
    enum: DNS_CHECK_LEVELS,
    nullable: true,
    description:
      'Registros DNS: aviso de colgante sin marcar como esperado (high: takeover o destino retirado; info: IP pública desconocida)',
  })
  dnsWarning: DnsCheckLevel | null;

  @ApiProperty({
    description:
      'Modo CA y el servidor no confía exactamente en las CA vigentes: hay que volver a ejecutar el script',
  })
  sshCaOutdated: boolean;

  @ApiProperty({
    enum: ['root-password', 'root', 'password'],
    nullable: true,
    description:
      'sshd admite el login de root o por contraseña (sshd -T, sudoers v7); null si no o sin datos',
  })
  sshdRisk: SshdRiskLevel | null;

  @ApiProperty({
    description:
      'Escaneo desactivado por su política: sus findings no cuentan en openFindings/fixableFindings',
  })
  scanDisabled: boolean;

  @ApiProperty({ type: () => [AssetTreeSummaryNodeDto] })
  children: AssetTreeSummaryNodeDto[];
}

export class CredentialRevocationDto implements CredentialRevocation {
  @ApiProperty({ format: 'uuid' })
  assetId: string;

  @ApiProperty({
    description: 'Si se borró la clave del proveedor de secretos',
  })
  secretRemoved: boolean;

  @ApiProperty({
    description: 'Comando para quitar el acceso de InfraWard del servidor',
  })
  command: string;
}

export class DeleteAssetResponseDto implements DeleteAssetResponse {
  @ApiProperty({ enum: ['retired', 'purged'] })
  mode: 'retired' | 'purged';

  @ApiProperty({ type: [String], format: 'uuid' })
  affectedIds: string[];

  @ApiProperty({ type: [CredentialRevocationDto] })
  revocations: CredentialRevocationDto[];
}

export class AssetRelationDto implements AssetRelation {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ format: 'uuid' })
  parentId: string;

  @ApiProperty({ format: 'uuid' })
  childId: string;

  @ApiProperty({ enum: ASSET_RELATION_TYPES })
  type: AssetRelationType;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;
}

export class AssetRelationWithPeerDto
  extends AssetRelationDto
  implements AssetRelationWithPeer
{
  @ApiProperty({
    type: AssetSummaryDto,
    description: 'El otro extremo de la relación',
  })
  peer: AssetSummaryDto;
}

export class AssetRelationsDto implements AssetRelations {
  @ApiProperty({ type: [AssetRelationWithPeerDto] })
  outgoing: AssetRelationWithPeerDto[];

  @ApiProperty({ type: [AssetRelationWithPeerDto] })
  incoming: AssetRelationWithPeerDto[];
}

export class SnapshotSummaryDto implements SnapshotSummary {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ format: 'uuid' })
  assetId: string;

  @ApiProperty({ format: 'date-time' })
  collectedAt: string;

  @ApiProperty({ type: [String] })
  roles: string[];

  @ApiProperty({ type: String, nullable: true })
  jobId: string | null;

  @ApiProperty(SNAPSHOT_SOURCE_DOC)
  source: SnapshotSource;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'Snapshot anterior con el que se calculó el diff',
  })
  previousId: string | null;

  @ApiProperty({
    type: [SnapshotChangeSummaryDto],
    nullable: true,
    description:
      'Cambios por sección respecto al anterior (null en el primero y en los anteriores al diff)',
  })
  changeSummary: SnapshotChangeSummaryDto[] | null;
}

export class SnapshotDto extends SnapshotSummaryDto implements Snapshot {
  @ApiProperty(FACTS_SCHEMA)
  facts: AssetFacts;

  @ApiProperty({ type: SnapshotDiffDto, nullable: true })
  diff: SnapshotDiffDto | null;
}

export class SnapshotPageDto implements Page<SnapshotSummary> {
  @ApiProperty({ type: [SnapshotSummaryDto] })
  items: SnapshotSummaryDto[];

  @ApiProperty()
  total: number;
}
