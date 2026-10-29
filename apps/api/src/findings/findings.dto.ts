import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  FINDING_STATUSES,
  IMAGE_SCAN_STATUSES,
  SEVERITIES,
  type AffectedAsset,
  type AssetFindingsPage,
  type AssetVulnerabilitiesPage,
  type AssetStatus,
  type AssetType,
  type ContainerImageSummary,
  type Finding,
  type FindingListQuery,
  type FindingSearchResult,
  type FindingStatus,
  type ImageScanSource,
  type ImageScanStatus,
  type Page,
  type ScanAssetResponse,
  type Severity,
  type VulnerabilityGroup,
  type VulnerablePackage,
  type PublicExposure,
  type VulnerabilitySummary,
  SEARCH_QUERY_INPUT_MAX,
  HIDDEN_REASONS,
  PRIORITY_BANDS,
  type HiddenReason,
  type NoiseReason,
  type PriorityBand,
  type VulnerabilitiesPage,
} from '@infraward/shared-types';
import { Transform, Type } from 'class-transformer';
import {
  IsBoolean,
  IsIn,
  IsISO8601,
  IsNumber,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { PageQueryDto } from '../assets/assets.dto.js';
import { EnqueueJobResponseDto } from '../jobs/jobs.dto.js';
import {
  HIDDEN_PROPERTY,
  HiddenCountsDto,
  NOISE_REASON_PROPERTY,
  PriorityInfoDto,
} from './priority.dto.js';
import { SbomSummaryDto } from './sboms.dto.js';

export class FindingListQueryDto
  extends PageQueryDto
  implements FindingListQuery
{
  @ApiPropertyOptional({ enum: FINDING_STATUSES })
  @IsOptional()
  @IsIn(FINDING_STATUSES)
  status?: FindingStatus;

  @ApiPropertyOptional({ enum: SEVERITIES })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.toUpperCase() : value,
  )
  @IsIn(SEVERITIES)
  severity?: Severity;

  @ApiPropertyOptional({
    enum: SEVERITIES,
    description: 'Severidad mínima: esta y las más graves',
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.toUpperCase() : value,
  )
  @IsIn(SEVERITIES)
  minSeverity?: Severity;

  @ApiPropertyOptional({
    description: 'true: solo los que tienen versión corregida (hay parche)',
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  fixable?: boolean;

  @ApiPropertyOptional({
    description:
      'true: sin los de imágenes sin uso (ningún contenedor activo las usa; prioridad baja)',
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  inUse?: boolean;

  @ApiPropertyOptional({
    enum: ['public', 'any'],
    description:
      'public: solo los de assets que sirven o dejan pasar un nombre público; any: expuestos de cualquier forma (puerto fuera de loopback, contenedor publicado o nombre público)',
  })
  @IsOptional()
  @IsIn(['public', 'any'])
  exposure?: 'public' | 'any';

  @ApiPropertyOptional({
    enum: PRIORITY_BANDS,
    description: 'Prioridad mínima: esta banda y las más altas',
  })
  @IsOptional()
  @IsIn(PRIORITY_BANDS)
  minPriority?: PriorityBand;

  @ApiPropertyOptional({ description: 'true: solo los CVE del catálogo KEV de CISA' })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  kev?: boolean;

  @ApiPropertyOptional({ minimum: 0, maximum: 1, description: 'EPSS mínimo (0–1)' })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  @Max(1)
  minEpss?: number;

  @ApiPropertyOptional({
    description:
      'true: también el ruido (kernel no en uso, sin corrección prevista), que por defecto sale de las listas globales',
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  includeNoise?: boolean;

  @ApiPropertyOptional({
    enum: HIDDEN_REASONS,
    description: 'Solo lo que la vista principal oculta por este motivo',
  })
  @IsOptional()
  @IsIn(HIDDEN_REASONS)
  hidden?: HiddenReason;

  @ApiPropertyOptional({
    enum: ['priority', 'severity'],
    description: 'Orden: por prioridad (por defecto) o por severidad',
  })
  @IsOptional()
  @IsIn(['priority', 'severity'])
  sort?: 'priority' | 'severity';

  @ApiPropertyOptional({
    description:
      'true: también los de assets con el escaneo desactivado por su política (por defecto no salen en las listas globales)',
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  includeScanDisabled?: boolean;

  @ApiPropertyOptional({
    format: 'uuid',
    description:
      'Solo los de assets del proyecto (heredados incluidos; las imágenes, por quienes las usan)',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;

  @ApiPropertyOptional({
    description: 'CVE, GHSA… exacto (sin distinguir mayúsculas)',
    example: 'CVE-2024-6387',
  })
  @IsOptional()
  @Matches(/^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/)
  vulnerabilityId?: string;

  @ApiPropertyOptional({
    description:
      'Búsqueda con la sintaxis de filtros: texto libre (CVE que empiece por él o paquete que lo contenga) y claves `cve:`, `paquete:`, `severidad:` y, sobre el asset afectado, `tag:`, `nombre:`, `tipo:`, `estado:`, `rol:`, `proyecto:` e `ip:`; lo que no se entiende se ignora',
    example: 'krb5 tag:prod -estado:parado',
    maxLength: SEARCH_QUERY_INPUT_MAX,
  })
  @IsOptional()
  @IsString()
  @MaxLength(SEARCH_QUERY_INPUT_MAX)
  q?: string;

  @ApiPropertyOptional({
    format: 'date-time',
    description: 'Solo los abiertos desde esta fecha (aparecidos o reabiertos después)',
  })
  @IsOptional()
  @IsISO8601({ strict: true })
  openedSince?: string;
}

export class ScanQueryDto {
  @ApiPropertyOptional({
    description:
      'Re-analizar aunque la imagen ya esté escaneada, o re-evaluar el SBOM de un servidor aunque no haya cambiado',
    default: false,
  })
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    value === 'true' ? true : value === 'false' ? false : value,
  )
  @IsBoolean()
  force?: boolean;
}

export class FindingDto implements Finding {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({
    format: 'uuid',
    description:
      'Asset en el que se detectó: la imagen (asset `image`) en los contenedores',
  })
  assetId: string;

  @ApiProperty({ example: 'CVE-2024-6387' })
  vulnerabilityId: string;

  @ApiProperty()
  packageName: string;

  @ApiProperty()
  installedVersion: string;

  @ApiProperty({ type: String, nullable: true })
  fixedVersion: string | null;

  @ApiProperty({ enum: SEVERITIES })
  severity: Severity;

  @ApiProperty({ type: String, nullable: true })
  title: string | null;

  @ApiProperty({ type: String, nullable: true })
  fixStatus: string | null;

  @ApiProperty({ type: String, nullable: true })
  pkgPath: string | null;

  @ApiProperty({ type: String, nullable: true })
  primaryUrl: string | null;

  @ApiProperty({ enum: FINDING_STATUSES })
  status: FindingStatus;

  @ApiProperty({ format: 'date-time' })
  firstSeenAt: string;

  @ApiProperty({ format: 'date-time' })
  lastSeenAt: string;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  fixedAt: string | null;

  @ApiProperty({ type: Number, nullable: true, description: 'CVSS de Trivy (NVD primero)' })
  cvss: number | null;

  @ApiProperty({
    type: PriorityInfoDto,
    nullable: true,
    description: 'Prioridad con contexto (null hasta que el worker la calcula)',
  })
  priority: PriorityInfoDto | null;

  @ApiProperty(NOISE_REASON_PROPERTY)
  noiseReason: NoiseReason | null;
}

export class AffectedAssetDto implements AffectedAsset {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty({ enum: ASSET_TYPES })
  type: AssetType;

  @ApiProperty({ enum: ASSET_STATUSES })
  status: AssetStatus;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'Padre `contains` (host Docker de un contenedor)',
  })
  parentId: string | null;
}

export class FindingSearchResultDto
  extends FindingDto
  implements FindingSearchResult
{
  @ApiProperty({
    type: AffectedAssetDto,
    description: 'Asset en el que se detectó (la imagen, en los contenedores)',
  })
  owner: AffectedAssetDto;

  @ApiProperty({
    type: [AffectedAssetDto],
    description:
      'Assets afectados: el propio asset o, si es una imagen, los contenedores que la usan',
  })
  affected: AffectedAssetDto[];
}

export class ContainerImageSummaryDto implements ContainerImageSummary {
  @ApiProperty({ format: 'uuid', description: 'Asset `image`' })
  assetId: string;

  @ApiProperty({ example: 'sha256:…' })
  imageId: string;

  @ApiProperty({ type: [String] })
  repoDigests: string[];

  @ApiProperty({ type: [String] })
  repoTags: string[];

  @ApiProperty({ type: String, nullable: true, example: 'linux/amd64' })
  platform: string | null;

  @ApiProperty({ enum: IMAGE_SCAN_STATUSES })
  scanStatus: ImageScanStatus;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Motivo de `skipped` (no escaneada) o `failed`',
  })
  scanReason: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  scannedAt: string | null;

  @ApiProperty({ type: String, enum: ['docker_save'], nullable: true })
  scanSource: ImageScanSource | null;

  @ApiProperty({ type: String, nullable: true })
  trivyVersion: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  dbUpdatedAt: string | null;

  @ApiProperty({ type: Number, nullable: true })
  vulnerabilityCount: number | null;
}

export class FindingPageDto implements Page<Finding> {
  @ApiProperty({ type: [FindingDto] })
  items: FindingDto[];

  @ApiProperty()
  total: number;
}

export class FindingSearchPageDto implements Page<FindingSearchResult> {
  @ApiProperty({ type: [FindingSearchResultDto] })
  items: FindingSearchResultDto[];

  @ApiProperty()
  total: number;
}

export class AssetFindingsPageDto
  extends FindingPageDto
  implements AssetFindingsPage
{
  @ApiProperty({
    type: ContainerImageSummaryDto,
    nullable: true,
    description: 'Imagen (del contenedor o la propia) y estado de su escaneo',
  })
  image: ContainerImageSummaryDto | null;

  @ApiProperty({
    type: SbomSummaryDto,
    nullable: true,
    description: 'SBOM del que salen (el de la imagen, en un contenedor)',
  })
  sbom: SbomSummaryDto | null;
}

export class VulnerablePackageDto implements VulnerablePackage {
  @ApiProperty({ format: 'uuid' })
  findingId: string;

  @ApiProperty()
  packageName: string;

  @ApiProperty()
  installedVersion: string;

  @ApiProperty({ type: String, nullable: true })
  fixedVersion: string | null;

  @ApiProperty({ type: String, nullable: true })
  pkgPath: string | null;

  @ApiProperty({ enum: FINDING_STATUSES })
  status: FindingStatus;

  @ApiProperty({ type: Number, nullable: true })
  priority: number | null;

  @ApiProperty(NOISE_REASON_PROPERTY)
  noiseReason: NoiseReason | null;
}

export class VulnerabilityGroupDto implements VulnerabilityGroup {
  @ApiProperty({ example: 'CVE-2024-37371' })
  vulnerabilityId: string;

  @ApiProperty({
    enum: SEVERITIES,
    description: 'La más grave de sus findings',
  })
  severity: Severity;

  @ApiProperty({ type: String, nullable: true })
  title: string | null;

  @ApiProperty({ type: String, nullable: true })
  primaryUrl: string | null;

  @ApiProperty({ description: 'Algún paquete tiene versión corregida' })
  fixable: boolean;

  @ApiProperty({ type: [VulnerablePackageDto] })
  packages: VulnerablePackageDto[];

  @ApiProperty({
    type: PriorityInfoDto,
    nullable: true,
    description: 'La de su finding más prioritario, con sus motivos',
  })
  priority: PriorityInfoDto | null;

  @ApiProperty({
    ...NOISE_REASON_PROPERTY,
    description: 'Todos sus findings son ruido: el motivo',
  })
  noiseReason: NoiseReason | null;

  @ApiProperty({ description: 'En el catálogo KEV de CISA' })
  kev: boolean;

  @ApiProperty({ type: Number, nullable: true, description: 'EPSS (0–1)' })
  epss: number | null;

  @ApiProperty({ type: Number, nullable: true })
  cvss: number | null;
}

export class PublicExposureDto implements PublicExposure {
  @ApiProperty({ description: 'Registros DNS públicos cuyo camino llega a él o pasa por él' })
  publicDomains: number;

  @ApiProperty({ type: String, nullable: true, example: 'app.example.com' })
  sample: string | null;
}

export class AssetVulnerabilitiesPageDto implements AssetVulnerabilitiesPage {
  @ApiProperty({ type: [VulnerabilityGroupDto] })
  items: VulnerabilityGroupDto[];

  @ApiProperty({ description: 'Número de vulnerabilidades distintas' })
  total: number;

  @ApiProperty({
    type: ContainerImageSummaryDto,
    nullable: true,
    description: 'Imagen (del contenedor o la propia) y estado de su escaneo',
  })
  image: ContainerImageSummaryDto | null;

  @ApiProperty({
    type: SbomSummaryDto,
    nullable: true,
    description: 'SBOM del que salen (el de la imagen, en un contenedor)',
  })
  sbom: SbomSummaryDto | null;

  @ApiProperty({
    type: PublicExposureDto,
    nullable: true,
    required: false,
    description: 'El asset sirve o deja pasar nombres públicos',
  })
  exposure?: PublicExposureDto | null;
}

export class ScanAssetResponseDto implements ScanAssetResponse {
  @ApiProperty({ type: [EnqueueJobResponseDto] })
  jobs: EnqueueJobResponseDto[];
}

export class VulnerabilitySummaryDto implements VulnerabilitySummary {
  @ApiProperty({ example: 'CVE-2024-37371' })
  vulnerabilityId: string;

  @ApiProperty({
    enum: SEVERITIES,
    description: 'La más grave de sus findings',
  })
  severity: Severity;

  @ApiProperty({ type: String, nullable: true })
  title: string | null;

  @ApiProperty({ type: String, nullable: true })
  primaryUrl: string | null;

  @ApiProperty({ description: 'Algún paquete tiene versión corregida' })
  fixable: boolean;

  @ApiProperty({ type: [String], description: 'Paquetes afectados' })
  packageNames: string[];

  @ApiProperty({ description: 'Imágenes con el CVE' })
  images: number;

  @ApiProperty({
    description: 'Contenedores no retirados que usan esas imágenes',
  })
  containers: number;

  @ApiProperty({ description: 'Otros assets con el CVE' })
  otherAssets: number;

  @ApiProperty({
    description:
      'De las imágenes, cuántas no usa ningún contenedor activo (sin uso)',
  })
  unusedImages: number;

  @ApiProperty({
    type: PublicExposureDto,
    nullable: true,
    description:
      'Algún afectado sirve o deja pasar un nombre público (uno de los motivos de su prioridad)',
  })
  exposure: PublicExposureDto | null;

  @ApiProperty({
    type: PriorityInfoDto,
    nullable: true,
    description: 'La de su finding más prioritario, con sus motivos',
  })
  priority: PriorityInfoDto | null;

  @ApiProperty({ description: 'En el catálogo KEV de CISA' })
  kev: boolean;

  @ApiProperty({ type: Number, nullable: true, description: 'EPSS (0–1)' })
  epss: number | null;

  @ApiProperty({ type: Number, nullable: true, description: 'El mayor CVSS de sus findings' })
  cvss: number | null;
}

export class VulnerabilitySummaryPageDto implements VulnerabilitiesPage {
  @ApiProperty({ type: [VulnerabilitySummaryDto] })
  items: VulnerabilitySummaryDto[];

  @ApiProperty({ description: 'Número de vulnerabilidades distintas' })
  total: number;

  @ApiProperty(HIDDEN_PROPERTY)
  hidden: HiddenCountsDto | null;
}
