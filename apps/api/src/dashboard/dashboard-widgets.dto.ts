import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  ATTENTION_KINDS,
  DASHBOARD_TAGS_MAX,
  DASHBOARD_WIDGETS,
  PRIORITY_BANDS,
  SEVERITIES,
  TREND_METRICS,
  TREND_RANGES,
  type AssetCountsData,
  type AssetType,
  type AttentionData,
  type AttentionItem,
  type AttentionKind,
  type ExpirationItem,
  type ExpirationsData,
  type FixableVulnerabilitiesData,
  type NewVulnerabilitiesData,
  type PendingEnrollmentData,
  type PriorityBand,
  type RecentActivityData,
  type RunningJobsData,
  type Severity,
  type TopVulnerabilitiesData,
  type TrendData,
  type TrendMetric,
  type TrendPoint,
  type TrendRange,
  type TrendSeries,
  type VulnerabilityCountsData,
  type WidgetDataQuery,
  type WidgetType,
} from '@infraward/shared-types';
import { Transform, Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { AssetSummaryDto } from '../assets/assets.dto.js';
import { JobRunSummaryDto } from '../jobs/jobs.dto.js';
import { DashboardVulnerabilityDto } from './dashboard.dto.js';

/** `tag=a&tag=b` (Fastify da un array) o `tag=a` (una cadena). */
const toArray = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? [value] : value;

/** Valores permitidos de una opción `select`/`multi` del catálogo (la misma fuente que la web). */
function choices(type: WidgetType, option: string): string[] {
  const spec = DASHBOARD_WIDGETS[type].options[option];
  return spec && spec.kind !== 'number' ? spec.choices.map((c) => c.value) : [];
}

// --- Peticiones ---

export class WidgetScopeQueryDto implements WidgetDataQuery {
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Solo lo del proyecto (heredado incluido)',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;

  @ApiPropertyOptional({
    type: [String],
    description: 'Alguno de estos tags (se repite: `tag=a&tag=b`)',
  })
  @IsOptional()
  @Transform(toArray)
  @ArrayMaxSize(DASHBOARD_TAGS_MAX)
  @IsString({ each: true })
  @MaxLength(255, { each: true })
  tag?: string[];

  @ApiPropertyOptional({
    type: [String],
    enum: ASSET_TYPES,
    description: 'Alguno de estos tipos de asset (se repite)',
  })
  @IsOptional()
  @Transform(toArray)
  @ArrayMaxSize(ASSET_TYPES.length)
  @IsIn(ASSET_TYPES, { each: true })
  type?: AssetType[];
}

export class AssetCountsQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({ enum: ['type', 'status'], default: 'type' })
  @IsOptional()
  @IsIn(choices('asset-counts', 'groupBy'))
  groupBy?: 'type' | 'status';
}

export class PendingEnrollmentQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({
    enum: choices('pending-enrollment', 'limit'),
    default: '0',
  })
  @IsOptional()
  @IsIn(choices('pending-enrollment', 'limit'))
  limit?: string;
}

export class TopVulnerabilitiesQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({
    enum: choices('top-vulnerabilities', 'limit'),
    default: '5',
  })
  @IsOptional()
  @IsIn(choices('top-vulnerabilities', 'limit'))
  limit?: string;

  @ApiPropertyOptional({
    enum: choices('top-vulnerabilities', 'minPriority'),
    default: 'medium',
  })
  @IsOptional()
  @IsIn(choices('top-vulnerabilities', 'minPriority'))
  minPriority?: PriorityBand;
}

export class NewVulnerabilitiesQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({
    enum: choices('new-vulnerabilities', 'since'),
    default: 'lastVisit',
    description: '`lastVisit`: desde «Marcar como vistos» del usuario',
  })
  @IsOptional()
  @IsIn(choices('new-vulnerabilities', 'since'))
  since?: 'lastVisit' | '7d' | '30d';

  @ApiPropertyOptional({
    enum: choices('new-vulnerabilities', 'limit'),
    default: '5',
  })
  @IsOptional()
  @IsIn(choices('new-vulnerabilities', 'limit'))
  limit?: string;
}

export class AttentionQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({
    type: [String],
    enum: ATTENTION_KINDS,
    description: 'Qué avisos (se repite; por defecto todos)',
  })
  @IsOptional()
  @Transform(toArray)
  @ArrayMinSize(1)
  @ArrayMaxSize(ATTENTION_KINDS.length)
  @IsIn(ATTENTION_KINDS, { each: true })
  kinds?: AttentionKind[];
}

export class ExpirationsQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({
    type: [String],
    enum: ['domain', 'certificate'],
    description: 'Qué (se repite; por defecto los dos)',
  })
  @IsOptional()
  @Transform(toArray)
  @ArrayMinSize(1)
  @ArrayMaxSize(2)
  @IsIn(choices('expirations', 'kinds'), { each: true })
  kinds?: ('domain' | 'certificate')[];

  @ApiPropertyOptional({
    minimum: 1,
    maximum: 730,
    description:
      'Que caduquen en menos de estos días (por defecto, el umbral mayor de los avisos)',
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(730)
  horizonDays?: number;

  @ApiPropertyOptional({ enum: choices('expirations', 'limit'), default: '10' })
  @IsOptional()
  @IsIn(choices('expirations', 'limit'))
  limit?: string;
}

export class RecentActivityQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({
    enum: choices('recent-activity', 'limit'),
    default: '8',
  })
  @IsOptional()
  @IsIn(choices('recent-activity', 'limit'))
  limit?: string;

  @ApiPropertyOptional({
    enum: choices('recent-activity', 'state'),
    default: 'all',
  })
  @IsOptional()
  @IsIn(choices('recent-activity', 'state'))
  state?: 'all' | 'failed' | 'running';
}

export class TrendQueryDto extends WidgetScopeQueryDto {
  @ApiPropertyOptional({ enum: TREND_METRICS, default: 'open-findings' })
  @IsOptional()
  @IsIn(TREND_METRICS)
  metric?: TrendMetric;

  @ApiPropertyOptional({ enum: TREND_RANGES, default: '90d' })
  @IsOptional()
  @IsIn(TREND_RANGES)
  range?: TrendRange;
}

// --- Respuestas ---

export class FixableVulnerabilitiesDataDto implements FixableVulnerabilitiesData {
  @ApiProperty({
    type: 'object',
    properties: Object.fromEntries(
      SEVERITIES.map((s) => [s, { type: 'integer' }]),
    ),
    description:
      'Hallazgos abiertos por severidad (dueños no retirados que escanean)',
  })
  openFindings: Record<Severity, number>;

  @ApiProperty({
    type: 'object',
    properties: { CRITICAL: { type: 'integer' }, HIGH: { type: 'integer' } },
    description: 'Hallazgos abiertos críticos y altos con parche',
  })
  fixableFindings: Record<'CRITICAL' | 'HIGH', number>;

  @ApiProperty({ description: 'CVE distintos con algún hallazgo abierto' })
  openVulnerabilities: number;
}

export class VulnerabilityCountsDataDto implements VulnerabilityCountsData {
  @ApiProperty({ description: 'CVE de prioridad urgente' })
  urgent: number;

  @ApiProperty({ description: 'CVE de prioridad alta' })
  high: number;

  @ApiProperty({ description: 'CVE de prioridad media' })
  medium: number;

  @ApiProperty({ description: 'CVE en el catálogo KEV' })
  kev: number;

  @ApiProperty({ description: 'CVE distintos (prioridad ≥ media)' })
  cves: number;
}

export class AssetCountsDataDto implements AssetCountsData {
  @ApiProperty({ enum: ['type', 'status'] })
  groupBy: 'type' | 'status';

  @ApiProperty({
    type: 'object',
    additionalProperties: { type: 'integer' },
    description: `Por tipo (${ASSET_TYPES.join(', ')}; sin retirados) o por estado (${ASSET_STATUSES.join(', ')})`,
  })
  counts: AssetCountsData['counts'];

  @ApiProperty()
  total: number;
}

export class PendingEnrollmentDataDto implements PendingEnrollmentData {
  @ApiProperty()
  count: number;

  @ApiProperty({ type: [AssetSummaryDto] })
  assets: AssetSummaryDto[];
}

export class RunningJobsDataDto implements RunningJobsData {
  @ApiProperty({ description: 'Jobs en cola o en curso' })
  count: number;
}

export class TopVulnerabilitiesDataDto implements TopVulnerabilitiesData {
  @ApiProperty({ description: 'CVE que cumplen el filtro' })
  total: number;

  @ApiProperty({ type: [DashboardVulnerabilityDto] })
  items: DashboardVulnerabilityDto[];
}

export class NewVulnerabilitiesDataDto
  extends TopVulnerabilitiesDataDto
  implements NewVulnerabilitiesData
{
  @ApiProperty({ format: 'date-time', description: 'Desde cuándo cuenta' })
  since: string;

  @ApiProperty({ description: 'De los nuevos, cuántos están en KEV' })
  kev: number;
}

export class AttentionItemDto implements AttentionItem {
  @ApiProperty({ enum: ATTENTION_KINDS })
  kind: AttentionKind;

  @ApiProperty()
  count: number;

  @ApiProperty({ type: [AssetSummaryDto], description: 'Como mucho 5' })
  assets: AssetSummaryDto[];
}

export class AttentionDataDto implements AttentionData {
  @ApiProperty({
    type: [AttentionItemDto],
    description: 'Solo los que tienen algo',
  })
  items: AttentionItemDto[];

  @ApiProperty({
    type: [Number],
    description: 'Umbrales de aviso de caducidad (días)',
  })
  expiryWarningDays: number[];
}

export class ExpirationItemDto implements ExpirationItem {
  @ApiProperty({ type: AssetSummaryDto })
  asset: AssetSummaryDto;

  @ApiProperty({ enum: ['domain', 'certificate'] })
  kind: 'domain' | 'certificate';

  @ApiProperty({ format: 'date-time' })
  expiresAt: string;

  @ApiProperty({ description: 'Negativo si ya caducó' })
  daysLeft: number;
}

export class ExpirationsDataDto implements ExpirationsData {
  @ApiProperty()
  horizonDays: number;

  @ApiProperty({ type: [Number] })
  expiryWarningDays: number[];

  @ApiProperty()
  total: number;

  @ApiProperty({ type: [ExpirationItemDto] })
  items: ExpirationItemDto[];
}

export class RecentActivityDataDto implements RecentActivityData {
  @ApiProperty({ type: [JobRunSummaryDto] })
  items: JobRunSummaryDto[];

  @ApiProperty({ description: 'Jobs en cola o en curso' })
  running: number;
}

export class TrendSeriesDto implements TrendSeries {
  @ApiProperty()
  key: string;

  @ApiProperty()
  label: string;

  @ApiPropertyOptional({ enum: SEVERITIES })
  severity?: Severity;

  @ApiPropertyOptional({ enum: PRIORITY_BANDS })
  band?: PriorityBand;
}

export class TrendPointDto implements TrendPoint {
  @ApiProperty({ format: 'date' })
  day: string;

  @ApiProperty({ type: 'object', additionalProperties: { type: 'integer' } })
  values: Record<string, number>;
}

export class TrendDataDto implements TrendData {
  @ApiProperty({ enum: TREND_METRICS })
  metric: TrendMetric;

  @ApiProperty({ enum: ['day', 'week'] })
  bucket: 'day' | 'week';

  @ApiProperty({
    description:
      'Reconstruido de opened_at/fixed_at: un finding reabierto pierde sus ciclos anteriores y los de assets purgados no están',
  })
  approximate: boolean;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Desde cuándo hay datos',
  })
  since: string | null;

  @ApiProperty({ description: 'Tiene tags o tipos que esta métrica no aplica' })
  ignoredFilters: boolean;

  @ApiProperty({ type: [TrendSeriesDto] })
  series: TrendSeriesDto[];

  @ApiProperty({ type: [TrendPointDto] })
  points: TrendPointDto[];
}
