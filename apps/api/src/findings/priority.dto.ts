import { ApiProperty } from '@nestjs/swagger';
import {
  HIDDEN_REASONS,
  INTEL_SOURCES,
  JOB_RUN_STATES,
  NOISE_REASONS,
  PRIORITY_BANDS,
  type EpssScore,
  type HiddenReason,
  type IntelFeedStatus,
  type IntelSource,
  type IntelStatus,
  type JobRunState,
  type KevEntry,
  type PriorityBand,
  type PriorityInfo,
  type PriorityReason,
  type TrivyDbStatus,
  type VulnerabilityEnrichment,
} from '@infraward/shared-types';

/** Prioridad 0–100 con su banda y sus motivos (DESIGN §9). */
export class PriorityInfoDto implements PriorityInfo {
  @ApiProperty({ minimum: 0, maximum: 100 })
  score: number;

  @ApiProperty({ enum: PRIORITY_BANDS })
  band: PriorityBand;

  @ApiProperty({
    type: 'array',
    items: { type: 'object', additionalProperties: true },
    description:
      'Motivos en orden de peso: `{ code, …datos }` (`kev`, `epss`, `port`, `public`, `service`, `container`, `fix`, `no_fix`, `cvss`, `severity`, `unused_image`, `no_process_data` y los de ruido `kernel_other`, `kernel_aux`, `kernel_guest`, `no_fix_planned`). El texto lo pone el cliente (`priorityReasonText`).',
  })
  reasons: PriorityReason[];
}

export const NOISE_REASON_PROPERTY = {
  enum: NOISE_REASONS,
  nullable: true,
  description: 'Por qué sale de la vista principal (null si no es ruido)',
} as const;

export class HiddenCountsDto implements Partial<Record<HiddenReason, number>> {
  @ApiProperty({ required: false })
  scan_disabled?: number;

  @ApiProperty({ required: false })
  unused_image?: number;

  @ApiProperty({ required: false })
  kernel_not_running?: number;

  @ApiProperty({ required: false })
  no_fix_planned?: number;

  @ApiProperty({ required: false })
  low_priority?: number;
}

export const HIDDEN_PROPERTY = {
  type: HiddenCountsDto,
  nullable: true,
  description: `Findings que el filtro deja fuera, por el primer motivo que los oculta (${HIDDEN_REASONS.join(', ')}); null si no oculta nada`,
} as const;

export class KevEntryDto implements KevEntry {
  @ApiProperty({ type: String, format: 'date', nullable: true })
  added: string | null;

  @ApiProperty({
    type: String,
    format: 'date',
    nullable: true,
    description: 'Plazo de CISA',
  })
  due: string | null;

  @ApiProperty({ description: 'Usado en campañas de ransomware' })
  ransomware: boolean;

  @ApiProperty({ type: String, nullable: true })
  name: string | null;
}

export class EpssScoreDto implements EpssScore {
  @ApiProperty({
    minimum: 0,
    maximum: 1,
    description: 'Probabilidad de explotación en 30 días',
  })
  score: number;

  @ApiProperty({ type: Number, minimum: 0, maximum: 1, nullable: true })
  percentile: number | null;
}

export class VulnerabilityEnrichmentDto implements VulnerabilityEnrichment {
  @ApiProperty({
    type: KevEntryDto,
    nullable: true,
    description: 'null si no está en KEV',
  })
  kev: KevEntry | null;

  @ApiProperty({
    type: EpssScoreDto,
    nullable: true,
    description: 'null sin puntuación',
  })
  epss: EpssScore | null;
}

export class IntelFeedStatusDto implements IntelFeedStatus {
  @ApiProperty({ enum: INTEL_SOURCES })
  source: IntelSource;

  @ApiProperty({ description: 'false si su URL está vacía en el worker' })
  enabled: boolean;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  fetchedAt: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  checkedAt: string | null;

  @ApiProperty({ type: String, nullable: true })
  version: string | null;

  @ApiProperty({ type: Number, nullable: true })
  recordCount: number | null;

  @ApiProperty({ type: String, nullable: true })
  lastError: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  lastErrorAt: string | null;

  @ApiProperty()
  stale: boolean;
}

class TrivyDbRunDto {
  @ApiProperty({ format: 'uuid' })
  jobId: string;

  @ApiProperty({ enum: JOB_RUN_STATES })
  state: JobRunState;

  @ApiProperty({ type: String, nullable: true })
  message: string | null;

  @ApiProperty({ type: String, nullable: true })
  error: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  finishedAt: string | null;
}

export class TrivyDbStatusDto implements TrivyDbStatus {
  @ApiProperty({
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'Fecha de la BD de Trivy más reciente con la que se ha evaluado algún SBOM',
  })
  dbUpdatedAt: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  evaluatedAt: string | null;

  @ApiProperty()
  sboms: number;

  @ApiProperty({
    type: TrivyDbRunDto,
    nullable: true,
    description: 'Última re-evaluación de todos los SBOMs',
  })
  lastRun: TrivyDbStatus['lastRun'];

  @ApiProperty({ description: 'BD de hace más de TRIVY_STALE_DAYS días o sin ninguna' })
  stale: boolean;
}

export class IntelStatusDto implements IntelStatus {
  @ApiProperty({ type: [IntelFeedStatusDto] })
  feeds: IntelFeedStatus[];

  @ApiProperty({ type: TrivyDbStatusDto })
  trivy: TrivyDbStatus;
}

export type { NoiseReason } from '@infraward/shared-types';
