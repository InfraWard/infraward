import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_TYPES,
  JOB_NAMES,
  JOB_RUN_STATE_FILTERS,
  JOB_RUN_STATES,
  QUEUE_NAMES,
  type AssetType,
  type EnqueueJobResponse,
  type JobRunListQuery,
  type JobRunState,
  type JobRunStateFilter,
  type JobRunSummary,
  type Page,
  type JobName,
  type JobProgressEvent,
  type QueueName,
  type WorkerReplica,
  type JobState,
  type JobStatus,
  type PingJobData,
  type PingJobResult,
} from '@infraward/shared-types';
import {
  IsIn,
  IsInt,
  IsOptional,
  IsUUID,
  IsString,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { PageQueryDto } from '../assets/assets.dto.js';

export const JOB_STATES: JobState[] = [
  'waiting',
  'active',
  'delayed',
  'prioritized',
  'waiting-children',
  'completed',
  'failed',
  'unknown',
];

export class PingJobDto implements Partial<PingJobData> {
  @ApiPropertyOptional({ minimum: 1, maximum: 20, default: 5 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(20)
  steps?: number;

  @ApiPropertyOptional({ minimum: 0, maximum: 5000, default: 200 })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(5000)
  stepDelayMs?: number;

  @ApiPropertyOptional({ maxLength: 200 })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  message?: string;
}

export class EnqueueJobResponseDto implements EnqueueJobResponse {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: Object.values(JOB_NAMES), example: 'ping' })
  name: JobName;

  @ApiProperty({ enum: Object.values(QUEUE_NAMES), example: 'system' })
  queue: QueueName;
}

export class JobProgressEventDto implements JobProgressEvent {
  @ApiProperty({ minimum: 0, maximum: 100 })
  progress: number;

  @ApiProperty()
  message: string;

  @ApiProperty({ format: 'date-time' })
  at: string;
}

export class PingJobResultDto implements PingJobResult {
  @ApiProperty({ enum: [true] })
  pong: true;

  @ApiPropertyOptional()
  message?: string;

  @ApiProperty()
  steps: number;

  @ApiProperty({ format: 'date-time' })
  processedAt: string;
}

export class JobStatusDto implements JobStatus<'ping'> {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ example: 'ping' })
  name: 'ping';

  @ApiProperty({ example: 'system' })
  queue: 'system';

  @ApiProperty({ enum: JOB_STATES })
  state: JobState;

  @ApiProperty({ minimum: 0, maximum: 100 })
  progress: number;

  @ApiProperty({ type: [JobProgressEventDto] })
  events: JobProgressEventDto[];

  @ApiPropertyOptional({ type: PingJobResultDto })
  result?: PingJobResultDto;

  @ApiPropertyOptional()
  failedReason?: string;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiPropertyOptional({ format: 'date-time' })
  finishedAt?: string;
}

export class JobRunListQueryDto
  extends PageQueryDto
  implements JobRunListQuery
{
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Del asset y, si es un contenedor, también de su imagen',
  })
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({
    enum: JOB_RUN_STATE_FILTERS,
    description: '`running`: en cola o en curso',
  })
  @IsOptional()
  @IsIn(JOB_RUN_STATE_FILTERS)
  state?: JobRunStateFilter;

  @ApiPropertyOptional({ enum: Object.values(JOB_NAMES) })
  @IsOptional()
  @IsIn(Object.values(JOB_NAMES))
  name?: JobName;

  @ApiPropertyOptional({
    format: 'uuid',
    description:
      'Los que lanzó una operación en lote (o encadenó otro job)',
  })
  @IsOptional()
  @IsUUID()
  parentJobId?: string;
}

class JobRunChildrenDto {
  @ApiProperty()
  total: number;

  @ApiProperty({ description: 'En cola o en curso' })
  running: number;

  @ApiProperty()
  failed: number;
}

export class JobRunSummaryDto implements JobRunSummary {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: Object.values(JOB_NAMES) })
  name: JobName;

  @ApiProperty({ enum: Object.values(QUEUE_NAMES) })
  queue: QueueName;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  assetId: string | null;

  @ApiProperty({ type: String, nullable: true })
  assetName: string | null;

  @ApiProperty({ enum: ASSET_TYPES, nullable: true })
  assetType: AssetType | null;

  @ApiProperty({ enum: JOB_RUN_STATES })
  state: JobRunState;

  @ApiProperty({ minimum: 0, maximum: 100 })
  progress: number;

  @ApiProperty({ type: String, nullable: true })
  message: string | null;

  @ApiProperty({ type: String, nullable: true })
  error: string | null;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  parentJobId: string | null;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Réplica del worker que lo ejecuta o lo ejecutó por última vez',
  })
  worker: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  startedAt: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  finishedAt: string | null;

  @ApiProperty({ type: Number, nullable: true })
  durationMs: number | null;

  @ApiPropertyOptional({
    type: JobRunChildrenDto,
    description: 'Jobs que colgaron de este (lote o cadena)',
  })
  children?: JobRunChildrenDto;
}

export class JobRunPageDto implements Page<JobRunSummary> {
  @ApiProperty({ type: [JobRunSummaryDto] })
  items: JobRunSummaryDto[];

  @ApiProperty()
  total: number;
}

export class WorkerReplicaDto implements WorkerReplica {
  @ApiProperty({ example: 'worker-1' })
  name: string;

  @ApiProperty({ enum: Object.values(QUEUE_NAMES), isArray: true })
  queues: QueueName[];

  @ApiProperty({ description: 'Máquina (hostname) en la que corre' })
  host: string;

  @ApiProperty({ description: 'Segundos desde que arrancó' })
  uptimeSeconds: number;

  @ApiProperty({
    description:
      'Es el líder: programa los jobs periódicos, registra la Actividad y recupera huérfanos',
  })
  leader: boolean;
}
