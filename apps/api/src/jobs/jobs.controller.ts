import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiCookieAuth,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  JOB_NAMES,
  type EnqueueJobResponse,
  type JobRunSummary,
  type JobStatus,
  type Page,
  type WorkerReplica,
} from '@infraward/shared-types';
import {
  EnqueueJobResponseDto,
  JobRunListQueryDto,
  JobRunPageDto,
  JobStatusDto,
  PingJobDto,
  WorkerReplicaDto,
} from './jobs.dto.js';
import { JobRunsService } from './job-runs.service.js';
import { JobsService } from './jobs.service.js';

@ApiTags('jobs')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('jobs')
export class JobsController {
  constructor(
    private readonly jobs: JobsService,
    private readonly runs: JobRunsService,
  ) {}

  /**
   * Historial de ejecuciones (recolecciones, descubrimientos, escaneos, verificaciones de alta),
   * de la más reciente a la más antigua. Se conserva aunque BullMQ ya haya borrado el job.
   */
  @Get()
  @ApiOkResponse({ type: JobRunPageDto })
  list(@Query() query: JobRunListQueryDto): Promise<Page<JobRunSummary>> {
    return this.runs.list(query);
  }

  /** Réplicas del worker conectadas, las colas que consume cada una y cuál es el líder. */
  @Get('workers')
  @ApiOkResponse({ type: [WorkerReplicaDto] })
  workers(): Promise<WorkerReplica[]> {
    return this.jobs.workers();
  }

  /** Encola un job de prueba que el worker procesa en varios pasos con progreso. */
  @Post('ping')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiAcceptedResponse({ type: EnqueueJobResponseDto })
  ping(@Body() body: PingJobDto): Promise<EnqueueJobResponse> {
    return this.jobs.enqueue(JOB_NAMES.ping, {
      steps: body.steps ?? 5,
      stepDelayMs: body.stepDelayMs ?? 200,
      message: body.message,
    });
  }

  /** Estado, progreso, eventos de progreso y resultado de un job. */
  @Get(':id')
  @ApiOkResponse({ type: JobStatusDto })
  @ApiNotFoundResponse({ description: 'El job no existe o ya caducó' })
  status(@Param('id', new ParseUUIDPipe()) id: string): Promise<JobStatus> {
    return this.jobs.status(id);
  }
}
