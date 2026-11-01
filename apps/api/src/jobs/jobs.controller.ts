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
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  JOB_NAMES,
  type EnqueueJobResponse,
  type JobRunLog,
  type JobRunSummary,
  type JobStatus,
  type Page,
  type WorkerReplica,
} from '@infraward/shared-types';
import { Can } from '../auth/permissions.decorator.js';
import {
  EnqueueJobResponseDto,
  JobRunListQueryDto,
  JobRunLogDto,
  JobRunPageDto,
  JobRunSummaryDto,
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

  /**
   * Una ejecución del historial (detalle de la Actividad): su origen, las tareas que lanzó y si
   * tiene log.
   */
  @Get('runs/:id')
  @ApiOkResponse({ type: JobRunSummaryDto })
  @ApiNotFoundResponse({ description: 'No existe o ya se borró del historial' })
  run(@Param('id', new ParseUUIDPipe()) id: string): Promise<JobRunSummary> {
    return this.runs.get(id);
  }

  /**
   * Log de una ejecución (DESIGN §20, «Log de cada ejecución»), también de las que no trabajan
   * sobre un asset. Como el de la ficha: solo con `assets.operate`, porque lleva el stderr de los
   * servidores.
   */
  @Get('runs/:id/log')
  @Can('assets.operate')
  @ApiOkResponse({ type: JobRunLogDto })
  @ApiForbiddenResponse({ description: 'Requiere assets.operate (admin, editor u operador)' })
  @ApiNotFoundResponse({ description: 'No existe o ya se borró del historial' })
  runLog(@Param('id', new ParseUUIDPipe()) id: string): Promise<JobRunLog> {
    return this.runs.runLog(id);
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
