import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Sse,
  type MessageEvent,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiExtraModels,
  ApiOkResponse,
  ApiProduces,
  ApiTags,
  getSchemaPath,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { finalize, Subject, takeUntil, type Observable } from 'rxjs';
import {
  hasPermission,
  type EnrollServerResponse,
  type Enrollment,
  type IssuedEnrollment,
} from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import {
  AuditCtx,
  type AuditActor,
} from '../audit/audit-context.decorator.js';
import type {
  AuthenticatedUser,
  RequestSession,
} from '../auth/authenticated-user.js';
import {
  CurrentSession,
  CurrentUser,
} from '../auth/current-user.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { SessionOnly } from '../auth/public.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import { SessionRegistry } from '../auth/session-registry.js';
import {
  ConfirmManualEnrollmentDto,
  EnrollmentDto,
  EnrollmentProgressDto,
  EnrollServerDto,
  EnrollServerResponseDto,
  IssueEnrollmentTokenDto,
  IssuedEnrollmentDto,
} from './enrollment.dto.js';
import { EnrollmentProgressService } from './enrollment-progress.service.js';
import { EnrollmentService } from './enrollment.service.js';

const uuid = new ParseUUIDPipe();

/** Alta de servidores (DESIGN §7). */
@ApiTags('enrollment')
@ApiExtraModels(EnrollmentProgressDto)
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class EnrollmentController {
  constructor(
    private readonly enrollment: EnrollmentService,
    private readonly progress: EnrollmentProgressService,
    private readonly registry: SessionRegistry,
  ) {}

  /**
   * "Añadir servidor": crea el asset en `pending_enrollment`, guarda la clave privada en el
   * proveedor de secretos (en la BD solo la referencia) y devuelve el comando de alta.
   */
  @Post('enroll')
  @Can('assets.write')
  @RecentAuth('admin_access.enable', (request) => enablesAdminAccess(request))
  @ApiForbiddenResponse({
    description:
      'Sin el permiso necesario para su rol; con el acceso de administración, `users.manage` y reautenticación reciente',
  })
  @ApiCreatedResponse({ type: EnrollServerResponseDto })
  @ApiBadRequestResponse()
  enroll(
    @Body() body: EnrollServerDto,
    @AuditCtx() actor: AuditActor,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<EnrollServerResponse> {
    return this.enrollment.enrollServer(body, actor, user.role);
  }

  /** Último enrolamiento del asset (sin token). */
  @Get(':id/enrollment')
  @ApiOkResponse({ type: EnrollmentDto })
  @ApiNotFoundResponse()
  latest(@Param('id', uuid) id: string): Promise<Enrollment> {
    return this.enrollment.latest(id);
  }

  /**
   * Progreso del alta en tiempo real (Server-Sent Events): `event: progress` con un
   * `EnrollmentProgress` completo en cada cambio (el primero, al conectar) y `event: heartbeat`
   * cada 15 s. El servidor cierra el flujo a los 30 min; el cliente reconecta.
   */
  @Sse(':id/enrollment/events')
  @SessionOnly()
  @ApiProduces('text/event-stream')
  @ApiOkResponse({
    description:
      'Flujo SSE; `data` de cada `progress` es un EnrollmentProgress',
    content: {
      'text/event-stream': {
        schema: { $ref: getSchemaPath(EnrollmentProgressDto) },
      },
    },
  })
  @ApiNotFoundResponse()
  async events(
    @Param('id', uuid) id: string,
    @CurrentSession() session: RequestSession,
  ): Promise<Observable<MessageEvent>> {
    const stream = await this.progress.stream(id);
    // El guard solo actúa al conectar: si la sesión se revoca, el flujo se corta al momento.
    const revoked = new Subject<void>();
    const unregister = this.registry.register(session.id, () => revoked.next());
    return stream.pipe(takeUntil(revoked), finalize(unregister));
  }

  /**
   * Comando nuevo: sustituye al pendiente (el token anterior deja de valer) o, con el asset ya
   * activo, sirve para volver a ejecutar el script y actualizar el sudoers con la misma clave.
   */
  @Post(':id/enrollment/token')
  @Can('assets.write')
  @RecentAuth('admin_access.enable', (request) => enablesAdminAccess(request))
  @ApiForbiddenResponse({
    description:
      'Sin el permiso necesario para su rol; activar el acceso de administración exige `users.manage` y reautenticación reciente',
  })
  @ApiCreatedResponse({ type: IssuedEnrollmentDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'Retirado, sin clave o verificando' })
  issueToken(
    @Param('id', uuid) id: string,
    @Body() body: IssueEnrollmentTokenDto,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<IssuedEnrollment> {
    // Dar a InfraWard una cuenta con sudo en el servidor es cosa de un admin (§7).
    if (body.adminAccess === 'operator' && !hasPermission(user.role, 'users.manage'))
      throw new ForbiddenException(
        'Solo un admin puede activar el acceso interactivo de administración',
      );
    return this.enrollment.issueToken(
      id,
      body.installSudo ?? false,
      body.authMode,
      actor,
      body.adminAccess,
    );
  }

  /**
   * "Ya lo he añadido" (clave a mano o script embebido): encola la verificación con el usuario
   * indicado y, si se pegan, las huellas de las host keys que imprimió el script.
   */
  @Post(':id/enrollment/confirm')
  @Can('assets.write')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: EnrollmentDto })
  @ApiBadRequestResponse({
    description: 'Usuario no válido (o root) o huellas mal formadas',
  })
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'No hay alta pendiente' })
  confirm(
    @Param('id', uuid) id: string,
    @Body() body: ConfirmManualEnrollmentDto,
  ): Promise<Enrollment> {
    return this.enrollment.confirmManual(id, body.sshUser, body.hostKeys);
  }

  /** Reintenta la verificación de un enrolamiento fallido. */
  @Post(':id/enrollment/verify')
  @Can('assets.write')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: EnrollmentDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'El último enrolamiento no ha fallado' })
  verify(@Param('id', uuid) id: string): Promise<Enrollment> {
    return this.enrollment.retryVerification(id);
  }
}

/** Activar el acceso de administración (no retirarlo) es una acción sensible. */
function enablesAdminAccess(request: FastifyRequest): boolean {
  return (request.body as Record<string, unknown> | undefined)?.adminAccess === 'operator';
}
