import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiProduces,
  ApiTags,
  ApiTooManyRequestsResponse,
} from '@nestjs/swagger';
import { Public } from '../auth/public.decorator.js';
import { EnrollDoneDto } from './enrollment.dto.js';
import { EnrollmentService } from './enrollment.service.js';
import { EnrollThrottlerGuard } from './enroll-throttler.guard.js';

const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** Formato inválido = token desconocido: 404 igual que caducado o usado. */
function checkToken(token: string): string {
  if (!TOKEN.test(token)) throw new NotFoundException();
  return token;
}

/**
 * Endpoints que llama el servidor que se da de alta (sin JWT: el token de un solo uso es la
 * credencial). Token desconocido, caducado o ya usado → 404, sin distinguir.
 */
@ApiTags('enroll')
@ApiNotFoundResponse({ description: 'Token desconocido, caducado o ya usado' })
@ApiTooManyRequestsResponse()
@Public()
@UseGuards(EnrollThrottlerGuard)
@Controller('enroll')
export class EnrollController {
  constructor(private readonly enrollment: EnrollmentService) {}

  /** Script de alta (`curl -fsSL … | sudo bash`). Se puede descargar hasta que se use el token. */
  @Get(':token')
  @Header('Content-Type', 'text/x-shellscript; charset=utf-8')
  @Header('Cache-Control', 'no-store')
  @ApiProduces('text/x-shellscript')
  @ApiOkResponse({ description: 'Script de alta', type: String })
  script(@Param('token') token: string): Promise<string> {
    return this.enrollment.script(checkToken(token));
  }

  /**
   * Aviso del script al terminar: consume el token y encola la verificación por SSH.
   * No activa el asset: eso solo ocurre cuando el worker consigue conectarse.
   */
  @Post(':token/done')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  async done(
    @Param('token') token: string,
    @Body() body: EnrollDoneDto,
  ): Promise<void> {
    await this.enrollment.consume(checkToken(token), body.hostKeys);
  }
}
