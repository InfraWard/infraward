import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  InvalidSecretRefError,
  parseSecretRef,
  SecretError,
  SecretsService,
} from '@infraward/secrets';
import type {
  CheckSecretResponse,
  SecretProviderInfo,
} from '@infraward/shared-types';
import { Can } from '../auth/permissions.decorator.js';
import {
  CheckSecretDto,
  CheckSecretResponseDto,
  SecretProviderInfoDto,
} from './secrets.dto.js';
import { SecretsCheckThrottlerGuard } from './secrets-check-throttler.guard.js';

/** Secretos: nunca se devuelve un valor, solo referencias y si resuelven. */
@ApiTags('secrets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Requiere secrets.status (lista) o assets.write (comprobar)' })
@Controller('secrets')
export class SecretsController {
  private readonly logger = new Logger(SecretsController.name);

  constructor(private readonly secrets: SecretsService) {}

  /** Proveedores de secretos activos con su estado y capacidades. */
  @Get('providers')
  @Can('secrets.status')
  @ApiOkResponse({ type: [SecretProviderInfoDto] })
  providers(): Promise<SecretProviderInfo[]> {
    return this.secrets.describeProviders();
  }

  /** Comprueba si una referencia resuelve. El valor se descarta: nunca sale de la API. */
  @Post('check')
  @Can('assets.write')
  @UseGuards(SecretsCheckThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiTooManyRequestsResponse({
    description: 'Demasiadas comprobaciones; reintentar tras Retry-After',
  })
  @ApiOkResponse({ type: CheckSecretResponseDto })
  @ApiBadRequestResponse({ description: 'Referencia mal formada' })
  async check(@Body() body: CheckSecretDto): Promise<CheckSecretResponse> {
    let provider: string;
    try {
      provider = parseSecretRef(body.ref).provider;
    } catch (e) {
      if (e instanceof InvalidSecretRefError) {
        throw new BadRequestException(e.message);
      }
      throw e;
    }
    const result: CheckSecretResponse = {
      ref: body.ref,
      provider,
      resolves: false,
    };
    try {
      await this.secrets.resolve(body.ref, { fresh: true });
      result.resolves = true;
    } catch (e) {
      if (e instanceof SecretError) {
        result.error = e.code;
      } else {
        // Fallo inesperado del proveedor: solo la referencia y el tipo de error, nunca el mensaje.
        result.error = 'provider_error';
        this.logger.warn(
          `No se pudo comprobar ${body.ref}: ${(e as Error).name ?? 'Error'}`,
        );
      }
    }
    return result;
  }
}
