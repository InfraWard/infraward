import { Controller, Get, Header, Query, Res } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiOkResponse,
  ApiProduces,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { exportFilename } from '../common/csv.js';
import {
  InventoryExportQueryDto,
  VulnerabilityExportQueryDto,
} from './exports.dto.js';
import { ExportsService, type ExportFile } from './exports.service.js';

/**
 * Exportaciones a CSV o JSON (QoL-6). Leer el inventario no exige permiso, así que tampoco
 * exportarlo; nunca salen secretos ni referencias a credenciales (lista blanca de columnas).
 */
@ApiTags('exports')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiBadRequestResponse()
@Controller()
export class ExportsController {
  constructor(private readonly exports: ExportsService) {}

  /** El inventario con los filtros del árbol y las columnas visibles. */
  @Get('assets/export')
  @Header('Cache-Control', 'no-store')
  @ApiProduces('text/csv', 'application/json')
  @ApiOkResponse({ description: 'Fichero CSV (con BOM) o JSON' })
  async inventory(
    @Query() query: InventoryExportQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<string> {
    return send(
      reply,
      await this.exports.inventory(query),
      'inventario',
      query.format,
    );
  }

  /** Las vulnerabilidades con los filtros de la lista, por CVE o por asset. */
  @Get('vulnerabilities/export')
  @Header('Cache-Control', 'no-store')
  @ApiProduces('text/csv', 'application/json')
  @ApiOkResponse({ description: 'Fichero CSV (con BOM) o JSON' })
  async vulnerabilities(
    @Query() query: VulnerabilityExportQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<string> {
    const what =
      query.groupBy === 'asset'
        ? 'vulnerabilidades-por-asset'
        : 'vulnerabilidades';
    return send(
      reply,
      await this.exports.vulnerabilities(query),
      what,
      query.format,
    );
  }
}

function send(
  reply: FastifyReply,
  file: ExportFile,
  what: string,
  format: 'csv' | 'json' | undefined,
): string {
  reply.header('Content-Type', file.contentType);
  reply.header(
    'Content-Disposition',
    `attachment; filename="${exportFilename(what, format ?? 'csv')}"`,
  );
  reply.header('X-Export-Rows', String(file.rows));
  return file.body;
}
