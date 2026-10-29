import {
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
  ApiConflictResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  AssetFindingsPage,
  AssetVulnerabilitiesPage,
  FindingSearchResult,
  Page,
  ScanAssetResponse,
  VulnerabilitySummary,
} from '@infraward/shared-types';
import { Can } from '../auth/permissions.decorator.js';
import {
  AssetFindingsPageDto,
  AssetVulnerabilitiesPageDto,
  FindingListQueryDto,
  FindingSearchPageDto,
  ScanAssetResponseDto,
  ScanQueryDto,
  VulnerabilitySummaryPageDto,
} from './findings.dto.js';
import { FindingsService } from './findings.service.js';

@ApiTags('findings')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller()
export class FindingsController {
  constructor(private readonly findings: FindingsService) {}

  /**
   * Escanea con Trivy: el SBOM de un servidor con conexión o de un CT (copiando solo sus BDs de
   * paquetes, sin sudo), la imagen de un contenedor, una imagen o las imágenes de los contenedores
   * activos de un host Docker. Cada imagen se escanea una sola vez (por image ID) y su SBOM y sus
   * findings se guardan una vez, en el asset `image`. Sin `force`, una imagen ya escaneada no se
   * vuelve a analizar. Lo que supera los límites o no se puede leer queda `skipped` con su motivo.
   */
  @Post('assets/:id/scan')
  @Can('assets.operate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: ScanAssetResponseDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description:
      'No es un servidor con conexión o CT activo, un contenedor activo, una imagen ni un host Docker con contenedores descubiertos',
  })
  scan(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: ScanQueryDto,
  ): Promise<ScanAssetResponse> {
    return this.findings.scan(id, query.force);
  }

  /**
   * Findings de un asset, de más a menos graves. En un contenedor son los de su imagen
   * (`instance_of`), con el estado de su escaneo.
   */
  @Get('assets/:id/findings')
  @ApiOkResponse({ type: AssetFindingsPageDto })
  @ApiNotFoundResponse()
  assetFindings(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: FindingListQueryDto,
  ): Promise<AssetFindingsPage> {
    return this.findings.assetFindings(id, query);
  }

  /**
   * Findings de un asset agrupados por vulnerabilidad: una fila por CVE con sus paquetes. Los
   * filtros se aplican a cada finding y la paginación es por CVE.
   */
  @Get('assets/:id/vulnerabilities')
  @ApiOkResponse({ type: AssetVulnerabilitiesPageDto })
  @ApiNotFoundResponse()
  assetVulnerabilities(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: FindingListQueryDto,
  ): Promise<AssetVulnerabilitiesPage> {
    return this.findings.assetVulnerabilities(id, query);
  }

  /**
   * Vulnerabilidades de todo el inventario: una fila por CVE con su severidad máxima, paquetes,
   * imágenes y contenedores afectados (sin retirados). Los filtros se aplican a cada finding; la
   * paginación es por CVE.
   */
  @Get('vulnerabilities')
  @ApiOkResponse({ type: VulnerabilitySummaryPageDto })
  vulnerabilities(
    @Query() query: FindingListQueryDto,
  ): Promise<Page<VulnerabilitySummary>> {
    return this.findings.vulnerabilities(query);
  }

  /**
   * Findings de todo el inventario, filtrables por CVE, paquete, severidad y estado. Cada uno lleva
   * los assets afectados: los contenedores de la imagen o el propio asset.
   */
  @Get('findings')
  @ApiOkResponse({ type: FindingSearchPageDto })
  search(
    @Query() query: FindingListQueryDto,
  ): Promise<Page<FindingSearchResult>> {
    return this.findings.search(query);
  }
}
