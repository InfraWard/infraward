import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  SBOM_SOURCES,
  type AssetPackagesPage,
  type PackageListQuery,
  type PackageSummary,
  type SbomSource,
  type SbomSummary,
} from '@infraward/shared-types';
import {
  IsBoolean,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
} from 'class-validator';
import { PageQueryDto } from '../assets/assets.dto.js';

export class PackageListQueryDto
  extends PageQueryDto
  implements PackageListQuery
{
  @ApiPropertyOptional({
    description: 'Nombre que contenga el texto (sin distinguir mayúsculas)',
  })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  q?: string;

  @ApiPropertyOptional({ example: 'deb', description: 'Tipo del purl' })
  @IsOptional()
  @Matches(/^[a-z0-9.+-]{1,32}$/)
  ecosystem?: string;
}

class SbomOsDto {
  @ApiProperty({ example: 'debian' })
  family: string;

  @ApiProperty({ example: '13.1' })
  name: string;
}

export class SbomSummaryDto implements SbomSummary {
  @ApiProperty({
    format: 'uuid',
    description: 'Asset del SBOM (la imagen, en un contenedor)',
  })
  assetId: string;

  @ApiProperty({ enum: SBOM_SOURCES })
  source: SbomSource;

  @ApiProperty({ enum: ['cyclonedx'] })
  format: 'cyclonedx';

  @ApiProperty({ example: '1.7' })
  specVersion: string;

  @ApiProperty({ type: SbomOsDto, nullable: true })
  os: SbomOsDto | null;

  @ApiProperty()
  packageCount: number;

  @ApiProperty({ description: 'Tamaño del JSON sin comprimir' })
  sizeBytes: number;

  @ApiProperty({ type: String, nullable: true })
  trivyVersion: string | null;

  @ApiProperty({ format: 'date-time' })
  generatedAt: string;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  evaluatedAt: string | null;

  @ApiProperty({
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'BD de vulnerabilidades de Trivy de la última evaluación',
  })
  dbUpdatedAt: string | null;

  @ApiProperty({ type: Number, nullable: true })
  vulnerabilityCount: number | null;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Motivo si la última re-evaluación falló',
  })
  evaluationError: string | null;
}

export class PackageSummaryDto implements PackageSummary {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ example: 'openssl' })
  name: string;

  @ApiProperty({ example: '3.5.1-1' })
  version: string;

  @ApiProperty({ example: 'deb' })
  ecosystem: string;

  @ApiProperty({ type: String, nullable: true })
  purl: string | null;

  @ApiProperty({ type: String, nullable: true })
  pkgPath: string | null;
}

export class AssetPackagesPageDto implements AssetPackagesPage {
  @ApiProperty({ type: [PackageSummaryDto] })
  items: PackageSummaryDto[];

  @ApiProperty()
  total: number;

  @ApiProperty({ type: SbomSummaryDto, nullable: true })
  sbom: SbomSummaryDto | null;
}

/** Cuerpo opcional de `POST /sboms/reevaluate`. */
export class ReevaluateSbomsDto {
  @ApiPropertyOptional({
    description:
      'Descargar antes la BD de Trivy aunque no haya caducado (sale a Internet desde el worker)',
  })
  @IsOptional()
  @IsBoolean()
  downloadDb?: boolean;
}
