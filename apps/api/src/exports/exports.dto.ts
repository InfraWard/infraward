import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  ATTENTIONS,
  EXPORT_FORMATS,
  INVENTORY_EXPORT_COLUMNS,
  VULNERABILITY_EXPORT_GROUPS,
  type AssetStatus,
  type AssetType,
  type Attention,
  type ExportFormat,
  type InventoryExportColumn,
  type InventoryExportQuery,
  type VulnerabilityExportGroup,
  SEARCH_QUERY_INPUT_MAX,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  ArrayMaxSize,
  IsBoolean,
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
} from 'class-validator';
import { toBoolean } from '../assets/assets.dto.js';
import { FindingListQueryDto } from '../findings/findings.dto.js';

/** `columns=name,type` o `columns=name&columns=type`. */
const toList = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string'
    ? value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean)
    : value;

export class InventoryExportQueryDto implements InventoryExportQuery {
  @ApiPropertyOptional({ enum: EXPORT_FORMATS, default: 'csv' })
  @IsOptional()
  @IsIn(EXPORT_FORMATS)
  format?: ExportFormat;

  @ApiPropertyOptional({
    type: [String],
    enum: INVENTORY_EXPORT_COLUMNS,
    description:
      'Columnas (separadas por comas), de una lista blanca: nunca conexión, credenciales ni facts',
  })
  @IsOptional()
  @Transform(toList)
  @ArrayMaxSize(INVENTORY_EXPORT_COLUMNS.length)
  @IsIn(INVENTORY_EXPORT_COLUMNS, { each: true })
  columns?: InventoryExportColumn[];

  @ApiPropertyOptional({
    description:
      'Búsqueda con la sintaxis de filtros, como la del árbol (`tag:prod nombre:web`)',
    maxLength: SEARCH_QUERY_INPUT_MAX,
  })
  @IsOptional()
  @IsString()
  @MaxLength(SEARCH_QUERY_INPUT_MAX)
  q?: string;

  @ApiPropertyOptional({ enum: ASSET_TYPES })
  @IsOptional()
  @IsIn(ASSET_TYPES)
  type?: AssetType;

  @ApiPropertyOptional({ enum: ASSET_STATUSES })
  @IsOptional()
  @IsIn(ASSET_STATUSES)
  status?: AssetStatus;

  @ApiPropertyOptional({ enum: ATTENTIONS })
  @IsOptional()
  @IsIn(ATTENTIONS)
  attention?: Attention;

  @ApiPropertyOptional({ format: 'uuid', description: 'Id de un proyecto' })
  @IsOptional()
  @IsUUID()
  project?: string;

  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @Transform(toBoolean)
  @IsBoolean()
  includeRetired?: boolean;
}

/** Los mismos filtros que GET /vulnerabilities, sin paginar. */
export class VulnerabilityExportQueryDto extends FindingListQueryDto {
  @ApiPropertyOptional({ enum: EXPORT_FORMATS, default: 'csv' })
  @IsOptional()
  @IsIn(EXPORT_FORMATS)
  format?: ExportFormat;

  @ApiPropertyOptional({
    enum: VULNERABILITY_EXPORT_GROUPS,
    default: 'cve',
    description:
      '`cve`: una fila por CVE; `asset`: una fila por asset afectado',
  })
  @IsOptional()
  @IsIn(VULNERABILITY_EXPORT_GROUPS)
  groupBy?: VulnerabilityExportGroup;
}
