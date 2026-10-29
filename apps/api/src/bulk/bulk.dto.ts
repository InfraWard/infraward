import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  BULK_ASSETS_MAX,
  BULK_PROJECT_MODES,
  BULK_VULNERABILITIES_MAX,
  VULNERABILITY_ID_PATTERN,
  type BulkAssetIds,
  type BulkAssetRef,
  type BulkAssetTarget,
  type BulkOperationResult,
  type BulkPolicyRequest,
  type BulkPreviewResponse,
  type BulkProjectMode,
  type BulkProjectRequest,
  type BulkSkipped,
  type BulkTagsRequest,
} from '@infraward/shared-types';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { LABEL, LABEL_MAX, LABELS_MAX } from '../assets/labels.js';
import { InventoryPolicyFieldsDto } from '../inventory/inventory.dto.js';

export class BulkAssetTargetDto implements BulkAssetTarget {
  @ApiPropertyOptional({
    type: [String],
    format: 'uuid',
    maxItems: BULK_ASSETS_MAX,
    description: 'Los assets (no se combina con vulnerabilityIds)',
  })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(BULK_ASSETS_MAX)
  @IsUUID('all', { each: true })
  assetIds?: string[];

  @ApiPropertyOptional({
    type: [String],
    maxItems: BULK_VULNERABILITIES_MAX,
    description:
      'Los assets con findings abiertos de estos CVE (servidores, CT e imágenes)',
  })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(BULK_VULNERABILITIES_MAX)
  @IsString({ each: true })
  @Matches(VULNERABILITY_ID_PATTERN, { each: true })
  vulnerabilityIds?: string[];

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Con vulnerabilityIds: solo los afectados de este proyecto',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;
}

/**
 * Solo por id: etiquetar, mover a un proyecto, fijar la política y dar de baja cambian el propio
 * asset. Un CVE no tiene tags, proyecto ni política (hereda el contexto de sus afectados), así que
 * estas acciones no aceptan `vulnerabilityIds` (400 por `forbidNonWhitelisted`).
 */
export class BulkAssetIdsDto implements BulkAssetIds {
  @ApiProperty({
    type: [String],
    format: 'uuid',
    maxItems: BULK_ASSETS_MAX,
    description: 'Los assets',
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(BULK_ASSETS_MAX)
  @IsUUID('all', { each: true })
  assetIds: string[];
}

export class BulkTagsDto extends BulkAssetIdsDto implements BulkTagsRequest {
  @ApiProperty({
    type: [String],
    maxItems: LABELS_MAX,
    description: 'Tags que se añaden',
  })
  @IsArray()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  add: string[];

  @ApiProperty({
    type: [String],
    maxItems: LABELS_MAX,
    description: 'Tags que se quitan',
  })
  @IsArray()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  remove: string[];
}

export class BulkProjectDto
  extends BulkAssetIdsDto
  implements BulkProjectRequest
{
  @ApiProperty({ format: 'uuid', description: 'Proyecto de destino' })
  @IsUUID()
  project: string;

  @ApiProperty({
    enum: BULK_PROJECT_MODES,
    description:
      '`include`, `exclude` (excepción) o `inherit` (quita la fila propia)',
  })
  @IsIn(BULK_PROJECT_MODES)
  mode: BulkProjectMode;
}

export class BulkPolicyDto
  extends BulkAssetIdsDto
  implements BulkPolicyRequest
{
  @ApiPropertyOptional({
    type: InventoryPolicyFieldsDto,
    description:
      'Campos que se fijan en la regla propia de cada asset (null = heredar; los que no vienen, no cambian)',
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => InventoryPolicyFieldsDto)
  fields?: InventoryPolicyFieldsDto;

  @ApiPropertyOptional({ description: 'Quita la regla propia de cada asset' })
  @IsOptional()
  @IsBoolean()
  clear?: boolean;
}

class BulkAssetRefDto implements BulkAssetRef {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  type: string;
}

class BulkSkippedDto extends BulkAssetRefDto implements BulkSkipped {
  @ApiProperty()
  reason: string;
}

export class BulkOperationResultDto implements BulkOperationResult {
  @ApiProperty({ format: 'uuid', description: 'Fila de la Actividad' })
  operationId: string;

  @ApiProperty()
  action: BulkOperationResult['action'];

  @ApiProperty({ type: [BulkAssetRefDto] })
  applied: BulkAssetRefDto[];

  @ApiProperty({ type: [BulkSkippedDto] })
  skipped: BulkSkippedDto[];

  @ApiProperty({ type: [String] })
  jobs: string[];

  @ApiPropertyOptional({ type: 'array', items: { type: 'object' } })
  revocations?: BulkOperationResult['revocations'];
}

class BulkRetirePreviewDto {
  @ApiProperty()
  total: number;

  @ApiProperty({ type: [BulkAssetRefDto] })
  descendants: BulkAssetRefDto[];
}

export class BulkPreviewResponseDto implements BulkPreviewResponse {
  @ApiProperty({ type: [BulkAssetRefDto] })
  assets: BulkAssetRefDto[];

  @ApiProperty({ type: BulkRetirePreviewDto })
  retire: BulkRetirePreviewDto;
}
