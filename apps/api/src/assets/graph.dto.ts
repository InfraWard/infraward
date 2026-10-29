import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_RELATION_TYPES,
  ASSET_RUNTIME_STATES,
  ASSET_TYPES,
  GRAPH_MAX_DEPTH,
  SEVERITIES,
  type AssetGraph,
  type AssetGraphQuery,
  type AssetRelationType,
  type AssetRuntimeState,
  type AssetType,
  type GraphEdge,
  type GraphNode,
  type Severity,
  type TopologyQuery,
} from '@infraward/shared-types';
import { Transform, Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsBoolean,
  IsInt,
  IsOptional,
  IsUUID,
  Max,
  Min,
} from 'class-validator';
import { AssetSummaryDto, toBoolean } from './assets.dto.js';

/** `?expand=a&expand=b` o `?expand=a,b`. */
const toList = ({ value }: { value: unknown }): unknown =>
  value === undefined
    ? undefined
    : (Array.isArray(value) ? value : [value])
        .flatMap((v) => String(v).split(','))
        .map((v) => v.trim())
        .filter(Boolean);

export class AssetGraphQueryDto implements AssetGraphQuery {
  @ApiPropertyOptional({
    type: 'integer',
    minimum: 1,
    maximum: GRAPH_MAX_DEPTH,
    default: 1,
    description: 'Saltos desde el asset',
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(GRAPH_MAX_DEPTH)
  depth?: number;

  @ApiPropertyOptional({ default: false, description: 'Incluir los retirados' })
  @IsOptional()
  @Transform(toBoolean)
  @IsBoolean()
  includeRetired?: boolean;
}

export class TopologyQueryDto implements TopologyQuery {
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Solo los del proyecto (heredados incluidos)',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Solo el asset y lo que contiene',
  })
  @IsOptional()
  @IsUUID()
  rootId?: string;

  @ApiPropertyOptional({
    type: [String],
    format: 'uuid',
    description: 'Assets cuyo contenido se carga (`?expand=a,b`)',
  })
  @IsOptional()
  @Transform(toList)
  @ArrayMaxSize(200)
  @IsUUID('all', { each: true })
  expand?: string[];

  @ApiPropertyOptional({ default: false, description: 'Incluir los retirados' })
  @IsOptional()
  @Transform(toBoolean)
  @IsBoolean()
  includeRetired?: boolean;
}

export class GraphNodeDto extends AssetSummaryDto implements GraphNode {
  @ApiProperty({ type: String, nullable: true })
  address: string | null;

  @ApiProperty({ enum: ASSET_RUNTIME_STATES, nullable: true })
  runtimeState: AssetRuntimeState | null;

  @ApiProperty({
    type: 'integer',
    description: 'Findings CRITICAL abiertos (un contenedor, los de su imagen)',
  })
  critical: number;

  @ApiProperty({ enum: SEVERITIES, nullable: true })
  maxSeverity: Severity | null;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description:
      'Grupo: padre `contains` presente en el grafo (o el host de una imagen de un solo host)',
  })
  parentId: string | null;

  @ApiProperty({
    type: 'integer',
    description: 'Saltos desde el centro (0 en la topología)',
  })
  depth: number;

  @ApiProperty({
    description: 'Vecinos o contenido sin cargar, por tipo',
    type: 'object',
    properties: Object.fromEntries(
      ASSET_TYPES.map((t) => [t, { type: 'integer' }]),
    ),
  })
  hidden: Partial<Record<AssetType, number>>;

  @ApiProperty({
    type: 'integer',
    description: 'Topología: CRITICAL abiertos del contenido sin cargar',
  })
  hiddenCritical: number;
}

export class GraphEdgeDto implements GraphEdge {
  @ApiProperty({
    description:
      'Id de la relación o `<origen>:<destino>:<tipo>` si es agregada',
  })
  id: string;

  @ApiProperty({ format: 'uuid', description: 'Origen (el `parent`)' })
  source: string;

  @ApiProperty({ format: 'uuid' })
  target: string;

  @ApiProperty({ enum: ASSET_RELATION_TYPES })
  type: AssetRelationType;

  @ApiProperty({ type: 'integer', description: 'Relaciones reales que agrupa' })
  count: number;
}

export class AssetGraphDto implements AssetGraph {
  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  centerId: string | null;

  @ApiProperty({ type: [GraphNodeDto] })
  nodes: GraphNodeDto[];

  @ApiProperty({ type: [GraphEdgeDto] })
  edges: GraphEdgeDto[];

  @ApiProperty({ description: 'Se llegó al tope de nodos' })
  truncated: boolean;

  @ApiProperty({
    type: [String],
    required: false,
    description:
      'Mapa de un registro DNS: assets de su camino hasta el que lo sirve, en orden (desde el registro)',
  })
  servicePath?: string[];
}
