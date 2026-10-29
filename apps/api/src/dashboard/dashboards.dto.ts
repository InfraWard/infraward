import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_TYPES,
  DASHBOARD_COLUMNS,
  DASHBOARD_MAX_WIDGETS,
  DASHBOARD_SCHEMA,
  WIDGET_TYPES,
  type AssetType,
  type DashboardDocument,
  type DashboardLayout,
  type DashboardWidget,
  type SaveDashboardRequest,
  type WidgetFilters,
  type WidgetType,
} from '@infraward/shared-types';
import { IsInt, IsObject, Min } from 'class-validator';

// Solo para la documentación: el diseño lo valida `validateDashboardLayout` (shared-types).

export class WidgetFiltersDto implements WidgetFilters {
  @ApiPropertyOptional({ format: 'uuid' })
  projectId?: string;

  @ApiPropertyOptional({ type: [String] })
  tags?: string[];

  @ApiPropertyOptional({ type: [String], enum: ASSET_TYPES })
  types?: AssetType[];

  @ApiPropertyOptional({
    description: 'Se guarda, pero aún no tiene efecto (no hay sitios)',
  })
  site?: string;
}

export class DashboardWidgetDto implements DashboardWidget {
  @ApiProperty({ pattern: '^[A-Za-z0-9_-]{1,40}$' })
  id: string;

  @ApiProperty({ enum: WIDGET_TYPES })
  type: WidgetType;

  @ApiProperty({ minimum: 0, maximum: DASHBOARD_COLUMNS - 1 })
  x: number;

  @ApiProperty({ minimum: 0 })
  y: number;

  @ApiProperty({ minimum: 1, maximum: DASHBOARD_COLUMNS })
  w: number;

  @ApiProperty({ minimum: 1 })
  h: number;

  @ApiPropertyOptional({ maxLength: 80 })
  title?: string;

  @ApiProperty({ type: WidgetFiltersDto })
  filters: WidgetFiltersDto;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: 'Opciones del tipo (catálogo DASHBOARD_WIDGETS)',
  })
  options: Record<string, unknown>;
}

export class DashboardLayoutDto implements DashboardLayout {
  @ApiProperty({ enum: [DASHBOARD_SCHEMA] })
  schema: typeof DASHBOARD_SCHEMA;

  @ApiProperty({ type: [DashboardWidgetDto], maxItems: DASHBOARD_MAX_WIDGETS })
  widgets: DashboardWidgetDto[];
}

export class DashboardDocumentDto implements DashboardDocument {
  @ApiProperty({ type: DashboardLayoutDto })
  layout: DashboardLayoutDto;

  @ApiProperty({
    description: 'No hay panel guardado: es el por defecto o la plantilla',
  })
  isDefault: boolean;

  @ApiProperty({ description: 'Versión para guardar (0 si es el por defecto)' })
  version: number;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  updatedAt: string | null;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Quién lo guardó por última vez',
  })
  updatedBy: string | null;
}

export class SaveDashboardDto implements SaveDashboardRequest {
  @ApiProperty({ type: DashboardLayoutDto })
  @IsObject()
  layout: DashboardLayout;

  @ApiProperty({
    minimum: 0,
    description:
      'La versión que se editó (0 si era el por defecto); 409 si alguien guardó antes',
  })
  @IsInt()
  @Min(0)
  version: number;
}
