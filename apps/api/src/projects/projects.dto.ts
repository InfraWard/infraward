import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_TYPES,
  COLOR_PATTERN,
  PROJECT_DESCRIPTION_MAX,
  PROJECT_MEMBERSHIP_MODES,
  PROJECT_NAME_MAX,
  SEVERITIES,
  type AssetProjects,
  type AssetType,
  type CreateProjectRequest,
  type Project,
  type ProjectDetail,
  type ProjectMember,
  type ProjectMembershipMode,
  type ProjectMembershipSource,
  type ProjectStats,
  type ProjectWithStats,
  type SetProjectMemberRequest,
  type SetTagStyleRequest,
  type Severity,
  type TagInfo,
  type UpdateProjectRequest,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  IsIn,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';
import { AssetSummaryDto } from '../assets/assets.dto.js';

const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;

export class CreateProjectDto implements CreateProjectRequest {
  @ApiProperty({ maxLength: PROJECT_NAME_MAX, example: 'Homelab' })
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(PROJECT_NAME_MAX)
  name: string;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    maxLength: PROJECT_DESCRIPTION_MAX,
  })
  @IsOptional()
  @IsString()
  @MaxLength(PROJECT_DESCRIPTION_MAX)
  description?: string | null;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    example: '#0d9488',
    description: '`#rrggbb`; null = sin color',
  })
  @IsOptional()
  @Matches(COLOR_PATTERN)
  color?: string | null;
}

export class UpdateProjectDto implements UpdateProjectRequest {
  @ApiPropertyOptional({ maxLength: PROJECT_NAME_MAX })
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(PROJECT_NAME_MAX)
  name?: string;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    maxLength: PROJECT_DESCRIPTION_MAX,
  })
  @IsOptional()
  @IsString()
  @MaxLength(PROJECT_DESCRIPTION_MAX)
  description?: string | null;

  @ApiPropertyOptional({ type: String, nullable: true, example: '#0d9488' })
  @IsOptional()
  @Matches(COLOR_PATTERN)
  color?: string | null;
}

export class SetProjectMemberDto implements SetProjectMemberRequest {
  @ApiProperty({
    enum: PROJECT_MEMBERSHIP_MODES,
    description:
      'include: entra el asset y lo que contiene; exclude: excepción, sale aunque lo herede',
  })
  @IsIn(PROJECT_MEMBERSHIP_MODES)
  mode: ProjectMembershipMode;
}

export class SetTagStyleDto implements SetTagStyleRequest {
  @ApiProperty({
    type: String,
    nullable: true,
    example: '#2563eb',
    description: '`#rrggbb`; null = sin color',
  })
  @ValidateIf((_o, v) => v !== null)
  @Matches(COLOR_PATTERN)
  color: string | null;
}

export class ProjectStatsDto implements ProjectStats {
  @ApiProperty({
    type: 'object',
    properties: Object.fromEntries(
      ASSET_TYPES.map((t) => [t, { type: 'integer' }]),
    ),
    description: 'Assets no retirados por tipo (heredados incluidos)',
  })
  assetsByType: Partial<Record<AssetType, number>>;

  @ApiProperty()
  assets: number;

  @ApiProperty({
    type: 'object',
    properties: Object.fromEntries(
      SEVERITIES.map((s) => [s, { type: 'integer' }]),
    ),
    required: [...SEVERITIES],
  })
  openFindings: Record<Severity, number>;

  @ApiProperty({
    type: 'object',
    properties: { CRITICAL: { type: 'integer' }, HIGH: { type: 'integer' } },
    required: ['CRITICAL', 'HIGH'],
  })
  fixableFindings: Record<'CRITICAL' | 'HIGH', number>;

  @ApiProperty({ description: 'CVE distintos con algún finding abierto' })
  openVulnerabilities: number;
}

export class ProjectDto implements Project {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty({ type: String, nullable: true })
  description: string | null;

  @ApiProperty({ type: String, nullable: true, example: '#0d9488' })
  color: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ format: 'date-time' })
  updatedAt: string;
}

export class ProjectWithStatsDto extends ProjectDto implements ProjectWithStats {
  @ApiProperty({ type: ProjectStatsDto })
  stats: ProjectStatsDto;
}

export class ProjectMemberDto implements ProjectMember {
  @ApiProperty({ type: AssetSummaryDto })
  asset: AssetSummaryDto;

  @ApiProperty({ enum: PROJECT_MEMBERSHIP_MODES })
  mode: ProjectMembershipMode;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;
}

export class ProjectDetailDto
  extends ProjectWithStatsDto
  implements ProjectDetail
{
  @ApiProperty({
    type: [ProjectMemberDto],
    description: 'Filas directas (incluidos y excepciones)',
  })
  members: ProjectMemberDto[];
}

export class ProjectMembershipSourceDto {
  @ApiProperty({ enum: ['direct', 'inherited', 'holders'] })
  kind: ProjectMembershipSource['kind'];

  @ApiPropertyOptional({
    type: AssetSummaryDto,
    description: 'inherited: antepasado con la fila',
  })
  from?: AssetSummaryDto;
}

export class AssetProjectDto extends ProjectDto {
  @ApiProperty({ type: ProjectMembershipSourceDto })
  source: ProjectMembershipSource;
}

export class AssetProjectsDto implements AssetProjects {
  @ApiProperty({ type: [AssetProjectDto] })
  projects: AssetProjectDto[];

  @ApiProperty({
    type: [ProjectDto],
    description: 'Excepciones propias del asset',
  })
  excluded: ProjectDto[];
}

export class TagInfoDto implements TagInfo {
  @ApiProperty()
  tag: string;

  @ApiProperty({ description: 'Assets no retirados con el tag' })
  assets: number;

  @ApiProperty({ type: String, nullable: true })
  color: string | null;
}
