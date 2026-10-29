import { PriorityInfoDto } from '../findings/priority.dto.js';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsUUID } from 'class-validator';
import {
  ASSET_TYPES,
  type AssetType,
  type DashboardAttention,
  type DashboardQuery,
  type DashboardSummary,
  SEVERITIES,
  type DashboardVulnerability,
  type Severity,
} from '@infraward/shared-types';
import { AssetSummaryDto } from '../assets/assets.dto.js';
import { JobRunSummaryDto } from '../jobs/jobs.dto.js';

export class DashboardAttentionDto implements DashboardAttention {
  @ApiProperty()
  count: number;

  @ApiProperty({ type: [AssetSummaryDto], description: 'Como mucho 5' })
  assets: AssetSummaryDto[];
}

export class DashboardVulnerabilityDto implements DashboardVulnerability {
  @ApiProperty({ example: 'CVE-2024-6387' })
  vulnerabilityId: string;

  @ApiProperty({ enum: SEVERITIES })
  severity: Severity;

  @ApiProperty({ type: PriorityInfoDto })
  priority: PriorityInfoDto;

  @ApiProperty()
  kev: boolean;

  @ApiProperty({ description: 'Assets afectados (servidores, CT e imágenes)' })
  assets: number;
}

export class DashboardVulnerabilitiesDto {
  @ApiProperty({ description: 'CVE de prioridad urgente' })
  urgent: number;

  @ApiProperty({ description: 'CVE de prioridad alta' })
  high: number;

  @ApiProperty({ description: 'CVE de prioridad media' })
  medium: number;

  @ApiProperty({ description: 'CVE en el catálogo KEV' })
  kev: number;

  @ApiProperty({ description: 'CVE distintos (prioridad ≥ media)' })
  cves: number;

  @ApiProperty({ type: [DashboardVulnerabilityDto] })
  top: DashboardVulnerabilityDto[];
}

export class DashboardAttentionsDto {
  @ApiProperty({ type: DashboardAttentionDto })
  sudoersOutdated: DashboardAttentionDto;

  @ApiProperty({ type: DashboardAttentionDto })
  partialCollection: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description: 'Assets cuya última ejecución falló en las últimas 24 h',
  })
  failedJobs: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description: 'Servidores cuyo machine-id ya es de otro asset',
  })
  duplicates: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Servidores clonados que comparten machine-id con otros (hay que regenerarlo)',
  })
  clones: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Certificados caducados o que caducan antes del umbral mayor de expiryWarningDays',
  })
  certificatesExpiring: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Dominios caducados o que caducan (RDAP) antes del umbral mayor de expiryWarningDays',
  })
  domainsExpiring: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Registros DNS colgantes de prioridad alta (takeover o destino retirado) sin marcar como esperados',
  })
  dnsDangling: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Registros DNS a IPs públicas que no están en el inventario, sin marcar como esperados (informativo)',
  })
  dnsUnknown: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Servidores en modo CA que no confían exactamente en las CA vigentes',
  })
  sshCaOutdated: DashboardAttentionDto;

  @ApiProperty({
    type: DashboardAttentionDto,
    description:
      'Servidores cuyo sshd admite el login de root o por contraseña (sshd -T, sudoers v7)',
  })
  sshdPasswordLogin: DashboardAttentionDto;
}

export class DashboardSummaryDto implements DashboardSummary {
  @ApiProperty({
    type: 'object',
    properties: Object.fromEntries(
      ASSET_TYPES.map((t) => [t, { type: 'integer' }]),
    ),
    required: [...ASSET_TYPES],
    description: 'Assets no retirados por tipo',
  })
  assetsByType: Record<AssetType, number>;

  @ApiProperty()
  pendingEnrollment: number;

  @ApiProperty({
    type: DashboardVulnerabilitiesDto,
    description:
      'Lo prioritario de la vista principal de Vulnerabilidades (sin ruido ni imágenes sin uso)',
  })
  vulnerabilities: DashboardVulnerabilitiesDto;

  @ApiProperty({ type: DashboardAttentionsDto })
  attention: DashboardAttentionsDto;

  @ApiProperty({
    type: Number,
    nullable: true,
    description:
      'Credenciales de la caja fuerte con la rotación vencida (null sin el permiso vault.manage)',
  })
  vaultRotationOverdue: number | null;

  @ApiProperty({
    type: [Number],
    description: 'Umbrales de aviso de caducidad (días, de mayor a menor)',
  })
  expiryWarningDays: number[];

  @ApiProperty({ description: 'Jobs en cola o en curso' })
  runningJobs: number;

  @ApiProperty({ type: [JobRunSummaryDto] })
  recentActivity: JobRunSummaryDto[];
}

export class DashboardQueryDto implements DashboardQuery {
  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Solo lo del proyecto (heredado incluido)',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;
}
