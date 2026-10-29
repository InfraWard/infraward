import { ApiProperty } from '@nestjs/swagger';
import {
  SERVICE_CUT_REASONS,
  SERVICE_PATH_STATUSES,
  SERVICE_RESOLVER_KINDS,
  type DomainServicePaths,
  type HopConfidence,
  type NatForward,
  type NatForwardInput,
  type ServedDomain,
  type ServedDomains,
  type ServiceCutReason,
  type ServiceHopView,
  type ServicePathStatus,
  type ServicePathView,
  type ServicePinRequest,
  type ServiceResolverKind,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  IsIn,
  IsInt,
  IsIP,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { AssetSummaryDto } from '../assets/assets.dto.js';

const CONFIDENCES = ['confirmed', 'deduced'] as const;
const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;

export class ServiceHopDto implements ServiceHopView {
  @ApiProperty({ format: 'uuid', nullable: true }) assetId: string | null;
  @ApiProperty({ type: AssetSummaryDto, nullable: true })
  asset: AssetSummaryDto | null;
  @ApiProperty({ example: 'npm:443' }) label: string;
  @ApiProperty({ nullable: true }) port: number | null;
  @ApiProperty({ enum: SERVICE_RESOLVER_KINDS }) resolver: ServiceResolverKind;
  @ApiProperty({ example: 'npm: server_name app.example.com → 172.18.0.5:3000' })
  source: string;
  @ApiProperty({ enum: CONFIDENCES }) confidence: HopConfidence;
}

export class ServicePinDto {
  @ApiProperty({ type: AssetSummaryDto }) asset: AssetSummaryDto;
  @ApiProperty({ nullable: true }) by: string | null;
  @ApiProperty({ format: 'date-time' }) at: string;
}

export class ServicePathDto implements ServicePathView {
  @ApiProperty({ format: 'uuid' }) recordId: string;
  @ApiProperty({ example: 'app.example.com' }) record: string;
  @ApiProperty({ enum: SERVICE_PATH_STATUSES }) status: ServicePathStatus;
  @ApiProperty({ enum: CONFIDENCES, nullable: true })
  confidence: HopConfidence | null;
  @ApiProperty({ enum: SERVICE_CUT_REASONS, nullable: true })
  cutReason: ServiceCutReason | null;
  @ApiProperty({ type: AssetSummaryDto, nullable: true })
  final: AssetSummaryDto | null;
  @ApiProperty({ type: [ServiceHopDto] }) hops: ServiceHopDto[];
  @ApiProperty({ type: ServicePinDto, nullable: true })
  pinned: ServicePinDto | null;
  @ApiProperty({ format: 'date-time', nullable: true })
  computedAt: string | null;
}

export class DomainServicePathsDto implements DomainServicePaths {
  @ApiProperty({ type: [ServicePathDto] }) paths: ServicePathDto[];
}

export class ServedDomainDto implements ServedDomain {
  @ApiProperty({ type: AssetSummaryDto }) record: AssetSummaryDto;
  @ApiProperty({ enum: ['final', 'via'] }) role: 'final' | 'via';
  @ApiProperty({ enum: SERVICE_PATH_STATUSES }) status: ServicePathStatus;
  @ApiProperty({ enum: CONFIDENCES, nullable: true })
  confidence: HopConfidence | null;
  @ApiProperty({ type: AssetSummaryDto, nullable: true })
  final: AssetSummaryDto | null;
}

export class ServedDomainsDto implements ServedDomains {
  @ApiProperty({ type: [ServedDomainDto] }) records: ServedDomainDto[];
}

export class ServicePinRequestDto implements ServicePinRequest {
  @ApiProperty({ format: 'uuid', description: 'Servidor, VM, CT, contenedor o base de datos' })
  @IsUUID()
  targetAssetId: string;
}

export class NatForwardDto implements NatForward {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty({ example: '203.0.113.7' }) publicIp: string;
  @ApiProperty({ example: 443 }) publicPort: number;
  @ApiProperty({ enum: ['tcp', 'udp'] }) proto: 'tcp' | 'udp';
  @ApiProperty({ type: AssetSummaryDto }) target: AssetSummaryDto;
  @ApiProperty({ example: 443 }) targetPort: number;
  @ApiProperty({ nullable: true }) description: string | null;
  @ApiProperty({ format: 'date-time' }) createdAt: string;
  @ApiProperty({ format: 'date-time' }) updatedAt: string;
}

export class NatForwardInputDto implements NatForwardInput {
  @ApiProperty({ example: '203.0.113.7', description: 'IP pública (v4 o v6)' })
  @Transform(trim)
  @IsIP()
  publicIp: string;

  @ApiProperty({ example: 443 })
  @IsInt()
  @Min(1)
  @Max(65535)
  publicPort: number;

  @ApiProperty({ enum: ['tcp', 'udp'], required: false, default: 'tcp' })
  @IsOptional()
  @IsIn(['tcp', 'udp'])
  proto?: 'tcp' | 'udp';

  @ApiProperty({ format: 'uuid', description: 'Servidor, VM, CT o contenedor que lo recibe' })
  @IsUUID()
  targetAssetId: string;

  @ApiProperty({ example: 443 })
  @IsInt()
  @Min(1)
  @Max(65535)
  targetPort: number;

  @ApiProperty({ required: false, nullable: true, maxLength: 255 })
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MaxLength(255)
  description?: string | null;
}
