import { ApiProperty } from '@nestjs/swagger';
import {
  ASSET_STATUSES,
  CONNECTOR_TOKEN_MAX_LENGTH,
  CONNECTOR_TOKEN_MIN_LENGTH,
  DNS_CHECK_LEVELS,
  DNS_CHECK_REASONS,
  DOMAIN_PROVIDER_KINDS,
  EXPIRY_WARNING_MAX_DAYS,
  EXPIRY_WARNING_MAX_THRESHOLDS,
  type AcceptDnsTargetRequest,
  type AcceptDnsTargetResponse,
  type AssetDomainRecord,
  type AssetDomains,
  type AssetStatus,
  type Connector,
  type ConnectorTestResponse,
  type ConnectorVerification,
  type CreateConnectorRequest,
  type DnsCheckLevel,
  type DnsCheckReason,
  type DnsRecordCheck,
  type DomainProviderKind,
  type ExpiryWarningSettings,
  type ReplaceConnectorTokenRequest,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsIn,
  IsInt,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';
import { AssetSummaryDto } from '../assets/assets.dto.js';

const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;

/** Caracteres de un token de API (Cloudflare: base64url). Nunca se repite en los errores. */
const TOKEN_PATTERN = /^[A-Za-z0-9._~+/=-]+$/;

export class CreateConnectorDto implements CreateConnectorRequest {
  @ApiProperty({ enum: DOMAIN_PROVIDER_KINDS })
  @IsIn(DOMAIN_PROVIDER_KINDS)
  kind: DomainProviderKind;

  @ApiProperty({ maxLength: 100, example: 'Cloudflare · pruebas' })
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name: string;

  @ApiProperty({
    description:
      'Token de API de solo lectura (Cloudflare: permisos Zone:Read y DNS:Read). Se guarda en el proveedor de secretos y no vuelve a salir.',
    writeOnly: true,
    minLength: CONNECTOR_TOKEN_MIN_LENGTH,
    maxLength: CONNECTOR_TOKEN_MAX_LENGTH,
  })
  @Transform(trim)
  @IsString()
  @MinLength(CONNECTOR_TOKEN_MIN_LENGTH)
  @MaxLength(CONNECTOR_TOKEN_MAX_LENGTH)
  @Matches(TOKEN_PATTERN, { message: 'apiToken tiene caracteres no válidos' })
  apiToken: string;
}

export class ReplaceConnectorTokenDto implements ReplaceConnectorTokenRequest {
  @ApiProperty({
    writeOnly: true,
    minLength: CONNECTOR_TOKEN_MIN_LENGTH,
    maxLength: CONNECTOR_TOKEN_MAX_LENGTH,
  })
  @Transform(trim)
  @IsString()
  @MinLength(CONNECTOR_TOKEN_MIN_LENGTH)
  @MaxLength(CONNECTOR_TOKEN_MAX_LENGTH)
  @Matches(TOKEN_PATTERN, { message: 'apiToken tiene caracteres no válidos' })
  apiToken: string;
}

export class ConnectorVerificationDto implements ConnectorVerification {
  @ApiProperty() ok: boolean;
  @ApiProperty({ format: 'date-time' }) checkedAt: string;
  @ApiProperty({ type: String, nullable: true }) error: string | null;
  @ApiProperty({ type: String, nullable: true }) tokenStatus: string | null;
  @ApiProperty({ type: String, nullable: true, format: 'date-time' })
  tokenExpiresAt: string | null;
  @ApiProperty({ type: [String] }) accounts: string[];
  @ApiProperty() zones: number;
  @ApiProperty({ type: [String] }) warnings: string[];
}

class ConnectorSyncDto {
  @ApiProperty({ format: 'date-time' }) at: string;
  @ApiProperty() zones: number;
  @ApiProperty() records: number;
  @ApiProperty() complete: boolean;
  @ApiProperty({ type: [String] }) warnings: string[];
}

export class ConnectorDto implements Connector {
  @ApiProperty({ format: 'uuid', description: 'Id del asset dns_provider' })
  id: string;
  @ApiProperty() name: string;
  @ApiProperty({ enum: DOMAIN_PROVIDER_KINDS }) kind: DomainProviderKind;
  @ApiProperty({ enum: ASSET_STATUSES }) status: AssetStatus;
  @ApiProperty({ type: String, nullable: true }) secretProvider: string | null;
  @ApiProperty() hasToken: boolean;
  @ApiProperty({ type: ConnectorVerificationDto, nullable: true })
  verify: ConnectorVerification | null;
  @ApiProperty({ type: ConnectorSyncDto, nullable: true })
  lastSync: Connector['lastSync'];
  @ApiProperty() domains: number;
  @ApiProperty() records: number;
  @ApiProperty({ format: 'date-time' }) createdAt: string;
}

export class ConnectorTestResponseDto implements ConnectorTestResponse {
  @ApiProperty({
    type: ConnectorVerificationDto,
    nullable: true,
    description: 'null si el worker no respondió a tiempo',
  })
  verify: ConnectorVerification | null;
}

class DnsRecordAcceptanceDto {
  @ApiProperty({ format: 'date-time' }) at: string;
  @ApiProperty({ type: String, nullable: true }) by: string | null;
}

export class DnsRecordCheckDto implements DnsRecordCheck {
  @ApiProperty({ enum: DNS_CHECK_LEVELS, nullable: true })
  level: DnsCheckLevel | null;
  @ApiProperty({ enum: DNS_CHECK_REASONS }) reason: DnsCheckReason;
  @ApiProperty() target: string;
  @ApiProperty() ambiguous: boolean;
  @ApiProperty({ type: String, nullable: true }) takeoverService: string | null;
  @ApiProperty({ format: 'date-time' }) checkedAt: string;
  @ApiProperty({
    description: 'Avisos informativos sin aceptar con el mismo destino (este incluido)',
  })
  sameTarget: number;
  @ApiProperty({ type: DnsRecordAcceptanceDto, nullable: true })
  accepted: DnsRecordCheck['accepted'];
}

class DomainRecordDnsDto {
  @ApiProperty() name: string;
  @ApiProperty() type: AssetDomainRecord['dns']['type'];
  @ApiProperty() content: string;
  @ApiProperty() proxied: boolean;
}

class DomainRecordCertificateDto {
  @ApiProperty({ format: 'uuid' }) id: string;
  @ApiProperty() name: string;
  @ApiProperty({ type: String, nullable: true, format: 'date-time' })
  notAfter: string | null;
}

export class AssetDomainRecordDto implements AssetDomainRecord {
  @ApiProperty({ type: AssetSummaryDto }) record: AssetSummaryDto;
  @ApiProperty({ type: AssetSummaryDto, nullable: true })
  domain: AssetSummaryDto | null;
  @ApiProperty({ type: DomainRecordDnsDto }) dns: DomainRecordDnsDto;
  @ApiProperty({ description: '1 = directo; más = a través de CNAME' })
  hops: number;
  @ApiProperty({ type: [AssetSummaryDto] }) via: AssetSummaryDto[];
  @ApiProperty({ type: DomainRecordCertificateDto, nullable: true })
  certificate: DomainRecordCertificateDto | null;
}

export class AssetDomainsDto implements AssetDomains {
  @ApiProperty({ type: [AssetDomainRecordDto] })
  records: AssetDomainRecordDto[];
}

export class AcceptDnsTargetDto implements AcceptDnsTargetRequest {
  @ApiProperty({ example: '203.0.113.10', description: 'IP o nombre de destino' })
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  target: string;
}

export class AcceptDnsTargetResponseDto implements AcceptDnsTargetResponse {
  @ApiProperty() accepted: number;
}

export class ExpiryWarningSettingsDto implements ExpiryWarningSettings {
  @ApiProperty({
    type: [Number],
    example: [30, 7],
    description: `Días antes de la caducidad en los que se avisa (1–${EXPIRY_WARNING_MAX_DAYS}, hasta ${EXPIRY_WARNING_MAX_THRESHOLDS}, sin repetir)`,
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(EXPIRY_WARNING_MAX_THRESHOLDS)
  @IsInt({ each: true })
  @Min(1, { each: true })
  @Max(EXPIRY_WARNING_MAX_DAYS, { each: true })
  days: number[];
}
