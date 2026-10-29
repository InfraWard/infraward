import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  TERMINAL_CLOSE_REASONS,
  type AssetTerminalStatus,
  type GatewayHeartbeatRequest,
  type GatewayHeartbeatResponse,
  type RedeemTerminalTicketRequest,
  type TerminalRevocation,
  type CreateTerminalSessionRequest,
  type CreateTerminalSessionResponse,
  type RedeemTerminalTicketResponse,
  type TerminalCertificateRequest,
  type TerminalCertificateResponse,
  type TerminalCloseReason,
  type TerminalClosedRequest,
  type TerminalOpenedRequest,
} from '@infraward/shared-types';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
  ValidateIf,
  ValidateNested,
} from 'class-validator';

export class CreateTerminalSessionDto implements CreateTerminalSessionRequest {
  @ApiProperty({ format: 'uuid', description: 'Servidor, CT o contenedor' })
  @IsUUID()
  assetId: string;
}

export class TerminalSessionTicketDto implements CreateTerminalSessionResponse {
  @ApiProperty({ format: 'uuid' })
  sessionId: string;

  @ApiProperty({
    description:
      'Ticket de un solo uso (60 s) para el primer mensaje del WebSocket del gateway; solo se devuelve aquí',
  })
  ticket: string;

  @ApiProperty({
    example: '/gateway/terminal',
    description: 'Ruta del mismo origen que la web (lo normal) o URL `ws://`/`wss://`',
  })
  gatewayUrl: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt: string;
}

// --- Rutas internas del gateway ---

export class AssetTerminalStatusDto implements AssetTerminalStatus {
  @ApiProperty({ description: 'Puede abrir terminal aquí (rol o regla de acceso)' })
  allowed: boolean;

  @ApiProperty({ description: 'El asset admite terminal ahora' })
  available: boolean;

  @ApiProperty({ type: String, nullable: true })
  reason: string | null;

  @ApiProperty({ type: 'object', nullable: true, additionalProperties: true })
  host: { id: string; name: string } | null;

  @ApiProperty({ type: String, nullable: true, example: 'infraward-admin' })
  account: string | null;
}

const GATEWAY_NAME = /^[A-Za-z0-9._-]{1,64}$/;

export class RedeemTicketDto implements RedeemTerminalTicketRequest {
  @ApiProperty()
  @IsString()
  @Matches(/^[A-Za-z0-9_-]{20,128}$/)
  ticket: string;

  @ApiProperty({ example: 'gateway-1' })
  @IsString()
  @Matches(GATEWAY_NAME)
  gateway: string;

  @ApiProperty({ type: String, nullable: true, description: 'sha256 (hex) de la cookie de sesión' })
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @Matches(/^[0-9a-f]{64}$/)
  sessionCookieHash: string | null;
}

class HeartbeatSessionDto {
  @ApiProperty({ format: 'uuid' })
  @IsUUID()
  id: string;

  @ApiProperty({ description: 'Hubo actividad desde el latido anterior' })
  @IsBoolean()
  active: boolean;
}

export class GatewayHeartbeatDto implements GatewayHeartbeatRequest {
  @ApiProperty({ example: 'gateway-1' })
  @IsString()
  @Matches(GATEWAY_NAME)
  gateway: string;

  @ApiProperty({ type: [HeartbeatSessionDto] })
  @IsArray()
  @ArrayMaxSize(2000)
  @ValidateNested({ each: true })
  @Type(() => HeartbeatSessionDto)
  sessions: HeartbeatSessionDto[];
}

class TerminalRevocationDto implements TerminalRevocation {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  message: string;
}

export class GatewayHeartbeatResponseDto implements GatewayHeartbeatResponse {
  @ApiProperty({ type: [TerminalRevocationDto] })
  revoke: TerminalRevocationDto[];
}

export class RedeemedTerminalSessionDto implements RedeemTerminalTicketResponse {
  @ApiProperty({ format: 'uuid' })
  sessionId: string;

  @ApiProperty({ format: 'uuid' })
  userId: string;

  @ApiProperty()
  userEmail: string;

  @ApiProperty({ format: 'uuid' })
  assetId: string;

  @ApiProperty()
  assetName: string;

  @ApiProperty({ example: 'infraward-admin' })
  account: string;
}

export class TerminalCertificateRequestDto implements TerminalCertificateRequest {
  @ApiProperty({ description: 'Clave pública efímera `ssh-ed25519 …` del gateway' })
  @IsString()
  @MaxLength(512)
  @Matches(/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [A-Za-z0-9@._:-]{1,64})?$/)
  publicKey: string;
}

export class TerminalCertificateDto implements TerminalCertificateResponse {
  @ApiProperty({ description: 'Certificado SSH de usuario (`ssh-ed25519-cert-v01@openssh.com …`)' })
  certificate: string;

  @ApiProperty()
  ttlSeconds: number;
}

export class TerminalOpenedDto implements TerminalOpenedRequest {
  @ApiProperty({ example: 'gateway-1' })
  @IsString()
  @Matches(GATEWAY_NAME)
  gateway: string;

  @ApiProperty({ type: String, nullable: true })
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(64)
  clientIp: string | null;
}

export class TerminalClosedDto implements TerminalClosedRequest {
  @ApiProperty({ enum: TERMINAL_CLOSE_REASONS })
  @IsIn(TERMINAL_CLOSE_REASONS)
  reason: TerminalCloseReason;

  @ApiProperty({ type: Number, nullable: true })
  @ValidateIf((_o, v) => v !== null)
  @IsInt()
  @Min(-1)
  @Max(255)
  exitCode: number | null;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(500)
  message?: string;
}
