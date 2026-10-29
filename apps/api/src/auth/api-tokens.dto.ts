import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  API_TOKEN_NAME_MAX,
  API_TOKEN_SCOPES,
  type ApiTokenScope,
  type ApiTokenSummary,
  type CreateApiTokenRequest,
  type CreatedApiTokenResponse,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  IsIn,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  MinLength,
} from 'class-validator';

const trim = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim() : value;

class ApiTokenOwnerDto {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  email: string;

  @ApiProperty()
  name: string;
}

export class ApiTokenSummaryDto implements ApiTokenSummary {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty({
    description: 'Primeros caracteres del token, para reconocerlo',
    example: 'iwt_ab12cd34',
  })
  prefix: string;

  @ApiProperty({
    enum: API_TOKEN_SCOPES,
    description: '`read`: solo GET/HEAD; `role`: lo que permita el rol',
  })
  scope: ApiTokenScope;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt: string;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  lastUsedAt: string | null;

  @ApiProperty({ type: String, nullable: true })
  lastUsedIp: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  revokedAt: string | null;

  @ApiProperty({ description: 'Ni revocado ni caducado' })
  active: boolean;

  @ApiPropertyOptional({
    type: ApiTokenOwnerDto,
    description: 'Dueño (solo en GET /api-tokens)',
  })
  user?: ApiTokenOwnerDto;
}

export class CreateApiTokenDto implements CreateApiTokenRequest {
  @ApiProperty({ example: 'Script de copias' })
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(API_TOKEN_NAME_MAX)
  name: string;

  @ApiProperty({ enum: API_TOKEN_SCOPES })
  @IsIn(API_TOKEN_SCOPES)
  scope: ApiTokenScope;

  @ApiProperty({
    format: 'date-time',
    description: 'Caducidad obligatoria, como mucho a 365 días',
  })
  @IsISO8601({ strict: true })
  expiresAt: string;
}

export class CreatedApiTokenResponseDto implements CreatedApiTokenResponse {
  @ApiProperty({ type: ApiTokenSummaryDto })
  token: ApiTokenSummaryDto;

  @ApiProperty({
    description:
      'El token. Solo aparece en esta respuesta: la API guarda su sha256',
  })
  secret: string;
}

export class ApiTokenListQueryDto {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  userId?: string;
}
