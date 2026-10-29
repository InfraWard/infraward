import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  SECRET_ERROR_CODES,
  SECRET_PROVIDER_CAPABILITIES,
  type CheckSecretRequest,
  type CheckSecretResponse,
  type SecretErrorCode,
  type SecretProviderCapability,
  type SecretProviderInfo,
} from '@infraward/shared-types';
import { IsString, MaxLength } from 'class-validator';

export class CheckSecretDto implements CheckSecretRequest {
  @ApiProperty({
    maxLength: 1024,
    example: 'secret://local/assets/3f0c…/ssh#private_key',
  })
  @IsString()
  @MaxLength(1024)
  ref: string;
}

export class CheckSecretResponseDto implements CheckSecretResponse {
  @ApiProperty()
  ref: string;

  @ApiProperty({ example: 'local' })
  provider: string;

  @ApiProperty()
  resolves: boolean;

  @ApiPropertyOptional({ enum: SECRET_ERROR_CODES })
  error?: SecretErrorCode;
}

export class SecretProviderInfoDto implements SecretProviderInfo {
  @ApiProperty({ example: 'local' })
  id: string;

  @ApiProperty()
  healthy: boolean;

  @ApiProperty({ enum: SECRET_PROVIDER_CAPABILITIES, isArray: true })
  capabilities: SecretProviderCapability[];
}
