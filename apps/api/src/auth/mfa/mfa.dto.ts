import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  SENSITIVE_ACTIONS,
  type MfaCodeRequest,
  type MfaSetupResponse,
  type MfaStatus,
  type ReauthResponse,
  type RecoveryCodesResponse,
  type SensitiveAction,
} from '@infraward/shared-types';
import { IsIn, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class MfaCodeDto implements MfaCodeRequest {
  @ApiProperty({
    description: 'Código TOTP de 6 cifras o de recuperación (xxxx-xxxx-xxxx-xxxx)',
    example: '123456',
  })
  @IsString()
  @MinLength(6)
  @MaxLength(32)
  code: string;
}

export class ReauthDto extends MfaCodeDto {
  @ApiPropertyOptional({
    enum: Object.keys(SENSITIVE_ACTIONS),
    description: 'Acción que la pidió (solo para la auditoría)',
  })
  @IsOptional()
  @IsIn(Object.keys(SENSITIVE_ACTIONS))
  action?: SensitiveAction;
}

export class MfaSetupResponseDto implements MfaSetupResponse {
  @ApiProperty({ description: 'URI otpauth:// (lo que lleva el QR); se enseña una vez' })
  otpauthUri: string;

  @ApiProperty({ description: 'Secreto en base32 para teclearlo a mano; se enseña una vez' })
  secret: string;

  @ApiProperty({ description: 'QR en PNG como data: URL' })
  qrDataUrl: string;
}

export class RecoveryCodesResponseDto implements RecoveryCodesResponse {
  @ApiProperty({
    type: [String],
    description: 'Códigos de un solo uso; se enseñan una vez (en la BD, solo su sha256)',
  })
  recoveryCodes: string[];
}

export class MfaStatusDto implements MfaStatus {
  @ApiProperty()
  enabled: boolean;

  @ApiProperty()
  recoveryCodesLeft: number;

  @ApiProperty({ description: 'Obligatoria (admin local)' })
  required: boolean;
}

export class ReauthResponseDto implements ReauthResponse {
  @ApiProperty({ format: 'date-time' })
  reauthenticatedUntil: string;
}
