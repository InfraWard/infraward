import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  USER_ROLES,
  type CreateUserRequest,
  type TemporaryPasswordResponse,
  type UpdateUserRequest,
  type UserRole,
  type UserSummary,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { UserProfileDto } from '../auth/auth.dto.js';

const trim = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim() : value;

export class UserSummaryDto extends UserProfileDto implements UserSummary {
  @ApiProperty()
  active: boolean;

  @ApiProperty({ description: 'Tiene una contraseña temporal pendiente' })
  mustChangePassword: boolean;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  lastLoginAt: string | null;

  @ApiProperty({
    description:
      'Es el admin local de emergencia (LOCAL_LOGIN_EMERGENCY_EMAIL)',
  })
  emergency: boolean;
}

export class CreateUserDto implements CreateUserRequest {
  @ApiProperty({ example: 'ana@example.com' })
  @IsEmail()
  @MaxLength(320)
  email: string;

  @ApiProperty({ example: 'Ana' })
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(120)
  name: string;

  @ApiProperty({ enum: USER_ROLES })
  @IsIn(USER_ROLES)
  role: UserRole;
}

export class UpdateUserDto implements UpdateUserRequest {
  @ApiPropertyOptional()
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(120)
  name?: string;

  @ApiPropertyOptional({ enum: USER_ROLES })
  @IsOptional()
  @IsIn(USER_ROLES)
  role?: UserRole;

  @ApiPropertyOptional({
    example: 'ana@example.com',
    description: 'Solo usuarios locales sin enlazar al proveedor OIDC',
  })
  @IsOptional()
  @Transform(trim)
  @IsEmail()
  @MaxLength(320)
  email?: string;
}

export class TemporaryPasswordResponseDto implements TemporaryPasswordResponse {
  @ApiProperty({ type: UserSummaryDto })
  user: UserSummaryDto;

  @ApiProperty({
    description:
      'Contraseña temporal de un solo uso. Solo aparece en esta respuesta: la API guarda su hash',
  })
  temporaryPassword: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt: string;
}
