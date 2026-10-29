import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  PASSWORD_MAX_LENGTH,
  USER_ORIGINS,
  USER_ROLES,
  type AuthProviders,
  type ChangeEmailRequest,
  type ChangePasswordRequest,
  type LoginRequest,
  type LogoutResponse,
  type UserOrigin,
  type SessionInfo,
  type UpdateProfileRequest,
  type UserProfile,
  type UserRole,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class LoginDto implements LoginRequest {
  @ApiProperty({ example: 'admin@example.com' })
  @IsEmail()
  @MaxLength(320)
  email: string;

  @ApiProperty({ format: 'password' })
  @IsString()
  @MinLength(1)
  @MaxLength(PASSWORD_MAX_LENGTH)
  password: string;
}

export class UserProfileDto implements UserProfile {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  email: string;

  @ApiProperty()
  name: string;

  @ApiProperty({ enum: USER_ROLES })
  role: UserRole;

  @ApiProperty({ enum: USER_ORIGINS })
  origin: UserOrigin;

  @ApiProperty({
    description: 'Enlazada al proveedor OIDC (el rol lo decide el proveedor)',
  })
  oidcLinked: boolean;

  @ApiProperty({ description: 'Tiene la verificación en dos pasos (TOTP) activa' })
  mfaEnabled: boolean;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;
}

export class SessionInfoDto implements SessionInfo {
  @ApiProperty({ type: UserProfileDto })
  user: UserProfileDto;

  @ApiProperty({
    description:
      'Token CSRF: va en la cabecera X-CSRF-Token de POST/PUT/PATCH/DELETE. La sesión va en la cookie httpOnly',
  })
  csrfToken: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt: string;

  @ApiProperty({
    description: 'Entró con una contraseña temporal: solo puede cambiarla',
  })
  mustChangePassword: boolean;

  @ApiProperty({
    description:
      'Puede cambiar su propio email (POST /auth/email); con OIDC configurado lo cambia un admin',
  })
  canChangeEmail: boolean;

  @ApiProperty({
    description:
      'Sesión intermedia del login: falta el código TOTP o de recuperación (POST /auth/mfa/verify)',
  })
  mfaPending: boolean;

  @ApiProperty({
    description:
      'Admin local sin TOTP: debe configurarlo (POST /auth/mfa/setup y /auth/mfa/enable) antes de seguir',
  })
  mfaSetupRequired: boolean;

  @ApiProperty({
    enum: ['totp', 'oidc'],
    description: 'Cómo confirma su identidad para una acción sensible',
  })
  reauthMethod: 'totp' | 'oidc';

  @ApiProperty({
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'Hasta cuándo vale la última reautenticación',
  })
  reauthenticatedUntil: string | null;
}

export class UpdateProfileDto implements UpdateProfileRequest {
  @ApiProperty()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @MinLength(1)
  @MaxLength(120)
  name: string;
}

export class ChangeEmailDto implements ChangeEmailRequest {
  @ApiProperty({ example: 'ana@example.com' })
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsEmail()
  @MaxLength(320)
  email: string;

  @ApiProperty({ format: 'password' })
  @IsString()
  @MinLength(1)
  @MaxLength(PASSWORD_MAX_LENGTH)
  currentPassword: string;
}

export class ChangePasswordDto implements ChangePasswordRequest {
  @ApiPropertyOptional({
    format: 'password',
    description: 'Obligatoria salvo al cambiar una contraseña temporal',
  })
  @IsOptional()
  @IsString()
  @MaxLength(PASSWORD_MAX_LENGTH)
  currentPassword: string;

  @ApiProperty({ format: 'password', minLength: 12 })
  @IsString()
  @MaxLength(PASSWORD_MAX_LENGTH)
  newPassword: string;
}

class OidcProviderDto {
  @ApiProperty({ example: 'Keycloak' })
  name: string;
}

export class AuthProvidersDto implements AuthProviders {
  @ApiProperty({
    description:
      'Login con contraseña para todos (false: solo el admin de emergencia)',
  })
  local: boolean;

  @ApiProperty({ type: OidcProviderDto, nullable: true })
  oidc: OidcProviderDto | null;
}

export class LogoutResponseDto implements LogoutResponse {
  @ApiProperty({
    type: String,
    nullable: true,
    description:
      'URL para cerrar también la sesión del proveedor OIDC (si la sesión vino de él)',
  })
  providerLogoutUrl: string | null;
}
