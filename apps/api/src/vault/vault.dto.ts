import { applyDecorators } from '@nestjs/common';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  VAULT_ENTRY_KINDS,
  VAULT_NAME_MAX,
  VAULT_NOTES_MAX,
  VAULT_REASON_MAX,
  VAULT_RETENTION_DAYS_MAX,
  VAULT_RETENTION_DAYS_MIN,
  VAULT_REVEAL_PURPOSES,
  VAULT_ROTATION_DAYS_MAX,
  VAULT_ROTATION_DAYS_MIN,
  VAULT_ROTATION_STATES,
  VAULT_SECRET_MAX,
  VAULT_URL_MAX,
  VAULT_USERNAME_MAX,
  VAULT_VERSION_ORIGINS,
  type CreateVaultEntryRequest,
  type ReplaceVaultSecretRequest,
  type RevealVaultSecretRequest,
  type RevealVaultSecretResponse,
  type UpdateVaultEntryRequest,
  type VaultEntry,
  type VaultEntryKind,
  type VaultEntryList,
  type VaultRevealPurpose,
  type VaultRotationState,
  type VaultSettings,
  type VaultStatus,
  type VaultVersion,
  type VaultVersionOrigin,
} from '@infraward/shared-types';
import { Transform } from 'class-transformer';
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
  MinLength,
  ValidateIf,
} from 'class-validator';

const trim = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim() : value;
/** Vacío = null (quitar el dato). */
const trimOrNull = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim() || null : value;

// Los mensajes de validación del secreto nunca llevan su valor (class-validator no lo incluye
// salvo con `$value`, que aquí no se usa).
const IsVaultSecret = () =>
  applyDecorators(
    IsString({ message: 'el secreto debe ser texto' }),
    MinLength(1, { message: 'el secreto no puede estar vacío' }),
    MaxLength(VAULT_SECRET_MAX, {
      message: `el secreto admite como mucho ${VAULT_SECRET_MAX} caracteres`,
    }),
  );

class VaultAssetRefDto {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  type: string;

  @ApiProperty({ type: [String], description: 'Roles detectados (para el comando de rotación)' })
  roles: string[];
}

export class VaultEntryDto implements VaultEntry {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: VAULT_ENTRY_KINDS })
  kind: VaultEntryKind;

  @ApiProperty()
  name: string;

  @ApiProperty({ type: String, nullable: true })
  username: string | null;

  @ApiProperty({ type: String, nullable: true })
  url: string | null;

  @ApiProperty({ type: String, nullable: true })
  notes: string | null;

  @ApiProperty({ type: VaultAssetRefDto, nullable: true })
  asset: VaultAssetRefDto | null;

  @ApiProperty({ description: 'Tiene secreto guardado (nunca se devuelve aquí)' })
  hasSecret: boolean;

  @ApiProperty({ type: Number, nullable: true })
  currentVersion: number | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  lastRotatedAt: string | null;

  @ApiProperty({ type: Number, nullable: true, description: 'Plazo propio (días) o null' })
  rotationDays: number | null;

  @ApiProperty({ description: 'Plazo que se aplica (días)' })
  effectiveRotationDays: number;

  @ApiProperty({ enum: VAULT_ROTATION_STATES })
  rotationState: VaultRotationState;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  rotationDueAt: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ type: String, nullable: true })
  createdBy: string | null;

  @ApiProperty({ format: 'date-time' })
  updatedAt: string;

  @ApiProperty({ type: String, nullable: true })
  updatedBy: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  deletedAt: string | null;

  @ApiProperty({ type: String, nullable: true })
  deletedBy: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  purgeAt: string | null;
}

export class VaultEntryListDto implements VaultEntryList {
  @ApiProperty({ type: [VaultEntryDto] })
  items: VaultEntryDto[];

  @ApiProperty({ description: 'Entradas vigentes con la rotación vencida' })
  overdue: number;
}

export class VaultEntryListQueryDto {
  @ApiPropertyOptional({ format: 'uuid', description: 'Solo las de este asset' })
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({ description: 'Papelera: las borradas (recuperables)' })
  @IsOptional()
  @Transform(({ value }) => value === true || value === 'true' || value === '1')
  @IsBoolean()
  deleted?: boolean;

  @ApiPropertyOptional({ description: 'Texto en nombre, usuario, URL o asset' })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  q?: string;
}

export class CreateVaultEntryDto implements CreateVaultEntryRequest {
  @ApiProperty({ enum: VAULT_ENTRY_KINDS })
  @IsIn(VAULT_ENTRY_KINDS)
  kind: VaultEntryKind;

  @ApiProperty({ example: 'root (consola)' })
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(VAULT_NAME_MAX)
  name: string;

  @ApiPropertyOptional({ type: String, nullable: true, example: 'root' })
  @IsOptional()
  @Transform(trimOrNull)
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(VAULT_USERNAME_MAX)
  username?: string | null;

  @ApiPropertyOptional({ type: String, nullable: true, example: 'https://pve1:8006' })
  @IsOptional()
  @Transform(trimOrNull)
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(VAULT_URL_MAX)
  url?: string | null;

  @ApiPropertyOptional({ type: String, nullable: true })
  @IsOptional()
  @Transform(trimOrNull)
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(VAULT_NOTES_MAX)
  notes?: string | null;

  @ApiPropertyOptional({ type: String, format: 'uuid', nullable: true })
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @IsUUID()
  assetId?: string | null;

  @ApiPropertyOptional({ type: Number, nullable: true })
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @IsInt()
  @Min(VAULT_ROTATION_DAYS_MIN)
  @Max(VAULT_ROTATION_DAYS_MAX)
  rotationDays?: number | null;

  @ApiPropertyOptional({
    description: 'El secreto (solo de escritura: ninguna respuesta lo devuelve)',
    writeOnly: true,
  })
  @IsOptional()
  @IsVaultSecret()
  secret?: string;

  @ApiPropertyOptional({ type: String, format: 'date-time', nullable: true })
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @IsISO8601({ strict: true })
  lastRotatedAt?: string | null;
}

export class UpdateVaultEntryDto implements UpdateVaultEntryRequest {
  @ApiPropertyOptional({ enum: VAULT_ENTRY_KINDS })
  @IsOptional()
  @IsIn(VAULT_ENTRY_KINDS)
  kind?: VaultEntryKind;

  @ApiPropertyOptional()
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MinLength(1)
  @MaxLength(VAULT_NAME_MAX)
  name?: string;

  @ApiPropertyOptional({ type: String, nullable: true })
  @IsOptional()
  @Transform(trimOrNull)
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(VAULT_USERNAME_MAX)
  username?: string | null;

  @ApiPropertyOptional({ type: String, nullable: true })
  @IsOptional()
  @Transform(trimOrNull)
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(VAULT_URL_MAX)
  url?: string | null;

  @ApiPropertyOptional({ type: String, nullable: true })
  @IsOptional()
  @Transform(trimOrNull)
  @ValidateIf((_o, v) => v !== null)
  @IsString()
  @MaxLength(VAULT_NOTES_MAX)
  notes?: string | null;

  @ApiPropertyOptional({ type: String, format: 'uuid', nullable: true })
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @IsUUID()
  assetId?: string | null;

  @ApiPropertyOptional({ type: Number, nullable: true })
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @IsInt()
  @Min(VAULT_ROTATION_DAYS_MIN)
  @Max(VAULT_ROTATION_DAYS_MAX)
  rotationDays?: number | null;

  @ApiPropertyOptional({ type: String, format: 'date-time', nullable: true })
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @IsISO8601({ strict: true })
  lastRotatedAt?: string | null;
}

export class ReplaceVaultSecretDto implements ReplaceVaultSecretRequest {
  @ApiProperty({ writeOnly: true, description: 'El secreto nuevo (una versión más)' })
  @IsVaultSecret()
  secret: string;

  @ApiProperty({
    description: 'Ya aplicada en el servidor: actualiza la fecha de la última rotación',
  })
  @IsBoolean()
  rotated: boolean;
}

export class RevealVaultSecretDto implements RevealVaultSecretRequest {
  @ApiPropertyOptional({ description: 'Motivo (queda en la auditoría)' })
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MaxLength(VAULT_REASON_MAX)
  reason?: string;

  @ApiProperty({ enum: VAULT_REVEAL_PURPOSES })
  @IsIn(VAULT_REVEAL_PURPOSES)
  purpose: VaultRevealPurpose;
}

export class RevealVaultSecretResponseDto implements RevealVaultSecretResponse {
  @ApiProperty({ description: 'El valor: no se guarda, no se loguea y caduca en la web' })
  value: string;

  @ApiProperty()
  version: number;

  @ApiProperty({ description: 'Segundos que la web lo enseña o lo deja en el portapapeles' })
  expiresInSeconds: number;
}

export class VaultVersionDto implements VaultVersion {
  @ApiProperty()
  version: number;

  @ApiProperty({ enum: VAULT_VERSION_ORIGINS })
  origin: VaultVersionOrigin;

  @ApiProperty({ type: Number, nullable: true })
  restoredFrom: number | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ type: String, nullable: true })
  createdBy: string | null;

  @ApiProperty()
  current: boolean;

  @ApiProperty({ description: 'El almacén aún la conserva (se puede restaurar)' })
  available: boolean;
}

export class VaultSettingsDto implements VaultSettings {
  @ApiProperty({ minimum: VAULT_ROTATION_DAYS_MIN, maximum: VAULT_ROTATION_DAYS_MAX })
  @IsInt()
  @Min(VAULT_ROTATION_DAYS_MIN)
  @Max(VAULT_ROTATION_DAYS_MAX)
  rotationWarnDays: number;

  @ApiProperty()
  @IsBoolean()
  notifyOnReveal: boolean;

  @ApiProperty({ minimum: VAULT_RETENTION_DAYS_MIN, maximum: VAULT_RETENTION_DAYS_MAX })
  @IsInt()
  @Min(VAULT_RETENTION_DAYS_MIN)
  @Max(VAULT_RETENTION_DAYS_MAX)
  deleteRetentionDays: number;
}

export class VaultStatusDto implements VaultStatus {
  @ApiProperty({ enum: ['none', 'local', 'openbao'] })
  provider: 'none' | 'local' | 'openbao';

  @ApiProperty()
  healthy: boolean;

  @ApiProperty()
  maxVersions: number;
}
