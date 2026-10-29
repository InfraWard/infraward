import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ASSET_STATUSES,
  ENROLLMENT_METHODS,
  ENROLLMENT_PHASES,
  JOB_NAMES,
  ENROLLMENT_PURPOSES,
  ENROLLMENT_STATUSES,
  HOST_KEY_TYPES,
  SSH_AUTH_MODES,
  ADMIN_ACCESS_REQUESTS,
  type AdminAccessRequest,
  type AssetStatus,
  type ConfirmManualEnrollmentRequest,
  type EnrollDoneRequest,
  type EnrollServerRequest,
  type EnrollServerResponse,
  type Enrollment,
  type EnrollmentJobProgress,
  type EnrollmentMethod,
  type EnrollmentPhase,
  type EnrollmentProgress,
  type EnrollmentPurpose,
  type EnrollmentStatus,
  type HostKeyFingerprint,
  type HostKeyType,
  type IssueEnrollmentTokenRequest,
  type IssuedEnrollment,
  type JobName,
  type JobState,
  type SshAuthMode,
} from '@infraward/shared-types';
import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsNotIn,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
  ValidateNested,
} from 'class-validator';
import { AssetDto } from '../assets/assets.dto.js';
import { LABEL, LABEL_MAX, LABELS_MAX } from '../assets/labels.js';
import { InventoryPolicyFieldsDto } from '../inventory/inventory.dto.js';
import { JOB_STATES } from '../jobs/jobs.dto.js';

/**
 * Hostname o IPv4 (letras, números, puntos y guiones; no empieza por guion, que `ssh` tomaría
 * como opción) o IPv6 sin corchetes.
 */
export const HOST = /^(?!-)[A-Za-z0-9.-]{1,253}$|^[0-9A-Fa-f:]{2,39}$/;

/** Nombre de usuario POSIX portable. */
export const SSH_USER = /^[a-z_][a-z0-9_-]{0,31}$/;

export const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;

// --- Peticiones ---

/** Proyectos que se pueden elegir en el alta. */
export const ENROLL_PROJECTS_MAX = 20;

export class EnrollServerDto implements EnrollServerRequest {
  @ApiProperty({ example: '192.0.2.10', description: 'IP o hostname' })
  @IsString()
  @Matches(HOST, { message: 'host debe ser una IP o un hostname' })
  host: string;

  @ApiPropertyOptional({ default: 22, minimum: 1, maximum: 65535 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  port?: number;

  @ApiPropertyOptional({ maxLength: 255, description: 'Por defecto, el host' })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  name?: string;

  @ApiPropertyOptional({
    default: false,
    description:
      'Añade `--install-sudo` a los comandos (el script instala sudo si falta, p. ej. en Proxmox) y los ejecuta como root sin sudo',
  })
  @IsOptional()
  @IsBoolean()
  installSudo?: boolean;

  @ApiPropertyOptional({
    enum: SSH_AUTH_MODES,
    description:
      'Acceso del worker: certificados de vida corta de la CA SSH (`ca_certificate`) o clave estática. Por defecto, `ca_certificate` si hay un proveedor con CA SSH',
  })
  @IsOptional()
  @IsIn(SSH_AUTH_MODES)
  authMode?: SshAuthMode;

  @ApiPropertyOptional({
    enum: ['operator'],
    description:
      'Instala además el acceso interactivo de administración (cuenta `infraward-admin` con sudo; solo en modo CA; exige `users.manage` y reautenticación reciente). Por defecto, no',
  })
  @IsOptional()
  @IsIn(['operator'])
  adminAccess?: 'operator';

  @ApiPropertyOptional({
    type: [String],
    maxItems: LABELS_MAX,
    description: 'Tags del servidor, desde el alta',
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(LABELS_MAX)
  @IsString({ each: true })
  @MaxLength(LABEL_MAX, { each: true })
  @Matches(LABEL, { each: true })
  tags?: string[];

  @ApiPropertyOptional({
    type: [String],
    format: 'uuid',
    maxItems: ENROLL_PROJECTS_MAX,
    description: 'Proyectos en los que entra (requiere `projects.write`)',
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(ENROLL_PROJECTS_MAX)
  @IsUUID('all', { each: true })
  projectIds?: string[];

  @ApiPropertyOptional({
    type: InventoryPolicyFieldsDto,
    description:
      'Regla propia de política (requiere `policy.write`): se aplica antes de la primera recolección y escaneo',
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => InventoryPolicyFieldsDto)
  policy?: InventoryPolicyFieldsDto;
}

export class IssueEnrollmentTokenDto implements IssueEnrollmentTokenRequest {
  @ApiPropertyOptional({ default: false, description: 'Como en el alta' })
  @IsOptional()
  @IsBoolean()
  installSudo?: boolean;

  @ApiPropertyOptional({
    enum: SSH_AUTH_MODES,
    description:
      '`ca_certificate` sobre un servidor activo con clave estática abre una migración a CA (`ca_migration`). Por defecto, el modo actual del asset',
  })
  @IsOptional()
  @IsIn(SSH_AUTH_MODES)
  authMode?: SshAuthMode;

  @ApiPropertyOptional({
    enum: ADMIN_ACCESS_REQUESTS,
    description:
      'Acceso interactivo de administración (terminal): `operator` instala la cuenta `infraward-admin` con sudo (solo en modo CA; exige `users.manage` y reautenticación reciente) y `none` lo retira. Por defecto no se toca',
  })
  @IsOptional()
  @IsIn(ADMIN_ACCESS_REQUESTS)
  adminAccess?: AdminAccessRequest;
}

export class HostKeyFingerprintDto implements HostKeyFingerprint {
  @ApiProperty({ enum: HOST_KEY_TYPES })
  @IsIn(HOST_KEY_TYPES)
  type: HostKeyType;

  @ApiProperty({ example: 'SHA256:…' })
  @IsString()
  @Matches(FINGERPRINT)
  fingerprint: string;
}

export class ConfirmManualEnrollmentDto implements ConfirmManualEnrollmentRequest {
  @ApiProperty({
    example: 'inventory',
    description:
      'Usuario en cuya cuenta se añadió la clave. Nunca root: todo el diseño parte de un usuario dedicado con permisos acotados.',
  })
  @IsString()
  @Matches(SSH_USER, { message: 'sshUser debe ser un usuario POSIX válido' })
  @IsNotIn(['root'], { message: 'sshUser no puede ser root' })
  sshUser: string;

  @ApiPropertyOptional({
    type: [HostKeyFingerprintDto],
    description:
      'Huellas de las host keys que imprime el script embebido. Con ellas, el worker solo acepta una de esas claves; sin ellas, TOFU.',
  })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @ValidateNested({ each: true })
  @Type(() => HostKeyFingerprintDto)
  hostKeys?: HostKeyFingerprintDto[];
}

export class EnrollDoneDto implements EnrollDoneRequest {
  @ApiProperty({ type: [HostKeyFingerprintDto] })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @ValidateNested({ each: true })
  @Type(() => HostKeyFingerprintDto)
  hostKeys: HostKeyFingerprintDto[];
}

// --- Respuestas ---

export class EnrollmentDto implements Enrollment {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ format: 'uuid' })
  assetId: string;

  @ApiProperty({ enum: ENROLLMENT_METHODS })
  method: EnrollmentMethod;

  @ApiProperty({ enum: ENROLLMENT_PURPOSES })
  purpose: EnrollmentPurpose;

  @ApiProperty({
    enum: SSH_AUTH_MODES,
    description: 'Modo de acceso que instala el script',
  })
  authMode: SshAuthMode;

  @ApiProperty({
    enum: ADMIN_ACCESS_REQUESTS,
    nullable: true,
    description:
      'Acceso de administración que pide el script (`operator` lo instala, `none` lo retira, null no lo toca)',
  })
  adminAccess: AdminAccessRequest | null;

  @ApiProperty({ enum: ENROLLMENT_STATUSES })
  status: EnrollmentStatus;

  @ApiProperty({ description: '`pending` con el token caducado' })
  expired: boolean;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  expiresAt: string | null;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Clave pública instalada (no es secreta); null en modo CA',
  })
  publicKey: string | null;

  @ApiProperty()
  sshUser: string;

  @ApiProperty({ type: [HostKeyFingerprintDto] })
  reportedHostKeys: HostKeyFingerprintDto[];

  @ApiProperty({ type: Number, nullable: true })
  sudoersVersion: number | null;

  @ApiProperty({ type: String, nullable: true })
  error: string | null;

  @ApiProperty({ type: String, nullable: true })
  jobId: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  confirmedAt: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  verifiedAt: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;
}

export class IssuedEnrollmentDto
  extends EnrollmentDto
  implements IssuedEnrollment
{
  @ApiProperty({
    description: 'Comando de alta (lleva el token: solo se muestra ahora)',
    example: 'curl -fsSL https://infraward.example/enroll/<token> | sudo bash',
  })
  command: string;

  @ApiProperty({
    description:
      'Servidores sin acceso a la API (VPN, NAT): script embebido, sin token; imprime las huellas de las host keys para pegarlas en la confirmación',
  })
  embeddedCommand: string;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Alternativa manual (solo con clave estática)',
  })
  manualCommand: string | null;
}

export class EnrollServerResponseDto implements EnrollServerResponse {
  @ApiProperty({ type: AssetDto })
  asset: AssetDto;

  @ApiProperty({ type: IssuedEnrollmentDto })
  enrollment: IssuedEnrollmentDto;
}

export class EnrollmentJobProgressDto implements EnrollmentJobProgress {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: Object.values(JOB_NAMES) })
  name: JobName;

  @ApiProperty({
    type: String,
    format: 'uuid',
    nullable: true,
    description: 'Asset sobre el que trabaja (null en `image.scan`)',
  })
  assetId: string | null;

  @ApiProperty({ enum: JOB_STATES })
  state: JobState;

  @ApiProperty({ minimum: 0, maximum: 100 })
  progress: number;

  @ApiProperty({ type: String, nullable: true })
  message: string | null;

  @ApiProperty({ type: String, nullable: true })
  failedReason: string | null;
}

export class EnrollmentProgressDto implements EnrollmentProgress {
  @ApiProperty({ format: 'uuid' })
  assetId: string;

  @ApiProperty()
  assetName: string;

  @ApiProperty({ enum: ASSET_STATUSES })
  assetStatus: AssetStatus;

  @ApiProperty({ enum: ENROLLMENT_PHASES })
  phase: EnrollmentPhase;

  @ApiProperty({ type: EnrollmentDto })
  enrollment: EnrollmentDto;

  @ApiProperty({ type: [EnrollmentJobProgressDto] })
  jobs: EnrollmentJobProgressDto[];

  @ApiProperty()
  truncated: boolean;

  @ApiProperty({ format: 'date-time' })
  at: string;
}
