import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ALERT_CHANNEL_NAME_MAX,
  ALERT_CHANNEL_TYPES,
  ALERT_EMAIL_RECIPIENTS_MAX,
  ALERT_WEBHOOK_SECRET_MAX,
  ALERT_WEBHOOK_SECRET_MIN,
  ALERT_WEBHOOK_URL_MAX,
  NOTIFICATION_KINDS,
  type AlertChannel,
  type AlertChannelType,
  type AlertsStatus,
  type AlertTestResult,
  type CreateAlertChannelRequest,
  type NotificationKind,
  type UpdateAlertChannelRequest,
} from '@infraward/shared-types';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsEmail,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class AlertChannelDto implements AlertChannel {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty({ enum: ALERT_CHANNEL_TYPES })
  type: AlertChannelType;

  @ApiProperty()
  enabled: boolean;

  @ApiProperty({ enum: NOTIFICATION_KINDS, isArray: true, nullable: true, description: 'null = todos' })
  kinds: NotificationKind[] | null;

  @ApiProperty({ description: 'También las que solo ven los admins' })
  includeAdminOnly: boolean;

  @ApiProperty({ type: String, nullable: true, description: 'Webhook: solo el host (la URL es secreta)' })
  host: string | null;

  @ApiProperty({ type: [String], nullable: true })
  recipients: string[] | null;

  @ApiProperty({ description: 'Tiene secreto de firma (nunca se devuelve)' })
  hasSecret: boolean;

  @ApiProperty({ type: String, nullable: true })
  secretProvider: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  lastSuccessAt: string | null;

  @ApiProperty({ type: String, format: 'date-time', nullable: true })
  lastErrorAt: string | null;

  @ApiProperty({ type: String, nullable: true })
  lastError: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ format: 'date-time' })
  updatedAt: string;
}

class AlertChannelFieldsDto {
  @ApiPropertyOptional({ enum: NOTIFICATION_KINDS, isArray: true, nullable: true })
  @IsOptional()
  @ValidateIf((_, v) => v !== null)
  @IsArray()
  @ArrayMinSize(1)
  @IsIn(NOTIFICATION_KINDS, { each: true })
  kinds?: NotificationKind[] | null;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  includeAdminOnly?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @ApiPropertyOptional({
    maxLength: ALERT_WEBHOOK_URL_MAX,
    description: 'Webhook: la URL (https); se guarda en el gestor de secretos',
    writeOnly: true,
  })
  @IsOptional()
  @IsString()
  @MaxLength(ALERT_WEBHOOK_URL_MAX)
  url?: string;

  @ApiPropertyOptional({ type: [String], maxItems: ALERT_EMAIL_RECIPIENTS_MAX })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(ALERT_EMAIL_RECIPIENTS_MAX)
  @IsEmail({}, { each: true })
  recipients?: string[];
}

export class CreateAlertChannelDto
  extends AlertChannelFieldsDto
  implements CreateAlertChannelRequest
{
  @ApiProperty({ maxLength: ALERT_CHANNEL_NAME_MAX })
  @IsString()
  @MinLength(1)
  @MaxLength(ALERT_CHANNEL_NAME_MAX)
  name: string;

  @ApiProperty({ enum: ALERT_CHANNEL_TYPES })
  @IsIn(ALERT_CHANNEL_TYPES)
  type: AlertChannelType;

  @ApiPropertyOptional({
    minLength: ALERT_WEBHOOK_SECRET_MIN,
    maxLength: ALERT_WEBHOOK_SECRET_MAX,
    description: 'Webhook: secreto de firma HMAC (se guarda en el gestor de secretos)',
    writeOnly: true,
  })
  @IsOptional()
  @IsString()
  @MinLength(ALERT_WEBHOOK_SECRET_MIN)
  @MaxLength(ALERT_WEBHOOK_SECRET_MAX)
  secret?: string;
}

export class UpdateAlertChannelDto
  extends AlertChannelFieldsDto
  implements UpdateAlertChannelRequest
{
  @ApiPropertyOptional({ maxLength: ALERT_CHANNEL_NAME_MAX })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(ALERT_CHANNEL_NAME_MAX)
  name?: string;

  @ApiPropertyOptional({
    type: String,
    nullable: true,
    minLength: ALERT_WEBHOOK_SECRET_MIN,
    maxLength: ALERT_WEBHOOK_SECRET_MAX,
    description: 'Nuevo secreto de firma; null lo quita',
    writeOnly: true,
  })
  @IsOptional()
  @ValidateIf((_, v) => v !== null)
  @IsString()
  @MinLength(ALERT_WEBHOOK_SECRET_MIN)
  @MaxLength(ALERT_WEBHOOK_SECRET_MAX)
  secret?: string | null;
}

export class AlertsStatusDto implements AlertsStatus {
  @ApiProperty({ type: Boolean, nullable: true, description: 'null: el worker aún no lo ha dicho' })
  smtpConfigured: boolean | null;

  @ApiProperty({ type: Boolean, nullable: true })
  allowPrivate: boolean | null;

  @ApiProperty({ type: Boolean, nullable: true })
  allowHttp: boolean | null;
}

export class AlertTestResultDto implements AlertTestResult {
  @ApiProperty()
  ok: boolean;

  @ApiProperty({ type: String, nullable: true })
  error: string | null;
}
