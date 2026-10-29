import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  AUDIT_ACTIONS,
  AUDIT_OUTCOMES,
  type AuditAction,
  type AuditCategory,
  type AuditDetails,
  type AuditEvent,
  type AuditOutcome,
  type AuditPage,
  type AuditQuery,
} from '@infraward/shared-types';
import { Transform, Type } from 'class-transformer';
import {
  IsIn,
  IsInt,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export const AUDIT_CATEGORIES = [
  ...new Set(AUDIT_ACTIONS.map((a) => a.split('.')[0])),
] as AuditCategory[];

/** `?action=a&action=b` o `?action=a,b`. */
const toList = ({ value }: { value: unknown }): unknown =>
  value === undefined
    ? undefined
    : (Array.isArray(value) ? value : [value])
        .flatMap((v) => String(v).split(','))
        .map((v) => v.trim())
        .filter(Boolean);

export class AuditQueryDto implements AuditQuery {
  @ApiPropertyOptional({ enum: AUDIT_ACTIONS, isArray: true })
  @IsOptional()
  @Transform(toList)
  @IsIn(AUDIT_ACTIONS, { each: true })
  action?: AuditAction[];

  @ApiPropertyOptional({ enum: AUDIT_CATEGORIES, isArray: true })
  @IsOptional()
  @Transform(toList)
  @IsIn(AUDIT_CATEGORIES, { each: true })
  category?: AuditCategory[];

  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  actorId?: string;

  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  targetId?: string;

  @ApiPropertyOptional({ enum: AUDIT_OUTCOMES })
  @IsOptional()
  @IsIn(AUDIT_OUTCOMES)
  outcome?: AuditOutcome;

  @ApiPropertyOptional({ description: 'Texto en el objetivo o en el email del actor' })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  q?: string;

  @ApiPropertyOptional({ format: 'date-time' })
  @IsOptional()
  @IsISO8601()
  from?: string;

  @ApiPropertyOptional({ format: 'date-time' })
  @IsOptional()
  @IsISO8601()
  to?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(200)
  cursor?: string;

  @ApiPropertyOptional({ minimum: 1, maximum: 200, default: 50 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number;
}

export class AuditEventDto implements AuditEvent {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ format: 'date-time' })
  occurredAt: string;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  actorId: string | null;

  @ApiProperty({ type: String, nullable: true })
  actorEmail: string | null;

  @ApiProperty({ enum: AUDIT_ACTIONS })
  action: AuditAction;

  @ApiProperty({ enum: AUDIT_OUTCOMES })
  outcome: AuditOutcome;

  @ApiProperty({ type: String, nullable: true })
  targetType: string | null;

  @ApiProperty({ type: String, format: 'uuid', nullable: true })
  targetId: string | null;

  @ApiProperty({ type: String, nullable: true })
  targetLabel: string | null;

  @ApiProperty({ type: String, nullable: true })
  ip: string | null;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: 'Detalle pequeño y plano; nunca secretos',
  })
  details: AuditDetails;
}

export class AuditPageDto implements AuditPage {
  @ApiProperty({ type: [AuditEventDto] })
  items: AuditEventDto[];

  @ApiProperty({ type: String, nullable: true })
  nextCursor: string | null;
}
