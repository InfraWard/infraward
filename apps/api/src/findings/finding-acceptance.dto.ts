import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  BULK_VULNERABILITIES_MAX,
  FINDING_ACCEPT_MAX,
  FINDING_ACCEPT_REASON_MAX,
  FINDING_ACCEPT_REASON_MIN,
  VULNERABILITY_ID_PATTERN,
  type AcceptFindingsRequest,
  type FindingAcceptance,
  type FindingAcceptanceResult,
  type ReopenFindingsRequest,
} from '@infraward/shared-types';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class FindingAcceptanceDto implements FindingAcceptance {
  @ApiProperty({ type: String, nullable: true, description: 'Email de quien lo aceptó' })
  by: string | null;

  @ApiProperty({ format: 'date-time' })
  at: string;

  @ApiProperty()
  reason: string;

  @ApiProperty({
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'Al llegar, vuelve a abierto; null: no caduca',
  })
  expiresAt: string | null;
}

export const ACCEPTANCE_PROPERTY = {
  type: FindingAcceptanceDto,
  nullable: true,
  description: 'Última aceptación del riesgo (vigente si status = accepted)',
} as const;

export class ReopenFindingsDto implements ReopenFindingsRequest {
  @ApiPropertyOptional({
    type: [String],
    format: 'uuid',
    maxItems: FINDING_ACCEPT_MAX,
    description: 'Los findings (no se combina con vulnerabilityIds)',
  })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(FINDING_ACCEPT_MAX)
  @IsUUID('all', { each: true })
  findingIds?: string[];

  @ApiPropertyOptional({
    type: [String],
    maxItems: BULK_VULNERABILITIES_MAX,
    description: 'Todos los findings de estos CVE (de assets no retirados que escanean)',
  })
  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(BULK_VULNERABILITIES_MAX)
  @IsString({ each: true })
  @Matches(VULNERABILITY_ID_PATTERN, { each: true })
  vulnerabilityIds?: string[];

  @ApiPropertyOptional({
    format: 'uuid',
    description: 'Con vulnerabilityIds: solo los de assets de este proyecto',
  })
  @IsOptional()
  @IsUUID()
  projectId?: string;
}

export class AcceptFindingsDto
  extends ReopenFindingsDto
  implements AcceptFindingsRequest
{
  @ApiProperty({
    minLength: FINDING_ACCEPT_REASON_MIN,
    maxLength: FINDING_ACCEPT_REASON_MAX,
    description: 'Por qué se acepta (queda en la ficha y en la auditoría)',
  })
  @IsString()
  @MinLength(FINDING_ACCEPT_REASON_MIN)
  @MaxLength(FINDING_ACCEPT_REASON_MAX)
  reason: string;

  @ApiPropertyOptional({
    type: String,
    format: 'date-time',
    nullable: true,
    description: 'Caducidad (futura, como mucho a un año); sin ella, no caduca',
  })
  @IsOptional()
  @ValidateIf((_, v) => v !== null)
  @IsISO8601({ strict: true })
  expiresAt?: string | null;
}

export class FindingAcceptanceResultDto implements FindingAcceptanceResult {
  @ApiProperty({ description: 'Findings que cambiaron de estado' })
  updated: number;

  @ApiProperty({ description: 'CVE distintos de esos findings' })
  vulnerabilities: number;
}
