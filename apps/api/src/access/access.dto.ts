import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ACCESS_PERMISSIONS,
  ACCESS_SCOPES,
  ACCESS_SUBJECT_TYPES,
  USER_ROLES,
  type AccessGrantSource,
  type AccessPermission,
  type AccessPolicyRule,
  type AccessScope,
  type AccessSubject,
  type AccessSubjectType,
  type AssetAccess,
  type AssetAccessEntry,
  type CreateAccessPolicyRequest,
  type UserRole,
} from '@infraward/shared-types';
import { IsIn, IsOptional, IsUUID, Matches, MaxLength, ValidateIf } from 'class-validator';
import { LABEL, LABEL_MAX } from '../assets/labels.js';

export class AccessPoliciesQueryDto {
  @ApiPropertyOptional({ format: 'uuid', description: 'Solo las reglas de ese asset' })
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({ format: 'uuid', description: 'Solo las reglas de esa persona' })
  @IsOptional()
  @IsUUID()
  userId?: string;
}

export class CreateAccessPolicyDto implements CreateAccessPolicyRequest {
  @ApiProperty({ enum: ACCESS_PERMISSIONS })
  @IsIn(ACCESS_PERMISSIONS)
  permission: AccessPermission;

  @ApiProperty({ enum: ACCESS_SUBJECT_TYPES })
  @IsIn(ACCESS_SUBJECT_TYPES)
  subjectType: AccessSubjectType;

  @ApiPropertyOptional({ format: 'uuid', description: 'subjectType = user' })
  @ValidateIf((o: CreateAccessPolicyDto) => o.subjectType === 'user')
  @IsUUID()
  userId?: string;

  @ApiPropertyOptional({ enum: USER_ROLES, description: 'subjectType = role' })
  @ValidateIf((o: CreateAccessPolicyDto) => o.subjectType === 'role')
  @IsIn(USER_ROLES)
  role?: UserRole;

  @ApiProperty({
    enum: ACCESS_SCOPES,
    description: 'asset (y lo que contiene), etiqueta o proyecto (miembros efectivos)',
  })
  @IsIn(ACCESS_SCOPES)
  scope: AccessScope;

  @ApiPropertyOptional({ format: 'uuid' })
  @ValidateIf((o: CreateAccessPolicyDto) => o.scope === 'asset')
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional()
  @ValidateIf((o: CreateAccessPolicyDto) => o.scope === 'tag')
  @MaxLength(LABEL_MAX)
  @Matches(LABEL)
  tag?: string;

  @ApiPropertyOptional({ format: 'uuid' })
  @ValidateIf((o: CreateAccessPolicyDto) => o.scope === 'project')
  @IsUUID()
  projectId?: string;
}

export class AccessPolicyRuleDto implements AccessPolicyRule {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ enum: ACCESS_PERMISSIONS })
  permission: AccessPermission;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: '`{ type: user, userId, email, name }` o `{ type: role, role }`',
  })
  subject: AccessSubject;

  @ApiProperty({ enum: ACCESS_SCOPES })
  scope: AccessScope;

  @ApiProperty({ type: String, nullable: true, format: 'uuid' })
  assetId: string | null;

  @ApiProperty({ type: String, nullable: true })
  assetName: string | null;

  @ApiProperty({ type: String, nullable: true })
  tag: string | null;

  @ApiProperty({ type: String, nullable: true, format: 'uuid' })
  projectId: string | null;

  @ApiProperty({ type: String, nullable: true })
  projectName: string | null;

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiProperty({ type: 'object', nullable: true, additionalProperties: true })
  createdBy: { id: string; email: string } | null;
}

export class AssetAccessEntryDto implements AssetAccessEntry {
  @ApiProperty({ type: AccessPolicyRuleDto })
  rule: AccessPolicyRuleDto;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    description: '`own`, `inherited` (assetId), `tag` (tag) o `project` (projectId)',
  })
  source: AccessGrantSource;

  @ApiProperty({ type: String, nullable: true, description: 'Nombre del antepasado o proyecto' })
  sourceName: string | null;
}

export class AssetAccessDto implements AssetAccess {
  @ApiProperty({ enum: USER_ROLES, isArray: true, description: 'Roles que lo tienen siempre' })
  roles: UserRole[];

  @ApiProperty({ type: [AssetAccessEntryDto] })
  entries: AssetAccessEntryDto[];
}
