import { AlertChannel } from './alert-channel.entity.js';
import { AppSetting } from './app-setting.entity.js';
import { AssetRelation } from './asset-relation.entity.js';
import { Asset } from './asset.entity.js';
import { ContainerImage } from './container-image.entity.js';
import { DnsRecordCheck } from './dns-record-check.entity.js';
import { Enrollment } from './enrollment.entity.js';
import { ExpiryAlert } from './expiry-alert.entity.js';
import { Finding } from './finding.entity.js';
import { InventoryPolicy } from './inventory-policy.entity.js';
import { JobRun } from './job-run.entity.js';
import { JobRunLog } from './job-run-log.entity.js';
import { MetricSample } from './metric-sample.entity.js';
import { Notification } from './notification.entity.js';
import { Package } from './package.entity.js';
import { Project, ProjectMembership, TagStyle } from './project.entity.js';
import { Sbom } from './sbom.entity.js';
import { DnsServicePath, NatForward } from './service-path.entity.js';
import { Snapshot } from './snapshot.entity.js';
import { IntelFeed, VulnerabilityIntel } from './vulnerability-intel.entity.js';

export * from './alert-channel.entity.js';
export * from './app-setting.entity.js';
export * from './asset-relation.entity.js';
export * from './asset-graph.js';
export * from './asset-tree.js';
export * from './asset.entity.js';
export * from './container-image.entity.js';
export * from './dns-record-check.entity.js';
export * from './enrollment.entity.js';
export * from './expiry-alert.entity.js';
export * from './finding.entity.js';
export * from './finding-view.js';
export * from './inventory-policy.entity.js';
export * from './inventory-policy.js';
export * from './job-run.entity.js';
export * from './job-run-log.entity.js';
export * from './job-runs.js';
export * from './metric-sample.entity.js';
export * from './notification.entity.js';
export * from './notifications.js';
export * from './package.entity.js';
export * from './project-membership.js';
export * from './project.entity.js';
export * from './sbom.entity.js';
export * from './service-path.entity.js';
export * from './snapshot-diff.js';
export * from './snapshot.entity.js';
export * from './vulnerability-intel.entity.js';
export * from './kernel.js';
export * from './exposure.js';

/** Entidades del dominio, para registrarlas en el DataSource. */
export const DOMAIN_ENTITIES = [
  Asset,
  AssetRelation,
  Snapshot,
  Enrollment,
  ContainerImage,
  Finding,
  JobRun,
  JobRunLog,
  Sbom,
  Package,
  InventoryPolicy,
  Notification,
  Project,
  ProjectMembership,
  TagStyle,
  DnsRecordCheck,
  ExpiryAlert,
  AppSetting,
  DnsServicePath,
  NatForward,
  VulnerabilityIntel,
  IntelFeed,
  MetricSample,
  AlertChannel,
];
