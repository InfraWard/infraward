// Migraciones registradas explícitamente, en orden. Al generar una nueva, añadirla aquí.
import { CreateUsers1791480572212 } from './1791480572212-CreateUsers.js';
import { AddUserRole1791484229000 } from './1791484229000-AddUserRole.js';
import { CreateInventory1791484229115 } from './1791484229115-CreateInventory.js';
import { CreateLocalSecrets1791497624345 } from './1791497624345-CreateLocalSecrets.js';
import { AddEnrollment1791498852177 } from './1791498852177-AddEnrollment.js';
import { AddFindings1791585034987 } from './1791585034987-AddFindings.js';
import { ImagesAsAssets1791586561533 } from './1791586561533-ImagesAsAssets.js';
import { JobRuns1791643688795 } from './1791643688795-JobRuns.js';
import { AssetDuplicateOf1791658859191 } from './1791658859191-AssetDuplicateOf.js';
import { SshCaAuth1791662400000 } from './1791662400000-SshCaAuth.js';
import { DockerPleskModel1791679091000 } from './1791679091000-DockerPleskModel.js';
import { AddSboms1791723743649 } from './1791723743649-AddSboms.js';
import { AddCveSearch1791736537161 } from './1791736537161-AddCveSearch.js';
import { Reconciliation1791838516040 } from './1791838516040-Reconciliation.js';
import { UserManagement1791900000000 } from './1791900000000-UserManagement.js';
import { MoreRoles1791910000000 } from './1791910000000-MoreRoles.js';
import { OidcLogin1791920000000 } from './1791920000000-OidcLogin.js';
import { InventoryOrganization1791930000000 } from './1791930000000-InventoryOrganization.js';
import { DomainInventory1792005868313 } from './1792005868313-DomainInventory.js';
import { ServicePaths1792090478667 } from './1792090478667-ServicePaths.js';
import { ApiTokens1792170000000 } from './1792170000000-ApiTokens.js';
import { ScanExclusions1792260000000 } from './1792260000000-ScanExclusions.js';
import { Prioritization1792350000000 } from './1792350000000-Prioritization.js';
import { MfaStepUp1792440000000 } from './1792440000000-MfaStepUp.js';
import { CredentialVault1792506804781 } from './1792506804781-CredentialVault.js';
import { Dashboards1792524409442 } from './1792524409442-Dashboards.js';
import { JobRunWorker1792600000000 } from './1792600000000-JobRunWorker.js';
import { TerminalGateway1792618164631 } from './1792618164631-TerminalGateway.js';
import { TerminalAccess1792696046490 } from './1792696046490-TerminalAccess.js';
import { AcceptFindingRisk1793313778000 } from './1793313778000-AcceptFindingRisk.js';
import { AlertChannels1793313779000 } from './1793313779000-AlertChannels.js';
import { TerminalAction1793313780000 } from './1793313780000-TerminalAction.js';
import { CollectionLogs1793453112117 } from './1793453112117-CollectionLogs.js';
import { JobRunTrigger1793487024000 } from './1793487024000-JobRunTrigger.js';

export const migrations = [
  CreateUsers1791480572212,
  AddUserRole1791484229000,
  CreateInventory1791484229115,
  CreateLocalSecrets1791497624345,
  AddEnrollment1791498852177,
  AddFindings1791585034987,
  ImagesAsAssets1791586561533,
  JobRuns1791643688795,
  AssetDuplicateOf1791658859191,
  SshCaAuth1791662400000,
  DockerPleskModel1791679091000,
  AddSboms1791723743649,
  AddCveSearch1791736537161,
  Reconciliation1791838516040,
  UserManagement1791900000000,
  MoreRoles1791910000000,
  OidcLogin1791920000000,
  InventoryOrganization1791930000000,
  DomainInventory1792005868313,
  ServicePaths1792090478667,
  ApiTokens1792170000000,
  ScanExclusions1792260000000,
  Prioritization1792350000000,
  MfaStepUp1792440000000,
  CredentialVault1792506804781,
  Dashboards1792524409442,
  JobRunWorker1792600000000,
  TerminalGateway1792618164631,
  TerminalAccess1792696046490,
  AcceptFindingRisk1793313778000,
  AlertChannels1793313779000,
  TerminalAction1793313780000,
  CollectionLogs1793453112117,
  JobRunTrigger1793487024000,
];
