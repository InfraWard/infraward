import { Component, computed, inject, input } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import type {
  Permission,
  SecretProviderCapability,
  SecretProviderInfo,
} from '@infraward/shared-types';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TabsModule } from '@openng/optimus-ui/tabs';
import { TagModule } from '@openng/optimus-ui/tag';
import { catchError, EMPTY, map, of, type Observable } from 'rxjs';
import { SettingsApi } from '../../core/api/settings-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { ApiTokensSettings } from './api-tokens-settings';
import { AuditLog } from './audit-log';
import { ConnectorsSettings } from './connectors-settings';
import { ExpiryWarningsSettings } from './expiry-warnings-settings';
import { NatForwardsSettings } from './nat-forwards-settings';
import { InventoryPolicySettings } from './inventory-policy-settings';
import { TagColorsSettings } from './tag-colors-settings';
import { ProfileCard } from './profile-card';
import { AccessSettings } from './access-settings';
import { UsersSettings } from './users-settings';
import { VaultSettingsCard } from './vault-settings';

type Loaded<T> =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; value: T };

const CAPABILITY_LABELS: Record<SecretProviderCapability, string> = {
  write: 'guarda secretos',
  ssh_certificates: 'certificados SSH',
};

export const SETTINGS_TABS = [
  'profile',
  'tokens',
  'policy',
  'connectors',
  'users',
  'access',
  'providers',
  'vault',
  'audit',
] as const;
export type SettingsTab = (typeof SETTINGS_TABS)[number];
/** Pestañas que exigen un permiso (las demás las ve todo el mundo). */
const TAB_PERMISSION: Partial<Record<SettingsTab, Permission>> = {
  connectors: 'connectors.write',
  users: 'users.manage',
  access: 'users.manage',
  providers: 'secrets.status',
  vault: 'vault.manage',
  audit: 'audit.read',
};

/**
 * Ajustes con pestañas (la abierta, en `?tab=`): Perfil (el propio, por defecto), Tokens de API
 * (los propios y, con users.manage, los de todos), Inventario
 * (política de inventario y avisos de caducidad) y, según los permisos del rol, Conectores
 * (dominios), Usuarios, Acceso (terminal), Secretos y Auditoría.
 */
@Component({
  selector: 'app-settings',
  imports: [
    CardModule,
    MessageModule,
    TabsModule,
    TagModule,
    ApiTokensSettings,
    AuditLog,
    ConnectorsSettings,
    ExpiryWarningsSettings,
    NatForwardsSettings,
    InventoryPolicySettings,
    TagColorsSettings,
    ProfileCard,
    UsersSettings,
    VaultSettingsCard,
    AccessSettings,
  ],
  templateUrl: './settings.html',
  styleUrl: './settings.scss',
})
export class Settings {
  private readonly api = inject(SettingsApi);
  private readonly router = inject(Router);
  protected readonly auth = inject(AuthService);
  protected readonly capabilityLabels: Readonly<Record<string, string>> =
    CAPABILITY_LABELS;

  /** `?tab=`: pestaña abierta. */
  readonly tab = input<string>();

  /** La pedida si existe y el usuario puede verla; si no, Perfil. */
  protected readonly shownTab = computed<SettingsTab>(() => {
    const tab = this.tab() as SettingsTab;
    return SETTINGS_TABS.includes(tab) && this.canSee(tab) ? tab : 'profile';
  });

  /** ¿Tiene alguna de las pestañas restringidas? (si no, se le explica por qué no las ve). */
  protected readonly restricted = computed(
    () =>
      !(['connectors', 'users', 'providers', 'vault', 'audit'] as const).some((t) =>
        this.canSee(t),
      ),
  );

  protected canSee(tab: SettingsTab): boolean {
    const permission = TAB_PERMISSION[tab];
    return !permission || this.auth.can(permission);
  }

  protected readonly providers = toSignal(
    this.adminOnly(
      () => this.api.secretProviders(),
      'No se pudo leer el estado de los proveedores de secretos.',
    ),
    { initialValue: { state: 'loading' } as Loaded<SecretProviderInfo[]> },
  );

  selectTab(value: string | number | undefined): void {
    const tab = String(value ?? 'profile');
    // Al cambiar de pestaña se quitan los filtros de la auditoría.
    void this.router.navigate([], {
      queryParams: { tab: tab === 'profile' ? null : tab },
      replaceUrl: true,
    });
  }

  private adminOnly<T>(
    load: () => Observable<T>,
    fallback: string,
  ): Observable<Loaded<T>> {
    if (!this.auth.can('secrets.status')) return EMPTY;
    return load().pipe(
      map((value): Loaded<T> => ({ state: 'ready', value })),
      catchError((err: unknown) =>
        of<Loaded<T>>({ state: 'error', message: apiErrorMessage(err, fallback) }),
      ),
    );
  }
}
