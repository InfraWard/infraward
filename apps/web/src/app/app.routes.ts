import type { Routes } from '@angular/router';
import {
  authGuard,
  guestGuard,
  mfaSetupGuard,
  mfaVerifyGuard,
  passwordChangeGuard,
  permissionGuard,
} from './core/auth/auth.guards';
import { unsavedChangesGuard } from './shared/unsaved-changes';

export const routes: Routes = [
  {
    path: 'login',
    // Exacta: si no, su canMatch también se evaluaría para /login/mfa (y redirigiría en bucle).
    pathMatch: 'full',
    canMatch: [guestGuard],
    title: 'Entrar · InfraWard',
    loadComponent: () => import('./features/login/login').then((m) => m.Login),
  },
  {
    path: 'login/mfa',
    canMatch: [mfaVerifyGuard],
    title: 'Verificación en dos pasos · InfraWard',
    loadComponent: () =>
      import('./features/mfa/mfa-verify').then((m) => m.MfaVerify),
  },
  {
    path: 'mfa-setup',
    canMatch: [mfaSetupGuard],
    title: 'Configura la verificación en dos pasos · InfraWard',
    loadComponent: () =>
      import('./features/mfa/mfa-setup-page').then((m) => m.MfaSetupPage),
  },
  {
    path: 'change-password',
    canMatch: [passwordChangeGuard],
    title: 'Cambiar contraseña · InfraWard',
    loadComponent: () =>
      import('./features/change-password/change-password').then(
        (m) => m.ChangePassword,
      ),
  },
  {
    path: '',
    canMatch: [authGuard],
    loadComponent: () => import('./layout/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        title: 'Panel · InfraWard',
        loadComponent: () =>
          import('./features/dashboard/dashboard').then((m) => m.Dashboard),
        canDeactivate: [unsavedChangesGuard],
      },
      {
        path: 'inventory',
        title: 'Inventario · InfraWard',
        loadComponent: () =>
          import('./features/inventory/inventory-tree').then(
            (m) => m.InventoryTree,
          ),
      },
      {
        path: 'projects',
        title: 'Proyectos · InfraWard',
        loadComponent: () =>
          import('./features/projects/project-list').then((m) => m.ProjectList),
      },
      {
        path: 'projects/:id',
        title: 'Proyecto · InfraWard',
        canDeactivate: [unsavedChangesGuard],
        loadComponent: () =>
          import('./features/projects/project-detail').then(
            (m) => m.ProjectDetail,
          ),
      },
      {
        path: 'vulnerabilities',
        title: 'Vulnerabilidades · InfraWard',
        loadComponent: () =>
          import('./features/vulnerabilities/vulnerability-list').then(
            (m) => m.VulnerabilityList,
          ),
      },
      {
        path: 'vulnerabilities/:id',
        title: 'Vulnerabilidad · InfraWard',
        loadComponent: () =>
          import('./features/vulnerabilities/vulnerability-detail').then(
            (m) => m.VulnerabilityDetail,
          ),
      },
      {
        path: 'activity',
        title: 'Actividad · InfraWard',
        loadComponent: () =>
          import('./features/activity/activity').then((m) => m.Activity),
      },
      {
        path: 'activity/:id',
        title: 'Ejecución · Actividad · InfraWard',
        loadComponent: () =>
          import('./features/activity/activity-run').then((m) => m.ActivityRun),
      },
      {
        path: 'vault',
        canMatch: [permissionGuard('vault.manage')],
        title: 'Caja fuerte · InfraWard',
        loadComponent: () =>
          import('./features/vault/vault-page').then((m) => m.VaultPage),
      },
      {
        path: 'settings',
        title: 'Ajustes · InfraWard',
        loadComponent: () =>
          import('./features/settings/settings').then((m) => m.Settings),
      },
      {
        path: 'enroll',
        canMatch: [permissionGuard('assets.write')],
        title: 'Añadir servidor · InfraWard',
        loadComponent: () =>
          import('./features/enrollment/enroll-start').then(
            (m) => m.EnrollStart,
          ),
      },
      {
        path: 'assets/:id/enrollment',
        title: 'Alta · InfraWard',
        loadComponent: () =>
          import('./features/enrollment/enroll-progress').then(
            (m) => m.EnrollProgress,
          ),
      },
      {
        // Terminal web (sesión 22): su propia pestaña; pregunta antes de salir con la sesión abierta.
        path: 'assets/:id/terminal',
        title: 'Terminal · InfraWard',
        canDeactivate: [
          (page: { canLeave(): boolean }) => page.canLeave(),
        ],
        loadComponent: () =>
          import('./features/terminal/terminal-page').then((m) => m.TerminalPage),
      },
      {
        path: 'assets/:id',
        title: 'Asset · InfraWard',
        loadComponent: () =>
          import('./features/asset-detail/asset-detail').then(
            (m) => m.AssetDetail,
          ),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
