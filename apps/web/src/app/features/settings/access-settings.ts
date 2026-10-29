import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  hasPermission,
  USER_ROLES,
  type AccessPolicyRule,
  type AccessScope,
  type AssetSummary,
  type UserRole,
  type UserSummary,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { SelectModule } from '@openng/optimus-ui/select';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { TableModule } from '@openng/optimus-ui/table';
import { firstValueFrom } from 'rxjs';
import { TerminalApi } from '../../core/api/terminal-api';
import { UsersApi } from '../../core/api/users-api';
import { OrganizationStore } from '../../core/organization-store';
import { accessSubjectLabel, accessTargetLabel } from '../../shared/access-labels';
import { apiErrorMessage } from '../../shared/api-errors';
import { AssetPicker } from '../../shared/asset-picker';
import { roleLabel } from '../../shared/role-labels';

/** Assets en los que tiene sentido una regla (el servidor la extiende a sus CT y contenedores). */
const TARGET_TYPES = ['server', 'lxc', 'container'] as const;

/**
 * Ajustes › Acceso (sesión 22, solo admins): quién puede abrir terminal además de los admins. Una
 * regla da `terminal.open` a una persona o a un rol en un asset (y lo que contiene), en los assets
 * con una etiqueta o en los de un proyecto. Conceder pide reautenticación; retirar corta al
 * momento las terminales abiertas que dependían de la regla.
 */
@Component({
  selector: 'app-access-settings',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    SelectModule,
    SelectButtonModule,
    TableModule,
    AssetPicker,
  ],
  template: `
    <p-card data-settings="access">
      <ng-template #title>
        <i class="bi bi-terminal" aria-hidden="true"></i> Acceso a la terminal
      </ng-template>
      <p class="muted intro">
        Los admins pueden abrir terminal en cualquier asset con el acceso de administración. Aquí
        se da a otras personas o roles, solo donde haga falta: en un asset (y lo que contiene), por
        etiqueta o por proyecto. Siempre con reautenticación al abrir.
      </p>

      <form class="add" (ngSubmit)="grant()" data-access-form>
        <div class="field">
          <label for="access-subject">A quién</label>
          <p-select
            inputId="access-subject"
            [options]="subjects()"
            optionLabel="label"
            optionValue="value"
            [(ngModel)]="subject"
            name="subject"
            [filter]="true"
            placeholder="Persona o rol"
            appendTo="body"
            [fluid]="true"
            data-access-subject
          />
        </div>
        <div class="field">
          <span class="label" id="access-scope-label">Dónde</span>
          <p-selectbutton
            [options]="scopes"
            optionLabel="label"
            optionValue="value"
            [(ngModel)]="scope"
            name="scope"
            [allowEmpty]="false"
            ariaLabelledBy="access-scope-label"
            data-access-scope
          />
        </div>
        <div class="field">
          @switch (scope) {
            @case ('asset') {
              <label for="access-asset">Asset (y lo que contiene)</label>
              @if (asset(); as a) {
                <span class="picked" data-access-asset>
                  <span>{{ a.name }}</span>
                  <p-button icon="bi bi-x" [text]="true" size="small" severity="secondary"
                    ariaLabel="Cambiar el asset" (onClick)="asset.set(null)" />
                </span>
              } @else {
                <app-asset-picker inputId="access-asset" [types]="targetTypes"
                  placeholder="Servidor, CT o contenedor" (picked)="asset.set($event)" />
              }
            }
            @case ('tag') {
              <label for="access-tag">Etiqueta</label>
              <p-select
                inputId="access-tag"
                [options]="store.tags()"
                optionLabel="tag"
                optionValue="tag"
                [(ngModel)]="tag"
                name="tag"
                [filter]="true"
                placeholder="Elige una etiqueta"
                appendTo="body"
                [fluid]="true"
                data-access-tag
              />
            }
            @case ('project') {
              <label for="access-project">Proyecto</label>
              <p-select
                inputId="access-project"
                [options]="store.projects()"
                optionLabel="name"
                optionValue="id"
                [(ngModel)]="projectId"
                name="project"
                [filter]="true"
                placeholder="Elige un proyecto"
                appendTo="body"
                [fluid]="true"
                data-access-project
              />
            }
          }
        </div>
        <div class="submit">
          <p-button
            type="submit"
            label="Dar acceso"
            icon="bi bi-plus-lg"
            [disabled]="!ready() || busy()"
            [loading]="busy()"
            data-action="grant-access"
          />
        </div>
      </form>

      <p-table [value]="rules()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm" data-access-rules>
        <ng-template #header>
          <tr>
            <th>A quién</th>
            <th>Dónde</th>
            <th>Concedido</th>
            <th></th>
          </tr>
        </ng-template>
        <ng-template #body let-rule>
          <tr [attr.data-access-rule]="rule.id">
            <td>
              <i class="bi {{ rule.subject.type === 'user' ? 'bi-person' : 'bi-people' }}" aria-hidden="true"></i>
              {{ subjectLabel(rule) }}
            </td>
            <td>
              @if (rule.scope === 'asset' && rule.assetId) {
                <a [routerLink]="['/assets', rule.assetId]">{{ rule.assetName }}</a>
                <span class="muted"> y lo que contiene</span>
              } @else {
                {{ targetLabel(rule) }}
              }
            </td>
            <td class="muted">
              {{ rule.createdAt | date: 'short' }}
              @if (rule.createdBy) {
                · {{ rule.createdBy.email }}
              }
            </td>
            <td class="end">
              <p-button
                label="Retirar"
                severity="danger"
                [text]="true"
                size="small"
                [disabled]="busy()"
                (onClick)="revoke(rule)"
                data-action="revoke-access"
              />
            </td>
          </tr>
        </ng-template>
        <ng-template #emptymessage>
          <tr>
            <td colspan="4" class="muted">Nadie más que los admins puede abrir terminal.</td>
          </tr>
        </ng-template>
      </p-table>
    </p-card>
  `,
  styles: `
    .muted {
      color: var(--p-text-muted-color);
    }
    .intro {
      margin: 0 0 1rem;
    }
    /* Columnas fijas: cambiar de ámbito no mueve nada. Una sola columna en pantallas estrechas. */
    .add {
      display: grid;
      grid-template-columns: minmax(12rem, 1fr) auto minmax(12rem, 1fr) auto;
      gap: 0.75rem;
      align-items: end;
      justify-items: stretch;
      margin-bottom: 1rem;
    }
    @media (max-width: 900px) {
      .add {
        grid-template-columns: 1fr;
      }
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      min-width: 0;
    }
    .field label,
    .field .label {
      font-size: 0.875rem;
      color: var(--p-text-muted-color);
    }
    .field app-asset-picker {
      display: block;
    }
    .picked {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.25rem;
      min-height: 2.5rem;
      padding: 0 0.25rem 0 0.75rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: 6px;
    }
    .end {
      text-align: right;
    }
  `,
})
export class AccessSettings implements OnInit {
  private readonly api = inject(TerminalApi);
  private readonly usersApi = inject(UsersApi);
  private readonly messages = inject(MessageService);
  protected readonly store = inject(OrganizationStore);

  protected readonly targetTypes = TARGET_TYPES;
  protected readonly scopes: { label: string; value: AccessScope }[] = [
    { label: 'Asset', value: 'asset' },
    { label: 'Etiqueta', value: 'tag' },
    { label: 'Proyecto', value: 'project' },
  ];

  protected readonly rules = signal<AccessPolicyRule[]>([]);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  private readonly users = signal<UserSummary[]>([]);

  protected subject: string | null = null;
  protected scope: AccessScope = 'tag';
  protected tag: string | null = null;
  protected projectId: string | null = null;
  protected readonly asset = signal<AssetSummary | null>(null);

  protected readonly subjects = computed(() => [
    ...USER_ROLES.filter((r) => !hasPermission(r, 'terminal.open')).map((r) => ({
      label: `Rol ${roleLabel(r)}`,
      value: `role:${r}`,
    })),
    ...this.users()
      .filter((u) => u.active && !hasPermission(u.role, 'terminal.open'))
      .map((u) => ({ label: `${u.name} (${u.email})`, value: `user:${u.id}` })),
  ]);

  ngOnInit(): void {
    this.store.ensureTags();
    this.store.ensureProjects();
    void firstValueFrom(this.usersApi.list())
      .then((users) => this.users.set(users))
      .catch(() => undefined);
    void this.load();
  }

  protected ready(): boolean {
    if (!this.subject) return false;
    if (this.scope === 'asset') return !!this.asset();
    if (this.scope === 'tag') return !!this.tag;
    return !!this.projectId;
  }

  protected subjectLabel(rule: AccessPolicyRule): string {
    return accessSubjectLabel(rule.subject);
  }

  protected targetLabel(rule: AccessPolicyRule): string {
    return accessTargetLabel(rule);
  }

  protected async grant(): Promise<void> {
    if (!this.ready()) return;
    const [kind, value] = this.subject!.split(':') as ['user' | 'role', string];
    await this.act(async () => {
      await firstValueFrom(
        this.api.grant({
          permission: 'terminal.open',
          subjectType: kind,
          ...(kind === 'user' ? { userId: value } : { role: value as UserRole }),
          scope: this.scope,
          ...(this.scope === 'asset' && { assetId: this.asset()!.id }),
          ...(this.scope === 'tag' && { tag: this.tag! }),
          ...(this.scope === 'project' && { projectId: this.projectId! }),
        }),
      );
      this.subject = null;
      this.tag = null;
      this.projectId = null;
      this.asset.set(null);
      this.messages.add({ severity: 'success', summary: 'Acceso concedido' });
    });
  }

  protected async revoke(rule: AccessPolicyRule): Promise<void> {
    await this.act(async () => {
      await firstValueFrom(this.api.revoke(rule.id));
      this.messages.add({
        severity: 'success',
        summary: 'Acceso retirado',
        detail: 'Sus terminales abiertas con esta regla se han cortado.',
      });
    });
  }

  private async act(fn: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    try {
      await fn();
      await this.load();
    } catch (err) {
      this.messages.add({
        severity: 'error',
        summary: apiErrorMessage(err, 'No se pudo cambiar el acceso'),
      });
    } finally {
      this.busy.set(false);
    }
  }

  private async load(): Promise<void> {
    try {
      this.rules.set(await firstValueFrom(this.api.rules()));
    } catch (err) {
      this.messages.add({
        severity: 'error',
        summary: apiErrorMessage(err, 'No se pudieron cargar las reglas de acceso'),
      });
    } finally {
      this.loading.set(false);
    }
  }
}
