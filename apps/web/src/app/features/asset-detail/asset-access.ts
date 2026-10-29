import { Component, computed, effect, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  USER_ROLES,
  hasPermission,
  type Asset,
  type AssetAccess,
  type AssetAccessEntry,
  type UserRole,
  type UserSummary,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { SelectModule } from '@openng/optimus-ui/select';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { firstValueFrom } from 'rxjs';
import { TerminalApi } from '../../core/api/terminal-api';
import { UsersApi } from '../../core/api/users-api';
import { accessSourceLabel, accessSubjectLabel } from '../../shared/access-labels';
import { apiErrorMessage } from '../../shared/api-errors';
import { roleLabel } from '../../shared/role-labels';

interface SubjectOption {
  label: string;
  value: string;
}

/**
 * Tarjeta «Acceso a la terminal» del Resumen (sesión 22, solo admins): quién puede abrir terminal
 * aquí y por qué regla (en el asset, heredada de un antepasado, por etiqueta o proyecto), y dar
 * o quitar acceso en este asset a una persona o un rol. Conceder pide reautenticación.
 */
@Component({
  selector: 'app-asset-access',
  imports: [FormsModule, ButtonModule, CardModule, SelectModule, TooltipModule],
  template: `
    <p-card styleClass="card" data-section="access">
      <ng-template #title>
        <i class="bi bi-terminal" aria-hidden="true"></i> Acceso a la terminal
      </ng-template>
      @if (data(); as d) {
        <ul class="list">
          @for (role of d.roles; track role) {
            <li data-access-role>
              <i class="bi bi-shield-lock" aria-hidden="true"></i>
              <span>Rol {{ roleName(role) }}</span>
              <span class="muted">· siempre</span>
            </li>
          }
          @for (e of d.entries; track e.rule.id) {
            <li [attr.data-access-entry]="subject(e)">
              <i class="bi {{ e.rule.subject.type === 'user' ? 'bi-person' : 'bi-people' }}" aria-hidden="true"></i>
              <span>{{ subject(e) }}</span>
              <span class="muted">· {{ source(e) }}</span>
              @if (e.source.kind === 'own') {
                <span class="spacer"></span>
                <p-button
                  label="Quitar"
                  severity="secondary"
                  [text]="true"
                  size="small"
                  [disabled]="busy()"
                  pTooltip="Sus terminales abiertas aquí se cortan al momento"
                  (onClick)="remove(e)"
                  data-action="revoke-access"
                />
              }
            </li>
          }
        </ul>
        <div class="add">
          <p-select
            [options]="subjects()"
            optionLabel="label"
            optionValue="value"
            [ngModel]="choice()"
            (ngModelChange)="choice.set($event)"
            [filter]="true"
            placeholder="Persona o rol…"
            ariaLabel="A quién dar acceso"
            appendTo="body"
            styleClass="pick"
            data-access-pick
          />
          <p-button
            label="Dar acceso"
            icon="bi bi-plus-lg"
            size="small"
            [disabled]="!choice() || busy()"
            (onClick)="grant()"
            data-action="grant-access"
          />
        </div>
        <small class="muted">
          Aquí y en todo lo que contiene. Por etiqueta o proyecto, en Ajustes › Acceso.
        </small>
      } @else if (error()) {
        <p class="muted">No se pudo cargar quién tiene acceso.</p>
      }
    </p-card>
  `,
  styles: `
    .list {
      list-style: none;
      margin: 0 0 0.5rem;
      padding: 0;
      display: grid;
      gap: 0.25rem;
    }
    li {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      flex-wrap: wrap;
    }
    .spacer {
      flex: 1;
    }
    .muted {
      color: var(--p-text-muted-color);
      margin: 0;
    }
    .add {
      display: flex;
      gap: 0.5rem;
      align-items: center;
      flex-wrap: wrap;
      margin: 0.5rem 0 0.25rem;
    }
    :host ::ng-deep .pick {
      flex: 1 1 12rem;
      min-width: 0;
    }
  `,
})
export class AssetAccessCard {
  private readonly api = inject(TerminalApi);
  private readonly usersApi = inject(UsersApi);
  private readonly messages = inject(MessageService);

  readonly asset = input.required<Asset>();

  protected readonly data = signal<AssetAccess | null>(null);
  protected readonly error = signal(false);
  protected readonly busy = signal(false);
  protected readonly choice = signal<string | null>(null);
  private readonly users = signal<UserSummary[]>([]);

  /** Personas activas y roles que no lo tienen ya por su rol. */
  protected readonly subjects = computed<SubjectOption[]>(() => [
    ...USER_ROLES.filter((r) => !hasPermission(r, 'terminal.open')).map((r) => ({
      label: `Rol ${roleLabel(r)}`,
      value: `role:${r}`,
    })),
    ...this.users()
      .filter((u) => u.active && !hasPermission(u.role, 'terminal.open'))
      .map((u) => ({ label: `${u.name} (${u.email})`, value: `user:${u.id}` })),
  ]);

  constructor() {
    effect(() => void this.load(this.asset().id));
    void firstValueFrom(this.usersApi.list())
      .then((users) => this.users.set(users))
      .catch(() => undefined);
  }

  protected roleName(role: UserRole): string {
    return roleLabel(role);
  }

  protected subject(e: AssetAccessEntry): string {
    return accessSubjectLabel(e.rule.subject);
  }

  protected source(e: AssetAccessEntry): string {
    return accessSourceLabel(e);
  }

  protected async grant(): Promise<void> {
    const choice = this.choice();
    if (!choice) return;
    const [kind, value] = choice.split(':') as ['user' | 'role', string];
    await this.act(async () => {
      await firstValueFrom(
        this.api.grant({
          permission: 'terminal.open',
          subjectType: kind,
          ...(kind === 'user' ? { userId: value } : { role: value as UserRole }),
          scope: 'asset',
          assetId: this.asset().id,
        }),
      );
      this.choice.set(null);
      this.messages.add({ severity: 'success', summary: 'Acceso concedido' });
    });
  }

  protected async remove(e: AssetAccessEntry): Promise<void> {
    await this.act(async () => {
      await firstValueFrom(this.api.revoke(e.rule.id));
      this.messages.add({ severity: 'success', summary: 'Acceso retirado' });
    });
  }

  private async act(fn: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    try {
      await fn();
      await this.load(this.asset().id);
    } catch (err) {
      this.messages.add({
        severity: 'error',
        summary: apiErrorMessage(err, 'No se pudo cambiar el acceso'),
      });
    } finally {
      this.busy.set(false);
    }
  }

  private async load(id: string): Promise<void> {
    try {
      this.data.set(await firstValueFrom(this.api.assetAccess(id)));
      this.error.set(false);
    } catch {
      this.error.set(true);
    }
  }
}
