import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ENROLL_SSH_USER, type AdminAccessRequest, type Asset } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { firstValueFrom } from 'rxjs';
import { EnrollmentApi } from '../../core/api/enrollment-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { IssuedCommands } from '../enrollment/issued-commands';

/**
 * «Acceso de administración» de un servidor (sesión 22, DESIGN §7): si InfraWard tiene la cuenta
 * `infraward-admin` (terminal) y, para un admin, activarlo o retirarlo volviendo a ejecutar el
 * script de alta. Solo en modo CA y con el usuario del script.
 */
@Component({
  selector: 'app-admin-access',
  imports: [DatePipe, ButtonModule, TooltipModule],
  template: `
    @if (asset().adminAccess; as access) {
      <span data-admin-access="on">
        <i class="bi bi-person-gear" aria-hidden="true"></i>
        Activado · <code>{{ access.account }}</code>
      </span>
      <small class="muted d-block">v{{ access.version }} desde {{ access.enabledAt | date: 'short' }}</small>
    } @else {
      <span class="muted" data-admin-access="off">Desactivado</span>
    }
    @if (canManage()) {
      <span [pTooltip]="disabledReason() ?? undefined" class="d-block">
        <p-button
          [label]="asset().adminAccess ? 'Retirar' : 'Activar'"
          [icon]="asset().adminAccess ? 'bi bi-person-dash' : 'bi bi-person-plus'"
          size="small"
          [text]="true"
          [severity]="asset().adminAccess ? 'danger' : 'secondary'"
          [disabled]="!!disabledReason() || busy()"
          [loading]="busy()"
          data-action="admin-access"
          (onClick)="toggle()"
        />
      </span>
    }
  `,
  styles: `
    .muted {
      color: var(--p-text-muted-color);
    }
    .d-block {
      display: block;
    }
  `,
})
export class AdminAccessControl {
  private readonly enrollment = inject(EnrollmentApi);
  private readonly commands = inject(IssuedCommands);
  private readonly router = inject(Router);
  private readonly confirmation = inject(ConfirmationService);
  private readonly messages = inject(MessageService);
  private readonly auth = inject(AuthService);

  readonly asset = input.required<Asset>();
  protected readonly busy = signal(false);

  protected readonly canManage = computed(() => this.auth.can('users.manage'));

  protected readonly disabledReason = computed(() => {
    const a = this.asset();
    if (a.status !== 'active') return 'El servidor no está activo';
    if (a.connection?.user !== ENROLL_SSH_USER)
      return 'Solo en servidores dados de alta con el script';
    if (a.sshAuth !== 'ca_certificate')
      return 'Requiere el modo CA: pásalo antes a certificados';
    return null;
  });

  protected toggle(): void {
    const enable = !this.asset().adminAccess;
    this.confirmation.confirm({
      header: enable
        ? 'Permitir el acceso interactivo de administración'
        : 'Retirar el acceso interactivo de administración',
      message: enable
        ? `Se genera un comando que crea en ${this.asset().name} la cuenta infraward-admin con sudo, que solo acepta certificados de pocos minutos de la CA de InfraWard (para la terminal). Cambia la confianza que se da a InfraWard en este servidor. ¿Continuar?`
        : `Se genera un comando que retira de ${this.asset().name} la cuenta infraward-admin, su sudo y su configuración de sshd. La terminal dejará de estar disponible. ¿Continuar?`,
      icon: enable ? 'bi bi-person-plus' : 'bi bi-person-dash',
      acceptLabel: 'Generar el comando',
      rejectLabel: 'Cancelar',
      acceptButtonProps: enable ? undefined : { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () => void this.issue(enable ? 'operator' : 'none'),
    });
  }

  private async issue(adminAccess: AdminAccessRequest): Promise<void> {
    this.busy.set(true);
    try {
      const issued = await firstValueFrom(
        this.enrollment.issueToken(this.asset().id, false, undefined, adminAccess),
      );
      // El comando lleva el token: solo en memoria, para que el stepper lo muestre.
      this.commands.set(issued);
      await this.router.navigate(['/assets', this.asset().id, 'enrollment']);
    } catch (err) {
      this.messages.add({
        severity: 'error',
        summary: apiErrorMessage(err, 'No se pudo generar el comando'),
      });
    } finally {
      this.busy.set(false);
    }
  }
}
