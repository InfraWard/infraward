import { Component, inject } from '@angular/core';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { HOME_URL } from '../../core/auth/auth.guards';
import { AuthService } from '../../core/auth/auth.service';
import { BrandMark } from '../../shared/brand-mark';
import { MfaSetupFlow } from './mfa-setup-flow';

/**
 * Alta obligada de la verificación en dos pasos (admin local que entró con contraseña y aún no la
 * tiene): hasta completarla, la API no deja hacer nada más.
 */
@Component({
  selector: 'app-mfa-setup-page',
  imports: [ButtonModule, BrandMark, MfaSetupFlow],
  template: `
    <main class="page">
      <section class="card">
        <header>
          <app-brand-mark [size]="36" />
          <h1>Configura la verificación en dos pasos</h1>
          <p>
            Los administradores tienen acceso a toda la infraestructura: para seguir, además de la
            contraseña necesitas un código de una app de autenticación.
          </p>
        </header>
        <app-mfa-setup-flow [account]="auth.user()?.email ?? ''" (done)="finish()" />
        <p-button label="Salir" severity="secondary" [text]="true" size="small" fluid (onClick)="logout()"
          styleClass="logout" />
      </section>
    </main>
  `,
  styleUrl: './mfa-page.scss',
  styles: `
    .card {
      width: min(34rem, 100%);
    }
    :host ::ng-deep .logout {
      margin-top: 1rem;
    }
  `,
})
export class MfaSetupPage {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected async finish(): Promise<void> {
    // La sesión ya no exige el alta: se recupera y se entra.
    await this.auth.verify();
    await this.router.navigateByUrl(HOME_URL);
  }

  protected async logout(): Promise<void> {
    if (!(await this.auth.logout())) await this.router.navigate(['/login']);
  }
}
