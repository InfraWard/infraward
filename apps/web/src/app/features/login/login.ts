import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  computed,
  inject,
  input,
  signal,
  type OnInit,
} from '@angular/core';
import {
  FormBuilder,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { IconFieldModule } from '@openng/optimus-ui/iconfield';
import { InputIconModule } from '@openng/optimus-ui/inputicon';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import type { AuthProviders, OidcLoginError } from '@infraward/shared-types';
import { safeReturnUrl } from '../../core/auth/auth.guards';
import { AuthService } from '../../core/auth/auth.service';
import { BrandMark } from '../../shared/brand-mark';

@Component({
  selector: 'app-login',
  imports: [
    ReactiveFormsModule,
    IconFieldModule,
    InputIconModule,
    InputTextModule,
    PasswordModule,
    ButtonModule,
    MessageModule,
    BrandMark,
  ],
  templateUrl: './login.html',
  styleUrl: './login.scss',
})
export class Login implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  /** Ruta a la que volver tras entrar (query param). */
  readonly returnUrl = input<string>();
  /** La sesión anterior terminó (caducada, revocada o usuario desactivado). */
  readonly expired = input<string>();
  /** Vuelta de un login OIDC fallido (`/login?oidcError=<código>`). */
  readonly oidcError = input<string>();
  /** Vuelta del cierre de sesión en el proveedor OIDC. */
  readonly loggedOut = input<string>();
  /** El segundo paso se cerró por demasiados códigos incorrectos. */
  readonly mfaFailed = input<string>();

  /** Cómo se puede entrar; null mientras se pregunta a la API. */
  protected readonly providers = signal<AuthProviders | null>(null);
  /** Con el login local desactivado, el formulario se abre a mano («Acceso de emergencia»). */
  protected readonly emergencyOpen = signal(false);
  protected readonly redirecting = signal(false);
  protected readonly showForm = computed(() => {
    const p = this.providers();
    return !!p && (p.local || this.emergencyOpen());
  });
  protected readonly oidcMessage = computed(() => {
    const code = this.oidcError();
    return code ? oidcErrorMessage(code, this.providers()?.oidc?.name ?? 'el proveedor') : null;
  });

  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly capsLock = signal(false);
  protected readonly form = inject(FormBuilder).nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
  });

  async ngOnInit(): Promise<void> {
    this.providers.set(await this.auth.providers());
  }

  /** Entra con el proveedor OIDC (sale de la app y vuelve con la sesión abierta). */
  protected startOidc(): void {
    this.redirecting.set(true);
    this.auth.startOidcLogin(safeReturnUrl(this.returnUrl()));
  }

  /** Errores de un campo solo cuando ya se ha tocado (o se intentó enviar). */
  protected showError(name: 'email' | 'password'): boolean {
    const control = this.form.controls[name];
    return control.invalid && control.touched;
  }

  protected checkCapsLock(event: KeyboardEvent): void {
    if (typeof event.getModifierState === 'function')
      this.capsLock.set(event.getModifierState('CapsLock'));
  }

  async submit(): Promise<void> {
    if (this.form.invalid || this.loading()) {
      this.form.markAllAsTouched();
      return;
    }
    this.loading.set(true);
    this.error.set(null);
    try {
      const session = await this.auth.login(this.form.getRawValue());
      if (session.mfaPending) {
        // Falta el código: el destino viaja con él.
        const returnUrl = this.returnUrl();
        await this.router.navigate(['/login/mfa'], {
          queryParams: returnUrl ? { returnUrl } : {},
        });
        return;
      }
      await this.router.navigateByUrl(
        session.mustChangePassword
          ? '/change-password'
          : session.mfaSetupRequired
            ? '/mfa-setup'
            : safeReturnUrl(this.returnUrl()),
      );
    } catch (err) {
      this.error.set(loginError(err));
      // La contraseña no se queda en el formulario tras un fallo.
      this.form.controls.password.reset();
    } finally {
      this.loading.set(false);
    }
  }
}

const OIDC_ERRORS: Record<OidcLoginError, (provider: string) => string> = {
  failed: (p) => `No se pudo completar el inicio de sesión con ${p}. Vuelve a intentarlo.`,
  denied: (p) =>
    `Tu cuenta de ${p} no tiene acceso a InfraWard. Pide a un administrador que te añada a un grupo con acceso.`,
  disabled: () => 'Tu cuenta de InfraWard está desactivada. Habla con un administrador.',
  email_conflict: () =>
    'Ya hay una cuenta de InfraWard con tu email y no se puede enlazar automáticamente. Habla con un administrador.',
  email_unverified: (p) =>
    `${p} no marca tu email como verificado y sin eso no se crea tu cuenta de InfraWard. Verifícalo en ${p} o habla con un administrador.`,
  unavailable: (p) => `${p} no responde ahora mismo. Inténtalo dentro de un rato.`,
};

export function oidcErrorMessage(code: string, provider: string): string {
  const message = Object.hasOwn(OIDC_ERRORS, code)
    ? OIDC_ERRORS[code as OidcLoginError]
    : OIDC_ERRORS.failed;
  return message(provider);
}

function loginError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 401) return 'Email o contraseña incorrectos.';
    if (err.status === 429) {
      const wait = Number(err.headers.get('Retry-After'));
      return Number.isFinite(wait) && wait > 0
        ? `Demasiados intentos. Espera ${wait} s y vuelve a probar.`
        : 'Demasiados intentos. Espera un poco y vuelve a probar.';
    }
    if (err.status === 0) return 'No se puede conectar con la API.';
  }
  return 'No se pudo iniciar sesión. Inténtalo de nuevo.';
}
