import { Component, DestroyRef, inject, signal, type OnInit } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  FormBuilder,
  FormsModule,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { RadioButtonModule } from '@openng/optimus-ui/radiobutton';
import { SelectModule } from '@openng/optimus-ui/select';
import {
  INVENTORY_POLICY_PRESETS,
  INVENTORY_RULE_FIELDS,
  type InventoryPolicyFields,
  type SshAuthMode,
} from '@infraward/shared-types';
import { firstValueFrom, startWith } from 'rxjs';
import { EnrollmentApi } from '../../core/api/enrollment-api';
import { SettingsApi } from '../../core/api/settings-api';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';
import { PolicyForm } from '../../shared/policy-form';
import { TagEditor } from '../../shared/tag-editor';
import { IssuedCommands } from './issued-commands';

/** Igual que la validación de la API: hostname/IPv4 (sin guion inicial) o IPv6 sin corchetes. */
export const HOST_PATTERN = /^(?!-)[A-Za-z0-9.-]{1,253}$|^[0-9A-Fa-f:]{2,39}$/;

/** Primer paso del alta: datos del servidor y opciones del script. */
@Component({
  selector: 'app-enroll-start',
  imports: [
    ReactiveFormsModule,
    FormsModule,
    RouterLink,
    MultiSelectModule,
    SelectModule,
    PolicyForm,
    TagEditor,
    ButtonModule,
    CardModule,
    CheckboxModule,
    InputNumberModule,
    InputTextModule,
    MessageModule,
    RadioButtonModule,
  ],
  template: `
    <nav class="crumbs" aria-label="Ruta">
      <a routerLink="/inventory"
        ><i class="bi bi-diagram-3" aria-hidden="true"></i> Inventario</a
      >
      <i class="bi bi-chevron-right" aria-hidden="true"></i>
      <span aria-current="page">Añadir servidor</span>
    </nav>
    <header class="enroll-head">
      <span class="head-icon" aria-hidden="true"><i class="bi bi-hdd-rack"></i></span>
      <div>
        <h1>Añadir servidor</h1>
        <p class="muted">Genera un comando, ejecútalo en el servidor y InfraWard hace el resto.</p>
      </div>
    </header>

    <div class="layout">
      <form [formGroup]="form" (ngSubmit)="submit()" class="form" novalidate>
        <section class="step">
          <h2><span class="num">1</span> Servidor</h2>
          <div class="row top">
            <div class="field grow">
              <label for="host">IP o hostname</label>
              <input
                pInputText
                id="host"
                formControlName="host"
                placeholder="192.0.2.10 o srv1.example.com"
                autocomplete="off"
                [invalid]="form.controls.host.invalid && form.controls.host.touched"
                fluid
              />
              <small class="muted">Con la que el worker de InfraWard llega al servidor por SSH.</small>
            </div>
            <div class="field port">
              <label for="port">Puerto SSH</label>
              <p-inputnumber inputId="port" formControlName="port" [min]="1" [max]="65535" [useGrouping]="false" fluid />
            </div>
          </div>
          <div class="field">
            <label for="name">Nombre <span class="muted">(opcional)</span></label>
            <input pInputText id="name" formControlName="name" placeholder="Por defecto, el host" fluid />
          </div>
        </section>

        <section class="step">
          <h2><span class="num">2</span> Acceso</h2>
          <fieldset class="tiles" data-field="authMode">
            <legend>Cómo entra InfraWard en el servidor</legend>
            @if (caAvailable() === false) {
              <div class="tile disabled" data-option="ca-unavailable">
                <i class="bi bi-slash-circle tile-icon" aria-hidden="true"></i>
                <span class="tile-text">
                  <strong>Certificados de vida corta: no disponibles</strong>
                  <small class="muted">Ahora mismo, ningún proveedor de secretos activo tiene CA SSH (OpenBao).</small>
                </span>
              </div>
            } @else {
              <label class="tile" for="authCa" [class.selected]="form.controls.authMode.value === 'ca_certificate'">
                <p-radiobutton inputId="authCa" value="ca_certificate" formControlName="authMode" />
                <i class="bi bi-patch-check tile-icon" aria-hidden="true"></i>
                <span class="tile-text">
                  <strong>Certificados de vida corta (CA SSH de OpenBao) <span class="badge">recomendado</span></strong>
                  <small class="muted">Sin claves permanentes: cada tarea entra con un certificado que caduca en minutos.</small>
                </span>
              </label>
            }
            <label class="tile" for="authStatic" [class.selected]="form.controls.authMode.value === 'static_key'">
              <p-radiobutton inputId="authStatic" value="static_key" formControlName="authMode" />
              <i class="bi bi-key tile-icon" aria-hidden="true"></i>
              <span class="tile-text">
                <strong>Clave estática
                  @if (caAvailable() !== false) {
                    <span class="badge neutral">alternativa</span>
                  }
                </strong>
                <small class="muted">Una clave fija en authorized_keys; admite el alta manual.</small>
              </span>
            </label>
          </fieldset>

          <div class="options">
            <label class="option" for="installSudo">
              <i class="bi bi-box-seam option-icon" aria-hidden="true"></i>
              <span class="tile-text">
                <strong>Instalar sudo si falta (<code>--install-sudo</code>)</strong>
                <small class="muted">
                  Con el gestor de paquetes del servidor; es lo único que instala, y solo con esta
                  opción. El comando se ejecuta entonces como root, sin <code>sudo</code>.
                </small>
              </span>
              <p-checkbox inputId="installSudo" formControlName="installSudo" [binary]="true" />
            </label>
            @if (auth.can('users.manage')) {
              <label class="option" for="adminAccess" data-field="adminAccess"
                [class.disabled]="form.controls.authMode.value !== 'ca_certificate'">
                <i class="bi bi-person-gear option-icon" aria-hidden="true"></i>
                <span class="tile-text">
                  <strong>Permitir acceso interactivo de administración</strong>
                  <small class="muted">
                    @if (form.controls.authMode.value === 'ca_certificate') {
                      Crea la cuenta <code>infraward-admin</code> con sudo, que solo acepta
                      certificados de pocos minutos de la CA: es la que usa la terminal web. Da a
                      InfraWard más confianza en este servidor; se puede retirar después desde la ficha.
                    } @else {
                      Solo con certificados de vida corta (CA SSH): no hay acceso humano con claves
                      estáticas.
                    }
                  </small>
                </span>
                <p-checkbox inputId="adminAccess" formControlName="adminAccess" [binary]="true" />
              </label>
            }
          </div>
        </section>

        <section class="step">
          <details class="organize" data-enroll-organize [open]="organizeOpen()" (toggle)="toggleOrganize($any($event.target).open)">
            <summary>
              <h2><span class="num">3</span> Organización y política <span class="muted optional">opcional</span></h2>
              <small class="muted">Se aplican antes de la primera recolección y del primer escaneo</small>
            </summary>
            @if (organizeOpen()) {
            <div class="organize-body">
              <div class="field">
                <span class="label" id="enroll-tags-label">Tags</span>
                <app-tag-editor
                  [tags]="tags()"
                  [editable]="true"
                  (tagsChange)="tags.set($event)"
                  aria-labelledby="enroll-tags-label"
                />
              </div>
              @if (auth.can('projects.write')) {
                <div class="field">
                  <label for="enroll-projects">Proyectos</label>
                  <p-multiselect
                    inputId="enroll-projects"
                    [options]="store.projects()"
                    optionLabel="name"
                    optionValue="id"
                    [ngModel]="projectIds()"
                    [ngModelOptions]="{ standalone: true }"
                    (ngModelChange)="projectIds.set($event ?? [])"
                    placeholder="Ninguno (los hereda de dónde esté)"
                    display="chip"
                    appendTo="body"
                    [fluid]="true"
                    data-field="projects"
                  />
                </div>
              }
              @if (auth.can('policy.write')) {
                <div class="field">
                  <label for="enroll-preset">Plantilla de política</label>
                  <p-select
                    inputId="enroll-preset"
                    [options]="presets"
                    optionLabel="label"
                    optionValue="id"
                    [ngModel]="preset()"
                    [ngModelOptions]="{ standalone: true }"
                    (ngModelChange)="applyPreset($event)"
                    placeholder="A medida"
                    appendTo="body"
                    [fluid]="true"
                    data-field="preset"
                  />
                  <small class="muted">{{ presetDescription() }}</small>
                </div>
                <app-policy-form
                  [value]="policy()"
                  (valueChange)="setPolicy($event)"
                  id="enroll-policy"
                />
              }
            </div>
            }
          </details>
        </section>

        @if (error(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle" role="alert">{{ message }}</p-message>
        }

        <div class="actions">
          <p-button
            type="submit"
            label="Generar comando de alta"
            icon="bi bi-terminal"
            [loading]="loading()"
            [disabled]="form.invalid"
          />
          <p-button label="Cancelar" severity="secondary" [text]="true" routerLink="/inventory" />
        </div>
      </form>

      <aside class="aside">
        <section class="panel">
          <h2>Qué va a pasar</h2>
          <ol class="timeline">
            <li><i class="bi bi-terminal" aria-hidden="true"></i>
              <span><strong>Generas el comando</strong><small class="muted">De un solo uso; caduca en unos minutos.</small></span></li>
            <li><i class="bi bi-hdd" aria-hidden="true"></i>
              <span><strong>Lo ejecutas en el servidor</strong><small class="muted">Como root. Crea el usuario <code>inventory</code>, de solo lectura.</small></span></li>
            <li><i class="bi bi-shield-check" aria-hidden="true"></i>
              <span><strong>InfraWard verifica y recolecta</strong><small class="muted">Comprueba la host key y descubre lo que contiene.</small></span></li>
          </ol>
        </section>
        <section class="panel requirements">
          <h2>El servidor necesita</h2>
          <ul>
            <li><i class="bi bi-check2-circle" aria-hidden="true"></i> <span><strong>sudo</strong>: el usuario de inventario tiene un sudoers acotado (solo lectura).</span></li>
            <li><i class="bi bi-check2-circle" aria-hidden="true"></i> <span><strong>python3</strong>: la recolección usa Ansible.</span></li>
          </ul>
          <p class="note"><i class="bi bi-info-circle" aria-hidden="true"></i>
            <span><strong>Proxmox no trae sudo de serie.</strong> Marca «Instalar sudo si falta».</span></p>
        </section>
      </aside>
    </div>
  `,
  styleUrls: ['./enrollment.scss', './enroll-start.scss'],
})
export class EnrollStart implements OnInit {
  private readonly api = inject(EnrollmentApi);
  private readonly settings = inject(SettingsApi);
  private readonly commands = inject(IssuedCommands);
  private readonly router = inject(Router);
  protected readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly store = inject(OrganizationStore);

  /** Organización y política desde el alta (QoL-6b). */
  protected readonly organizeOpen = signal(false);
  protected readonly tags = signal<string[]>([]);
  protected readonly projectIds = signal<string[]>([]);
  protected readonly presets = [...INVENTORY_POLICY_PRESETS];
  protected readonly preset = signal<string | null>('standard');
  protected readonly policy = signal<InventoryPolicyFields>({});
  protected presetDescription(): string {
    return (
      this.presets.find((p) => p.id === this.preset())?.description ??
      'Regla propia a medida'
    );
  }

  /** ¿Hay un proveedor sano con CA SSH? null mientras no se sabe. */
  protected readonly caAvailable = signal<boolean | null>(null);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).nonNullable.group({
    host: ['', [Validators.required, Validators.pattern(HOST_PATTERN)]],
    port: [22, [Validators.required, Validators.min(1), Validators.max(65535)]],
    name: ['', Validators.maxLength(255)],
    installSudo: [false],
    // Sin marcar hasta saber si hay CA; si no se toca, decide la API (la misma regla).
    authMode: [null as SshAuthMode | null],
    // Acceso de administración (sesión 22): desmarcado y solo en modo CA.
    adminAccess: [{ value: false, disabled: true }],
  });

  protected applyPreset(id: string): void {
    const preset = this.presets.find((p) => p.id === id);
    if (!preset) return;
    this.preset.set(id);
    this.policy.set({ ...preset.fields });
  }

  /** Retocar el formulario deja de ser la plantilla (salvo que vuelva a coincidir). */
  protected setPolicy(fields: InventoryPolicyFields): void {
    this.policy.set(fields);
    const same = this.presets.find((p) =>
      INVENTORY_RULE_FIELDS.every(
        (f) =>
          JSON.stringify(p.fields[f] ?? null) === JSON.stringify(fields[f] ?? null),
      ),
    );
    this.preset.set(same?.id ?? null);
  }

  private organization(): Record<string, unknown> {
    const policy = Object.fromEntries(
      INVENTORY_RULE_FIELDS.filter(
        (f) => this.policy()[f] !== null && this.policy()[f] !== undefined,
      ).map((f) => [f, this.policy()[f]]),
    ) as InventoryPolicyFields;
    return {
      ...(this.tags().length ? { tags: this.tags() } : {}),
      ...(this.projectIds().length && this.auth.can('projects.write')
        ? { projectIds: this.projectIds() }
        : {}),
      ...(Object.keys(policy).length && this.auth.can('policy.write')
        ? { policy }
        : {}),
    };
  }

  /** Tags y proyectos se piden al abrir la sección (casi nadie la abre). */
  protected toggleOrganize(open: boolean): void {
    this.organizeOpen.set(open);
    if (!open) return;
    this.store.ensureProjects();
    this.store.ensureTags();
  }

  ngOnInit(): void {
    // La casilla del acceso de administración solo vale con certificados.
    this.form.controls.authMode.valueChanges
      .pipe(startWith(this.form.controls.authMode.value), takeUntilDestroyed(this.destroyRef))
      .subscribe((mode) => {
        const control = this.form.controls.adminAccess;
        if (mode === 'ca_certificate') control.enable({ emitEvent: false });
        else {
          control.setValue(false, { emitEvent: false });
          control.disable({ emitEvent: false });
        }
      });
    // Por defecto, certificados si hay CA; sin CA (o si no se puede saber), clave estática.
    const preselect = (ca: boolean) => {
      this.caAvailable.set(ca);
      if (!this.form.controls.authMode.dirty)
        this.form.controls.authMode.setValue(
          ca ? 'ca_certificate' : 'static_key',
        );
    };
    this.settings.secretProviders().subscribe({
      next: (providers) =>
        preselect(
          providers.some(
            (p) => p.healthy && p.capabilities.includes('ssh_certificates'),
          ),
        ),
      error: () => preselect(false),
    });
  }

  async submit(): Promise<void> {
    if (this.form.invalid || this.loading()) {
      this.form.markAllAsTouched();
      return;
    }
    this.loading.set(true);
    this.error.set(null);
    const { host, port, name, installSudo, authMode, adminAccess } = this.form.getRawValue();
    try {
      const res = await firstValueFrom(
        this.api.enroll({
          host: host.trim(),
          port,
          ...(name.trim() ? { name: name.trim() } : {}),
          installSudo,
          // Solo si se ha elegido: si no, la API usa CA cuando la hay (como la preselección).
          ...(this.form.controls.authMode.dirty && authMode
            ? { authMode }
            : {}),
          // Va con el modo explícito: el acceso de administración exige CA.
          ...(adminAccess && authMode === 'ca_certificate' && this.auth.can('users.manage')
            ? { adminAccess: 'operator' as const, authMode }
            : {}),
          ...this.organization(),
        }),
      );
      this.commands.set(res.enrollment);
      await this.router.navigate(['/assets', res.asset.id, 'enrollment']);
    } catch (err) {
      this.error.set(
        apiErrorMessage(err, 'No se pudo dar de alta el servidor.'),
      );
    } finally {
      this.loading.set(false);
    }
  }
}
