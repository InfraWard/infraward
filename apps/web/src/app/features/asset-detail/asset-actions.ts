import {
  Component,
  computed,
  DestroyRef,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import type {
  Asset,
  AssetRuntimeState,
  CredentialRevocation,
  JobRunSummary,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressBarModule } from '@openng/optimus-ui/progressbar';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import {
  catchError,
  combineLatest,
  firstValueFrom,
  map,
  of,
  startWith,
  Subject,
  switchMap,
  type Observable,
} from 'rxjs';
import { EnrollmentApi } from '../../core/api/enrollment-api';
import { InventoryApi } from '../../core/api/inventory-api';
import { JobsApi } from '../../core/api/jobs-api';
import { SettingsApi } from '../../core/api/settings-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { JOB_LABELS } from '../../shared/labels';
import { pollWhile } from '../../shared/poll';
import { IssuedCommands } from '../enrollment/issued-commands';
import { AuthService } from '../../core/auth/auth.service';
import {
  ACTION_PERMISSION,
  availableActions,
  type AssetActionId,
} from './available-actions';

/** Con un job en curso para el asset, se vuelve a mirar con esta cadencia. */
export const ACTIONS_POLL_MS = 3000;

const LABELS: Record<AssetActionId, { label: string; icon: string }> = {
  collect: { label: 'Recolectar de nuevo', icon: 'bi-cloud-download' },
  scan: { label: 'Escanear vulnerabilidades', icon: 'bi-shield-check' },
  enrollment: { label: 'Ver el comando de alta', icon: 'bi-terminal' },
  regenerate: { label: 'Regenerar el comando', icon: 'bi-arrow-clockwise' },
  'migrate-ca': { label: 'Pasar a certificados (CA)', icon: 'bi-patch-check' },
  retire: { label: 'Dar de baja', icon: 'bi-archive' },
  purge: { label: 'Purgar', icon: 'bi-trash' },
};

/**
 * Acciones de la ficha (solo admin). Mientras haya un job en cola o en curso para el asset (o para
 * la imagen de un contenedor) los botones se deshabilitan y se muestra su progreso; al terminar,
 * la ficha se recarga. Dar de baja, purgar y regenerar el comando piden confirmación.
 */
@Component({
  selector: 'app-asset-actions',
  imports: [
    FormsModule,
    RouterLink,
    ButtonModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    ProgressBarModule,
    TooltipModule,
  ],
  templateUrl: './asset-actions.html',
  styleUrl: './asset-actions.scss',
})
export class AssetActions {
  private readonly inventory = inject(InventoryApi);
  private readonly enrollment = inject(EnrollmentApi);
  private readonly jobs = inject(JobsApi);
  private readonly settings = inject(SettingsApi);
  private readonly commands = inject(IssuedCommands);
  private readonly confirmation = inject(ConfirmationService);
  private readonly messages = inject(MessageService);
  private readonly router = inject(Router);
  private readonly auth = inject(AuthService);

  readonly asset = input.required<Asset>();
  readonly runtimeState = input<AssetRuntimeState | null>(null);
  readonly sudoersOutdated = input(false);
  readonly sshCaOutdated = input(false);
  /** Ha terminado un job o ha cambiado el asset: la ficha tiene que recargarse. */
  readonly changed = output<void>();

  protected readonly labels = LABELS;
  protected readonly jobLabels: Readonly<Record<string, string>> = JOB_LABELS;
  protected readonly actions = computed(() =>
    availableActions(this.asset(), {
      runtimeState: this.runtimeState(),
      sudoersOutdated: this.sudoersOutdated(),
      sshCaOutdated: this.sshCaOutdated(),
      caAvailable: this.caAvailable(),
    }).filter((a) => this.auth.can(ACTION_PERMISSION[a.id])),
  );

  /** Las destructivas van aparte, a la derecha del todo. */
  protected readonly mainActions = computed(() =>
    this.actions().filter((a) => a.id !== 'retire' && a.id !== 'purge'),
  );
  protected readonly dangerActions = computed(() =>
    this.actions().filter((a) => a.id === 'retire' || a.id === 'purge'),
  );

  /** ¿Algún proveedor sano con CA SSH? (para «Pasar a certificados»). null mientras no se sabe. */
  protected readonly caAvailable = signal<boolean | null>(null);

  /** Jobs en cola o en curso del asset; null mientras no se sabe. */
  protected readonly running = signal<JobRunSummary[] | null>(null);
  protected readonly busy = computed(() => (this.running()?.length ?? 0) > 0);
  protected readonly pending = signal<AssetActionId | null>(null);
  protected readonly error = signal<string | null>(null);

  // Purga: hay que escribir el nombre del asset. Puede ser otro (el duplicado de este).
  protected readonly purgeOpen = signal(false);
  protected readonly purgeTarget = signal<{ id: string; name: string } | null>(
    null,
  );
  protected readonly purgeName = signal('');
  protected readonly purgeMatches = computed(
    () => this.purgeName().trim() === this.purgeTarget()?.name,
  );
  // Tras dar de baja o purgar: cómo quitar el acceso de InfraWard del servidor.
  protected readonly revocations = signal<CredentialRevocation[]>([]);
  private afterRevocations: (() => void) | null = null;

  private readonly watch$ = new Subject<void>();

  constructor() {
    // Solo para «Pasar a certificados» (assets.write); el estado de los proveedores exige
    // secrets.status (admin y editor lo tienen).
    if (!this.auth.can('secrets.status')) this.caAvailable.set(false);
    else
      this.settings
        .secretProviders()
        .pipe(takeUntilDestroyed())
        .subscribe({
          next: (providers) =>
            this.caAvailable.set(
              providers.some(
                (p) => p.healthy && p.capabilities.includes('ssh_certificates'),
              ),
            ),
          error: () => this.caAvailable.set(false),
        });
    let wasBusy = false;
    // Al cambiar de asset y tras cada acción, se vuelve a mirar (y a sondear si hay algo en curso).
    combineLatest([
      toObservable(computed(() => this.asset().id)),
      this.watch$.pipe(startWith(undefined)),
    ])
      .pipe(
        switchMap(([id]) =>
          pollWhile(
            () => this.runningJobs(id),
            (runs) => runs.length > 0,
            ACTIONS_POLL_MS,
          ),
        ),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe((runs) => {
        this.running.set(runs);
        const nowBusy = runs.length > 0;
        if (wasBusy && !nowBusy) this.changed.emit();
        wasBusy = nowBusy;
      });
  }

  private runningJobs(assetId: string): Observable<JobRunSummary[]> {
    return this.jobs.list({ assetId, state: 'running', limit: 20 }).pipe(
      map((page) => page.items),
      // Si no se puede consultar, no se bloquean las acciones (la API dirá si no se puede).
      catchError(() => of<JobRunSummary[]>([])),
    );
  }

  /** «en curso · 40 % · Recogiendo facts» o «en cola». */
  runText(run: JobRunSummary): string {
    if (run.state === 'queued') return 'en cola';
    return ['en curso', `${run.progress} %`, run.message]
      .filter(Boolean)
      .join(' · ');
  }

  disabledReason(id: AssetActionId, reason: string | null): string | null {
    if (reason) return reason;
    if (this.busy() && id !== 'enrollment')
      return 'Hay una tarea en curso para este asset';
    return null;
  }

  run(id: AssetActionId): void {
    switch (id) {
      case 'collect':
        void this.act(id, async () => {
          await firstValueFrom(this.inventory.collect(this.asset().id));
          this.toast(
            'Recolección encolada',
            'Se verá su progreso aquí y en Actividad.',
          );
          this.watch$.next();
        });
        return;
      case 'scan':
        void this.act(id, async () => {
          const { jobs } = await firstValueFrom(
            this.inventory.scan(this.asset().id),
          );
          this.toast('Escaneo encolado', scanMessage(jobs));
          this.watch$.next();
        });
        return;
      case 'enrollment':
        void this.router.navigate(['/assets', this.asset().id, 'enrollment']);
        return;
      case 'regenerate': {
        // Activo = actualizar (sudoers o CA SSH) volviendo a ejecutar el script con la misma clave.
        const update = this.asset().status === 'active';
        this.confirmation.confirm({
          header: update
            ? 'Actualizar el servidor'
            : 'Regenerar el comando de alta',
          message: update
            ? 'Se genera un comando para volver a ejecutar el script de alta en el servidor: actualiza el sudoers y la CA SSH sin cambiar la clave ni el modo de acceso. ¿Continuar?'
            : 'El comando anterior dejará de funcionar. ¿Generar uno nuevo?',
          icon: 'bi bi-arrow-clockwise',
          acceptLabel: update ? 'Generar el comando' : 'Regenerar',
          rejectLabel: 'Cancelar',
          rejectButtonProps: { severity: 'secondary', text: true },
          accept: () =>
            void this.act(id, async () => {
              const issued = await firstValueFrom(
                this.enrollment.issueToken(this.asset().id, false),
              );
              // El comando lleva el token: solo en memoria, para que el stepper lo muestre.
              this.commands.set(issued);
              await this.router.navigate([
                '/assets',
                this.asset().id,
                'enrollment',
              ]);
            }),
        });
        return;
      }
      case 'migrate-ca':
        this.confirmation.confirm({
          header: 'Pasar a certificados de la CA',
          message:
            'Se genera un comando que configura sshd para aceptar solo certificados de vida corta de la CA de InfraWard y quita la clave estática del servidor. Cuando InfraWard conecte con un certificado, la clave estática se borra también del proveedor de secretos. ¿Continuar?',
          icon: 'bi bi-patch-check',
          acceptLabel: 'Generar el comando',
          rejectLabel: 'Cancelar',
          rejectButtonProps: { severity: 'secondary', text: true },
          accept: () =>
            void this.act(id, async () => {
              const issued = await firstValueFrom(
                this.enrollment.issueToken(
                  this.asset().id,
                  false,
                  'ca_certificate',
                ),
              );
              this.commands.set(issued);
              await this.router.navigate([
                '/assets',
                this.asset().id,
                'enrollment',
              ]);
            }),
        });
        return;
      case 'retire':
        this.confirmation.confirm({
          header: `Dar de baja ${this.asset().name}`,
          message:
            'Se retira el asset y todo lo que contiene (se conserva su historial). Si tiene credenciales, se borran del proveedor de secretos.',
          icon: 'bi bi-archive',
          acceptLabel: 'Dar de baja',
          rejectLabel: 'Cancelar',
          acceptButtonProps: { severity: 'danger' },
          rejectButtonProps: { severity: 'secondary', text: true },
          accept: () =>
            void this.act(id, async () => {
              const result = await firstValueFrom(
                this.inventory.remove(this.asset().id, false),
              );
              this.toast(
                'Dado de baja',
                `${result.affectedIds.length} ${result.affectedIds.length === 1 ? 'asset retirado' : 'assets retirados'}.`,
              );
              this.showRevocations(result.revocations, () =>
                this.changed.emit(),
              );
            }),
        });
        return;
      case 'purge':
        this.openPurge(this.asset());
        return;
    }
  }

  /** Abre la confirmación de purga de este asset o de otro (p. ej. su duplicado). */
  openPurge(target: { id: string; name: string }): void {
    this.purgeTarget.set({ id: target.id, name: target.name });
    this.purgeName.set('');
    this.purgeOpen.set(true);
  }

  async purge(): Promise<void> {
    const target = this.purgeTarget();
    if (!target || !this.purgeMatches()) return;
    this.purgeOpen.set(false);
    const self = target.id === this.asset().id;
    await this.act('purge', async () => {
      const result = await firstValueFrom(
        this.inventory.remove(target.id, true),
      );
      this.toast(
        'Purgado',
        `${result.affectedIds.length} ${result.affectedIds.length === 1 ? 'asset borrado' : 'assets borrados'}.`,
      );
      this.showRevocations(result.revocations, () =>
        self ? void this.router.navigate(['/inventory']) : this.changed.emit(),
      );
    });
  }

  closeRevocations(): void {
    this.revocations.set([]);
    const next = this.afterRevocations;
    this.afterRevocations = null;
    next?.();
  }

  async copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.toast('Copiado', 'Comando copiado al portapapeles.');
    } catch {
      // Sin permiso de portapapeles: el comando sigue a la vista para copiarlo a mano.
    }
  }

  private showRevocations(
    revocations: CredentialRevocation[],
    then: () => void,
  ): void {
    // Un conector de dominios solo borra su token: no hay servidor al que quitar el acceso.
    revocations = revocations.filter((r) => r.command);
    if (revocations.length === 0) {
      then();
      return;
    }
    this.afterRevocations = then;
    this.revocations.set(revocations);
  }

  private async act(id: AssetActionId, fn: () => Promise<void>): Promise<void> {
    this.pending.set(id);
    this.error.set(null);
    try {
      await fn();
    } catch (err) {
      this.error.set(
        apiErrorMessage(err, `No se pudo ${LABELS[id].label.toLowerCase()}.`),
      );
    } finally {
      this.pending.set(null);
    }
  }

  private toast(summary: string, detail: string): void {
    this.messages.add({ severity: 'success', summary, detail, life: 4000 });
  }
}

/** «Se analizarán con Trivy el SBOM del sistema y 2 imágenes.» */
export function scanMessage(jobs: readonly { name: string }[]): string {
  const images = jobs.filter((j) => j.name === 'image.scan').length;
  const parts = [
    jobs.some((j) => j.name === 'host.scan') ? 'el SBOM del sistema' : null,
    images ? `${images} ${images === 1 ? 'imagen' : 'imágenes'}` : null,
  ].filter(Boolean);
  return parts.length
    ? `Se analizará${parts.length > 1 || images > 1 ? 'n' : ''} con Trivy ${parts.join(' y ')}.`
    : 'Nada que analizar.';
}
