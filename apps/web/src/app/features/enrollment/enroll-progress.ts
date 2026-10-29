import { DatePipe, NgTemplateOutlet } from '@angular/common';
import {
  Component,
  computed,
  DestroyRef,
  inject,
  input,
  linkedSignal,
  signal,
} from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  ENROLL_SSH_USER,
  parseHostKeyFingerprints,
  type EnrollmentProgress,
  type IssuedEnrollment,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressBarModule } from '@openng/optimus-ui/progressbar';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { StepperModule } from '@openng/optimus-ui/stepper';
import { TabsModule } from '@openng/optimus-ui/tabs';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import {
  catchError,
  EMPTY,
  filter,
  firstValueFrom,
  map,
  switchMap,
  tap,
} from 'rxjs';
import { EnrollmentApi } from '../../core/api/enrollment-api';
import { SseClient, SseHttpError } from '../../core/api/sse-client';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import {
  chainFailures,
  ENROLL_STEPS,
  groupJobs,
  JOB_LABELS,
  JOB_STATE_LABELS,
  JOB_STATE_SEVERITY,
  stepOf,
} from './enrollment-steps';
import { IssuedCommands } from './issued-commands';

/** Usuario POSIX (como en la API); nunca root. */
const SSH_USER = /^[a-z_][a-z0-9_-]{0,31}$/;

export type CommandTab = 'url' | 'embedded' | 'manual';

/**
 * Stepper del alta (DESIGN §7): Comando generado → Esperando clave → Conectando → Escaneando →
 * Listo, alimentado por el SSE de progreso. Los comandos solo están si se acaban de generar en
 * esta pestaña (la API no los vuelve a dar).
 */
@Component({
  selector: 'app-enroll-progress',
  imports: [
    DatePipe,
    NgTemplateOutlet,
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    CheckboxModule,
    InputTextModule,
    MessageModule,
    ProgressBarModule,
    SkeletonModule,
    StepperModule,
    TabsModule,
    TagModule,
    TextareaModule,
  ],
  templateUrl: './enroll-progress.html',
  styleUrl: './enrollment.scss',
})
export class EnrollProgress {
  private readonly api = inject(EnrollmentApi);
  private readonly sse = inject(SseClient);
  private readonly commands = inject(IssuedCommands);
  protected readonly auth = inject(AuthService);

  /** Parámetro `:id` de la ruta. */
  readonly id = input.required<string>();

  protected readonly steps = ENROLL_STEPS;
  protected readonly jobLabels: Readonly<Record<string, string>> = JOB_LABELS;
  protected readonly jobStateLabels: Readonly<Record<string, string>> =
    JOB_STATE_LABELS;
  protected readonly jobStateSeverity = JOB_STATE_SEVERITY;
  protected readonly enrollUser = ENROLL_SSH_USER;

  protected readonly progress = signal<EnrollmentProgress | null>(null);
  protected readonly streamError = signal<string | null>(null);

  /** Comandos emitidos en esta pestaña para el asset (se renuevan al generar otro). */
  protected readonly issued = linkedSignal<string, IssuedEnrollment | null>({
    source: this.id,
    computation: (id) => this.commands.get(id),
  });
  /** Los comandos solo valen para el enrolamiento pendiente vigente. */
  protected readonly commandsShown = computed(() => {
    const issued = this.issued();
    const p = this.progress();
    if (!issued || !p) return null;
    return p.enrollment.id === issued.id && p.enrollment.status === 'pending'
      ? issued
      : null;
  });

  protected readonly phase = computed(() => this.progress()?.phase ?? null);
  protected readonly step = computed(() => {
    const phase = this.phase();
    return phase ? stepOf(phase) : 1;
  });
  protected readonly groups = computed(() =>
    groupJobs(this.progress()?.jobs ?? []),
  );
  protected readonly failures = computed(() =>
    chainFailures(this.progress()?.jobs ?? []),
  );
  protected readonly verifyJob = computed(
    () =>
      this.progress()?.jobs.find((j) => j.name === 'enrollment.verify') ?? null,
  );

  // --- Acciones (admin) ---
  protected readonly tab = signal<CommandTab>('url');
  protected readonly installSudo = linkedSignal(() =>
    (this.issued()?.command ?? '').includes('--install-sudo'),
  );
  protected readonly fingerprintsText = signal('');
  protected readonly fingerprints = computed(() =>
    parseHostKeyFingerprints(this.fingerprintsText()),
  );
  protected readonly manualUser = signal('');
  protected readonly manualUserValid = computed(() => {
    const user = this.manualUser().trim();
    return SSH_USER.test(user) && user !== 'root';
  });
  protected readonly busy = signal(false);
  protected readonly actionError = signal<string | null>(null);
  protected readonly copied = signal<string | null>(null);

  constructor() {
    toObservable(this.id)
      .pipe(
        tap(() => {
          this.progress.set(null);
          this.streamError.set(null);
        }),
        switchMap((id) =>
          this.sse.stream(this.api.eventsPath(id)).pipe(
            filter((m) => m.type === 'progress'),
            map((m) => JSON.parse(m.data) as EnrollmentProgress),
            catchError((err: unknown) => {
              this.streamError.set(streamErrorMessage(err));
              return EMPTY;
            }),
          ),
        ),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe((p) => {
        this.progress.set(p);
        if (p.phase !== 'waiting') this.commands.clear(p.assetId);
      });
  }

  async regenerate(): Promise<void> {
    await this.act(async () => {
      const issued = await firstValueFrom(
        // Mismo modo y acceso de administración que el enrolamiento en curso (una migración a CA
        // sigue siéndolo; activar el acceso vuelve a pedir la reautenticación si caducó).
        this.api.issueToken(
          this.id(),
          this.installSudo(),
          this.progress()?.enrollment.authMode,
          this.progress()?.enrollment.adminAccess ?? undefined,
        ),
      );
      this.commands.set(issued);
      this.issued.set(issued);
      this.fingerprintsText.set('');
    }, 'No se pudo generar el comando.');
  }

  /** Script embebido: confirma con las huellas pegadas (el worker solo aceptará una de ellas). */
  async confirmEmbedded(): Promise<void> {
    const hostKeys = this.fingerprints();
    if (hostKeys.length === 0) return;
    await this.act(
      () =>
        firstValueFrom(
          this.api.confirm(this.id(), { sshUser: ENROLL_SSH_USER, hostKeys }),
        ),
      'No se pudo confirmar el alta.',
    );
  }

  /** Clave añadida a mano: sin huellas, el worker fija la primera que vea (TOFU). */
  async confirmManual(): Promise<void> {
    if (!this.manualUserValid()) return;
    await this.act(
      () =>
        firstValueFrom(
          this.api.confirm(this.id(), { sshUser: this.manualUser().trim() }),
        ),
      'No se pudo confirmar el alta.',
    );
  }

  async retry(): Promise<void> {
    await this.act(
      () => firstValueFrom(this.api.retry(this.id())),
      'No se pudo reintentar la verificación.',
    );
  }

  async copy(key: string, text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(key);
      setTimeout(() => {
        if (this.copied() === key) this.copied.set(null);
      }, 2000);
    } catch {
      this.actionError.set(
        'No se pudo copiar: selecciona el texto y cópialo a mano.',
      );
    }
  }

  private async act(
    action: () => Promise<unknown>,
    fallback: string,
  ): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.actionError.set(null);
    try {
      await action();
    } catch (err) {
      this.actionError.set(apiErrorMessage(err, fallback));
    } finally {
      this.busy.set(false);
    }
  }
}

function streamErrorMessage(err: unknown): string {
  if (err instanceof SseHttpError) {
    if (err.status === 404)
      return 'Este asset no existe o no se dio de alta con enrolamiento.';
    if (err.status === 400) return 'Identificador de asset no válido.';
    if (err.status === 401) return 'La sesión ha caducado.';
  }
  return 'No se pudo seguir el progreso del alta.';
}
