import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type {
  Enrollment,
  EnrollmentProgress,
  IssuedEnrollment,
} from '@infraward/shared-types';
import { Subject } from 'rxjs';
import { SseClient, type SseMessage } from '../../core/api/sse-client';
import { storeSession } from '../../testing/session';
import { EnrollProgress } from './enroll-progress';
import { IssuedCommands } from './issued-commands';

const FP = `SHA256:${'a'.repeat(43)}`;

const enrollment: Enrollment = {
  id: 'e1',
  assetId: 'a1',
  method: 'script',
  purpose: 'initial',
  authMode: 'static_key',
  adminAccess: null,
  status: 'pending',
  expired: false,
  expiresAt: '2026-10-10T12:20:00.000Z',
  publicKey: 'ssh-ed25519 AAAA inventory@infraward:a1',
  sshUser: 'inventory',
  reportedHostKeys: [],
  sudoersVersion: null,
  error: null,
  jobId: null,
  confirmedAt: null,
  verifiedAt: null,
  createdAt: '2026-10-10T12:00:00.000Z',
};

const issued: IssuedEnrollment = {
  ...enrollment,
  command: 'curl -fsSL http://iw/enroll/TOKEN | bash -s -- --install-sudo',
  embeddedCommand: "echo 'H4sI' | base64 -d | gunzip | bash -s -- --install-sudo",
  manualCommand: "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA' >> ~/.ssh/authorized_keys",
};

function progress(over: Partial<EnrollmentProgress> = {}): EnrollmentProgress {
  return {
    assetId: 'a1',
    assetName: 'srv1',
    assetStatus: 'pending_enrollment',
    phase: 'waiting',
    enrollment,
    jobs: [],
    truncated: false,
    at: '2026-10-10T12:00:00.000Z',
    ...over,
  };
}

describe('EnrollProgress', () => {
  let events: Subject<SseMessage>;
  let http: HttpTestingController;
  let streamed: string[];

  async function setup(
    role: 'admin' | 'viewer' = 'admin',
    withCommands = true,
    commands: IssuedEnrollment = issued,
  ) {
    storeSession(role);
    events = new Subject();
    streamed = [];
    TestBed.configureTestingModule({
      imports: [EnrollProgress],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: SseClient,
          useValue: {
            stream: (path: string) => {
              streamed.push(path);
              return events.asObservable();
            },
          },
        },
      ],
    });
    if (withCommands) TestBed.inject(IssuedCommands).set(commands);
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(EnrollProgress);
    fixture.componentRef.setInput('id', 'a1');
    await fixture.whenStable();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  async function emit(fixture: { whenStable(): Promise<unknown> }, p: EnrollmentProgress) {
    events.next({ type: 'progress', data: JSON.stringify(p) });
    await fixture.whenStable();
  }

  const button = (el: HTMLElement, action: string) =>
    el.querySelector<HTMLButtonElement>(`[data-action="${action}"] button`)!;

  beforeEach(() => {
    sessionStorage.clear();
    // jsdom no lo tiene; lo usa la lista de pestañas.
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe = vi.fn();
        unobserve = vi.fn();
        disconnect = vi.fn();
      },
    );
  });
  afterEach(() => {
    http.verify();
    vi.unstubAllGlobals();
  });

  it('sigue el SSE del asset y marca el paso activo', async () => {
    const { fixture, el } = await setup();
    expect(streamed).toEqual(['/assets/a1/enrollment/events']);
    await emit(fixture, progress());
    expect(el.querySelector('[data-phase="waiting"]')).not.toBeNull();
    expect(el.querySelector('[data-step="2"]')?.getAttribute('aria-current')).toBe('step');
    expect(el.querySelector('[data-step="1"]')?.classList).toContain('done');

    await emit(fixture, progress({ phase: 'connecting', enrollment: { ...enrollment, status: 'confirmed' } }));
    expect(el.querySelector('[data-phase="connecting"]')).not.toBeNull();
    expect(el.querySelector('[data-step="3"]')?.getAttribute('aria-current')).toBe('step');

    await emit(
      fixture,
      progress({
        phase: 'scanning',
        assetStatus: 'active',
        enrollment: { ...enrollment, status: 'verified' },
        jobs: [
          { id: 'j1', name: 'enrollment.verify', assetId: 'a1', state: 'completed', progress: 100, message: 'Conexión verificada', failedReason: null },
          { id: 'j2', name: 'asset.collect', assetId: 'a1', state: 'active', progress: 40, message: 'Ejecutando Ansible', failedReason: null },
        ],
      }),
    );
    const collect = el.querySelector('[data-job="asset.collect"]');
    expect(collect?.textContent).toContain('Recolección');
    expect(collect?.textContent).toContain('0/1');
    expect(collect?.textContent).toContain('Ejecutando Ansible');

    await emit(fixture, progress({ phase: 'ready', assetStatus: 'active', enrollment: { ...enrollment, status: 'verified' } }));
    expect(el.querySelector('[data-phase="ready"]')?.textContent).toContain('srv1 está dado de alta');
    expect(el.querySelector('[data-step="5"]')?.classList).toContain('done');
  });

  it('muestra los tres comandos con el aviso de sudo y python3', async () => {
    const { fixture, el } = await setup();
    await emit(fixture, progress());
    expect(el.textContent).toContain('sudo');
    expect(el.textContent).toContain('python3');
    expect(el.textContent).toContain('como root');
    expect(el.querySelector('[data-command="url"]')?.textContent).toBe(issued.command);
  });

  it('modo CA: sin pestaña manual y el texto dice que configura sshd con la CA', async () => {
    const ca: IssuedEnrollment = {
      ...issued,
      authMode: 'ca_certificate',
      purpose: 'ca_migration',
      publicKey: null,
      manualCommand: null,
    };
    const { fixture, el } = await setup('admin', true, ca);
    await emit(fixture, progress({ enrollment: ca }));
    const tabs = [...el.querySelectorAll('p-tablist [role="tab"]')].map((t) =>
      t.textContent?.trim(),
    );
    expect(tabs).toEqual(['Por URL', 'Script embebido (VPN/NAT)']);
    expect(el.textContent).toContain('certificados de vida corta de la CA');
    expect(el.textContent).toContain('quita la clave estática de este servidor');
    expect(el.querySelector('[data-command="manual"]')).toBeNull();
  });

  it('script embebido: confirma solo con huellas reconocidas, que se envían', async () => {
    const { fixture, el } = await setup();
    await emit(fixture, progress());
    const component = fixture.componentInstance as unknown as {
      tab: { set(v: string): void };
      fingerprintsText: { set(v: string): void };
    };
    component.tab.set('embedded');
    await fixture.whenStable();
    expect(el.querySelector('[data-command="embedded"]')?.textContent).toBe(issued.embeddedCommand);
    expect(button(el, 'confirm-embedded').disabled).toBe(true);

    component.fingerprintsText.set('texto sin huellas');
    await fixture.whenStable();
    expect(el.textContent).toContain('No se reconoce ninguna huella');
    expect(button(el, 'confirm-embedded').disabled).toBe(true);

    component.fingerprintsText.set(`----- infraward host keys -----\nED25519 ${FP}\n----- fin -----`);
    await fixture.whenStable();
    expect(el.querySelector('[data-fingerprints]')?.textContent).toContain(FP);
    button(el, 'confirm-embedded').click();
    const req = http.expectOne('/api/assets/a1/enrollment/confirm');
    expect(req.request.body).toEqual({
      sshUser: 'inventory',
      hostKeys: [{ type: 'ED25519', fingerprint: FP }],
    });
    req.flush({ ...enrollment, status: 'confirmed' });
  });

  it('manual: no deja confirmar con root', async () => {
    const { fixture, el } = await setup();
    await emit(fixture, progress());
    const component = fixture.componentInstance as unknown as {
      tab: { set(v: string): void };
      manualUser: { set(v: string): void };
    };
    component.tab.set('manual');
    component.manualUser.set('root');
    await fixture.whenStable();
    expect(el.textContent).toContain('Nunca root');
    expect(button(el, 'confirm-manual').disabled).toBe(true);
    component.manualUser.set('deploy');
    await fixture.whenStable();
    button(el, 'confirm-manual').click();
    const req = http.expectOne('/api/assets/a1/enrollment/confirm');
    expect(req.request.body).toEqual({ sshUser: 'deploy' });
    req.flush({ ...enrollment, status: 'confirmed' });
  });

  it('sin los comandos en memoria (recarga), ofrece generar otro con la opción de sudo', async () => {
    const { fixture, el } = await setup('admin', false);
    await emit(fixture, progress());
    expect(el.querySelector('[data-command="url"]')).toBeNull();
    expect(el.textContent).toContain('El comando solo se muestra al generarlo');
    const component = fixture.componentInstance as unknown as { installSudo: { set(v: boolean): void } };
    component.installSudo.set(true);
    button(el, 'regenerate').click();
    const req = http.expectOne('/api/assets/a1/enrollment/token');
    // Mismo modo que el enrolamiento en curso.
    expect(req.request.body).toEqual({ installSudo: true, authMode: 'static_key' });
    req.flush({ ...issued, id: 'e2' });
    await emit(fixture, progress({ enrollment: { ...enrollment, id: 'e2' } }));
    expect(el.querySelector('[data-command="url"]')?.textContent).toBe(issued.command);
  });

  it('fallo: muestra el error y permite reintentar', async () => {
    const { fixture, el } = await setup();
    await emit(
      fixture,
      progress({
        phase: 'failed',
        enrollment: { ...enrollment, status: 'failed', error: 'La host key del servidor ha cambiado… posible suplantación' },
      }),
    );
    expect(el.querySelector('[data-phase="failed"]')?.textContent).toContain('posible suplantación');
    button(el, 'retry').click();
    http.expectOne('/api/assets/a1/enrollment/verify').flush({ ...enrollment, status: 'confirmed' });
  });

  it('un usuario sin rol admin ve el progreso pero no las acciones', async () => {
    const { fixture, el } = await setup('viewer');
    await emit(fixture, progress());
    expect(el.querySelector('[data-action="regenerate"]')).toBeNull();
    await emit(fixture, progress({ phase: 'failed', enrollment: { ...enrollment, status: 'failed', error: 'x' } }));
    expect(el.querySelector('[data-action="retry"]')).toBeNull();
  });

  it('error del flujo (404)', async () => {
    const { fixture, el } = await setup();
    const { SseHttpError } = await import('../../core/api/sse-client');
    events.error(new SseHttpError(404));
    await fixture.whenStable();
    expect(el.textContent).toContain('no existe');
  });
});
