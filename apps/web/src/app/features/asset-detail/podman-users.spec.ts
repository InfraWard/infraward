import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { PODMAN_ENABLE_SCRIPT, type Asset } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { PodmanUsersCard, podmanEnableTerminalUrl } from './podman-users';

const user = (uid: number, name: string | null, enabled: boolean, socket: boolean, containers = 0) => ({
  uid, name, enabled, socket, storage: true, linger: false, containers,
});

async function render(status: object) {
  storeSession('editor');
  TestBed.configureTestingModule({
    imports: [PodmanUsersCard],
    providers: [provideHttpClient(), provideHttpClientTesting(), MessageService],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(PodmanUsersCard);
  fixture.componentRef.setInput('asset', {
    id: 's1',
    type: 'server',
    name: 'pod01',
    facts: {
      detected: {
        podman: '5.4.2',
        podmanUsers: [
          user(1000, 'alice', true, true, 1),
          user(1001, 'bob', true, false),
          user(1002, 'carol', false, false, 2),
          user(1003, null, false, false, 1),
        ],
      },
    },
  } as unknown as Asset);
  fixture.detectChanges();
  http.expectOne('/api/assets/s1/terminal').flush(status);
  await fixture.whenStable();
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement };
}

const ALLOWED = {
  allowed: true,
  available: true,
  reason: null,
  host: { id: 's1', name: 'pod01' },
  account: 'infraward-admin',
};

describe('PodmanUsersCard', () => {
  it('lista los usuarios detectados con su estado y ofrece habilitar los que faltan (con nombre)', async () => {
    const { fixture, el } = await render({ ...ALLOWED, allowed: false });
    const states = [...el.querySelectorAll('[data-podman-state]')].map((t) =>
      t.getAttribute('data-podman-state'),
    );
    expect(states).toEqual(['inventoried', 'no_socket', 'not_enabled', 'not_enabled']);
    expect(el.textContent).toContain('uid 1003');
    el.querySelector<HTMLButtonElement>('[data-action="podman-enable"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    const command = document.querySelector('[data-podman-command]')!.textContent!;
    expect(command.startsWith("sudo sh -s -- bob carol <<'INFRAWARD_PODMAN'")).toBe(true);
    expect(command).toContain(PODMAN_ENABLE_SCRIPT.slice(0, 40));
    // Sin permiso de terminal: solo el comando.
    expect(document.querySelector('[data-action="podman-run"]')).toBeNull();
  });

  it('con terminal: «Ejecutar con infraward-admin» abre la terminal de solo lectura en otra pestaña', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const { fixture, el } = await render(ALLOWED);
    el.querySelector<HTMLButtonElement>('[data-action="podman-enable"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    document.querySelector<HTMLButtonElement>('[data-action="podman-run"] button')!.click();
    expect(open).toHaveBeenCalledWith(
      '/assets/s1/terminal?action=podman-enable&users=bob%2Ccarol',
      '_blank',
      'noopener',
    );
    expect(podmanEnableTerminalUrl('s1', ['a'])).toBe('/assets/s1/terminal?action=podman-enable&users=a');
  });
});
