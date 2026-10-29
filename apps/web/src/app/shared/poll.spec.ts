import { of, defer } from 'rxjs';
import { pollWhile } from './poll';

describe('pollWhile', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('repite mientras haya trabajo pendiente y luego para', async () => {
    const answers = [2, 1, 0, 5];
    let calls = 0;
    const seen: number[] = [];
    let done = false;
    pollWhile(
      () => defer(() => of(answers[calls++]!)),
      (n) => n > 0,
      3000,
    ).subscribe({ next: (n) => seen.push(n), complete: () => (done = true) });

    expect(seen).toEqual([2]);
    await vi.advanceTimersByTimeAsync(3000);
    expect(seen).toEqual([2, 1]);
    await vi.advanceTimersByTimeAsync(3000);
    expect(seen).toEqual([2, 1, 0]);
    expect(done).toBe(true);
    // Sin trabajo pendiente no vuelve a pedir.
    await vi.advanceTimersByTimeAsync(30_000);
    expect(calls).toBe(3);
  });
});
