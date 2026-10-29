/**
 * Copia un secreto al portapapeles y lo vacía pasados `seconds` segundos si sigue ahí (si el
 * navegador no deja leerlo, lo vacía igualmente: es lo que se le ha prometido al usuario). El
 * valor solo vive en este cierre; devuelve una función que cancela el vaciado.
 */
export async function copyEphemeral(
  value: string,
  seconds: number,
  clipboard: Clipboard | undefined = globalThis.navigator?.clipboard,
): Promise<{ cancel: () => void; clearNow: () => Promise<void> }> {
  if (!clipboard) throw new Error('Sin portapapeles');
  await clipboard.writeText(value);
  let done = false;
  const clearNow = async () => {
    if (done) return;
    done = true;
    let current: string | null;
    try {
      current = await clipboard.readText();
    } catch {
      current = null;
    }
    if (current === null || current === value) {
      try {
        await clipboard.writeText('');
      } catch {
        // Sin foco o sin permiso: no se puede hacer más.
      }
    }
  };
  const timer = setTimeout(() => void clearNow(), seconds * 1000);
  return {
    cancel: () => {
      done = true;
      clearTimeout(timer);
    },
    clearNow: async () => {
      clearTimeout(timer);
      await clearNow();
    },
  };
}
