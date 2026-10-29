import { Injectable } from '@nestjs/common';
import { HostKeyMismatchError, type ScannedHostKey } from '../ssh/host-keys.js';
import { SshClient, SshError } from '../ssh/ssh-client.js';

/** Hosts recordados como mucho (las claves cambian casi nunca; son públicas). */
const MAX_ENTRIES = 1000;

/**
 * Host key fijada de un servidor para la terminal, con el menor número de conexiones sin
 * autenticar: OpenSSH ≥ 9.8 penaliza las que se acumulan desde una misma IP
 * (`PerSourcePenalties noauth`, y cada tipo de `ssh-keyscan` es una conexión). Escanea primero
 * solo ED25519 (lo que casi siempre está fijado) y, si no coincide, el resto; la clave que
 * coincide con la huella fijada se recuerda en memoria (por host, puerto y huella). Si una
 * conexión falla, se olvida.
 */
@Injectable()
export class PinnedHostKeys {
  private readonly cache = new Map<string, ScannedHostKey>();

  constructor(private readonly ssh: SshClient) {}

  async get(host: string, port: number, pinned: string): Promise<ScannedHostKey> {
    const key = `${host}:${port}:${pinned}`;
    const known = this.cache.get(key);
    if (known) return known;
    for (const types of [['ed25519'], ['ecdsa', 'rsa']]) {
      let scanned: ScannedHostKey[];
      try {
        scanned = await this.ssh.scanHostKeys(host, port, types);
      } catch (error) {
        // Sin claves de ese tipo, el siguiente; un fallo de red no se arregla con otro tipo.
        if (error instanceof SshError && types.length === 1) continue;
        throw error;
      }
      const match = scanned.find((k) => k.fingerprint === pinned);
      if (match) {
        if (this.cache.size >= MAX_ENTRIES) this.cache.delete(this.cache.keys().next().value!);
        this.cache.set(key, match);
        return match;
      }
    }
    throw new HostKeyMismatchError(
      `La host key del servidor ha cambiado (se esperaba ${pinned}); posible suplantación`,
    );
  }

  forget(host: string, port: number, pinned: string): void {
    this.cache.delete(`${host}:${port}:${pinned}`);
  }
}
