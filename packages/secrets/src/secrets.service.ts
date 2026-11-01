import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';
import type {
  SecretProviderCapability,
  SecretProviderInfo,
} from '@infraward/shared-types';
import { SecretProviderNotConfiguredError } from './errors.js';
import {
  isSshCertificateCapable,
  SECRET_PROVIDERS,
  type SecretProvider,
  type SshCertificateCapable,
} from './secret-provider.js';
import { formatSecretRef, parseSecretRef } from './secret-ref.js';

/** Token con la vida de la caché en segundos (0 = sin caché). */
export const SECRETS_CACHE_TTL = Symbol('SECRETS_CACHE_TTL');

/** Vida máxima de un valor en la caché (segundos). */
export const MAX_SECRETS_CACHE_TTL = 300;

/** Entrada de la caché: el valor va en un campo privado para que no salga al inspeccionar. */
class CacheEntry {
  readonly #value: string;

  constructor(
    value: string,
    readonly expiresAt: number,
  ) {
    this.#value = value;
  }

  get value(): string {
    return this.#value;
  }

  toJSON(): object {
    return { expiresAt: this.expiresAt };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `CacheEntry(expiresAt=${this.expiresAt})`;
  }
}

/**
 * Resuelve referencias `secret://…` contra los proveedores activos. Los valores solo viven
 * en memoria, en una caché de vida corta; este servicio nunca los escribe en logs.
 */
@Injectable()
export class SecretsService implements OnModuleDestroy {
  private readonly cache = new Map<string, CacheEntry>();
  /**
   * Contador de invalidaciones por ruta (y global, para clearCache). Una lectura que empezó
   * antes de una escritura o un borrado no puede dejar en caché el valor antiguo.
   */
  private readonly generations = new Map<string, number>();
  private epoch = 0;
  private readonly ttlMs: number;

  constructor(
    @Inject(SECRET_PROVIDERS) private readonly providers: SecretProvider[],
    @Inject(SECRETS_CACHE_TTL) cacheTtlSeconds: number,
  ) {
    this.ttlMs =
      Math.min(Math.max(cacheTtlSeconds, 0), MAX_SECRETS_CACHE_TTL) * 1000;
  }

  /**
   * Devuelve el valor del secreto. Quien lo recibe lo usa y lo descarta.
   * Con `fresh` se consulta al proveedor aunque esté en caché (y se refresca la caché).
   */
  async resolve(
    ref: string,
    options: { fresh?: boolean } = {},
  ): Promise<string> {
    const parsed = parseSecretRef(ref);
    const key = formatSecretRef(parsed);
    const now = Date.now();
    const cached = this.cache.get(key);
    if (!options.fresh && cached && cached.expiresAt > now) {
      return cached.value;
    }
    this.cache.delete(key);

    const base = formatSecretRef({
      provider: parsed.provider,
      path: parsed.path,
    });
    const generation = this.generations.get(base) ?? 0;
    const epoch = this.epoch;
    const value = await this.provider(parsed.provider).get(
      parsed.path,
      parsed.field,
    );
    if (
      this.ttlMs > 0 &&
      epoch === this.epoch &&
      generation === (this.generations.get(base) ?? 0)
    ) {
      this.purgeExpired(now);
      this.cache.set(key, new CacheEntry(value, now + this.ttlMs));
    }
    return value;
  }

  /**
   * Guarda `data` en `secret://<proveedor>/<ruta>` (sin campo) y devuelve esa referencia.
   * Falla si el proveedor no admite escritura.
   */
  async store(ref: string, data: Record<string, string>): Promise<string> {
    const parsed = parseSecretRef(ref);
    if (parsed.field !== undefined) {
      throw new TypeError('Para guardar, la referencia no lleva #campo');
    }
    const provider = this.provider(parsed.provider);
    if (!provider.set) {
      throw new TypeError(
        `El proveedor de secretos ${provider.id} es de solo lectura`,
      );
    }
    try {
      await provider.set(parsed.path, data);
    } finally {
      this.invalidate(parsed.provider, parsed.path);
    }
    return formatSecretRef(parsed);
  }

  /**
   * Borra `secret://<proveedor>/<ruta>` (todos sus campos) y lo quita de la caché, aunque el
   * borrado falle. Devuelve si existía. Falla si el proveedor no admite borrado.
   */
  async remove(ref: string): Promise<boolean> {
    const parsed = parseSecretRef(ref);
    if (parsed.field !== undefined) {
      throw new TypeError('Para borrar, la referencia no lleva #campo');
    }
    const provider = this.provider(parsed.provider);
    if (!provider.delete) {
      throw new TypeError(
        `El proveedor de secretos ${provider.id} no admite borrado`,
      );
    }
    try {
      return await provider.delete(parsed.path);
    } finally {
      this.invalidate(parsed.provider, parsed.path);
    }
  }

  /** Proveedores activos con su estado y capacidades. */
  async describeProviders(): Promise<SecretProviderInfo[]> {
    return Promise.all(
      this.providers.map(async (p) => {
        const capabilities: SecretProviderCapability[] = [];
        if (p.set) capabilities.push('write');
        if (isSshCertificateCapable(p)) capabilities.push('ssh_certificates');
        let healthy: boolean;
        try {
          healthy = await p.healthCheck();
        } catch {
          healthy = false;
        }
        return { id: p.id, healthy, capabilities };
      }),
    );
  }

  /** Primer proveedor activo con CA SSH (`SshCertificateCapable`), si lo hay. */
  sshCertificates(): (SecretProvider & SshCertificateCapable) | undefined {
    return this.providers.find(isSshCertificateCapable);
  }

  /** Proveedor activo por id (p. ej., para firmar certificados SSH). */
  provider(id: string): SecretProvider {
    const impl = this.providers.find((p) => p.id === id);
    if (!impl) throw new SecretProviderNotConfiguredError(id);
    return impl;
  }

  clearCache(): void {
    this.epoch++;
    this.cache.clear();
  }

  async onModuleDestroy(): Promise<void> {
    this.clearCache();
    await Promise.all(this.providers.map((p) => p.close?.() ?? Promise.resolve()));
  }

  /** Quita de la caché todos los campos de una ruta. */
  private invalidate(provider: string, path: string): void {
    const base = formatSecretRef({ provider, path });
    this.generations.set(base, (this.generations.get(base) ?? 0) + 1);
    for (const key of this.cache.keys()) {
      if (key === base || key.startsWith(`${base}#`)) this.cache.delete(key);
    }
  }

  private purgeExpired(now: number): void {
    for (const [key, entry] of this.cache) {
      if (entry.expiresAt <= now) this.cache.delete(key);
    }
  }
}
