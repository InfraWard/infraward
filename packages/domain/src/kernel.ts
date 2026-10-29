/**
 * ¿Es un paquete del kernel y, si lo es, está en uso? (DESIGN §9, «kernel no en uso»). Pura y
 * con tests: los patrones viven solo aquí.
 *
 * Trivy cuelga los CVE del kernel (miles en Ubuntu, casi todos `affected`) de **cada** paquete
 * binario de la fuente `linux`: imagen y módulos, pero también cabeceras, herramientas, perf,
 * bpftool o `linux-libc-dev`. Solo los del kernel que arrancó (`uname -r`) ejecutan ese código.
 */
export type KernelPackageUse =
  /** El kernel en ejecución (o no se sabe cuál corre: se trata como en uso). */
  | { use: 'running' }
  /** Imagen o módulos de otro kernel instalado. */
  | { use: 'other'; running: string }
  /** Cabeceras, herramientas, metapaquetes…: de la fuente del kernel, pero no lo ejecutan. */
  | { use: 'aux' }
  /** Un CT o una imagen: usan el kernel del nodo o del host. */
  | { use: 'guest' };

/** Imagen o módulos de un kernel concreto: el grupo 1 es su `uname -r`. */
const KERNEL_RELEASE: readonly RegExp[] = [
  // Debian/Ubuntu: linux-image-7.0.0-38-generic, linux-modules-extra-…, linux-main-modules-zfs-…,
  // linux-image-unsigned-…
  /^linux-(?:image|modules|modules-extra|main-modules-[a-z0-9]+)-(?:unsigned-)?(\d[^\s]*)$/,
  // Proxmox: proxmox-kernel-7.0.2-6-pve-signed, pve-kernel-6.8.12-4-pve
  /^(?:proxmox|pve)-kernel-(\d+\.\d+\.\d+-\d+-pve)(?:-signed)?$/,
];

/** Paquetes del kernel que no lo ejecutan (o metapaquetes sin versión). */
const KERNEL_AUX: readonly RegExp[] = [
  /^linux-(?:headers|tools|cloud-tools|buildinfo|source|doc|lib-rust|bpf-dev|kbuild|compiler|support|config)(?:-|$)/,
  /^linux-(?:image|modules|modules-extra)-(?!\d)[a-z]/, // linux-image-generic, linux-image-amd64
  /^linux-(?:libc-dev|perf|generic|virtual|kvm)(?:-|$)/,
  /^(?:proxmox|pve)-(?:headers|kernel)-\d+\.\d+$/, // metapaquetes de Proxmox (proxmox-kernel-7.0)
  /^(?:proxmox|pve)-headers-/,
  /^proxmox-default-(?:kernel|headers)$/,
  /^bpftool$/,
  /^(?:kernel-(?:headers|devel|tools|tools-libs|doc|abi-stablelists)|perf|python3-perf)(?:-|$)/,
];

/** RHEL y derivadas: el nombre no lleva la versión; se compara la instalada. */
const RPM_KERNEL =
  /^kernel(?:-core|-modules(?:-core|-extra)?|-uek(?:-core)?|-rt(?:-core)?)?$/;

export function kernelPackageUse(input: {
  packageName: string;
  installedVersion: string;
  /** `uname -r` de los facts (null si no se sabe). */
  runningKernel: string | null;
  assetType: string;
}): KernelPackageUse | null {
  const name = input.packageName;
  const release = KERNEL_RELEASE.map((re) => re.exec(name)?.[1]).find(Boolean);
  const rpm = RPM_KERNEL.test(name);
  const aux = !release && !rpm && KERNEL_AUX.some((re) => re.test(name));
  if (!release && !rpm && !aux) return null;
  if (input.assetType === 'lxc' || input.assetType === 'image')
    return { use: 'guest' };
  if (aux) return { use: 'aux' };
  const running = input.runningKernel?.trim();
  if (!running) return { use: 'running' };
  if (release)
    return release === running ? { use: 'running' } : { use: 'other', running };
  // RPM: uname -r = <versión>-<release>.<arch> (5.14.0-427.13.1.el9_4.x86_64).
  const version = input.installedVersion.replace(/^\d+:/, '');
  return running === version || running.startsWith(`${version}.`)
    ? { use: 'running' }
    : { use: 'other', running };
}
