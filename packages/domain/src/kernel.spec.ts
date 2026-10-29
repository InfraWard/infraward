import { describe, expect, it } from 'vitest';
import { kernelPackageUse } from './kernel.js';

const use = (
  packageName: string,
  runningKernel: string | null,
  assetType = 'server',
  installedVersion = '7.0.0-38.38',
) =>
  kernelPackageUse({ packageName, installedVersion, runningKernel, assetType })
    ?.use ?? null;

describe('kernelPackageUse', () => {
  // Los paquetes reales de plesk-pruebas (Ubuntu 26.04) con findings del kernel.
  it('Ubuntu: solo los módulos del kernel que corre están en uso', () => {
    const running = '7.0.0-38-generic';
    expect(use('linux-modules-7.0.0-38-generic', running)).toBe('running');
    expect(use('linux-image-7.0.0-38-generic', running)).toBe('running');
    expect(use('linux-main-modules-zfs-7.0.0-38-generic', running)).toBe(
      'running',
    );
    for (const aux of [
      'linux-headers-7.0.0-38-generic',
      'linux-headers-7.0.0-38',
      'linux-tools-7.0.0-38-generic',
      'linux-tools-7.0.0-38',
      'linux-tools-common',
      'linux-perf',
      'linux-libc-dev',
      'bpftool',
      'linux-image-generic',
      'linux-headers-generic',
      'linux-generic',
    ])
      expect(use(aux, running), aux).toBe('aux');
  });

  it('otro kernel instalado no está en uso', () => {
    expect(
      kernelPackageUse({
        packageName: 'linux-image-6.8.0-40-generic',
        installedVersion: '6.8.0-40.40',
        runningKernel: '7.0.0-38-generic',
        assetType: 'server',
      }),
    ).toEqual({ use: 'other', running: '7.0.0-38-generic' });
    expect(
      use('linux-image-unsigned-6.8.0-40-generic', '7.0.0-38-generic'),
    ).toBe('other');
    expect(use('linux-image-6.12.38+deb13-amd64', '6.12.38+deb13-amd64')).toBe(
      'running',
    );
  });

  it('Proxmox', () => {
    const running = '7.0.2-6-pve';
    expect(use('proxmox-kernel-7.0.2-6-pve-signed', running)).toBe('running');
    expect(use('proxmox-kernel-6.14.8-2-pve-signed', running)).toBe('other');
    expect(use('pve-kernel-6.8.12-4-pve', running)).toBe('other');
    expect(use('proxmox-kernel-7.0', running)).toBe('aux');
    expect(use('proxmox-default-kernel', running)).toBe('aux');
    expect(use('proxmox-headers-7.0.2-6-pve', running)).toBe('aux');
    expect(use('proxmox-kernel-helper', running)).toBeNull();
  });

  it('RHEL: compara la versión instalada', () => {
    const running = '5.14.0-427.13.1.el9_4.x86_64';
    expect(use('kernel-core', running, 'server', '5.14.0-427.13.1.el9_4')).toBe(
      'running',
    );
    expect(use('kernel', running, 'server', '0:5.14.0-362.8.1.el9_3')).toBe(
      'other',
    );
    expect(use('kernel-headers', running)).toBe('aux');
    expect(
      use('kernel-modules-extra', running, 'server', '5.14.0-427.13.1.el9_4'),
    ).toBe('running');
  });

  it('en un CT o una imagen ningún kernel está en uso', () => {
    expect(use('linux-image-7.0.0-38-generic', '7.0.0-38-generic', 'lxc')).toBe(
      'guest',
    );
    expect(use('linux-libc-dev', null, 'image')).toBe('guest');
  });

  it('sin uname -r, la imagen y los módulos cuentan como en uso', () => {
    expect(use('linux-modules-7.0.0-38-generic', null)).toBe('running');
    expect(use('linux-headers-7.0.0-38', null)).toBe('aux');
  });

  it('lo que no es del kernel', () => {
    for (const name of [
      'linux-base',
      'linux-firmware',
      'linux-sysctl-defaults',
      'util-linux',
      'libselinux1',
      'kernelshark',
      'openssl',
      'perl',
    ])
      expect(use(name, '7.0.0-38-generic'), name).toBeNull();
  });
});
