import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';
import { Sbom } from './sbom.entity.js';

/**
 * Paquete instalado según el SBOM de un asset (DESIGN §5): servidor, CT o imagen, nunca un
 * contenedor (llega a los de su imagen por `instance_of`). Se reemplazan todos al guardar un SBOM
 * nuevo. Solo inventario: qué es vulnerable lo decide Trivy, nunca una comparación de versiones.
 */
@Entity({ name: 'packages' })
@Index('IDX_packages_asset_name', ['assetId', 'name'])
export class Package {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @Index('IDX_packages_sbom_id')
  @Column({ name: 'sbom_id', type: 'uuid' })
  sbomId: string;

  @ManyToOne(() => Sbom, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sbom_id' })
  sbom?: Sbom;

  /** Como lo nombra Trivy en sus findings (`openssl`, `@scope/pkg`, `org.group:artifact`). */
  @Index('IDX_packages_name')
  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 255 })
  version: string;

  /** Tipo del purl (`deb`, `rpm`, `apk`, `npm`, `pypi`, `golang`, `maven`…). */
  @Column({ type: 'varchar', length: 32 })
  ecosystem: string;

  @Index('IDX_packages_purl')
  @Column({ type: 'varchar', length: 1024, nullable: true })
  purl: string | null;

  @Column({ name: 'pkg_path', type: 'varchar', length: 1024, nullable: true })
  pkgPath: string | null;
}
