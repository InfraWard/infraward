import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Exclusiones del escaneo en las reglas de la política de inventario (QoL-6b). */
export class ScanExclusions1792260000000 implements MigrationInterface {
  name = 'ScanExclusions1792260000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "inventory_policies"
            ADD "scan_exclusions" jsonb
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "inventory_policies" DROP COLUMN "scan_exclusions"
        `);
  }
}
