import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Marca de servidor duplicado: su machine-id ya es de otro asset no retirado. */
export class AssetDuplicateOf1791658859191 implements MigrationInterface {
  name = 'AssetDuplicateOf1791658859191';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "duplicate_of_id" uuid
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD CONSTRAINT "FK_7e1a712dec66b462b8b0c21bbb4" FOREIGN KEY ("duplicate_of_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "assets" DROP CONSTRAINT "FK_7e1a712dec66b462b8b0c21bbb4"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "duplicate_of_id"
        `);
  }
}
