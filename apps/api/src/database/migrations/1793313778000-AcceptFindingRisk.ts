import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * «Aceptar el riesgo» de findings (DESIGN §9): quién, cuándo, por qué y hasta cuándo, y el índice
 * parcial con el que el worker busca las aceptaciones caducadas.
 */
export class AcceptFindingRisk1793313778000 implements MigrationInterface {
  name = 'AcceptFindingRisk1793313778000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "findings"
            ADD "accepted_at" TIMESTAMP WITH TIME ZONE,
            ADD "accepted_by" character varying(320),
            ADD "accept_reason" text,
            ADD "accept_expires_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_findings_accept_expires" ON "findings" ("accept_expires_at")
            WHERE "status" = 'accepted' AND "accept_expires_at" IS NOT NULL
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."IDX_findings_accept_expires"`);
    await queryRunner.query(`
            ALTER TABLE "findings"
            DROP COLUMN "accept_expires_at",
            DROP COLUMN "accept_reason",
            DROP COLUMN "accepted_by",
            DROP COLUMN "accepted_at"
        `);
  }
}
