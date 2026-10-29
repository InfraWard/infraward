import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Tokens de API personales y el índice para ver los jobs de una operación en lote en la
 * Actividad (QoL-6).
 */
export class ApiTokens1792170000000 implements MigrationInterface {
  name = 'ApiTokens1792170000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."api_token_scope" AS ENUM('read', 'role')
        `);
    await queryRunner.query(`
            CREATE TABLE "api_tokens" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "user_id" uuid NOT NULL,
                "name" character varying(100) NOT NULL,
                "prefix" character varying(16) NOT NULL,
                "token_hash" bytea NOT NULL,
                "scope" "public"."api_token_scope" NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "last_used_at" TIMESTAMP WITH TIME ZONE,
                "last_used_ip" inet,
                "revoked_at" TIMESTAMP WITH TIME ZONE,
                "revoked_by_id" uuid,
                CONSTRAINT "PK_api_tokens" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_api_tokens_user_id" ON "api_tokens" ("user_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_api_tokens_token_hash" ON "api_tokens" ("token_hash")
        `);
    await queryRunner.query(`
            ALTER TABLE "api_tokens"
            ADD CONSTRAINT "FK_b74883f5884a42fd8496d389b25" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "api_tokens"
            ADD CONSTRAINT "FK_3f40edfea17f9e1f9ca91427050" FOREIGN KEY ("revoked_by_id") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    // A mano (parcial): solo los jobs encadenados o de un lote tienen padre.
    await queryRunner.query(`
            CREATE INDEX "IDX_job_runs_parent" ON "job_runs" ("parent_job_id")
            WHERE "parent_job_id" IS NOT NULL
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."IDX_job_runs_parent"`);
    await queryRunner.query(
      `ALTER TABLE "api_tokens" DROP CONSTRAINT "FK_3f40edfea17f9e1f9ca91427050"`,
    );
    await queryRunner.query(
      `ALTER TABLE "api_tokens" DROP CONSTRAINT "FK_b74883f5884a42fd8496d389b25"`,
    );
    await queryRunner.query(`DROP INDEX "public"."UQ_api_tokens_token_hash"`);
    await queryRunner.query(`DROP INDEX "public"."IDX_api_tokens_user_id"`);
    await queryRunner.query(`DROP TABLE "api_tokens"`);
    await queryRunner.query(`DROP TYPE "public"."api_token_scope"`);
  }
}
