import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Gateway I (sesión 21, DESIGN §5, §7 y §11): sesiones interactivas (`terminal_sessions`) y el
 * acceso de administración que pide un alta (`enrollments.admin_access`) y que tiene un servidor
 * (`assets.admin_access`).
 */
export class TerminalGateway1792618164631 implements MigrationInterface {
  name = 'TerminalGateway1792618164631';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."terminal_session_state" AS ENUM(
                'pending',
                'starting',
                'active',
                'closed',
                'rejected'
            )
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."terminal_close_reason" AS ENUM(
                'exit',
                'client',
                'idle',
                'max_duration',
                'gateway_shutdown',
                'limit',
                'connect_failed',
                'expired',
                'denied'
            )
        `);
    await queryRunner.query(`
            CREATE TABLE "terminal_sessions" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "user_id" uuid NOT NULL,
                "auth_session_id" uuid,
                "asset_id" uuid,
                "host_asset_id" uuid,
                "asset_name" character varying(255) NOT NULL,
                "account" character varying(32) NOT NULL,
                "state" "public"."terminal_session_state" NOT NULL DEFAULT 'pending',
                "ticket_hash" bytea,
                "ticket_expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "redeemed_at" TIMESTAMP WITH TIME ZONE,
                "certificates_issued" integer NOT NULL DEFAULT '0',
                "gateway" character varying(64),
                "request_ip" inet,
                "client_ip" inet,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "started_at" TIMESTAMP WITH TIME ZONE,
                "ended_at" TIMESTAMP WITH TIME ZONE,
                "close_reason" "public"."terminal_close_reason",
                "exit_code" integer,
                "close_message" character varying(500),
                CONSTRAINT "PK_10286b807e2224f1183d4d8a774" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_terminal_sessions_user_id" ON "terminal_sessions" ("user_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_terminal_sessions_asset_id" ON "terminal_sessions" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_terminal_sessions_ticket_hash" ON "terminal_sessions" ("ticket_hash")
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "admin_access" jsonb
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments"
            ADD "admin_access" character varying(16)
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ADD CONSTRAINT "FK_1f744e8472bc1c6da83fe48aec3" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ADD CONSTRAINT "FK_8d41cba59321ec723ffdd839210" FOREIGN KEY ("auth_session_id") REFERENCES "user_sessions"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ADD CONSTRAINT "FK_e218b1be4dc85baf94222a3cb9e" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ADD CONSTRAINT "FK_8e197fe3d10f5eb49027017c19c" FOREIGN KEY ("host_asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions" DROP CONSTRAINT "FK_8e197fe3d10f5eb49027017c19c"
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions" DROP CONSTRAINT "FK_e218b1be4dc85baf94222a3cb9e"
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions" DROP CONSTRAINT "FK_8d41cba59321ec723ffdd839210"
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions" DROP CONSTRAINT "FK_1f744e8472bc1c6da83fe48aec3"
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments" DROP COLUMN "admin_access"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "admin_access"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_terminal_sessions_ticket_hash"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_terminal_sessions_asset_id"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_terminal_sessions_user_id"
        `);
    await queryRunner.query(`
            DROP TABLE "terminal_sessions"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."terminal_close_reason"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."terminal_session_state"
        `);
  }
}
