import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Gestión de usuarios (QoL-1, DESIGN §5 y §14): nombre, desactivación y contraseña temporal en
 * `users`; sesiones opacas en servidor (`user_sessions`, sustituyen al JWT) y registro de
 * auditoría (`audit_events`, solo se añaden filas). El nombre de los usuarios existentes es la
 * parte del email antes de la arroba.
 */
export class UserManagement1791900000000 implements MigrationInterface {
  name = 'UserManagement1791900000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "name" character varying(120)
        `);
    await queryRunner.query(`
            UPDATE "users" SET "name" = left(split_part("email", '@', 1), 120)
        `);
    await queryRunner.query(`
            ALTER TABLE "users" ALTER COLUMN "name" SET NOT NULL
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "disabled_at" TIMESTAMP WITH TIME ZONE,
            ADD "must_change_password" boolean NOT NULL DEFAULT false,
            ADD "temp_password_expires_at" TIMESTAMP WITH TIME ZONE,
            ADD "password_changed_at" TIMESTAMP WITH TIME ZONE,
            ADD "last_login_at" TIMESTAMP WITH TIME ZONE
        `);

    await queryRunner.query(`
            CREATE TYPE "public"."user_session_purpose" AS ENUM('full', 'password_change')
        `);
    await queryRunner.query(`
            CREATE TABLE "user_sessions" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "user_id" uuid NOT NULL,
                "token_hash" bytea NOT NULL,
                "csrf_token" character varying(64) NOT NULL,
                "purpose" "public"."user_session_purpose" NOT NULL DEFAULT 'full',
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "last_seen_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "ip" inet,
                "user_agent" character varying(255),
                CONSTRAINT "PK_user_sessions_id" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_user_sessions_user_id" ON "user_sessions" ("user_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_user_sessions_token_hash" ON "user_sessions" ("token_hash")
        `);
    await queryRunner.query(`
            ALTER TABLE "user_sessions"
            ADD CONSTRAINT "FK_e9658e959c490b0a634dfc54783" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);

    await queryRunner.query(`
            CREATE TYPE "public"."audit_outcome" AS ENUM('success', 'failure')
        `);
    await queryRunner.query(`
            CREATE TABLE "audit_events" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "occurred_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "actor_id" uuid,
                "actor_email" character varying(320),
                "action" character varying(64) NOT NULL,
                "outcome" "public"."audit_outcome" NOT NULL DEFAULT 'success',
                "target_type" character varying(32),
                "target_id" uuid,
                "target_label" character varying(255),
                "ip" inet,
                "details" jsonb NOT NULL DEFAULT '{}',
                CONSTRAINT "PK_audit_events_id" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_audit_events_occurred_at" ON "audit_events" ("occurred_at" DESC, "id" DESC)
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_audit_events_actor" ON "audit_events" ("actor_id", "occurred_at" DESC)
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_audit_events_action" ON "audit_events" ("action", "occurred_at" DESC)
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_audit_events_target_id" ON "audit_events" ("target_id")
        `);
    await queryRunner.query(`
            ALTER TABLE "audit_events"
            ADD CONSTRAINT "FK_04c7c044146c6632491a370fc04" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "audit_events"`);
    await queryRunner.query(`DROP TYPE "public"."audit_outcome"`);
    await queryRunner.query(`DROP TABLE "user_sessions"`);
    await queryRunner.query(`DROP TYPE "public"."user_session_purpose"`);
    await queryRunner.query(`
            ALTER TABLE "users"
            DROP COLUMN "last_login_at",
            DROP COLUMN "password_changed_at",
            DROP COLUMN "temp_password_expires_at",
            DROP COLUMN "must_change_password",
            DROP COLUMN "disabled_at",
            DROP COLUMN "name"
        `);
  }
}
