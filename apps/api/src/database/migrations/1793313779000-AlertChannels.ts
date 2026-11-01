import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Alertas fuera de la app (DESIGN §10): canales (`alert_channels`, webhook o correo) y la marca de
 * reparto de cada notificación (`notifications.dispatched_at`). Las que ya había se dan por
 * repartidas: no se envía el histórico.
 */
export class AlertChannels1793313779000 implements MigrationInterface {
  name = 'AlertChannels1793313779000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "alert_channels" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "name" character varying(100) NOT NULL,
                "type" character varying(16) NOT NULL,
                "enabled" boolean NOT NULL DEFAULT true,
                "kinds" character varying(32) array,
                "include_admin_only" boolean NOT NULL DEFAULT false,
                "config" jsonb NOT NULL,
                "secret_ref" character varying(512),
                "last_success_at" TIMESTAMP WITH TIME ZONE,
                "last_error_at" TIMESTAMP WITH TIME ZONE,
                "last_error" character varying(255),
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_alert_channels_type" CHECK ("type" IN ('webhook', 'email')),
                CONSTRAINT "PK_alert_channels" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications"
            ADD "dispatched_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            UPDATE "notifications" SET "dispatched_at" = "created_at"
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_notifications_undispatched" ON "notifications" ("created_at")
            WHERE "dispatched_at" IS NULL
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."IDX_notifications_undispatched"`);
    await queryRunner.query(`ALTER TABLE "notifications" DROP COLUMN "dispatched_at"`);
    await queryRunner.query(`DROP TABLE "alert_channels"`);
  }
}
