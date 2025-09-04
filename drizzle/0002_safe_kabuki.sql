ALTER TABLE "verification" ALTER COLUMN "id" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "verification" ALTER COLUMN "id" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "updated_at" timestamp DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "ip_address" text;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "user_agent" text;