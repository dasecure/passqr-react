import { pgTable, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  username: text("username").unique().notNull(),
  password: text("password"),
  email: text("email").unique().notNull(),
  googleId: text("google_id").unique(),
  avatarUrl: text("avatar_url"),
  provider: text("provider").default("local"),
});

export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  userId: integer("user_id").notNull().references(() => users.id),
  token: text("token").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  used: integer("used").notNull().default(0),
});

export const insertUserSchema = createInsertSchema(users, {
  email: z.string().email(),
  password: z.string().optional(),
  provider: z.enum(['local', 'google']).default('local'),
  googleId: z.string().optional(),
  avatarUrl: z.string().optional(),
});
export const loginUserSchema = createInsertSchema(users, {
  username: z.string(),
  password: z.string(),
}).omit({ email: true, provider: true, googleId: true, avatarUrl: true });
export const selectUserSchema = createSelectSchema(users);
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = z.infer<typeof selectUserSchema>;

export const insertPasswordResetTokenSchema = createInsertSchema(passwordResetTokens);
export const selectPasswordResetTokenSchema = createSelectSchema(passwordResetTokens);
export type InsertPasswordResetToken = z.infer<typeof insertPasswordResetTokenSchema>;
export type PasswordResetToken = z.infer<typeof selectPasswordResetTokenSchema>;
