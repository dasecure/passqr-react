import { pgTable, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  username: text("username").unique().notNull(),
  password: text("password").notNull(),
  email: text("email").unique().notNull(),
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
});
export const loginUserSchema = createInsertSchema(users, {
  username: z.string(),
  password: z.string(),
}).omit({ email: true });
export const selectUserSchema = createSelectSchema(users);
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = z.infer<typeof selectUserSchema>;

export const insertPasswordResetTokenSchema = createInsertSchema(passwordResetTokens);
export const selectPasswordResetTokenSchema = createSelectSchema(passwordResetTokens);
export type InsertPasswordResetToken = z.infer<typeof insertPasswordResetTokenSchema>;
export type PasswordResetToken = z.infer<typeof selectPasswordResetTokenSchema>;
