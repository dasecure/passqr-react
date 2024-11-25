import { type Express } from "express";
import { setupAuth } from "./auth";

import { randomBytes } from "crypto";
import { crypto } from "./auth";
import { db } from "../db";
import { users, passwordResetTokens } from "@db/schema";
import { eq } from "drizzle-orm";

export function registerRoutes(app: Express) {
  // Set up authentication routes
  setupAuth(app);

  // Add QR code-specific routes here if needed
  app.post("/api/qr/generate", (req, res) => {
    // In a real implementation, this would generate a unique QR code token
    const token = Math.random().toString(36).substring(7);
    res.json({ token });
  });

  app.post("/api/qr/verify", (req, res) => {
    // In a real implementation, this would verify the QR code token
    const { token } = req.body;
    if (!token) {
  // Password reset endpoints
  app.post("/api/reset-password", passwordResetLimiter, async (req, res) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).send("Email is required");
    }

    try {
      // Find user by email
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.email, email))
        .limit(1);

      if (!user) {
        // Don't reveal whether a user exists
        return res.json({ message: "If an account exists with that email, you will receive a password reset link." });
      }

      // Check for existing valid tokens and invalidate them
      await db
        .update(passwordResetTokens)
        .set({ used: 1 })
        .where(
          and(
            eq(passwordResetTokens.userId, user.id),
            eq(passwordResetTokens.used, 0)
          )
        );

      // Generate reset token
      const token = randomBytes(32).toString("hex");
      const expiresAt = addHours(new Date(), 1); // Token expires in 1 hour

      // Save token to database
      await db.insert(passwordResetTokens).values({
        userId: user.id,
        token,
        expiresAt,
        used: 0,
      });

      // In a real application, you would send an email here with a link like:
      // ${process.env.APP_URL}/reset-password?token=${token}
      console.log(`Password reset token for ${email}: ${token}`);

      res.json({ message: "If an account exists with that email, you will receive a password reset link." });
    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).send("Internal server error");
    }
  });

  app.post("/api/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password) {
      return res.status(400).send("Token and password are required");
    }

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).send("Password must be at least 8 characters long");
    }

    try {
      const [resetToken] = await db
        .select()
        .from(passwordResetTokens)
        .where(
          and(
            eq(passwordResetTokens.token, token),
            eq(passwordResetTokens.used, 0)
          )
        )
        .limit(1);

      if (!resetToken) {
        return res.status(400).send("Invalid reset token");
      }

      if (isAfter(new Date(), resetToken.expiresAt)) {
        await db
          .update(passwordResetTokens)
          .set({ used: 1 })
          .where(eq(passwordResetTokens.id, resetToken.id));
        return res.status(400).send("Reset token has expired");
      }

      // Update password and mark token as used
      await db.transaction(async (tx) => {
        // Hash the new password
        const hashedPassword = await crypto.hash(password);

        // Update user's password
        await tx
          .update(users)
          .set({ password: hashedPassword })
          .where(eq(users.id, resetToken.userId));

        // Mark token as used
        await tx
          .update(passwordResetTokens)
          .set({ used: 1 })
          .where(eq(passwordResetTokens.id, resetToken.id));

        // Invalidate any other unused tokens for this user
        await tx
          .update(passwordResetTokens)
          .set({ used: 1 })
          .where(
            and(
              eq(passwordResetTokens.userId, resetToken.userId),
              eq(passwordResetTokens.used, 0)
            )
          );
      });

      res.json({ message: "Password updated successfully" });
    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).send("Internal server error");
    }
  });
      return res.status(400).send("Token is required");
    }
    res.json({ verified: true });
  });
}
