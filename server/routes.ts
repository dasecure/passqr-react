import { type Express } from "express";
import { setupAuth } from "./auth";

import { randomBytes } from "crypto";
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
  app.post("/api/reset-password", async (req, res) => {
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

      // Generate reset token
      const token = randomBytes(32).toString("hex");
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1); // Token expires in 1 hour

      // Save token to database
      await db.insert(passwordResetTokens).values({
        userId: user.id,
        token,
        expiresAt,
        used: 0,
      });

      // In a real application, you would send an email here
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

    try {
      const [resetToken] = await db
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.token, token))
        .limit(1);

      if (!resetToken || resetToken.used || new Date() > resetToken.expiresAt) {
        return res.status(400).send("Invalid or expired reset token");
      }

      // Update password and mark token as used
      await db.transaction(async (tx) => {
        await tx
          .update(users)
          .set({ password: await crypto.hash(password) })
          .where(eq(users.id, resetToken.userId));

        await tx
          .update(passwordResetTokens)
          .set({ used: 1 })
          .where(eq(passwordResetTokens.id, resetToken.id));
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
