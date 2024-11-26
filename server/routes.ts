import { type Express } from "express";
import { setupAuth } from "./auth";
import { randomBytes } from "crypto";
import { crypto } from "./auth";
import { db } from "../db";
import { users, passwordResetTokens } from "@db/schema";
import { eq } from "drizzle-orm";
import { isAfter, addHours } from "date-fns";
import nodemailer from "nodemailer";
import { rateLimit } from "express-rate-limit";
import { and } from "drizzle-orm";

// Rate limiter for password reset attempts
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 requests per hour
  message: "Too many password reset attempts. Please try again in an hour.",
  standardHeaders: true,
  legacyHeaders: false,
});

async function sendPasswordResetEmail(email: string, token: string) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    }
  });

  const resetUrl = `${process.env.PUBLIC_URL || 'http://localhost:5000'}/auth?token=${token}`;

  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <h1>Password Reset Request</h1>
        <p>Click the link below to reset your password:</p>
        <a href="${resetUrl}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });
    console.log('Password reset email sent successfully');
  } catch (error) {
    console.error('Failed to send password reset email:', error);
    throw new Error('Failed to send password reset email');
  }
}

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
    const { token } = req.body;
    if (!token) {
      return res.status(400).send("Token is required");
    }
    res.json({ verified: true });
  });
}

export function setupRoutes(app: Express) {
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

      // Send password reset email
      await sendPasswordResetEmail(email, token);

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
}