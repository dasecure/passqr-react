import { type Express } from "express";
import { setupAuth } from "./auth";
import { randomBytes } from "crypto";
import { crypto } from "./auth";
import { db } from "../db";
import { users, passwordResetTokens, qrTokens } from "@db/schema";
import { eq } from "drizzle-orm";
import { isAfter, addHours } from "date-fns";
import nodemailer from "nodemailer";
import { rateLimit } from "express-rate-limit";
import { and } from "drizzle-orm";

interface EmailError extends Error {
  code?: string;
  command?: string;
}

// Rate limiter for password reset attempts
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 requests per hour
  message: "Too many password reset attempts. Please try again in an hour.",
  standardHeaders: true,
  legacyHeaders: false,
});

async function sendPasswordResetEmail(email: string, token: string) {
  console.log('=== Password Reset Email Process Starting ===');
  console.log('Environment Check:');
  console.log('- NODE_ENV:', process.env.NODE_ENV);
  console.log('- Gmail User Status:', process.env.GMAIL_USER ? 'Configured' : 'Missing');
  console.log('- Gmail Password Status:', process.env.GMAIL_APP_PASSWORD ? 'Configured' : 'Missing');
  console.log('- Public URL:', process.env.PUBLIC_URL || 'http://localhost:5000');

  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] Starting email process...`);

  // Connection debugging with detailed SMTP configuration
  console.log(`[${timestamp}] SMTP Configuration:`, {
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.GMAIL_USER ? 'configured' : 'missing',
      pass: process.env.GMAIL_APP_PASSWORD ? 'configured' : 'missing'
    },
    tls: {
      rejectUnauthorized: true
    }
  });

  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    },
    debug: true,
    logger: true // Enable built-in logger
  });

  // Verify transporter configuration
  try {
    console.log('Attempting SMTP connection verification...');
    await transporter.verify();
    console.log('SMTP verification successful');
  } catch (error) {
    const emailError = error as EmailError;
    console.error('SMTP verification failed:', {
      name: emailError.name,
      message: emailError.message,
      code: emailError.code,
      command: emailError.command,
      stack: emailError.stack
    });
    
    // Check for specific Gmail errors
    if (emailError.code === 'EAUTH') {
      console.error('Authentication failed - check Gmail credentials');
    } else if (emailError.code === 'ESOCKET') {
      console.error('Socket connection failed - check network/firewall');
    }
    
    throw error;
  }

  const resetUrl = `${process.env.PUBLIC_URL || 'http://localhost:5000'}/auth?token=${token}`;

  try {
    const sendTimestamp = new Date().toISOString();
    console.log(`[${sendTimestamp}] Initiating email sending process...`);
    console.log(`[${sendTimestamp}] Preparing to send email to:`, email);
    console.log(`[${sendTimestamp}] Generated reset URL:`, resetUrl);
    
    const info = await transporter.sendMail({
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
    
    const successTimestamp = new Date().toISOString();
    console.log(`[${successTimestamp}] Email sent successfully`);
    console.log(`[${successTimestamp}] Message ID:`, info.messageId);
    console.log(`[${successTimestamp}] Preview URL:`, nodemailer.getTestMessageUrl(info));
    console.log(`[${successTimestamp}] Email sending process completed`);
  } catch (error) {
    const emailError = error as EmailError;
    console.error('Email sending failed with error:', {
      name: emailError.name,
      message: emailError.message,
      code: emailError.code,
      command: emailError.command
    });
    throw new Error('Failed to send password reset email: ' + emailError.message);
  }
}

export function registerRoutes(app: Express) {
  // Set up authentication routes
  setupAuth(app);

  // QR code login routes
  app.post("/api/qr/generate", async (req, res) => {
    try {
      const token = randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // Token expires in 5 minutes

      await db.insert(qrTokens).values({
        token,
        expiresAt,
        used: 0
      });

      res.json({ token });
    } catch (error) {
      console.error('QR token generation error:', error);
      res.status(500).send('Failed to generate QR code');
    }
  });

  app.post("/api/qr/verify", async (req, res) => {
    const { token } = req.body;
    if (!token) {
      return res.status(400).send("Token is required");
    }

    try {
      const [qrToken] = await db
        .select()
        .from(qrTokens)
        .where(
          and(
            eq(qrTokens.token, token),
            eq(qrTokens.used, 0)
          )
        )
        .limit(1);

      if (!qrToken) {
        return res.status(400).send("Invalid or expired token");
      }

      if (isAfter(new Date(), qrToken.expiresAt)) {
        await db
          .update(qrTokens)
          .set({ used: 1 })
          .where(eq(qrTokens.id, qrToken.id));
        return res.status(400).send("Token has expired");
      }

      // If token is valid, update it as used
      await db
        .update(qrTokens)
        .set({ used: 1 })
        .where(eq(qrTokens.id, qrToken.id));

      // Create session for the user
      if (qrToken.userId) {
        const [user] = await db
          .select()
          .from(users)
          .where(eq(users.id, qrToken.userId))
          .limit(1);

        if (user) {
          req.login(user, (err) => {
            if (err) {
              return res.status(500).send("Login failed");
            }
            return res.json({ success: true, user: { id: user.id, username: user.username } });
          });
        } else {
          res.status(400).send("User not found");
        }
      } else {
        res.status(400).send("Token not associated with a user");
      }
    } catch (error) {
      console.error('QR token verification error:', error);
      res.status(500).send('Failed to verify QR code');
    }
  });

  app.post("/api/qr/link", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).send("Not authenticated");
    }

    const { token } = req.body;
    if (!token) {
      return res.status(400).send("Token is required");
    }

    try {
      const result = await db
        .update(qrTokens)
        .set({ userId: req.user.id })
        .where(
          and(
            eq(qrTokens.token, token),
            eq(qrTokens.used, 0)
          )
        )
        .returning();

      if (!result.length) {
        return res.status(400).send("Invalid or expired token");
      }

      res.json({ success: true });
    } catch (error) {
      console.error('QR token linking error:', error);
      res.status(500).send('Failed to link QR code');
    }
  });
}

export function setupRoutes(app: Express) {
  // Password reset endpoints
  app.post("/api/reset-password", passwordResetLimiter, async (req, res) => {
    const { email } = req.body;
    console.log('Password reset requested for email:', email);
    
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

      // Send password reset email with better error handling
      try {
        await sendPasswordResetEmail(email, token);
      } catch (error) {
        console.error('Failed to send password reset email:', error);
        return res.status(500).send("Failed to send password reset email. Please try again later.");
      }

      res.json({ message: "If an account exists with that email, you will receive a password reset link." });
    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).send("An error occurred while processing your request");
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