declare module 'express-session' {
  interface SessionData {
    authState?: string;
    loginMethod?: 'google' | 'local';
    userId?: number;
  }
}

import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { type Express, type Request } from "express";
import { type IVerifyOptions } from "passport-local";
import session from "express-session";
import cookieParser from "cookie-parser";
import csrf from "csurf";
import createMemoryStore from "memorystore";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { users, insertUserSchema, loginUserSchema, type User as SelectUser } from "@db/schema";
import { db } from "../db";
import { eq } from "drizzle-orm";
import { rateLimit } from "express-rate-limit";

const scryptAsync = promisify(scrypt);

export const crypto = {
  hash: async (password: string) => {
    const salt = randomBytes(16).toString("hex");
    const buf = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${buf.toString("hex")}.${salt}`;
  },
  compare: async (suppliedPassword: string, storedPassword: string) => {
    const [hashedPassword, salt] = storedPassword.split(".");
    const hashedPasswordBuf = Buffer.from(hashedPassword, "hex");
    const suppliedPasswordBuf = (await scryptAsync(
      suppliedPassword,
      salt,
      64
    )) as Buffer;
    return timingSafeEqual(hashedPasswordBuf, suppliedPasswordBuf);
  },
};

declare global {
  namespace Express {
    interface User extends SelectUser {}
  }
}

// Define session type outside global namespace
declare module "express-session" {
  interface SessionData {
    loginMethod?: "google" | "local";
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (request) => {
    return request.ip || request.connection.remoteAddress || '';
  },
});

export function setupAuth(app: Express) {
  // Add this before any middleware
  app.enable('trust proxy');
  
  const MemoryStore = createMemoryStore(session);
  const sessionSettings: session.SessionOptions = {
    secret: process.env.REPL_ID || "secure-session-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    name: 'sessionId',
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    },
    store: new MemoryStore({
      checkPeriod: 86400000
    })
  };

  if (app.get("env") === "production") {
    app.set("trust proxy", 1);
    if (sessionSettings.cookie) {
      sessionSettings.cookie.secure = true;
    }
  }

  // Add CORS headers before all other middleware
  app.use((req, res, next) => {
    // Allow Google domains for OAuth
    const allowedOrigins = [
      process.env.PUBLIC_URL || 'http://localhost:5000',
      'https://accounts.google.com'
    ];
    const origin = req.headers.origin;
    
    if (origin && allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
    
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  app.use(cookieParser());

  app.use(session(sessionSettings));
  app.use(csrf({ 
    cookie: true,
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
    value: (req) => {
      return req.headers['x-csrf-token'] as string;
    }
  }));
  app.use(passport.initialize());
  app.use(passport.session());

  // CSRF token middleware
  app.use((req: Request & { csrfToken: () => string }, res, next) => {
    res.cookie("XSRF-TOKEN", req.csrfToken());
    next();
  });

  // Error handler for CSRF token errors
  app.use((err: any, req: any, res: any, next: any) => {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    res.status(403).json({ error: 'Invalid CSRF token' });
  });

  // Local Strategy
  passport.use(new LocalStrategy(async (username, password, done) => {
    try {
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);

      if (!user || !user.password) {
        return done(null, false, { message: "Incorrect username or password." });
      }
      
      const isMatch = await crypto.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Incorrect username or password." });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }));

  // Google Strategy
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: `${process.env.PUBLIC_URL || 'https://passqr.vincent8.repl.co'}/api/auth/google/callback`,
    proxy: true
  }, async (accessToken: string, refreshToken: string, profile: any, done: (error: any, user?: any) => void) => {
    try {
      // Check if user exists
      const [existingUser] = await db
        .select()
        .from(users)
        .where(eq(users.googleId, profile.id))
        .limit(1);

      if (existingUser) {
        return done(null, existingUser);
      }

      // Create new user
      const [newUser] = await db
        .insert(users)
        .values({
          username: profile.displayName || profile.emails?.[0]?.value?.split("@")[0] || profile.id,
          email: profile.emails?.[0]?.value || `${profile.id}@google.com`,
          googleId: profile.id,
          avatarUrl: profile.photos?.[0]?.value,
          provider: "google"
        })
        .returning();

      return done(null, newUser);
    } catch (error) {
      return done(error as Error);
    }
  }));

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: number, done) => {
    try {
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, id))
        .limit(1);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });

  // Authentication routes
  app.post("/api/register", async (req, res, next) => {
    try {
      const result = insertUserSchema.safeParse(req.body);
      if (!result.success) {
        return res
          .status(400)
          .send("Invalid input: " + result.error.issues.map(i => i.message).join(", "));
      }

      const { username, password, email } = result.data;

      // Check for existing email
      const [existingEmail] = await db
        .select()
        .from(users)
        .where(eq(users.email, email))
        .limit(1);

      if (existingEmail) {
        return res.status(400).send("Email already registered");
      }

      const [existingUser] = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);

      if (existingUser) {
        return res.status(400).send("Username already exists");
      }

      const hashedPassword = password ? await crypto.hash(password) : null;

      const [newUser] = await db
        .insert(users)
        .values({
          username,
          password: hashedPassword,
          email,
          provider: "local"
        })
        .returning();

      req.login(newUser, (err) => {
        if (err) {
          return next(err);
        }
        return res.json({
          message: "Registration successful",
          user: { id: newUser.id, username: newUser.username },
        });
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/login", loginLimiter, (req, res, next) => {
    const result = loginUserSchema.safeParse(req.body);
    if (!result.success) {
      return res
        .status(400)
        .send("Invalid input: " + result.error.issues.map(i => i.message).join(", "));
    }

    passport.authenticate("local", (err: any, user: Express.User, info: IVerifyOptions) => {
      if (err) {
        return next(err);
      }

      if (!user) {
        return res.status(400).send(info.message ?? "Login failed");
      }

      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }

        return res.json({
          message: "Login successful",
          user: { id: user.id, username: user.username },
        });
      });
    })(req, res, next);
  });

  // Google OAuth routes
  app.get("/api/auth/google", (req, res, next) => {
    const fullUrl = process.env.PUBLIC_URL || 'https://passqr.vincent8.repl.co';
    req.session.authState = Math.random().toString(36).substring(7);
    passport.authenticate("google", {
      scope: ["email", "profile"],
      state: req.session.authState,
      prompt: "select_account",
      callbackURL: `${fullUrl}/api/auth/google/callback`
    })(req, res, next);
  });

  app.get("/api/auth/google/callback",
    (req, res, next) => {
      const fullUrl = process.env.PUBLIC_URL || 'https://passqr.vincent8.repl.co';
      
      if (req.query.state !== req.session.authState) {
        return res.redirect('/auth?error=invalid_state');
      }
      
      passport.authenticate("google", {
        failureRedirect: "/auth?error=oauth_failed",
        successRedirect: "/",
        callbackURL: `${fullUrl}/api/auth/google/callback`
      })(req, res, next);
    }
  );

  app.post("/api/logout", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.json({ message: "Already logged out" });
    }

    const userId = req.user?.id;
    const sessionId = req.sessionID;
    
    req.logout((err) => {
      if (err) {
        return res.status(500).send("Logout failed");
      }
      
      if (userId && req.sessionStore) {
        const store = req.sessionStore;
        store.all((error: any, sessions: any) => {
          if (error) return;
          
          Object.entries(sessions).forEach(([sid, session]: [string, any]) => {
            if (session?.passport?.user === userId && sid !== sessionId) {
              store.destroy(sid);
            }
          });
        });
      }

      // Destroy current session last
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction failed:', err);
        }
        res.clearCookie('sessionId');
        res.json({ message: "Logout successful" });
      });
    });
  });

  app.get("/api/user", (req, res) => {
    if (req.isAuthenticated()) {
      return res.json(req.user);
    }
    res.status(401).send("Not logged in");
  });
}
