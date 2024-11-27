# PassQR Authentication System

A modern authentication system providing multiple login methods through a web interface. Features include:

## Features
- Password-based authentication with registration
- QR code login functionality
- Password reset with email verification
- OAuth integration (Google, GitHub)
- Profile management with customizable user details
- Session management with CSRF protection
- Secure session cookies

## Tech Stack
- React/TypeScript frontend
- Express.js backend
- PostgreSQL database
- Express-session for session management
- Passport.js for authentication
- Nodemailer for email services

## Setup
1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment variables (see .env.example)
4. Run migrations: `npm run db:push`
5. Start development server: `npm run dev`

## Environment Variables Required
- DATABASE_URL: PostgreSQL connection string
- GOOGLE_CLIENT_ID: Google OAuth client ID
- GOOGLE_CLIENT_SECRET: Google OAuth client secret
- GITHUB_CLIENT_ID: GitHub OAuth client ID
- GITHUB_CLIENT_SECRET: GitHub OAuth client secret
- GMAIL_USER: Email address for password reset
- GMAIL_APP_PASSWORD: Gmail app password
