# PhishGuard Setup Guide 🚀

Complete step-by-step instructions to get PhishGuard running locally on your machine.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Database Setup](#database-setup)
4. [Environment Configuration](#environment-configuration)
5. [Running the Application](#running-the-application)
6. [Troubleshooting](#troubleshooting)
7. [Optional Features](#optional-features)
8. [Production Deployment](#production-deployment)

---

## Prerequisites

Before starting, ensure you have the following installed:

### Required Software
- **Node.js**: Version 18.17.0 or higher
- **npm**: Version 9.0.0 or higher (comes with Node.js)
- **Git**: For cloning the repository

### Check Your Versions
```bash
node --version    # Should be v18.17.0 or higher
npm --version     # Should be 9.0.0 or higher
git --version     # Any recent version
```

### Installing Node.js (if needed)
- **Windows/Mac**: Download from [nodejs.org](https://nodejs.org)
- **Linux**: Use your package manager
  ```bash
  # Ubuntu/Debian
  sudo apt update
  sudo apt install nodejs npm

  # Using nvm (recommended)
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
  nvm install 18
  ```

---

## Installation

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone <your-repo-url>

# Navigate to project directory
cd "Phishing Detection Application"
```

### Step 2: Install Dependencies

```bash
# Install all npm packages (this may take 2-3 minutes)
npm install
```

**Expected Output:**
```
added XXX packages in YYs
```

If you see any warnings about peer dependencies, they're usually safe to ignore.

---

## Database Setup

PhishGuard uses PostgreSQL via Neon for data storage. You need a database to store scan results and threat intelligence.

### Step 1: Create Neon Account

1. Visit [neon.tech](https://neon.tech)
2. Click **"Sign Up"** (it's free!)
3. Sign up with GitHub, Google, or Email
4. Verify your email if required

### Step 2: Create a New Project

1. Once logged in, click **"Create Project"**
2. Give your project a name (e.g., "PhishGuard")
3. Select a region (choose closest to you)
4. Click **"Create Project"**

### Step 3: Get Database Connection String

1. After project creation, you'll see a connection string
2. It looks like this:
   ```
   postgresql://username:password@ep-random-name-123456.region.aws.neon.tech/neondb?sslmode=require
   ```
3. **Copy this entire string** - you'll need it in the next step

### Alternative: Local PostgreSQL (Advanced)

If you prefer running PostgreSQL locally:

```bash
# Install PostgreSQL locally
# Then create a database
createdb phishguard

# Your connection string will be:
# postgresql://localhost:5432/phishguard
```

---

## Environment Configuration

### Step 1: Create Environment File

Create a file named `.env.local` in the root directory:

**Windows (Command Prompt):**
```cmd
type nul > .env.local
```

**Windows (PowerShell):**
```powershell
New-Item .env.local
```

**Mac/Linux:**
```bash
touch .env.local
```

### Step 2: Add Required Variables

Open `.env.local` in your text editor and add:

```env
# DATABASE (REQUIRED)
# Replace with your Neon connection string from previous step
DATABASE_URL="postgresql://user:pass@ep-xxxxx.region.aws.neon.tech/neondb?sslmode=require"

# APPLICATION URL (REQUIRED)
NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

**Important:** Replace the `DATABASE_URL` value with your actual Neon connection string!

### Step 3: Optional Variables (Skip for now)

You can add these later if you want enhanced features:

```env
# OPTIONAL: For AI Chatbot feature
OPENAI_API_KEY="sk-proj-your-key-here"

# OPTIONAL: For multi-engine file scanning
VIRUSTOTAL_API_KEY="your-virustotal-key"

# OPTIONAL: For URL reputation enhancement
GOOGLE_SAFE_BROWSING_API_KEY="your-google-key"
```

**Note:** The app works perfectly without these optional keys!

---

## Running the Application

### Step 1: Generate Prisma Client

```bash
npx prisma generate
```

**Expected Output:**
```
✔ Generated Prisma Client (x.x.x) to ./node_modules/@prisma/client in XXms
```

### Step 2: Initialize Database Schema

```bash
npx prisma db push
```

**Expected Output:**
```
🚀 Your database is now in sync with your Prisma schema. Done in XXXms

✔ Generated Prisma Client (x.x.x) to ./node_modules/@prisma/client in XXms
```

This command creates all necessary tables in your database:
- ScanResult
- User
- UserSettings
- ModelConfig
- TrustedDomain
- BlockedDomain
- ThreatIntelligence

### Step 3: Start Development Server

```bash
npm run dev
```

**Expected Output:**
```
   ▲ Next.js 16.0.6 (Turbopack)
   - Local:         http://localhost:3000
   - Network:       http://192.168.x.x:3000

 ✓ Starting...
 ✓ Ready in XXXms
```

### Step 4: Open Application

Open your web browser and navigate to:
```
http://localhost:3000
```

You should see the PhishGuard dashboard! 🎉

---

## Troubleshooting

### Problem: Port 3000 Already in Use

**Error Message:**
```
Error: listen EADDRINUSE: address already in use :::3000
```

**Solution 1:** Kill the process using port 3000
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID_NUMBER> /F

# Mac/Linux
lsof -ti:3000 | xargs kill -9
```

**Solution 2:** Use a different port
```bash
PORT=3001 npm run dev
```

### Problem: Database Connection Failed

**Error Message:**
```
P1001: Can't reach database server
```

**Solutions:**
1. Check your `.env.local` file exists and has correct `DATABASE_URL`
2. Verify your Neon database is active (visit Neon dashboard)
3. Ensure connection string includes `?sslmode=require` at the end
4. Check your internet connection

**Test database connection:**
```bash
npx prisma db pull
```

### Problem: Prisma Client Not Found

**Error Message:**
```
Cannot find module '@prisma/client'
```

**Solution:**
```bash
npx prisma generate
npm install @prisma/client
```

### Problem: TypeScript Errors During Build

**Error Message:**
```
Type error: ...
```

**Solution:**
```bash
# Regenerate Prisma Client
npx prisma generate

# Clear Next.js cache
rmdir /s /q .next    # Windows
rm -rf .next         # Mac/Linux

# Rebuild
npm run build
```

### Problem: Module Not Found Errors

**Error Message:**
```
Module not found: Can't resolve 'xyz'
```

**Solution:**
```bash
# Clear node_modules and reinstall
rmdir /s /q node_modules    # Windows
rm -rf node_modules         # Mac/Linux

npm install
```

### Problem: Build Succeeds but Runtime Errors

**Solution:**
1. Check browser console for errors (F12)
2. Verify all environment variables are set correctly
3. Ensure database tables are created (`npx prisma db push`)
4. Check if you're using the correct Node.js version

---

## Optional Features

### Enable AI Chatbot

The AI Assistant tab requires an OpenAI API key:

1. Get API key from [platform.openai.com](https://platform.openai.com)
2. Add to `.env.local`:
   ```env
   OPENAI_API_KEY="sk-proj-your-key-here"
   ```
3. Restart dev server

### Enable VirusTotal Scanning

For multi-engine file scanning:

1. Get API key from [virustotal.com](https://www.virustotal.com)
2. Add to `.env.local`:
   ```env
   VIRUSTOTAL_API_KEY="your-key-here"
   ```
3. Restart dev server

### Enable Google Safe Browsing

For enhanced URL reputation:

1. Get API key from [Google Cloud Console](https://console.cloud.google.com)
2. Enable Safe Browsing API
3. Add to `.env.local`:
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY="your-key-here"
   ```
4. Restart dev server

**Note:** All these features are OPTIONAL. The app works fully without them!

---

## Production Deployment

### Deploy to Vercel (Easiest)

#### Step 1: Push to GitHub

```bash
# Initialize git (if not already)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: PhishGuard application"

# Add remote (replace with your GitHub repo URL)
git remote add origin https://github.com/yourusername/phishguard.git

# Push to GitHub
git push -u origin main
```

#### Step 2: Deploy to Vercel

1. Go to [vercel.com](https://vercel.com)
2. Sign up/Login with GitHub
3. Click **"Add New Project"**
4. Import your GitHub repository
5. Vercel will auto-detect Next.js settings
6. Add environment variables:
   - Click **"Environment Variables"**
   - Add `DATABASE_URL` with your Neon connection string
   - Add `NEXT_PUBLIC_APP_URL` with your Vercel URL (you'll get this after first deploy)
7. Click **"Deploy"**

#### Step 3: Update Environment

After first deployment:
1. Copy your Vercel URL (e.g., `https://phishguard.vercel.app`)
2. Update `NEXT_PUBLIC_APP_URL` in Vercel dashboard
3. Redeploy

### Deploy to Other Platforms

#### Netlify
```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
netlify deploy --prod
```

#### Railway
1. Visit [railway.app](https://railway.app)
2. Create new project from GitHub
3. Add DATABASE_URL environment variable
4. Deploy

#### Docker (Self-Hosted)
```bash
# Build image
docker build -t phishguard .

# Run container
docker run -p 3000:3000 \
  -e DATABASE_URL="your-connection-string" \
  -e NEXT_PUBLIC_APP_URL="http://localhost:3000" \
  phishguard
```

---

## Database Management

### View Database (Prisma Studio)

```bash
npx prisma studio
```

This opens a GUI at `http://localhost:5555` to view and edit database records.

### Backup Database (Neon)

Neon automatically backs up your database. To manual backup:
1. Go to Neon dashboard
2. Navigate to your project
3. Click **"Backups"**
4. Create backup

### Reset Database

**⚠️ WARNING: This deletes all data!**

```bash
npx prisma db push --force-reset
```

### Update Database Schema

If you modify `prisma/schema.prisma`:

```bash
npx prisma db push
npx prisma generate
```

---

## Development Workflow

### Daily Development

```bash
# Start dev server
npm run dev

# In another terminal, watch for type errors
npm run type-check

# Run linting
npm run lint
```

### Before Committing

```bash
# Check TypeScript
npm run build

# Run linter
npm run lint

# Check for errors
```

### Recommended VS Code Extensions

- **Prisma** - Syntax highlighting for `.prisma` files
- **ESLint** - JavaScript/TypeScript linting
- **Tailwind CSS IntelliSense** - Tailwind class suggestions
- **GitLens** - Enhanced Git integration

---

## Performance Tips

### Speed Up Development

```bash
# Next.js 16 uses Turbopack by default (3x faster)
npm run dev
```

### Reduce Bundle Size

- Code splitting is automatic in Next.js 16
- Images are optimized automatically
- Unused code is tree-shaken in production builds

### Optimize Database Queries

- Prisma includes query caching
- Indexes are defined in `schema.prisma`
- Use `select` to fetch only needed fields

---

## Security Best Practices

### Environment Variables
- ✅ Never commit `.env.local` to Git
- ✅ Use different databases for dev/prod
- ✅ Rotate API keys periodically
- ✅ Use strong database passwords

### API Keys
- 🔒 Store in `.env.local` (not in code)
- 🔒 Add `.env.local` to `.gitignore`
- 🔒 Use environment-specific keys

### Database
- 🔐 Enable SSL (Neon has this by default)
- 🔐 Use connection pooling for production
- 🔐 Regularly backup data

---

## Getting Help

### Documentation
- **This Guide**: Complete setup instructions
- **[README.md](README.md)**: Project overview
- **[CODE_STRUCTURE.md](CODE_STRUCTURE.md)**: Code organization guide

### Common Resources
- [Next.js Docs](https://nextjs.org/docs)
- [Prisma Docs](https://www.prisma.io/docs)
- [Neon Docs](https://neon.tech/docs)
- [Vercel Docs](https://vercel.com/docs)

### Issues?
1. Check this guide's [Troubleshooting](#troubleshooting) section
2. Review error messages in terminal
3. Check browser console (F12) for frontend errors
4. Search existing issues on GitHub
5. Create new issue with detailed information

---

## Next Steps

Now that PhishGuard is running:

1. **Explore Features**
   - Try scanning a URL
   - Upload a file for malware analysis
   - Check the scan history
   - Test the dark mode toggle

2. **Customize**
   - Add your own trusted/blocked domains in Prisma Studio
   - Modify detection patterns in `src/services/`
   - Adjust UI styling in components

3. **Deploy**
   - Follow [Production Deployment](#production-deployment) section
   - Set up custom domain
   - Configure analytics

4. **Extend**
   - Add machine learning models
   - Integrate additional threat feeds
   - Build custom detection rules
   - Add user authentication

---

**🎉 Congratulations!** You now have PhishGuard running locally.

For code navigation and architecture details, see [CODE_STRUCTURE.md](CODE_STRUCTURE.md).

**Happy coding! 🚀**
