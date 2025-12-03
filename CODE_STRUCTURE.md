# PhishGuard Code Structure Guide 📖

Complete guide to understanding the codebase architecture, file organization, and execution flow.

## Table of Contents
1. [Quick Start for Developers](#quick-start-for-developers)
2. [Architecture Overview](#architecture-overview)
3. [Directory Structure](#directory-structure)
4. [Execution Flow](#execution-flow)
5. [Key Files Explained](#key-files-explained)
6. [Detection Engine Deep Dive](#detection-engine-deep-dive)
7. [Adding New Features](#adding-new-features)
8. [Code Conventions](#code-conventions)

---

## Quick Start for Developers

### Where to Start?

**New to the project? Read these files first:**

1. **[src/app/page.tsx](src/app/page.tsx)** - Main dashboard (start here!)
2. **[src/services/detection/masterDetector.ts](src/services/detection/masterDetector.ts)** - Core detection logic
3. **[prisma/schema.prisma](prisma/schema.prisma)** - Database schema
4. **[src/utils/BackendService.tsx](src/utils/BackendService.tsx)** - API client

### Understanding the Flow

```
User opens app → page.tsx (Dashboard)
                    ↓
User clicks "Scan" → ScanInterface.tsx
                    ↓
Submit URL/File → BackendService.tsx (API client)
                    ↓
API Route → /api/analyze/* (Backend)
                    ↓
Detection Engine → masterDetector.ts
                    ↓
Multiple analyzers → URL, Domain, SSL, File, etc.
                    ↓
Save to database → Prisma (PostgreSQL)
                    ↓
Return results → Display in UI
```

---

## Architecture Overview

### Technology Stack

```
┌─────────────────────────────────────────┐
│         Frontend (React 19)             │
│  ┌────────────────────────────────┐    │
│  │   page.tsx (Dashboard)         │    │
│  │   ScanInterface.tsx            │    │
│  │   ScanHistory.tsx              │    │
│  │   AIChatbot.tsx                │    │
│  └────────────────────────────────┘    │
└───────────────┬─────────────────────────┘
                │ HTTP Requests
                ↓
┌─────────────────────────────────────────┐
│     Backend (Next.js API Routes)        │
│  ┌────────────────────────────────┐    │
│  │   /api/analyze/*               │    │
│  │   /api/scans/*                 │    │
│  │   /api/threat-intel/*          │    │
│  └────────────────────────────────┘    │
└───────────────┬─────────────────────────┘
                │ Calls
                ↓
┌─────────────────────────────────────────┐
│   Detection Engines (Services Layer)    │
│  ┌────────────────────────────────┐    │
│  │  URL Analyzer                  │    │
│  │  Domain Service                │    │
│  │  SSL Validator                 │    │
│  │  File Analyzer                 │    │
│  │  Email Analyzer                │    │
│  │  IP Service                    │    │
│  └────────────────────────────────┘    │
└───────────────┬─────────────────────────┘
                │ Stores/Retrieves
                ↓
┌─────────────────────────────────────────┐
│     Database (PostgreSQL + Prisma)      │
│  ScanResult, User, ThreatIntelligence   │
└─────────────────────────────────────────┘
```

### Design Pattern: Layered Architecture

1. **Presentation Layer** (`src/app` + `src/components`)
   - React components
   - User interface
   - State management

2. **API Layer** (`src/app/api`)
   - RESTful endpoints
   - Request validation
   - Response formatting

3. **Business Logic Layer** (`src/services`)
   - Detection engines
   - Threat analysis
   - Intelligence gathering

4. **Data Layer** (`prisma` + `src/lib`)
   - Database operations
   - Data models
   - Caching

---

## Directory Structure

### Root Level
```
phishing-detection-application/
├── src/                    # Source code
├── prisma/                 # Database schema & migrations
├── public/                 # Static assets
├── .next/                  # Build output (auto-generated)
├── node_modules/           # Dependencies (auto-generated)
├── .env.local              # Environment variables (YOU create this)
├── .env.example            # Environment template
├── next.config.js          # Next.js configuration
├── tailwind.config.ts      # Tailwind CSS configuration
├── tsconfig.json           # TypeScript configuration
├── package.json            # Dependencies & scripts
├── README.md               # Project overview
├── SETUP_GUIDE.md          # Setup instructions
└── CODE_STRUCTURE.md       # This file
```

### Source Directory (`src/`)

```
src/
├── app/                      # Next.js App Router
│   ├── api/                  # Backend API Routes
│   │   ├── analyze/
│   │   │   ├── url/
│   │   │   │   └── route.ts  # POST /api/analyze/url
│   │   │   ├── email/
│   │   │   │   └── route.ts  # POST /api/analyze/email
│   │   │   ├── file/
│   │   │   │   └── route.ts  # POST /api/analyze/file
│   │   │   ├── message/
│   │   │   │   └── route.ts  # POST /api/analyze/message
│   │   │   └── batch/
│   │   │       └── route.ts  # POST /api/analyze/batch
│   │   ├── scans/
│   │   │   ├── route.ts      # GET /api/scans
│   │   │   └── [scanId]/
│   │   │       └── route.ts  # GET /api/scans/:id
│   │   ├── threat-intel/
│   │   │   ├── domain/
│   │   │   ├── ip/
│   │   │   └── certificate/
│   │   ├── health/
│   │   │   └── route.ts      # GET /api/health
│   │   ├── stats/
│   │   │   └── route.ts      # GET /api/stats
│   │   └── models/
│   │       └── route.ts      # GET /api/models
│   ├── globals.css           # Global styles
│   ├── layout.tsx            # Root layout (wraps all pages)
│   └── page.tsx              # Home page (Dashboard)
│
├── components/               # React Components
│   ├── ui/                   # Reusable UI primitives
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── dialog.tsx
│   │   ├── tabs.tsx
│   │   └── ... (20+ components)
│   ├── Dashboard.tsx         # Main dashboard component
│   ├── ScanInterface.tsx     # Scanning interface
│   ├── ScanHistory.tsx       # History viewer
│   ├── AIChatbot.tsx         # AI assistant
│   └── Settings.tsx          # Settings panel
│
├── services/                 # Business Logic (Detection Engines)
│   ├── detection/            # Core detection services
│   │   ├── urlAnalyzer.ts    # URL pattern analysis
│   │   ├── domainService.ts  # Domain intelligence
│   │   ├── sslValidator.ts   # SSL/TLS validation
│   │   ├── ipService.ts      # IP intelligence
│   │   └── masterDetector.ts # Orchestrates all detectors
│   ├── malware/              # Malware detection
│   │   ├── fileAnalyzer.ts   # File signature analysis
│   │   ├── documentAnalyzer.ts # Office doc scanning
│   │   ├── scriptAnalyzer.ts # Script pattern detection
│   │   ├── virusTotalFile.ts # VirusTotal integration
│   │   └── masterMalwareDetector.ts # Orchestrates malware detection
│   ├── email/                # Email analysis
│   │   └── emailAnalyzer.ts  # Email phishing detection
│   └── external/             # External API integrations
│       ├── virusTotal.ts     # VirusTotal API
│       ├── googleSafeBrowsing.ts # Google Safe Browsing
│       └── phishTank.ts      # PhishTank database
│
├── lib/                      # Utilities & Configurations
│   ├── prisma.ts             # Prisma client singleton
│   └── utils.ts              # Helper functions (cn, etc.)
│
├── providers/                # React Context Providers
│   └── theme-provider.tsx    # Theme management (dark/light)
│
└── utils/                    # Application Utilities
    └── BackendService.tsx    # API client with fallback logic
```

---

## Execution Flow

### 1. Application Startup

**Entry Point:** `src/app/layout.tsx`

```typescript
// Root layout wraps entire application
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <ThemeProvider>  {/* Dark/Light mode */}
          {children}     {/* Page content */}
          <Toaster />    {/* Toast notifications */}
        </ThemeProvider>
      </body>
    </html>
  )
}
```

**Main Page:** `src/app/page.tsx`

```typescript
export default function Home() {
  // Dashboard with tabs:
  // 1. Dashboard (overview)
  // 2. Scan (URL/file scanning)
  // 3. History (past scans)
  // 4. AI Assistant (chatbot)
  // 5. Settings
}
```

### 2. URL Scan Flow

**Step 1:** User enters URL in `ScanInterface.tsx`

```typescript
const handleScan = async () => {
  // Calls BackendService
  const result = await BackendService.analyzeURL(url, userId)
}
```

**Step 2:** `BackendService.tsx` sends request to API

```typescript
async analyzeURL(url: string, userId?: string) {
  const response = await fetch('/api/analyze/url', {
    method: 'POST',
    body: JSON.stringify({ url, userId })
  })
}
```

**Step 3:** API route `src/app/api/analyze/url/route.ts` handles request

```typescript
export async function POST(request: Request) {
  const { url, userId } = await request.json()

  // Call master detector
  const result = await MasterDetector.analyzeURL(url, userId)

  // Save to database
  await prisma.scanResult.create({ data: result })

  return Response.json(result)
}
```

**Step 4:** `masterDetector.ts` orchestrates analysis

```typescript
static async analyzeURL(url: string) {
  // Layer 1: Static URL Analysis
  const staticAnalysis = await URLAnalyzer.analyze(url)

  // Layer 2: Domain Intelligence
  const domainAnalysis = await DomainService.analyze(domain)

  // Layer 3: SSL Validation
  const sslAnalysis = await SSLValidator.analyze(domain)

  // Layer 4: External APIs (if available)
  const virusTotal = await VirusTotalService.analyzeURL(url)

  // Calculate final risk score
  const riskScore = this.calculateRiskScore(...)

  return comprehensiveResult
}
```

**Step 5:** Results display in UI

```typescript
// ScanInterface.tsx shows results
<Card>
  <ThreatLevel level={result.threatLevel} />
  <RiskScore score={result.riskScore} />
  <Indicators items={result.indicators} />
  <Recommendations items={result.recommendations} />
</Card>
```

### 3. File Scan Flow

**Step 1:** User uploads file in `ScanInterface.tsx`

```typescript
const handleFileUpload = async (file: File) => {
  // Convert to buffer
  const buffer = await file.arrayBuffer()

  // Send to API
  const result = await BackendService.analyzeFile(buffer, fileName)
}
```

**Step 2:** API route `src/app/api/analyze/file/route.ts`

```typescript
export async function POST(request: Request) {
  const formData = await request.formData()
  const file = formData.get('file')

  // Get file buffer
  const buffer = Buffer.from(await file.arrayBuffer())

  // Analyze with malware detector
  const result = await MasterMalwareDetector.analyze(buffer, fileName)

  return Response.json(result)
}
```

**Step 3:** `masterMalwareDetector.ts` analyzes file

```typescript
static async analyze(buffer: Buffer, fileName: string) {
  // Check file signature
  const fileAnalysis = await FileAnalyzer.analyze(buffer, fileName)

  // Check for scripts
  const scriptAnalysis = await ScriptAnalyzer.analyze(content)

  // Check for macros (Office docs)
  const docAnalysis = await DocumentAnalyzer.analyze(buffer)

  // Optional: VirusTotal multi-engine scan
  if (VIRUSTOTAL_API_KEY) {
    const vtResult = await VirusTotalFile.scanFile(buffer)
  }

  return comprehensiveResult
}
```

---

## Key Files Explained

### Frontend Core

#### `src/app/page.tsx` - Main Dashboard
**Purpose:** Home page with tabbed interface
**Key Features:**
- System status monitoring
- Tab navigation (Dashboard/Scan/History/AI/Settings)
- Theme toggle
- Backend connectivity check

**When to Edit:**
- Adding new dashboard tabs
- Modifying header/footer
- Changing theme implementation

#### `src/components/ScanInterface.tsx` - Scanning UI
**Purpose:** Interface for scanning URLs, files, emails
**Key Features:**
- Tab-based scanning (URL/File/Email/Message)
- File upload handling
- Real-time scan results
- Error handling & loading states

**When to Edit:**
- Adding new scan types
- Modifying scan UI
- Changing result display format

#### `src/components/Dashboard.tsx` - Statistics Dashboard
**Purpose:** Overview of system statistics and threats
**Key Features:**
- Threat level distribution chart
- Recent scans display
- System health indicators
- Statistics cards

**When to Edit:**
- Adding new charts
- Modifying statistics display
- Changing dashboard layout

### Backend Core

#### `src/app/api/analyze/url/route.ts` - URL Analysis Endpoint
**Purpose:** API endpoint for URL scanning
**Request:** `POST /api/analyze/url`
**Body:**
```json
{
  "url": "https://example.com",
  "userId": "optional-user-id"
}
```

**Response:**
```json
{
  "target": "https://example.com",
  "type": "URL",
  "threatLevel": "HIGH",
  "riskScore": 85,
  "confidence": 92,
  "indicators": ["Suspicious keyword", "High-risk TLD"],
  "recommendations": ["Do not visit", "Report to security team"]
}
```

**When to Edit:**
- Modifying request validation
- Changing response format
- Adding authentication

#### `src/services/detection/masterDetector.ts` - Detection Orchestrator
**Purpose:** Coordinates all detection engines
**Key Method:** `analyzeURL(url: string)`
**Flow:**
1. Static URL analysis (fast)
2. Domain intelligence check
3. SSL certificate validation
4. IP reputation check
5. External API calls (optional)
6. Calculate risk score
7. Generate recommendations

**When to Edit:**
- Adding new detection layers
- Modifying risk scoring algorithm
- Changing orchestration logic

#### `src/lib/prisma.ts` - Database Client
**Purpose:** Prisma client singleton
**Key Feature:** Ensures only one Prisma client instance exists

**When to Edit:**
- Modifying connection settings
- Adding query middleware
- Changing logging configuration

### Detection Engines

#### `src/services/detection/urlAnalyzer.ts` - URL Pattern Analysis
**Purpose:** Analyzes URL patterns for phishing indicators
**Detection Patterns:**
- Suspicious keywords (login, verify, banking, etc.)
- IP addresses in URLs
- Homograph attacks (Cyrillic lookalikes)
- High-risk TLDs (.tk, .ml, .xyz)
- URL shorteners
- Excessive length
- Multiple subdomains

**Key Method:** `analyze(url: string)`
**Returns:** Risk score, indicators, details

**When to Edit:**
- Adding new suspicious keywords
- Adding new high-risk TLDs
- Modifying risk scoring

#### `src/services/detection/domainService.ts` - Domain Intelligence
**Purpose:** Domain reputation and age analysis
**Features:**
- Trusted domain whitelist
- Blocked domain blacklist
- Domain age estimation
- Subdomain complexity analysis
- Reputation tracking

**When to Edit:**
- Adding trusted/blocked domains
- Modifying reputation algorithm
- Adding WHOIS integration

#### `src/services/malware/fileAnalyzer.ts` - File Malware Detection
**Purpose:** Analyzes files for malware signatures
**Features:**
- Magic number validation
- Extension mismatch detection
- Executable identification
- Archive analysis
- Suspicious pattern detection

**Supported File Types:**
- Executables (.exe, .dll, .bat, .cmd, .ps1)
- Archives (.zip, .rar, .7z, .tar, .gz)
- Scripts (.js, .vbs, .ps1, .sh)
- Documents (.doc, .docx, .xls, .xlsx, .pdf)

**When to Edit:**
- Adding new file type support
- Modifying signature patterns
- Adding new detection rules

### Utility Files

#### `src/utils/BackendService.tsx` - API Client
**Purpose:** Centralized API communication with fallback logic
**Key Features:**
- Automatic retry on failure
- Fallback to local detection if backend unavailable
- Error handling
- Response formatting

**Methods:**
- `analyzeURL(url: string)` - Scan URL
- `analyzeFile(buffer: Buffer)` - Scan file
- `analyzeEmail(content: string)` - Scan email
- `getHealth()` - Health check
- `getStats()` - Get statistics
- `getScans()` - Get scan history

**When to Edit:**
- Adding new API methods
- Modifying error handling
- Changing fallback behavior

#### `src/lib/utils.ts` - Helper Functions
**Purpose:** Utility functions used across the app
**Key Function:** `cn()` - Combines Tailwind classes

```typescript
import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs) {
  return twMerge(clsx(inputs))
}
```

**When to Edit:**
- Adding new utility functions
- Modifying class merging logic

---

## Detection Engine Deep Dive

### How Detection Works

#### 1. URL Analysis Pipeline

```
URL Input: https://paypa1-verify.tk/login
      ↓
┌─────────────────────────────────────┐
│    URLAnalyzer.analyze()            │
│  • Parse URL structure              │
│  • Check for IP addresses           │
│  • Detect suspicious keywords       │
│  • Identify homograph characters    │
│  • Analyze TLD risk                 │
│  • Check URL length                 │
└─────────────────────────────────────┘
      ↓
Indicators Found:
  - "Suspicious keyword: verify"
  - "Suspicious keyword: login"
  - "High-risk TLD: .tk"
  - "Typosquatting: paypa1 vs paypal"
Risk Score: 85/100
```

#### 2. File Analysis Pipeline

```
File Input: invoice.pdf.exe (Buffer)
      ↓
┌─────────────────────────────────────┐
│    FileAnalyzer.analyze()           │
│  • Read magic number (first bytes)  │
│  • Validate file signature          │
│  • Check extension match            │
│  • Identify file type               │
└─────────────────────────────────────┘
      ↓
┌─────────────────────────────────────┐
│    ScriptAnalyzer.analyze()         │
│  • Scan for obfuscated code         │
│  • Detect eval() usage              │
│  • Find suspicious patterns         │
└─────────────────────────────────────┘
      ↓
┌─────────────────────────────────────┐
│   DocumentAnalyzer.analyze()        │
│  • Check for macros                 │
│  • Scan embedded scripts            │
│  • Analyze document metadata        │
└─────────────────────────────────────┘
      ↓
Result:
  Type: Executable (PE32)
  Extension Mismatch: .pdf vs .exe
  Status: MALWARE DETECTED
  Risk Score: 95/100
```

### Risk Scoring Algorithm

Located in `masterDetector.ts`:

```typescript
private static calculateRiskScore(layers: any): number {
  let score = 0

  // Static analysis (0-30 points)
  score += layers.staticAnalysis?.riskScore || 0

  // Domain intelligence (0-25 points)
  if (layers.domainIntelligence?.isBlocked) score += 25
  if (layers.domainIntelligence?.isSuspicious) score += 15

  // SSL issues (0-20 points)
  if (!layers.sslAnalysis?.isValid) score += 20
  if (layers.sslAnalysis?.isSelfSigned) score += 15

  // IP issues (0-15 points)
  if (layers.ipIntelligence?.isMalicious) score += 15

  // External scans (0-30 points)
  if (layers.externalScans?.virusTotal?.detectionCount > 5) {
    score += 30
  }

  return Math.min(score, 100) // Cap at 100
}
```

### Threat Level Mapping

```typescript
function getThreatLevel(riskScore: number): ThreatLevel {
  if (riskScore >= 80) return 'CRITICAL'
  if (riskScore >= 60) return 'HIGH'
  if (riskScore >= 40) return 'MEDIUM'
  if (riskScore >= 20) return 'LOW'
  return 'SAFE'
}
```

---

## Adding New Features

### 1. Adding a New Detection Pattern

**Example:** Detect cryptocurrency scam keywords

**File:** `src/services/detection/urlAnalyzer.ts`

```typescript
// Add to SUSPICIOUS_KEYWORDS array
const CRYPTO_SCAM_KEYWORDS = [
  'double-bitcoin',
  'free-crypto',
  'eth-giveaway',
  'send-btc-get',
  'wallet-verify'
]

// In analyze() method
if (CRYPTO_SCAM_KEYWORDS.some(kw => url.toLowerCase().includes(kw))) {
  indicators.push('Cryptocurrency scam keyword detected')
  riskScore += 25
}
```

### 2. Adding a New API Endpoint

**Example:** Get threat statistics

**File:** Create `src/app/api/threat-stats/route.ts`

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function GET(request: NextRequest) {
  try {
    const stats = await prisma.scanResult.groupBy({
      by: ['threatLevel'],
      _count: {
        threatLevel: true
      }
    })

    return NextResponse.json({
      success: true,
      stats
    })
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to fetch stats' },
      { status: 500 }
    )
  }
}
```

### 3. Adding a New UI Component

**Example:** Alert banner for high-risk scans

**File:** Create `src/components/AlertBanner.tsx`

```typescript
interface AlertBannerProps {
  threatLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  message: string
}

export function AlertBanner({ threatLevel, message }: AlertBannerProps) {
  const colors = {
    SAFE: 'bg-green-100 text-green-800',
    LOW: 'bg-yellow-100 text-yellow-800',
    MEDIUM: 'bg-orange-100 text-orange-800',
    HIGH: 'bg-red-100 text-red-800',
    CRITICAL: 'bg-red-600 text-white'
  }

  return (
    <div className={`p-4 rounded-lg ${colors[threatLevel]}`}>
      <p className="font-medium">{message}</p>
    </div>
  )
}
```

**Usage in page:**
```typescript
import { AlertBanner } from '@/components/AlertBanner'

<AlertBanner
  threatLevel="HIGH"
  message="Warning: This URL appears to be malicious!"
/>
```

### 4. Adding a Database Model

**File:** `prisma/schema.prisma`

```prisma
model URLReputation {
  id                String   @id @default(cuid())
  url               String   @unique
  totalScans        Int      @default(0)
  threatDetections  Int      @default(0)
  lastSeen          DateTime @updatedAt
  createdAt         DateTime @default(now())
}
```

**Apply changes:**
```bash
npx prisma db push
npx prisma generate
```

**Use in code:**
```typescript
// Create reputation record
await prisma.urlReputation.create({
  data: {
    url: 'https://example.com',
    totalScans: 1,
    threatDetections: 0
  }
})

// Update reputation
await prisma.urlReputation.update({
  where: { url: 'https://example.com' },
  data: {
    totalScans: { increment: 1 },
    threatDetections: isThreat ? { increment: 1 } : undefined
  }
})
```

---

## Code Conventions

### TypeScript Standards

```typescript
// ✅ DO: Use interfaces for props
interface ScanResultProps {
  scanId: string
  threatLevel: ThreatLevel
  riskScore: number
}

// ✅ DO: Use explicit types
async function analyzeURL(url: string): Promise<ScanResult> {
  // ...
}

// ❌ DON'T: Use 'any'
function process(data: any) { // Bad!
  // ...
}

// ✅ DO: Use 'unknown' and type guards
function process(data: unknown) {
  if (typeof data === 'string') {
    // TypeScript knows data is string here
  }
}
```

### File Naming

- **Components:** PascalCase - `ScanInterface.tsx`
- **Utilities:** camelCase - `urlAnalyzer.ts`
- **API Routes:** lowercase - `route.ts`
- **Types:** PascalCase - `ScanResult`, `ThreatLevel`

### Component Structure

```typescript
'use client' // If needed

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'

// Types
interface MyComponentProps {
  title: string
  onSubmit: (data: string) => void
}

// Component
export function MyComponent({ title, onSubmit }: MyComponentProps) {
  // State
  const [value, setValue] = useState('')

  // Effects
  useEffect(() => {
    // ...
  }, [])

  // Handlers
  const handleSubmit = () => {
    onSubmit(value)
  }

  // Render
  return (
    <div>
      <h1>{title}</h1>
      <Button onClick={handleSubmit}>Submit</Button>
    </div>
  )
}
```

### API Route Structure

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function POST(request: NextRequest) {
  try {
    // 1. Parse request
    const { url } = await request.json()

    // 2. Validate input
    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      )
    }

    // 3. Process request
    const result = await analyzeURL(url)

    // 4. Return response
    return NextResponse.json({
      success: true,
      data: result
    })
  } catch (error) {
    // 5. Error handling
    console.error('API Error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
```

### Styling Guidelines

```typescript
// ✅ DO: Use Tailwind utility classes
<div className="flex items-center gap-4 rounded-lg border bg-card p-4">
  <Button variant="default" size="lg">Click Me</Button>
</div>

// ✅ DO: Use cn() for conditional classes
<div className={cn(
  "base-classes",
  isActive && "active-classes",
  variant === 'danger' && "danger-classes"
)}>

// ❌ DON'T: Use inline styles
<div style={{ display: 'flex', gap: '16px' }}> // Bad!
```

---

## Debugging Tips

### 1. TypeScript Errors
```bash
# Check all type errors
npm run build

# Regenerate Prisma types
npx prisma generate
```

### 2. API Debugging
```typescript
// Add logging in API routes
console.log('Request:', await request.json())
console.log('Result:', result)

// Check Network tab in browser (F12)
// Look for failed requests, status codes
```

### 3. Component Debugging
```typescript
// Use React DevTools browser extension
// Add console logs
useEffect(() => {
  console.log('Component mounted', props)
}, [])

// Check state updates
console.log('State changed:', value)
```

### 4. Database Debugging
```bash
# Open Prisma Studio
npx prisma studio

# Check database logs
# View data directly in Neon dashboard
```

---

## Performance Optimization

### 1. Caching Strategy
```typescript
// Cache detection results
const cacheKey = `scan:${url}:${Date.now()}`
const cached = await redis.get(cacheKey)
if (cached) return JSON.parse(cached)

// Store result
await redis.set(cacheKey, JSON.stringify(result), 'EX', 3600)
```

### 2. Parallel Processing
```typescript
// Run detectors in parallel
const [staticAnalysis, domainAnalysis, sslAnalysis] = await Promise.all([
  URLAnalyzer.analyze(url),
  DomainService.analyze(domain),
  SSLValidator.analyze(domain)
])
```

### 3. Database Optimization
```prisma
// Add indexes in schema.prisma
model ScanResult {
  id          String   @id @default(cuid())
  target      String
  userId      String?

  @@index([userId])
  @@index([target])
  @@index([createdAt])
}
```

---

## Next Steps

1. **Explore Code**: Start with `src/app/page.tsx` and follow the flow
2. **Run Debugger**: Use VS Code debugger with breakpoints
3. **Modify Features**: Try adding a new detection pattern
4. **Read Documentation**: Check [README.md](README.md) and [SETUP_GUIDE.md](SETUP_GUIDE.md)
5. **Experiment**: Make changes and see what happens!

---

**Happy coding! 🚀**

For setup help, see [SETUP_GUIDE.md](SETUP_GUIDE.md).
For project overview, see [README.md](README.md).
