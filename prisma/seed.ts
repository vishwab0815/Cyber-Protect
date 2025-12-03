import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

const modelDefaults = [
  {
    modelId: 'url_analyzer_v1',
    name: 'URL Analyzer',
    description: 'Advanced URL threat detection and analysis with domain reputation checking, SSL verification, and content scanning',
    version: '1.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.7,
    features: ['domain_analysis', 'ssl_check', 'content_scan', 'reputation_lookup', 'typosquatting_detection'],
  },
  {
    modelId: 'email_scanner_v2',
    name: 'Email Scanner',
    description: 'Comprehensive email phishing detection with header analysis, attachment scanning, and NLP-based content analysis',
    version: '2.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.8,
    features: ['header_analysis', 'attachment_scan', 'content_nlp', 'sender_reputation', 'spf_dkim_check', 'link_analysis'],
  },
  {
    modelId: 'file_detector_v1',
    name: 'File Detector',
    description: 'Malicious file detection system with signature analysis, metadata inspection, and behavioral pattern recognition',
    version: '1.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.75,
    features: ['file_signature', 'metadata_analysis', 'behavioral_patterns', 'entropy_analysis', 'pe_analysis'],
  },
  {
    modelId: 'message_classifier_v1',
    name: 'Message Classifier',
    description: 'SMS and message phishing detection with social engineering pattern recognition and urgency analysis',
    version: '1.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.85,
    features: ['nlp_analysis', 'social_engineering_detection', 'urgency_patterns', 'financial_indicators', 'link_detection'],
  },
]

const trustedDomains = [
  { domain: 'google.com', reason: 'Major tech company', addedBy: 'system' },
  { domain: 'microsoft.com', reason: 'Major tech company', addedBy: 'system' },
  { domain: 'apple.com', reason: 'Major tech company', addedBy: 'system' },
  { domain: 'amazon.com', reason: 'Major e-commerce platform', addedBy: 'system' },
  { domain: 'github.com', reason: 'Developer platform', addedBy: 'system' },
  { domain: 'stackoverflow.com', reason: 'Developer community', addedBy: 'system' },
  { domain: 'linkedin.com', reason: 'Professional network', addedBy: 'system' },
  { domain: 'facebook.com', reason: 'Social media platform', addedBy: 'system' },
  { domain: 'twitter.com', reason: 'Social media platform', addedBy: 'system' },
  { domain: 'x.com', reason: 'Social media platform', addedBy: 'system' },
]

const blockedDomains = [
  { domain: 'phishing-example.com', reason: 'Known phishing domain - impersonates banking sites', addedBy: 'system' },
  { domain: 'malware-test.net', reason: 'Malware distribution site', addedBy: 'system' },
  { domain: 'scam-lottery.org', reason: 'Lottery scam operations', addedBy: 'system' },
  { domain: 'fake-paypal-verify.com', reason: 'PayPal phishing campaign', addedBy: 'system' },
  { domain: 'secure-amazon-update.net', reason: 'Amazon impersonation', addedBy: 'system' },
]

const threatIntelligence = [
  {
    domain: 'suspicious-bank-login.com',
    reputation: 15.0,
    sources: ['URLhaus', 'PhishTank', 'OpenPhish'],
    indicators: {
      blacklisted: true,
      malware_hosting: false,
      phishing_reports: 47,
      first_seen: '2024-01-15',
      last_seen: '2024-12-01',
      categories: ['phishing', 'banking-fraud'],
    },
  },
  {
    domain: 'legit-company.com',
    reputation: 95.0,
    sources: ['Google Safe Browsing', 'Norton SafeWeb'],
    indicators: {
      blacklisted: false,
      malware_hosting: false,
      phishing_reports: 0,
      ssl_valid: true,
      domain_age_days: 3650,
      categories: ['business', 'technology'],
    },
  },
  {
    domain: 'medium-risk-site.net',
    reputation: 55.0,
    sources: ['Custom Analysis'],
    indicators: {
      blacklisted: false,
      malware_hosting: false,
      phishing_reports: 2,
      ssl_valid: true,
      recently_registered: true,
      categories: ['unknown'],
    },
  },
]

async function main() {
  console.log('🌱 Starting database seeding...')

  try {
    // Clear existing data (optional - comment out if you want to keep existing data)
    console.log('🗑️  Cleaning up existing seed data...')
    await prisma.threatIntelligence.deleteMany({})
    await prisma.blockedDomain.deleteMany({})
    await prisma.trustedDomain.deleteMany({})
    await prisma.modelConfig.deleteMany({})

    // Seed Model Configurations
    console.log('📊 Seeding AI model configurations...')
    for (const model of modelDefaults) {
      await prisma.modelConfig.upsert({
        where: { modelId: model.modelId },
        update: model,
        create: model,
      })
      console.log(`  ✅ Created model: ${model.name} (${model.modelId})`)
    }

    // Seed Trusted Domains
    console.log('🛡️  Seeding trusted domains...')
    for (const domain of trustedDomains) {
      await prisma.trustedDomain.upsert({
        where: { domain: domain.domain },
        update: domain,
        create: domain,
      })
    }
    console.log(`  ✅ Added ${trustedDomains.length} trusted domains`)

    // Seed Blocked Domains
    console.log('🚫 Seeding blocked domains...')
    for (const domain of blockedDomains) {
      await prisma.blockedDomain.upsert({
        where: { domain: domain.domain },
        update: domain,
        create: domain,
      })
    }
    console.log(`  ✅ Added ${blockedDomains.length} blocked domains`)

    // Seed Threat Intelligence
    console.log('🔍 Seeding threat intelligence data...')
    for (const intel of threatIntelligence) {
      await prisma.threatIntelligence.upsert({
        where: { domain: intel.domain },
        update: intel,
        create: intel,
      })
    }
    console.log(`  ✅ Added ${threatIntelligence.length} threat intelligence entries`)

    // Print summary
    console.log('\n✨ Database seeding completed successfully!')
    console.log('\n📈 Summary:')
    console.log(`  - AI Models: ${modelDefaults.length}`)
    console.log(`  - Trusted Domains: ${trustedDomains.length}`)
    console.log(`  - Blocked Domains: ${blockedDomains.length}`)
    console.log(`  - Threat Intelligence Entries: ${threatIntelligence.length}`)
    console.log('\n🚀 Your PhishGuard application is ready to use!')
  } catch (error) {
    console.error('❌ Error during seeding:', error)
    throw error
  }
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
