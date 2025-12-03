/**
 * Domain Intelligence Service
 * Performs WHOIS lookups, DNS queries, and domain reputation analysis
 */

import { prisma } from '@/lib/prisma';

export interface DomainAnalysisResult {
  domain: string;
  riskScore: number; // 0-100
  indicators: string[];
  whoisData?: {
    registrar?: string;
    createdDate?: Date;
    expiresDate?: Date;
    updatedDate?: Date;
    registrantName?: string;
    registrantOrg?: string;
    domainAge?: number; // days
  };
  dnsData?: {
    ipAddresses: string[];
    mxRecords: string[];
    nsRecords: string[];
    txtRecords: string[];
  };
  reputation: {
    isKnownPhishing: boolean;
    isKnownMalware: boolean;
    reportCount: number;
  };
}

export class DomainService {
  /**
   * Analyze domain with caching
   */
  static async analyze(domain: string): Promise<DomainAnalysisResult> {
    // Clean domain (remove protocol, path, etc.)
    const cleanDomain = this.cleanDomain(domain);

    // Check cache first
    const cached = await this.getCachedIntelligence(cleanDomain);
    if (cached && this.isCacheValid(cached.lastChecked, cached.cacheExpiry)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh analysis
    const result = await this.performFreshAnalysis(cleanDomain);

    // Cache the result
    await this.cacheIntelligence(cleanDomain, result);

    return result;
  }

  /**
   * Perform fresh domain analysis
   */
  private static async performFreshAnalysis(domain: string): Promise<DomainAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    // Perform DNS lookup (simplified - in production use dns.promises)
    const dnsData = await this.performDNSLookup(domain);

    // Perform WHOIS lookup (placeholder - requires external service)
    const whoisData = await this.performWHOISLookup(domain);

    // Calculate domain age risk
    if (whoisData?.domainAge !== undefined) {
      if (whoisData.domainAge < 30) {
        indicators.push('Domain is less than 30 days old');
        riskScore += 30;
      } else if (whoisData.domainAge < 180) {
        indicators.push('Domain is less than 6 months old');
        riskScore += 15;
      }
    }

    // Check for privacy protection
    if (whoisData?.registrantName?.toLowerCase().includes('privacy')) {
      indicators.push('WHOIS privacy protection enabled');
      riskScore += 10;
    }

    // Check DNS records
    if (dnsData.mxRecords.length === 0) {
      indicators.push('No MX records found (suspicious for legitimate domains)');
      riskScore += 10;
    }

    // Check if domain is in our threat intelligence database
    const reputation = await this.checkReputation(domain);
    if (reputation.isKnownPhishing) {
      indicators.push('Domain flagged as known phishing site');
      riskScore += 50;
    }
    if (reputation.isKnownMalware) {
      indicators.push('Domain flagged as malware distributor');
      riskScore += 50;
    }

    // Cap risk score
    riskScore = Math.min(riskScore, 100);

    return {
      domain,
      riskScore,
      indicators,
      whoisData,
      dnsData,
      reputation,
    };
  }

  /**
   * Perform DNS lookup
   */
  private static async performDNSLookup(domain: string): Promise<{
    ipAddresses: string[];
    mxRecords: string[];
    nsRecords: string[];
    txtRecords: string[];
  }> {
    // In production, use Node's dns.promises module
    // For now, return placeholder data
    // Example: const dns = require('dns').promises;
    // const addresses = await dns.resolve4(domain);

    return {
      ipAddresses: [],
      mxRecords: [],
      nsRecords: [],
      txtRecords: [],
    };
  }

  /**
   * Perform WHOIS lookup
   */
  private static async performWHOISLookup(domain: string): Promise<{
    registrar?: string;
    createdDate?: Date;
    expiresDate?: Date;
    updatedDate?: Date;
    registrantName?: string;
    registrantOrg?: string;
    domainAge?: number;
  } | undefined> {
    // In production, use a WHOIS API service like:
    // - whoisxmlapi.com
    // - whois.arin.net
    // - whoisfreaks.com

    // For now, return placeholder
    return undefined;
  }

  /**
   * Check domain reputation
   */
  private static async checkReputation(domain: string): Promise<{
    isKnownPhishing: boolean;
    isKnownMalware: boolean;
    reportCount: number;
  }> {
    // Check if domain is in blocked domains
    const blockedDomain = await prisma.blockedDomain.findUnique({
      where: { domain },
    });

    if (blockedDomain) {
      return {
        isKnownPhishing: true,
        isKnownMalware: false,
        reportCount: 1,
      };
    }

    // Check threat intelligence database
    const threatIntel = await prisma.threatIntelligence.findUnique({
      where: { domain },
    });

    if (threatIntel && threatIntel.reputation < 30) {
      return {
        isKnownPhishing: true,
        isKnownMalware: false,
        reportCount: 1,
      };
    }

    return {
      isKnownPhishing: false,
      isKnownMalware: false,
      reportCount: 0,
    };
  }

  /**
   * Get cached domain intelligence
   */
  private static async getCachedIntelligence(domain: string) {
    try {
      return await prisma.domainIntelligence.findUnique({
        where: { domain },
      });
    } catch {
      return null;
    }
  }

  /**
   * Check if cache is still valid
   */
  private static isCacheValid(lastChecked: Date, cacheExpiry: Date): boolean {
    const now = new Date();
    return now < cacheExpiry;
  }

  /**
   * Build result from cached data
   */
  private static buildResultFromCache(cached: any): DomainAnalysisResult {
    const indicators: string[] = [];
    let riskScore = cached.riskScore;

    if (cached.isKnownPhishing) {
      indicators.push('Domain flagged as known phishing site');
    }
    if (cached.isKnownMalware) {
      indicators.push('Domain flagged as malware distributor');
    }
    if (cached.domainAge !== null && cached.domainAge < 30) {
      indicators.push('Domain is less than 30 days old');
    }

    return {
      domain: cached.domain,
      riskScore,
      indicators,
      whoisData: {
        registrar: cached.registrar || undefined,
        createdDate: cached.createdDate || undefined,
        expiresDate: cached.expiresDate || undefined,
        updatedDate: cached.updatedDate || undefined,
        registrantName: cached.registrantName || undefined,
        registrantOrg: cached.registrantOrg || undefined,
        domainAge: cached.domainAge || undefined,
      },
      dnsData: {
        ipAddresses: cached.ipAddresses,
        mxRecords: cached.mxRecords,
        nsRecords: cached.nsRecords,
        txtRecords: cached.txtRecords,
      },
      reputation: {
        isKnownPhishing: cached.isKnownPhishing,
        isKnownMalware: cached.isKnownMalware,
        reportCount: cached.reportCount,
      },
    };
  }

  /**
   * Cache domain intelligence
   */
  private static async cacheIntelligence(
    domain: string,
    result: DomainAnalysisResult
  ): Promise<void> {
    const now = new Date();
    const cacheExpiry = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours

    try {
      await prisma.domainIntelligence.upsert({
        where: { domain },
        create: {
          domain,
          registrar: result.whoisData?.registrar,
          createdDate: result.whoisData?.createdDate,
          expiresDate: result.whoisData?.expiresDate,
          updatedDate: result.whoisData?.updatedDate,
          registrantName: result.whoisData?.registrantName,
          registrantOrg: result.whoisData?.registrantOrg,
          ipAddresses: result.dnsData?.ipAddresses || [],
          mxRecords: result.dnsData?.mxRecords || [],
          nsRecords: result.dnsData?.nsRecords || [],
          txtRecords: result.dnsData?.txtRecords || [],
          riskScore: result.riskScore,
          isKnownPhishing: result.reputation.isKnownPhishing,
          isKnownMalware: result.reputation.isKnownMalware,
          reportCount: result.reputation.reportCount,
          domainAge: result.whoisData?.domainAge,
          lastChecked: now,
          cacheExpiry,
        },
        update: {
          registrar: result.whoisData?.registrar,
          createdDate: result.whoisData?.createdDate,
          expiresDate: result.whoisData?.expiresDate,
          updatedDate: result.whoisData?.updatedDate,
          registrantName: result.whoisData?.registrantName,
          registrantOrg: result.whoisData?.registrantOrg,
          ipAddresses: result.dnsData?.ipAddresses || [],
          mxRecords: result.dnsData?.mxRecords || [],
          nsRecords: result.dnsData?.nsRecords || [],
          txtRecords: result.dnsData?.txtRecords || [],
          riskScore: result.riskScore,
          isKnownPhishing: result.reputation.isKnownPhishing,
          isKnownMalware: result.reputation.isKnownMalware,
          reportCount: result.reputation.reportCount,
          domainAge: result.whoisData?.domainAge,
          lastChecked: now,
          cacheExpiry,
        },
      });
    } catch (error) {
      console.error('Failed to cache domain intelligence:', error);
    }
  }

  /**
   * Clean domain string
   */
  private static cleanDomain(input: string): string {
    try {
      const url = new URL(input.startsWith('http') ? input : `http://${input}`);
      return url.hostname;
    } catch {
      // If URL parsing fails, try to extract domain from string
      return input.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0];
    }
  }

  /**
   * Check if domain is trusted
   */
  static async isTrustedDomain(domain: string): Promise<boolean> {
    const cleanDomain = this.cleanDomain(domain);

    const trusted = await prisma.trustedDomain.findUnique({
      where: { domain: cleanDomain },
    });

    return !!trusted;
  }

  /**
   * Check if domain is blocked
   */
  static async isBlockedDomain(domain: string): Promise<boolean> {
    const cleanDomain = this.cleanDomain(domain);

    const blocked = await prisma.blockedDomain.findUnique({
      where: { domain: cleanDomain },
    });

    return !!blocked;
  }

  /**
   * Add domain to blocklist
   */
  static async blockDomain(
    domain: string,
    reason: string,
    addedBy?: string
  ): Promise<void> {
    const cleanDomain = this.cleanDomain(domain);

    await prisma.blockedDomain.create({
      data: {
        domain: cleanDomain,
        reason,
        addedBy,
      },
    });
  }

  /**
   * Add domain to trusted list
   */
  static async trustDomain(
    domain: string,
    reason?: string,
    addedBy?: string
  ): Promise<void> {
    const cleanDomain = this.cleanDomain(domain);

    await prisma.trustedDomain.create({
      data: {
        domain: cleanDomain,
        reason,
        addedBy,
      },
    });
  }
}
