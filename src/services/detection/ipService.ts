/**
 * IP Intelligence Service
 * Provides IP geolocation, reputation, and threat analysis
 */

import { prisma } from '@/lib/prisma';

export interface IPAnalysisResult {
  ipAddress: string;
  riskScore: number; // 0-100
  indicators: string[];
  geolocation?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
  };
  network?: {
    asn?: string;
    asnOrg?: string;
    isp?: string;
    organization?: string;
  };
  reputation: {
    abuseScore: number; // 0-100
    threatScore: number; // 0-100
    isProxy: boolean;
    isVPN: boolean;
    isTor: boolean;
    isDataCenter: boolean;
    isHosting: boolean;
    isBlacklisted: boolean;
    blacklistCount: number;
    isBot: boolean;
  };
}

export class IPService {
  /**
   * Analyze IP address
   */
  static async analyze(ipAddress: string): Promise<IPAnalysisResult> {
    // Validate IP format
    if (!this.isValidIP(ipAddress)) {
      return this.createInvalidResult(ipAddress);
    }

    // Check cache first
    const cached = await this.getCachedIntelligence(ipAddress);
    if (cached && this.isCacheValid(cached.lastChecked)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh analysis
    const result = await this.performFreshAnalysis(ipAddress);

    // Cache the result
    await this.cacheIntelligence(ipAddress, result);

    return result;
  }

  /**
   * Perform fresh IP analysis
   */
  private static async performFreshAnalysis(ipAddress: string): Promise<IPAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    // Fetch geolocation data (placeholder - use ipapi.co, ipinfo.io, etc.)
    const geolocation = await this.fetchGeolocation(ipAddress);

    // Fetch network information (placeholder - use ipwhois.io, etc.)
    const network = await this.fetchNetworkInfo(ipAddress);

    // Fetch reputation data (placeholder - use AbuseIPDB, IPVoid, etc.)
    const reputation = await this.fetchReputationData(ipAddress);

    // Calculate risk based on reputation
    if (reputation.isBlacklisted) {
      indicators.push('IP is blacklisted on threat intelligence feeds');
      riskScore += 50;
    }

    if (reputation.blacklistCount > 0) {
      indicators.push(`IP appears on ${reputation.blacklistCount} blacklists`);
      riskScore += Math.min(reputation.blacklistCount * 10, 40);
    }

    if (reputation.abuseScore > 50) {
      indicators.push(`High abuse score: ${reputation.abuseScore}/100`);
      riskScore += 30;
    }

    if (reputation.isProxy || reputation.isVPN) {
      indicators.push('IP is a proxy or VPN service');
      riskScore += 15;
    }

    if (reputation.isTor) {
      indicators.push('IP is a Tor exit node');
      riskScore += 25;
    }

    if (reputation.isDataCenter || reputation.isHosting) {
      indicators.push('IP belongs to a data center or hosting provider');
      riskScore += 10;
    }

    if (reputation.isBot) {
      indicators.push('IP associated with bot activity');
      riskScore += 20;
    }

    // Check for known malicious countries (high-risk regions)
    const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
    if (geolocation?.countryCode && highRiskCountries.includes(geolocation.countryCode)) {
      indicators.push(`IP originates from high-risk country: ${geolocation.country}`);
      riskScore += 10;
    }

    // Cap risk score
    riskScore = Math.min(riskScore, 100);

    return {
      ipAddress,
      riskScore,
      indicators,
      geolocation,
      network,
      reputation,
    };
  }

  /**
   * Fetch geolocation data
   */
  private static async fetchGeolocation(ipAddress: string): Promise<{
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
  }> {
    // In production, use services like:
    // - ipapi.co (free tier: 30k/month)
    // - ipinfo.io (free tier: 50k/month)
    // - ip-api.com (free, no key required)

    // Placeholder implementation
    return {};
  }

  /**
   * Fetch network information
   */
  private static async fetchNetworkInfo(ipAddress: string): Promise<{
    asn?: string;
    asnOrg?: string;
    isp?: string;
    organization?: string;
  }> {
    // In production, use services like:
    // - ipwhois.io
    // - ipinfo.io

    // Placeholder implementation
    return {};
  }

  /**
   * Fetch reputation data
   */
  private static async fetchReputationData(ipAddress: string): Promise<{
    abuseScore: number;
    threatScore: number;
    isProxy: boolean;
    isVPN: boolean;
    isTor: boolean;
    isDataCenter: boolean;
    isHosting: boolean;
    isBlacklisted: boolean;
    blacklistCount: number;
    isBot: boolean;
  }> {
    // In production, use services like:
    // - AbuseIPDB (free tier: 1k/day)
    // - IPVoid
    // - Shodan
    // - GreyNoise

    // Placeholder implementation
    return {
      abuseScore: 0,
      threatScore: 0,
      isProxy: false,
      isVPN: false,
      isTor: false,
      isDataCenter: false,
      isHosting: false,
      isBlacklisted: false,
      blacklistCount: 0,
      isBot: false,
    };
  }

  /**
   * Validate IP address format
   */
  private static isValidIP(ipAddress: string): boolean {
    // IPv4 pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Pattern.test(ipAddress)) {
      // Check each octet is 0-255
      const octets = ipAddress.split('.');
      return octets.every(octet => {
        const num = parseInt(octet);
        return num >= 0 && num <= 255;
      });
    }

    // IPv6 pattern (simplified)
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
    return ipv6Pattern.test(ipAddress);
  }

  /**
   * Create result for invalid IP
   */
  private static createInvalidResult(ipAddress: string): IPAnalysisResult {
    return {
      ipAddress,
      riskScore: 0,
      indicators: ['Invalid IP address format'],
      reputation: {
        abuseScore: 0,
        threatScore: 0,
        isProxy: false,
        isVPN: false,
        isTor: false,
        isDataCenter: false,
        isHosting: false,
        isBlacklisted: false,
        blacklistCount: 0,
        isBot: false,
      },
    };
  }

  /**
   * Get cached IP intelligence
   */
  private static async getCachedIntelligence(ipAddress: string) {
    try {
      return await prisma.iPIntelligence.findUnique({
        where: { ipAddress },
      });
    } catch {
      return null;
    }
  }

  /**
   * Check if cache is valid (24 hours)
   */
  private static isCacheValid(lastChecked: Date): boolean {
    const now = new Date();
    const cacheAge = now.getTime() - lastChecked.getTime();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    return cacheAge < maxAge;
  }

  /**
   * Build result from cached data
   */
  private static buildResultFromCache(cached: any): IPAnalysisResult {
    const indicators: string[] = [];
    let riskScore = cached.threatScore;

    if (cached.isBlacklisted) {
      indicators.push('IP is blacklisted on threat intelligence feeds');
    }
    if (cached.blacklistCount > 0) {
      indicators.push(`IP appears on ${cached.blacklistCount} blacklists`);
    }
    if (cached.abuseScore > 50) {
      indicators.push(`High abuse score: ${cached.abuseScore}/100`);
    }
    if (cached.isProxy || cached.isVPN) {
      indicators.push('IP is a proxy or VPN service');
    }
    if (cached.isTor) {
      indicators.push('IP is a Tor exit node');
    }
    if (cached.isBot) {
      indicators.push('IP associated with bot activity');
    }

    return {
      ipAddress: cached.ipAddress,
      riskScore,
      indicators,
      geolocation: {
        country: cached.country || undefined,
        countryCode: cached.countryCode || undefined,
        region: cached.region || undefined,
        city: cached.city || undefined,
        latitude: cached.latitude || undefined,
        longitude: cached.longitude || undefined,
        timezone: cached.timezone || undefined,
      },
      network: {
        asn: cached.asn || undefined,
        asnOrg: cached.asnOrg || undefined,
        isp: cached.isp || undefined,
        organization: cached.organization || undefined,
      },
      reputation: {
        abuseScore: cached.abuseScore,
        threatScore: cached.threatScore,
        isProxy: cached.isProxy,
        isVPN: cached.isVPN,
        isTor: cached.isTor,
        isDataCenter: cached.isDataCenter,
        isHosting: cached.isHosting,
        isBlacklisted: cached.isBlacklisted,
        blacklistCount: cached.blacklistCount,
        isBot: cached.isBot,
      },
    };
  }

  /**
   * Cache IP intelligence
   */
  private static async cacheIntelligence(
    ipAddress: string,
    result: IPAnalysisResult
  ): Promise<void> {
    const now = new Date();

    try {
      await prisma.iPIntelligence.upsert({
        where: { ipAddress },
        create: {
          ipAddress,
          country: result.geolocation?.country,
          countryCode: result.geolocation?.countryCode,
          region: result.geolocation?.region,
          city: result.geolocation?.city,
          latitude: result.geolocation?.latitude,
          longitude: result.geolocation?.longitude,
          timezone: result.geolocation?.timezone,
          asn: result.network?.asn,
          asnOrg: result.network?.asnOrg,
          isp: result.network?.isp,
          organization: result.network?.organization,
          abuseScore: result.reputation.abuseScore,
          threatScore: result.reputation.threatScore,
          isProxy: result.reputation.isProxy,
          isVPN: result.reputation.isVPN,
          isTor: result.reputation.isTor,
          isDataCenter: result.reputation.isDataCenter,
          isHosting: result.reputation.isHosting,
          isBlacklisted: result.reputation.isBlacklisted,
          blacklistCount: result.reputation.blacklistCount,
          isBot: result.reputation.isBot,
          firstSeen: now,
          lastChecked: now,
          checkCount: 1,
        },
        update: {
          country: result.geolocation?.country,
          countryCode: result.geolocation?.countryCode,
          region: result.geolocation?.region,
          city: result.geolocation?.city,
          latitude: result.geolocation?.latitude,
          longitude: result.geolocation?.longitude,
          timezone: result.geolocation?.timezone,
          asn: result.network?.asn,
          asnOrg: result.network?.asnOrg,
          isp: result.network?.isp,
          organization: result.network?.organization,
          abuseScore: result.reputation.abuseScore,
          threatScore: result.reputation.threatScore,
          isProxy: result.reputation.isProxy,
          isVPN: result.reputation.isVPN,
          isTor: result.reputation.isTor,
          isDataCenter: result.reputation.isDataCenter,
          isHosting: result.reputation.isHosting,
          isBlacklisted: result.reputation.isBlacklisted,
          blacklistCount: result.reputation.blacklistCount,
          isBot: result.reputation.isBot,
          lastChecked: now,
          checkCount: { increment: 1 },
        },
      });
    } catch (error) {
      console.error('Failed to cache IP intelligence:', error);
    }
  }

  /**
   * Extract IP addresses from URL
   */
  static extractIPFromURL(url: string): string | null {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname;

      if (this.isValidIP(hostname)) {
        return hostname;
      }
    } catch {
      // Invalid URL
    }

    return null;
  }

  /**
   * Check if IP is from a private network
   */
  static isPrivateIP(ipAddress: string): boolean {
    if (!this.isValidIP(ipAddress)) return false;

    const octets = ipAddress.split('.').map(Number);

    // Check private ranges
    // 10.0.0.0 - 10.255.255.255
    if (octets[0] === 10) return true;

    // 172.16.0.0 - 172.31.255.255
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;

    // 192.168.0.0 - 192.168.255.255
    if (octets[0] === 192 && octets[1] === 168) return true;

    // 127.0.0.0 - 127.255.255.255 (loopback)
    if (octets[0] === 127) return true;

    return false;
  }
}
