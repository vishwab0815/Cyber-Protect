/**
 * SSL/TLS Certificate Validation Service
 * Analyzes SSL certificates for security issues and trust indicators
 */

import { prisma } from '@/lib/prisma';

export interface SSLAnalysisResult {
  isValid: boolean;
  riskScore: number; // 0-100
  indicators: string[];
  certificateDetails?: {
    issuer: string;
    subject: string;
    validFrom: Date;
    validUntil: Date;
    serialNumber: string;
    fingerprint: string;
    algorithm: string;
    keySize?: number;
  };
  trustAnalysis: {
    isSelfSigned: boolean;
    isWildcard: boolean;
    isEV: boolean; // Extended Validation
    chainValid: boolean;
    isExpired: boolean;
    isRevoked: boolean;
    hasWeakCipher: boolean;
    trustScore: number; // 0-100
  };
}

export class SSLValidator {
  /**
   * Analyze SSL certificate for a domain
   */
  static async analyze(domain: string): Promise<SSLAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    // Check cache first
    const cached = await this.getCachedCertificate(domain);
    if (cached && this.isCacheValid(cached.lastChecked)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh SSL analysis
    const certificateDetails = await this.fetchCertificate(domain);

    if (!certificateDetails) {
      return {
        isValid: false,
        riskScore: 100,
        indicators: ['No valid SSL certificate found'],
        trustAnalysis: {
          isSelfSigned: false,
          isWildcard: false,
          isEV: false,
          chainValid: false,
          isExpired: false,
          isRevoked: false,
          hasWeakCipher: false,
          trustScore: 0,
        },
      };
    }

    // Analyze certificate
    const trustAnalysis = await this.analyzeTrust(certificateDetails, domain);

    // Calculate risk based on trust analysis
    if (trustAnalysis.isSelfSigned) {
      indicators.push('Self-signed certificate detected');
      riskScore += 40;
    }

    if (trustAnalysis.isExpired) {
      indicators.push('Certificate has expired');
      riskScore += 50;
    }

    if (trustAnalysis.isRevoked) {
      indicators.push('Certificate has been revoked');
      riskScore += 50;
    }

    if (!trustAnalysis.chainValid) {
      indicators.push('Certificate chain validation failed');
      riskScore += 30;
    }

    if (trustAnalysis.hasWeakCipher) {
      indicators.push('Weak cryptographic algorithm detected');
      riskScore += 20;
    }

    if (certificateDetails.keySize && certificateDetails.keySize < 2048) {
      indicators.push(`Weak key size: ${certificateDetails.keySize} bits`);
      riskScore += 25;
    }

    // Check certificate age
    const certAge = this.getCertificateAge(certificateDetails.validFrom);
    if (certAge < 7) {
      indicators.push('Certificate is very new (less than 7 days old)');
      riskScore += 15;
    }

    // Check remaining validity
    const remainingDays = this.getRemainingValidity(certificateDetails.validUntil);
    if (remainingDays < 30) {
      indicators.push('Certificate expires soon');
      riskScore += 10;
    }

    // EV certificates are more trustworthy
    if (trustAnalysis.isEV) {
      riskScore = Math.max(0, riskScore - 20);
    }

    // Cap risk score
    riskScore = Math.min(riskScore, 100);

    const result: SSLAnalysisResult = {
      isValid: true,
      riskScore,
      indicators,
      certificateDetails,
      trustAnalysis,
    };

    // Cache the result
    await this.cacheCertificate(domain, result);

    return result;
  }

  /**
   * Fetch SSL certificate for domain
   */
  private static async fetchCertificate(domain: string): Promise<{
    issuer: string;
    subject: string;
    validFrom: Date;
    validUntil: Date;
    serialNumber: string;
    fingerprint: string;
    algorithm: string;
    keySize?: number;
  } | null> {
    // In production, use Node's tls module:
    // const tls = require('tls');
    // const socket = tls.connect(443, domain, { servername: domain });
    // const cert = socket.getPeerCertificate();

    // For now, return null (placeholder)
    // This would be implemented with proper TLS connection
    return null;
  }

  /**
   * Analyze certificate trust
   */
  private static async analyzeTrust(
    cert: any,
    domain: string
  ): Promise<{
    isSelfSigned: boolean;
    isWildcard: boolean;
    isEV: boolean;
    chainValid: boolean;
    isExpired: boolean;
    isRevoked: boolean;
    hasWeakCipher: boolean;
    trustScore: number;
  }> {
    const now = new Date();

    const isSelfSigned = cert.issuer === cert.subject;
    const isWildcard = cert.subject.includes('*');
    const isExpired = now > cert.validUntil || now < cert.validFrom;
    const isRevoked = false; // Would check OCSP/CRL in production

    // Check if EV certificate (requires checking issuer OID)
    const isEV = cert.issuer.toLowerCase().includes('extended validation');

    // Validate chain (placeholder)
    const chainValid = !isSelfSigned;

    // Check for weak algorithms
    const weakAlgorithms = ['md5', 'sha1', 'des'];
    const hasWeakCipher = weakAlgorithms.some(alg =>
      cert.algorithm.toLowerCase().includes(alg)
    );

    // Calculate trust score
    let trustScore = 100;
    if (isSelfSigned) trustScore -= 40;
    if (isExpired) trustScore -= 50;
    if (isRevoked) trustScore -= 50;
    if (!chainValid) trustScore -= 30;
    if (hasWeakCipher) trustScore -= 20;
    if (isEV) trustScore = Math.min(100, trustScore + 20);

    trustScore = Math.max(0, trustScore);

    return {
      isSelfSigned,
      isWildcard,
      isEV,
      chainValid,
      isExpired,
      isRevoked,
      hasWeakCipher,
      trustScore,
    };
  }

  /**
   * Get certificate age in days
   */
  private static getCertificateAge(validFrom: Date): number {
    const now = new Date();
    const diffMs = now.getTime() - validFrom.getTime();
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  }

  /**
   * Get remaining validity in days
   */
  private static getRemainingValidity(validUntil: Date): number {
    const now = new Date();
    const diffMs = validUntil.getTime() - now.getTime();
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  }

  /**
   * Get cached certificate
   */
  private static async getCachedCertificate(domain: string) {
    try {
      const certs = await prisma.certificateInfo.findMany({
        where: { domain },
        orderBy: { lastChecked: 'desc' },
        take: 1,
      });

      return certs[0] || null;
    } catch {
      return null;
    }
  }

  /**
   * Check if cache is valid (7 days)
   */
  private static isCacheValid(lastChecked: Date): boolean {
    const now = new Date();
    const cacheAge = now.getTime() - lastChecked.getTime();
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days

    return cacheAge < maxAge;
  }

  /**
   * Build result from cached data
   */
  private static buildResultFromCache(cached: any): SSLAnalysisResult {
    const indicators: string[] = [];
    let riskScore = 100 - cached.trustScore;

    if (cached.isSelfSigned) {
      indicators.push('Self-signed certificate detected');
    }
    if (cached.isRevoked) {
      indicators.push('Certificate has been revoked');
    }
    if (!cached.chainValid) {
      indicators.push('Certificate chain validation failed');
    }
    if (cached.hasWeakCipher) {
      indicators.push('Weak cryptographic algorithm detected');
    }

    const now = new Date();
    const isExpired = now > cached.validUntil || now < cached.validFrom;
    if (isExpired) {
      indicators.push('Certificate has expired');
    }

    return {
      isValid: true,
      riskScore,
      indicators,
      certificateDetails: {
        issuer: cached.issuer,
        subject: cached.subject,
        validFrom: cached.validFrom,
        validUntil: cached.validUntil,
        serialNumber: cached.serialNumber,
        fingerprint: cached.fingerprint,
        algorithm: cached.algorithm,
        keySize: cached.keySize || undefined,
      },
      trustAnalysis: {
        isSelfSigned: cached.isSelfSigned,
        isWildcard: cached.isWildcard,
        isEV: cached.isEV,
        chainValid: cached.chainValid,
        isExpired,
        isRevoked: cached.isRevoked,
        hasWeakCipher: cached.hasWeakCipher,
        trustScore: cached.trustScore,
      },
    };
  }

  /**
   * Cache certificate information
   */
  private static async cacheCertificate(
    domain: string,
    result: SSLAnalysisResult
  ): Promise<void> {
    if (!result.certificateDetails) return;

    const now = new Date();

    try {
      await prisma.certificateInfo.create({
        data: {
          domain,
          issuer: result.certificateDetails.issuer,
          subject: result.certificateDetails.subject,
          validFrom: result.certificateDetails.validFrom,
          validUntil: result.certificateDetails.validUntil,
          serialNumber: result.certificateDetails.serialNumber,
          fingerprint: result.certificateDetails.fingerprint,
          algorithm: result.certificateDetails.algorithm,
          keySize: result.certificateDetails.keySize,
          isSelfSigned: result.trustAnalysis.isSelfSigned,
          isWildcard: result.trustAnalysis.isWildcard,
          isEV: result.trustAnalysis.isEV,
          chainValid: result.trustAnalysis.chainValid,
          chainLength: 1,
          isRevoked: result.trustAnalysis.isRevoked,
          hasWeakCipher: result.trustAnalysis.hasWeakCipher,
          trustScore: result.trustAnalysis.trustScore,
          sanDomains: [], // Would extract from cert.subjectAltName
          ctLogged: false, // Would check Certificate Transparency logs
          ctLogCount: 0,
          lastChecked: now,
          checkCount: 1,
        },
      });
    } catch (error) {
      // If fingerprint exists, update instead
      if (result.certificateDetails.fingerprint) {
        await prisma.certificateInfo.update({
          where: { fingerprint: result.certificateDetails.fingerprint },
          data: {
            lastChecked: now,
            checkCount: { increment: 1 },
          },
        });
      }
    }
  }

  /**
   * Verify SSL certificate is valid for domain
   */
  static async verifyCertificate(url: string): Promise<boolean> {
    try {
      const domain = new URL(url).hostname;
      const result = await this.analyze(domain);
      return result.isValid && result.riskScore < 50;
    } catch {
      return false;
    }
  }
}
