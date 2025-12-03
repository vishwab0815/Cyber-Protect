/**
 * Master Detection Service
 * Orchestrates all detection layers for comprehensive threat analysis
 */

import { URLAnalyzer } from './urlAnalyzer';
import { DomainService } from './domainService';
import { SSLValidator } from './sslValidator';
import { IPService } from './ipService';
import { VirusTotalService } from '../external/virusTotal';
import { GoogleSafeBrowsingService } from '../external/googleSafeBrowsing';
import { PhishTankService } from '../external/phishTank';
import { prisma } from '@/lib/prisma';
import { ThreatLevel, ScanType } from '@prisma/client';

export interface ComprehensiveAnalysisResult {
  target: string;
  type: ScanType;
  confidence: number; // 0-100
  threatLevel: ThreatLevel;
  riskScore: number; // 0-100
  indicators: string[];
  recommendations: string[];
  layers: {
    staticAnalysis?: any;
    domainIntelligence?: any;
    sslAnalysis?: any;
    ipIntelligence?: any;
    externalScans?: {
      virusTotal?: any;
      safeBrowsing?: any;
      phishTank?: any;
    };
  };
  scanDuration: number; // milliseconds
  timestamp: Date;
}

export class MasterDetector {
  /**
   * Perform comprehensive URL analysis
   */
  static async analyzeURL(url: string, userId?: string): Promise<ComprehensiveAnalysisResult> {
    const startTime = Date.now();
    const indicators: string[] = [];
    const recommendations: string[] = [];
    const layers: any = {};

    // Layer 1: Static URL Analysis (Fast, Synchronous)
    try {
      const staticAnalysis = await URLAnalyzer.analyze(url);
      layers.staticAnalysis = staticAnalysis;
      indicators.push(...staticAnalysis.indicators);
    } catch (error) {
      console.error('Static analysis failed:', error);
    }

    // Extract domain from URL
    const domain = URLAnalyzer.extractDomain(url);

    // Layer 2: Domain Intelligence (Cached, Fast)
    if (domain) {
      try {
        // Check if domain is trusted or blocked first
        const isTrusted = await DomainService.isTrustedDomain(domain);
        const isBlocked = await DomainService.isBlockedDomain(domain);

        if (isTrusted) {
          // Trusted domain - reduce risk significantly
          const scanDuration = Date.now() - startTime;
          return this.buildTrustedResult(url, scanDuration);
        }

        if (isBlocked) {
          // Blocked domain - immediate high risk
          const scanDuration = Date.now() - startTime;
          return this.buildBlockedResult(url, scanDuration);
        }

        const domainAnalysis = await DomainService.analyze(domain);
        layers.domainIntelligence = domainAnalysis;
        indicators.push(...domainAnalysis.indicators);
      } catch (error) {
        console.error('Domain intelligence failed:', error);
      }

      // Layer 3: SSL/TLS Certificate Analysis (Cached, Medium)
      if (url.startsWith('https://')) {
        try {
          const sslAnalysis = await SSLValidator.analyze(domain);
          layers.sslAnalysis = sslAnalysis;
          indicators.push(...sslAnalysis.indicators);
        } catch (error) {
          console.error('SSL analysis failed:', error);
        }
      } else {
        indicators.push('URL does not use HTTPS encryption');
      }
    }

    // Layer 4: IP Intelligence (if URL uses IP)
    const ipAddress = IPService.extractIPFromURL(url);
    if (ipAddress) {
      try {
        const ipAnalysis = await IPService.analyze(ipAddress);
        layers.ipIntelligence = ipAnalysis;
        indicators.push(...ipAnalysis.indicators);
      } catch (error) {
        console.error('IP intelligence failed:', error);
      }
    }

    // Layer 5: External Threat Intelligence (Async, Slower)
    const externalScans: any = {};

    // Run external scans in parallel
    const externalPromises = [
      GoogleSafeBrowsingService.checkURL(url)
        .then(result => { externalScans.safeBrowsing = result; })
        .catch(err => console.error('Safe Browsing failed:', err)),

      PhishTankService.checkURL(url)
        .then(result => { externalScans.phishTank = result; })
        .catch(err => console.error('PhishTank failed:', err)),

      VirusTotalService.analyzeURL(url)
        .then(result => { externalScans.virusTotal = result; })
        .catch(err => console.error('VirusTotal failed:', err)),
    ];

    await Promise.allSettled(externalPromises);

    // Process external scan results
    if (externalScans.safeBrowsing?.isThreat) {
      indicators.push(`Google Safe Browsing: ${externalScans.safeBrowsing.threatType}`);
    }

    if (externalScans.phishTank?.isPhishing) {
      indicators.push('PhishTank: URL identified as phishing site');
    }

    if (externalScans.virusTotal?.isPhishing || externalScans.virusTotal?.isMalware) {
      indicators.push(
        `VirusTotal: ${externalScans.virusTotal.detectionCount}/${externalScans.virusTotal.totalEngines} engines detected threats`
      );
    }

    layers.externalScans = externalScans;

    // Calculate final risk score
    const riskScore = this.calculateRiskScore(layers);

    // Determine threat level
    const threatLevel = this.determineThreatLevel(riskScore);

    // Calculate confidence
    const confidence = this.calculateConfidence(layers);

    // Generate recommendations
    recommendations.push(...this.generateRecommendations(riskScore, layers));

    // Calculate scan duration
    const scanDuration = Date.now() - startTime;

    const result: ComprehensiveAnalysisResult = {
      target: url,
      type: 'URL',
      confidence,
      threatLevel,
      riskScore,
      indicators,
      recommendations,
      layers,
      scanDuration,
      timestamp: new Date(),
    };

    // Save result to database
    await this.saveScanResult(result, userId);

    return result;
  }

  /**
   * Calculate overall risk score from all layers
   */
  private static calculateRiskScore(layers: any): number {
    let riskScore = 0;
    let layerCount = 0;

    // Static analysis weight: 20%
    if (layers.staticAnalysis) {
      riskScore += layers.staticAnalysis.riskScore * 0.2;
      layerCount++;
    }

    // Domain intelligence weight: 25%
    if (layers.domainIntelligence) {
      riskScore += layers.domainIntelligence.riskScore * 0.25;
      layerCount++;
    }

    // SSL analysis weight: 15%
    if (layers.sslAnalysis) {
      riskScore += layers.sslAnalysis.riskScore * 0.15;
      layerCount++;
    }

    // IP intelligence weight: 10%
    if (layers.ipIntelligence) {
      riskScore += layers.ipIntelligence.riskScore * 0.1;
      layerCount++;
    }

    // External scans weight: 30% (combined)
    if (layers.externalScans) {
      let externalRisk = 0;

      if (layers.externalScans.safeBrowsing?.isThreat) {
        externalRisk += 33.33; // Critical finding
      }

      if (layers.externalScans.phishTank?.isPhishing) {
        externalRisk += 33.33; // Critical finding
      }

      if (layers.externalScans.virusTotal) {
        const vtRisk = (layers.externalScans.virusTotal.confidence || 0);
        externalRisk += vtRisk * 0.3333;
      }

      riskScore += externalRisk * 0.3;
      layerCount++;
    }

    return Math.min(Math.round(riskScore), 100);
  }

  /**
   * Determine threat level based on risk score
   */
  private static determineThreatLevel(riskScore: number): ThreatLevel {
    if (riskScore >= 80) return 'CRITICAL';
    if (riskScore >= 60) return 'HIGH';
    if (riskScore >= 40) return 'MEDIUM';
    if (riskScore >= 20) return 'LOW';
    return 'SAFE';
  }

  /**
   * Calculate confidence level
   */
  private static calculateConfidence(layers: any): number {
    let confidence = 50; // Base confidence

    // More layers analyzed = higher confidence
    if (layers.staticAnalysis) confidence += 10;
    if (layers.domainIntelligence) confidence += 15;
    if (layers.sslAnalysis) confidence += 10;
    if (layers.ipIntelligence) confidence += 5;

    // External verification significantly boosts confidence
    if (layers.externalScans) {
      if (layers.externalScans.safeBrowsing) confidence += 5;
      if (layers.externalScans.phishTank) confidence += 5;
      if (layers.externalScans.virusTotal) confidence += 10;
    }

    return Math.min(confidence, 100);
  }

  /**
   * Generate recommendations based on analysis
   */
  private static generateRecommendations(riskScore: number, layers: any): string[] {
    const recommendations: string[] = [];

    if (riskScore >= 80) {
      recommendations.push('DO NOT visit this URL or enter any personal information');
      recommendations.push('Block this domain in your firewall or security software');
      recommendations.push('Report this phishing attempt to authorities');
    } else if (riskScore >= 60) {
      recommendations.push('Exercise extreme caution when accessing this URL');
      recommendations.push('Do not enter sensitive information like passwords or credit cards');
      recommendations.push('Verify the legitimacy through official channels');
    } else if (riskScore >= 40) {
      recommendations.push('Approach with caution and verify the sender/source');
      recommendations.push('Look for official contact information to verify legitimacy');
      recommendations.push('Enable two-factor authentication before proceeding');
    } else if (riskScore >= 20) {
      recommendations.push('Exercise normal internet safety precautions');
      recommendations.push('Verify the URL matches the expected domain');
    } else {
      recommendations.push('URL appears safe, but always remain vigilant online');
    }

    // Specific recommendations based on layers
    if (!layers.sslAnalysis && riskScore > 20) {
      recommendations.push('Use HTTPS version of this site if available');
    }

    if (layers.domainIntelligence?.whoisData?.domainAge < 30) {
      recommendations.push('Verify this is a legitimate new service before sharing data');
    }

    return recommendations;
  }

  /**
   * Build result for trusted domain
   */
  private static buildTrustedResult(url: string, scanDuration: number): ComprehensiveAnalysisResult {
    return {
      target: url,
      type: 'URL',
      confidence: 95,
      threatLevel: 'SAFE',
      riskScore: 0,
      indicators: ['Domain is on trusted whitelist'],
      recommendations: ['URL is verified as trusted'],
      layers: {},
      scanDuration,
      timestamp: new Date(),
    };
  }

  /**
   * Build result for blocked domain
   */
  private static buildBlockedResult(url: string, scanDuration: number): ComprehensiveAnalysisResult {
    return {
      target: url,
      type: 'URL',
      confidence: 100,
      threatLevel: 'CRITICAL',
      riskScore: 100,
      indicators: ['Domain is on blocklist'],
      recommendations: ['DO NOT access this URL - it has been blocked for security reasons'],
      layers: {},
      scanDuration,
      timestamp: new Date(),
    };
  }

  /**
   * Save scan result to database
   */
  private static async saveScanResult(
    result: ComprehensiveAnalysisResult,
    userId?: string
  ): Promise<void> {
    try {
      await prisma.scanResult.create({
        data: {
          userId,
          type: result.type,
          target: result.target,
          status: 'COMPLETED',
          confidence: result.confidence,
          threatLevel: result.threatLevel,
          riskScore: result.riskScore,
          indicators: result.indicators,
          recommendations: result.recommendations,
          scanDuration: result.scanDuration,
          timestamp: result.timestamp,
          metadata: result.layers,
        },
      });
    } catch (error) {
      console.error('Failed to save scan result:', error);
    }
  }

  /**
   * Perform lightweight quick scan (no external APIs)
   */
  static async quickScan(url: string): Promise<{
    riskScore: number;
    threatLevel: ThreatLevel;
    isSafe: boolean;
  }> {
    const staticAnalysis = await URLAnalyzer.analyze(url);
    const domain = URLAnalyzer.extractDomain(url);

    let riskScore = staticAnalysis.riskScore;

    if (domain) {
      const isBlocked = await DomainService.isBlockedDomain(domain);
      if (isBlocked) {
        riskScore = 100;
      }

      const isTrusted = await DomainService.isTrustedDomain(domain);
      if (isTrusted) {
        riskScore = 0;
      }
    }

    const threatLevel = this.determineThreatLevel(riskScore);

    return {
      riskScore,
      threatLevel,
      isSafe: riskScore < 40,
    };
  }
}
