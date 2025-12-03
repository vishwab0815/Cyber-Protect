/**
 * Domain Intelligence API
 * Provides detailed domain information and threat analysis
 */

import { NextRequest, NextResponse } from 'next/server';
import { DomainService } from '@/services/detection/domainService';

export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json();

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Invalid domain provided' },
        { status: 400 }
      );
    }

    // Analyze domain
    const analysis = await DomainService.analyze(domain);

    return NextResponse.json({
      success: true,
      domain_intelligence: {
        domain: analysis.domain,
        risk_score: analysis.riskScore,
        indicators: analysis.indicators,
        whois_data: analysis.whoisData,
        dns_data: analysis.dnsData,
        reputation: analysis.reputation,
      },
    });
  } catch (error) {
    console.error('Error analyzing domain:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to analyze domain' },
      { status: 500 }
    );
  }
}

/**
 * GET endpoint to check if domain is trusted or blocked
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const domain = searchParams.get('domain');

    if (!domain) {
      return NextResponse.json(
        { success: false, error: 'Domain parameter is required' },
        { status: 400 }
      );
    }

    const isTrusted = await DomainService.isTrustedDomain(domain);
    const isBlocked = await DomainService.isBlockedDomain(domain);

    return NextResponse.json({
      success: true,
      domain,
      is_trusted: isTrusted,
      is_blocked: isBlocked,
      status: isBlocked ? 'BLOCKED' : isTrusted ? 'TRUSTED' : 'UNKNOWN',
    });
  } catch (error) {
    console.error('Error checking domain status:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to check domain status' },
      { status: 500 }
    );
  }
}

/**
 * PUT endpoint to add domain to trusted/blocked lists
 */
export async function PUT(request: NextRequest) {
  try {
    const { domain, action, reason, added_by } = await request.json();

    if (!domain || !action) {
      return NextResponse.json(
        { success: false, error: 'Domain and action are required' },
        { status: 400 }
      );
    }

    if (action === 'trust') {
      await DomainService.trustDomain(domain, reason, added_by);
      return NextResponse.json({
        success: true,
        message: 'Domain added to trusted list',
      });
    } else if (action === 'block') {
      if (!reason) {
        return NextResponse.json(
          { success: false, error: 'Reason is required for blocking' },
          { status: 400 }
        );
      }
      await DomainService.blockDomain(domain, reason, added_by);
      return NextResponse.json({
        success: true,
        message: 'Domain added to blocked list',
      });
    } else {
      return NextResponse.json(
        { success: false, error: 'Invalid action. Use "trust" or "block"' },
        { status: 400 }
      );
    }
  } catch (error) {
    console.error('Error updating domain status:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to update domain status' },
      { status: 500 }
    );
  }
}
