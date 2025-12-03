/**
 * IP Intelligence API
 * Provides IP address reputation and threat analysis
 */

import { NextRequest, NextResponse } from 'next/server';
import { IPService } from '@/services/detection/ipService';

export async function POST(request: NextRequest) {
  try {
    const { ip_address } = await request.json();

    if (!ip_address || typeof ip_address !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Invalid IP address provided' },
        { status: 400 }
      );
    }

    // Analyze IP
    const analysis = await IPService.analyze(ip_address);

    return NextResponse.json({
      success: true,
      ip_intelligence: {
        ip_address: analysis.ipAddress,
        risk_score: analysis.riskScore,
        indicators: analysis.indicators,
        geolocation: analysis.geolocation,
        network: analysis.network,
        reputation: analysis.reputation,
      },
    });
  } catch (error) {
    console.error('Error analyzing IP:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to analyze IP address' },
      { status: 500 }
    );
  }
}

/**
 * GET endpoint to quickly check if IP is valid and safe
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const ipAddress = searchParams.get('ip');

    if (!ipAddress) {
      return NextResponse.json(
        { success: false, error: 'IP address parameter is required' },
        { status: 400 }
      );
    }

    // Quick validation
    const isPrivate = IPService.isPrivateIP(ipAddress);

    // Get analysis if not private
    let analysis = null;
    if (!isPrivate) {
      analysis = await IPService.analyze(ipAddress);
    }

    return NextResponse.json({
      success: true,
      ip_address: ipAddress,
      is_private: isPrivate,
      is_safe: analysis ? analysis.riskScore < 40 : true,
      risk_score: analysis?.riskScore || 0,
      threat_level: analysis
        ? analysis.riskScore >= 80
          ? 'CRITICAL'
          : analysis.riskScore >= 60
          ? 'HIGH'
          : analysis.riskScore >= 40
          ? 'MEDIUM'
          : analysis.riskScore >= 20
          ? 'LOW'
          : 'SAFE'
        : 'SAFE',
    });
  } catch (error) {
    console.error('Error checking IP:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to check IP address' },
      { status: 500 }
    );
  }
}
