/**
 * SSL Certificate Intelligence API
 * Provides SSL/TLS certificate analysis and validation
 */

import { NextRequest, NextResponse } from 'next/server';
import { SSLValidator } from '@/services/detection/sslValidator';

export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json();

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Invalid domain provided' },
        { status: 400 }
      );
    }

    // Analyze SSL certificate
    const analysis = await SSLValidator.analyze(domain);

    return NextResponse.json({
      success: true,
      certificate_analysis: {
        domain,
        is_valid: analysis.isValid,
        risk_score: analysis.riskScore,
        indicators: analysis.indicators,
        certificate_details: analysis.certificateDetails,
        trust_analysis: analysis.trustAnalysis,
      },
    });
  } catch (error) {
    console.error('Error analyzing certificate:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to analyze certificate' },
      { status: 500 }
    );
  }
}

/**
 * GET endpoint to quickly verify SSL certificate
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const url = searchParams.get('url');

    if (!url) {
      return NextResponse.json(
        { success: false, error: 'URL parameter is required' },
        { status: 400 }
      );
    }

    // Verify certificate
    const isValid = await SSLValidator.verifyCertificate(url);

    return NextResponse.json({
      success: true,
      url,
      certificate_valid: isValid,
      message: isValid
        ? 'SSL certificate is valid and trusted'
        : 'SSL certificate validation failed or has security issues',
    });
  } catch (error) {
    console.error('Error verifying certificate:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to verify certificate' },
      { status: 500 }
    );
  }
}
