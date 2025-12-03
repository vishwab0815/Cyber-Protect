import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { EmailAnalyzer } from '@/services/email/emailAnalyzer'

export async function POST(request: NextRequest) {
  try {
    const { from, to, subject, body, bodyHtml, headers, attachments, user_id } = await request.json()

    // Validate required fields
    if (!from || !subject || !body) {
      return NextResponse.json(
        { success: false, error: 'Missing required fields: from, subject, body' },
        { status: 400 }
      )
    }

    const modelConfig = await prisma.modelConfig.findUnique({
      where: { modelId: 'email_scanner_v2' }
    })

    if (!modelConfig || modelConfig.state !== 'ACTIVE') {
      return NextResponse.json(
        { success: false, error: 'Email scanner model not available' },
        { status: 503 }
      )
    }

    // Perform comprehensive email analysis
    const analysis = await EmailAnalyzer.analyzeEmail({
      headers: headers || {},
      from,
      to: to || '',
      subject,
      body,
      bodyHtml,
      attachments,
    })

    // Save scan result
    const scanResult = await prisma.scanResult.create({
      data: {
        userId: user_id,
        type: 'EMAIL',
        target: `From: ${from} - Subject: ${subject}`,
        confidence: analysis.confidence,
        threatLevel: analysis.threatLevel,
        riskScore: analysis.riskScore,
        indicators: analysis.indicators,
        recommendations: analysis.recommendations,
        modelVersion: modelConfig.version,
        metadata: {
          header_analysis: analysis.headerAnalysis,
          content_analysis: analysis.contentAnalysis,
          sender_reputation: analysis.senderReputation,
        },
      },
    })

    return NextResponse.json({
      success: true,
      analysis: {
        id: scanResult.id,
        type: scanResult.type,
        target: scanResult.target,
        result: {
          is_phishing: analysis.isPhishing,
          is_spam: analysis.isSpam,
          is_spoofed: analysis.isSpoofed,
          confidence: scanResult.confidence,
          threat_level: scanResult.threatLevel,
          risk_score: scanResult.riskScore,
          indicators: scanResult.indicators,
          recommendations: scanResult.recommendations,
          spf_result: analysis.headerAnalysis.spfResult,
          dkim_result: analysis.headerAnalysis.dkimResult,
          dmarc_result: analysis.headerAnalysis.dmarcResult,
          suspicious_links: analysis.contentAnalysis.hasSuspiciousLinks,
          suspicious_attachments: analysis.contentAnalysis.hasSuspiciousAttachments,
        },
        user_id: scanResult.userId,
        timestamp: scanResult.timestamp.toISOString(),
        model_version: scanResult.modelVersion,
      },
    })
  } catch (error) {
    console.error('Error analyzing email:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to analyze email' },
      { status: 500 }
    )
  }
}
