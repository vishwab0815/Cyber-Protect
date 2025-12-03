import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  try {
    const { scanId } = await params;
    const scan = await prisma.scanResult.findUnique({
      where: { id: scanId },
    })

    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      scan: {
        id: scan.id,
        type: scan.type,
        target: scan.target,
        result: {
          confidence: scan.confidence,
          threat_level: scan.threatLevel,
          risk_score: scan.riskScore,
          indicators: scan.indicators,
          recommendations: scan.recommendations,
        },
        user_id: scan.userId,
        timestamp: scan.timestamp.toISOString(),
        model_version: scan.modelVersion,
        metadata: scan.metadata,
      },
    })
  } catch (error) {
    console.error('Error fetching scan:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to fetch scan details' },
      { status: 500 }
    )
  }
}
