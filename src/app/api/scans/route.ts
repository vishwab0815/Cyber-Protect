import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const user_id = searchParams.get('user_id')

    const where = user_id ? { userId: user_id } : {}

    const scans = await prisma.scanResult.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: 100, // Limit to 100 most recent scans
    })

    return NextResponse.json({
      success: true,
      scans: scans.map(scan => ({
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
      })),
    })
  } catch (error) {
    console.error('Error fetching scans:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to fetch scan history' },
      { status: 500 }
    )
  }
}
