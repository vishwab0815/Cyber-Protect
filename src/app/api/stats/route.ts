import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const user_id = searchParams.get('user_id')

    const where = user_id ? { userId: user_id } : {}

    // Get all scans for the user
    const scans = await prisma.scanResult.findMany({
      where,
    })

    // Calculate statistics
    const totalScans = scans.length
    const threatsDetected = scans.filter(
      s => s.threatLevel === 'HIGH' || s.threatLevel === 'CRITICAL'
    ).length
    const safeItems = scans.filter(s => s.threatLevel === 'SAFE').length
    const suspiciousItems = scans.filter(
      s => s.threatLevel === 'MEDIUM' || s.threatLevel === 'LOW'
    ).length

    // Group by type
    const byType = {
      url: scans.filter(s => s.type === 'URL').length,
      email: scans.filter(s => s.type === 'EMAIL').length,
      message: scans.filter(s => s.type === 'MESSAGE').length,
      file: scans.filter(s => s.type === 'FILE').length,
    }

    // Recent activity (last 24 hours)
    const yesterday = new Date()
    yesterday.setDate(yesterday.getDate() - 1)
    const recentActivity = scans.filter(
      s => new Date(s.timestamp) >= yesterday
    ).length

    return NextResponse.json({
      success: true,
      stats: {
        total_scans: totalScans,
        threats_detected: threatsDetected,
        safe_items: safeItems,
        suspicious_items: suspiciousItems,
        by_type: byType,
        recent_activity: recentActivity,
      },
    })
  } catch (error) {
    console.error('Error calculating stats:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to calculate statistics' },
      { status: 500 }
    )
  }
}
