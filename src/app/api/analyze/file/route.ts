/**
 * File Malware Analysis API
 * Upload and scan files for malware using comprehensive multi-layer detection
 */

import { NextRequest, NextResponse } from 'next/server';
import { MasterMalwareDetector } from '@/services/malware/masterMalwareDetector';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File;
    const userId = formData.get('user_id') as string | null;

    if (!file) {
      return NextResponse.json(
        { success: false, error: 'No file provided' },
        { status: 400 }
      );
    }

    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        {
          success: false,
          error: `File size exceeds maximum limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB`,
        },
        { status: 400 }
      );
    }

    // Check for empty files
    if (file.size === 0) {
      return NextResponse.json(
        { success: false, error: 'File is empty' },
        { status: 400 }
      );
    }

    // Convert file to buffer
    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Perform comprehensive malware analysis
    const analysis = await MasterMalwareDetector.analyzeFile(
      buffer,
      file.name,
      userId || undefined
    );

    // Format response
    return NextResponse.json({
      success: true,
      analysis: {
        file: {
          name: analysis.fileName,
          size: analysis.fileSize,
          type: analysis.fileType,
        },
        result: {
          is_malicious: analysis.isMalicious,
          threat_level: analysis.threatLevel,
          risk_score: analysis.riskScore,
          confidence: analysis.confidence,
          indicators: analysis.indicators,
          recommendations: analysis.recommendations,
        },
        summary: {
          total_detections: analysis.summary.totalDetections,
          signature_matches: analysis.summary.signatureMatches,
          behavioral_flags: analysis.summary.behavioralFlags,
          external_engine_detections: analysis.summary.externalEngineDetections,
        },
        layers: {
          static_analysis: analysis.analysisLayers.staticAnalysis ? 'completed' : 'skipped',
          document_analysis: analysis.analysisLayers.documentAnalysis ? 'completed' : 'skipped',
          script_analysis: analysis.analysisLayers.scriptAnalysis ? 'completed' : 'skipped',
          virus_total: analysis.analysisLayers.virusTotal ? 'completed' : 'skipped',
        },
        scan_duration_ms: analysis.scanDuration,
        timestamp: analysis.timestamp.toISOString(),
      },
    });
  } catch (error) {
    console.error('Error analyzing file:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to analyze file' },
      { status: 500 }
    );
  }
}

/**
 * GET endpoint for quick hash check
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const hash = searchParams.get('hash');

    if (!hash) {
      return NextResponse.json(
        { success: false, error: 'File hash is required' },
        { status: 400 }
      );
    }

    // Quick check without upload
    const result = await MasterMalwareDetector.quickCheck(hash);

    return NextResponse.json({
      success: true,
      result: {
        hash,
        is_malicious: result.isMalicious,
        source: result.source || 'local_cache',
      },
    });
  } catch (error) {
    console.error('Error checking hash:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to check file hash' },
      { status: 500 }
    );
  }
}
