/**
 * PhishTank API Integration
 * Checks URLs against PhishTank's community-driven phishing database
 */

export interface PhishTankResult {
  isPhishing: boolean;
  verified: boolean;
  verifiedAt?: Date;
  phishId?: string;
  submissionDate?: Date;
  details?: string;
}

export class PhishTankService {
  private static readonly API_BASE_URL = 'https://checkurl.phishtank.com/checkurl/';
  private static readonly API_KEY = process.env.PHISHTANK_API_KEY || '';

  /**
   * Check URL against PhishTank database
   */
  static async checkURL(url: string): Promise<PhishTankResult> {
    // PhishTank API key is optional but recommended for higher rate limits
    if (!this.API_KEY) {
      console.warn('PhishTank API key not configured - using limited rate');
    }

    try {
      const response = await this.queryAPI(url);
      return this.parseResponse(response);
    } catch (error) {
      console.error('PhishTank API error:', error);
      return { isPhishing: false, verified: false };
    }
  }

  /**
   * Query PhishTank API
   */
  private static async queryAPI(url: string): Promise<any> {
    const formData = new URLSearchParams();
    formData.append('url', url);
    formData.append('format', 'json');
    if (this.API_KEY) {
      formData.append('app_key', this.API_KEY);
    }

    const response = await fetch(this.API_BASE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'phishguard/1.0',
      },
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`PhishTank API error: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Parse PhishTank response
   */
  private static parseResponse(response: any): PhishTankResult {
    const results = response.results;

    if (!results) {
      return { isPhishing: false, verified: false };
    }

    const isPhishing = results.in_database === true;
    const verified = results.verified === true;

    if (!isPhishing) {
      return { isPhishing: false, verified: false };
    }

    return {
      isPhishing: true,
      verified,
      verifiedAt: results.verified_at ? new Date(results.verified_at) : undefined,
      phishId: results.phish_id,
      submissionDate: results.submission_time ? new Date(results.submission_time) : undefined,
      details: results.phish_detail_page,
    };
  }

  /**
   * Download PhishTank database (for offline checking)
   * Note: PhishTank provides hourly database dumps
   */
  static async downloadDatabase(): Promise<string[]> {
    // PhishTank database URL (requires registration)
    const databaseUrl = 'http://data.phishtank.com/data/online-valid.json';

    try {
      const response = await fetch(databaseUrl);

      if (!response.ok) {
        throw new Error(`Database download error: ${response.statusText}`);
      }

      const data = await response.json();

      // Extract URLs from database
      const urls: string[] = data.map((entry: any) => entry.url);

      return urls;
    } catch (error) {
      console.error('Failed to download PhishTank database:', error);
      return [];
    }
  }

  /**
   * Check URL against local database (offline mode)
   */
  static async checkURLOffline(url: string, database: string[]): Promise<boolean> {
    // Normalize URL for comparison
    const normalizedUrl = this.normalizeURL(url);

    return database.some(dbUrl => this.normalizeURL(dbUrl) === normalizedUrl);
  }

  /**
   * Normalize URL for comparison
   */
  private static normalizeURL(url: string): string {
    try {
      const parsed = new URL(url);
      // Remove protocol, www, trailing slash
      return parsed.hostname.replace(/^www\./, '') + parsed.pathname.replace(/\/$/, '');
    } catch {
      return url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
    }
  }

  /**
   * Submit phishing URL to PhishTank
   */
  static async submitPhishing(url: string, additionalInfo?: string): Promise<boolean> {
    if (!this.API_KEY) {
      console.warn('PhishTank API key required for submissions');
      return false;
    }

    try {
      const formData = new URLSearchParams();
      formData.append('url', url);
      formData.append('format', 'json');
      formData.append('app_key', this.API_KEY);
      if (additionalInfo) {
        formData.append('additional_info', additionalInfo);
      }

      const response = await fetch('https://www.phishtank.com/add_web_phish.php', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData,
      });

      return response.ok;
    } catch (error) {
      console.error('Failed to submit to PhishTank:', error);
      return false;
    }
  }

  /**
   * Get PhishTank statistics
   */
  static async getStats(): Promise<{
    totalPhish: number;
    validPhish: number;
    invalidPhish: number;
  }> {
    try {
      const response = await fetch('https://www.phishtank.com/stats.json');

      if (!response.ok) {
        throw new Error('Failed to fetch stats');
      }

      const data = await response.json();

      return {
        totalPhish: data.stats.total_phish || 0,
        validPhish: data.stats.valid_phish || 0,
        invalidPhish: data.stats.invalid_phish || 0,
      };
    } catch (error) {
      console.error('Failed to fetch PhishTank stats:', error);
      return {
        totalPhish: 0,
        validPhish: 0,
        invalidPhish: 0,
      };
    }
  }
}
