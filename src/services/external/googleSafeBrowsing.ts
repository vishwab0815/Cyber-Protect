/**
 * Google Safe Browsing API Integration
 * Checks URLs against Google's threat intelligence database
 */

export interface SafeBrowsingResult {
  isThreat: boolean;
  threatType?: 'MALWARE' | 'SOCIAL_ENGINEERING' | 'UNWANTED_SOFTWARE' | 'POTENTIALLY_HARMFUL_APPLICATION';
  platformType?: string;
  threatEntryType?: string;
  details?: any;
}

export class GoogleSafeBrowsingService {
  private static readonly API_BASE_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  private static readonly API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY || '';

  /**
   * Check URL against Safe Browsing database
   */
  static async checkURL(url: string): Promise<SafeBrowsingResult> {
    // Check if API key is configured
    if (!this.API_KEY) {
      console.warn('Google Safe Browsing API key not configured');
      return { isThreat: false };
    }

    try {
      const response = await this.queryAPI(url);
      return this.parseResponse(response);
    } catch (error) {
      console.error('Google Safe Browsing API error:', error);
      return { isThreat: false };
    }
  }

  /**
   * Query Safe Browsing API
   */
  private static async queryAPI(url: string): Promise<any> {
    const requestBody = {
      client: {
        clientId: 'phishguard-app',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };

    const response = await fetch(`${this.API_BASE_URL}?key=${this.API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error(`Safe Browsing API error: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Parse Safe Browsing response
   */
  private static parseResponse(response: any): SafeBrowsingResult {
    // If no matches found, URL is safe
    if (!response.matches || response.matches.length === 0) {
      return { isThreat: false };
    }

    // Get first match (highest priority threat)
    const match = response.matches[0];

    return {
      isThreat: true,
      threatType: match.threatType,
      platformType: match.platformType,
      threatEntryType: match.threatEntryType,
      details: match,
    };
  }

  /**
   * Batch check multiple URLs
   */
  static async checkURLs(urls: string[]): Promise<Map<string, SafeBrowsingResult>> {
    if (!this.API_KEY) {
      console.warn('Google Safe Browsing API key not configured');
      return new Map(urls.map(url => [url, { isThreat: false }]));
    }

    try {
      const requestBody = {
        client: {
          clientId: 'phishguard-app',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map(url => ({ url })),
        },
      };

      const response = await fetch(`${this.API_BASE_URL}?key=${this.API_KEY}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        throw new Error(`Safe Browsing API error: ${response.statusText}`);
      }

      const data = await response.json();

      // Build results map
      const results = new Map<string, SafeBrowsingResult>();

      // Initialize all URLs as safe
      urls.forEach(url => {
        results.set(url, { isThreat: false });
      });

      // Update with threat matches
      if (data.matches) {
        data.matches.forEach((match: any) => {
          const url = match.threat.url;
          results.set(url, {
            isThreat: true,
            threatType: match.threatType,
            platformType: match.platformType,
            threatEntryType: match.threatEntryType,
            details: match,
          });
        });
      }

      return results;
    } catch (error) {
      console.error('Google Safe Browsing batch API error:', error);
      return new Map(urls.map(url => [url, { isThreat: false }]));
    }
  }

  /**
   * Get threat type description
   */
  static getThreatDescription(threatType: string): string {
    const descriptions: { [key: string]: string } = {
      MALWARE: 'The URL contains malware',
      SOCIAL_ENGINEERING: 'The URL is a phishing or social engineering site',
      UNWANTED_SOFTWARE: 'The URL contains unwanted software',
      POTENTIALLY_HARMFUL_APPLICATION: 'The URL contains potentially harmful applications',
    };

    return descriptions[threatType] || 'Unknown threat type';
  }
}
