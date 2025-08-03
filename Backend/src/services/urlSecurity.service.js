import axios from 'axios';
import { URL } from 'url';

// Known malicious domains list (expand as needed)
const MALICIOUS_DOMAINS = [
  'malware.com',
  'phishing.net', 
  'spam.org',
  'scam.info',
  'virus.site',
  'trojan.host',
  // Add more known malicious domains
];

// Suspicious URL patterns
const SUSPICIOUS_PATTERNS = [
  /bit\.ly\/[a-zA-Z0-9]+/, // Nested URL shorteners
  /tinyurl\.com\/[a-zA-Z0-9]+/,
  /t\.co\/[a-zA-Z0-9]+/,
  /goo\.gl\/[a-zA-Z0-9]+/,
  /ow\.ly\/[a-zA-Z0-9]+/,
  /is\.gd\/[a-zA-Z0-9]+/,
  /buff\.ly\/[a-zA-Z0-9]+/,
  // Suspicious file extensions in URLs
  /\.(exe|bat|cmd|scr|pif|com|vbs|jar)(\?|$)/i,
  // IP addresses instead of domains
  /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/,
  // Suspicious query parameters
  /[?&](download|exec|cmd|script|payload)=/i
];

// Suspicious TLDs (Top Level Domains)
const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'
];

// URL length threshold (suspiciously long URLs)
const MAX_SAFE_URL_LENGTH = 2048;
const SUSPICIOUS_URL_LENGTH = 1000;

/**
 * Validates URL safety against various threat vectors
 * @param {string} url - The URL to validate
 * @returns {Promise<{safe: boolean, reason?: string}>}
 */
export const validateUrlSafety = async (url) => {
  try {
    // Basic URL format validation
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (error) {
      return { safe: false, reason: 'Invalid URL format' };
    }

    // Check URL length
    if (url.length > MAX_SAFE_URL_LENGTH) {
      return { safe: false, reason: 'URL exceeds maximum length' };
    }

    if (url.length > SUSPICIOUS_URL_LENGTH) {
      console.warn(`Suspicious URL length detected: ${url.length} characters`);
    }

    // Check protocol
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return { safe: false, reason: 'Only HTTP and HTTPS protocols are allowed' };
    }

    const hostname = parsedUrl.hostname.toLowerCase();

    // Check against known malicious domains
    if (MALICIOUS_DOMAINS.includes(hostname)) {
      return { safe: false, reason: 'URL contains known malicious domain' };
    }

    // Check for suspicious TLDs
    const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
    if (hasSuspiciousTLD) {
      console.warn(`Suspicious TLD detected: ${hostname}`);
      // Don't block but log for monitoring
    }

    // Check for suspicious patterns
    const hasSuspiciousPattern = SUSPICIOUS_PATTERNS.some(pattern => 
      pattern.test(url)
    );
    if (hasSuspiciousPattern) {
      return { safe: false, reason: 'URL contains suspicious patterns' };
    }

    // Check for nested URL shorteners
    if (isNestedShortener(hostname)) {
      return { safe: false, reason: 'Nested URL shorteners are not allowed' };
    }

    // Check for localhost/private IPs (in production)
    if (process.env.NODE_ENV === 'production' && isLocalOrPrivateIP(hostname)) {
      return { safe: false, reason: 'Local and private IP addresses are not allowed' };
    }

    // Optional: Check against external threat intelligence
    // Uncomment if you have access to threat intelligence APIs
    // const threatCheckResult = await checkExternalThreatIntelligence(url);
    // if (!threatCheckResult.safe) {
    //   return threatCheckResult;
    // }

    return { safe: true };

  } catch (error) {
    console.error('URL safety validation error:', error);
    return { safe: false, reason: 'URL safety validation failed' };
  }
};

/**
 * Check if domain is a known URL shortener
 * @param {string} hostname 
 * @returns {boolean}
 */
const isNestedShortener = (hostname) => {
  const shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
    'is.gd', 'buff.ly', 'short.link', 'tiny.cc', 'rb.gy'
  ];
  return shorteners.includes(hostname);
};

/**
 * Check if hostname is localhost or private IP
 * @param {string} hostname 
 * @returns {boolean}
 */
const isLocalOrPrivateIP = (hostname) => {
  // Check for localhost
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    return true;
  }

  // Check for private IP ranges
  const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = hostname.match(ipRegex);
  
  if (match) {
    const [, a, b, c, d] = match.map(Number);
    
    // Private IP ranges:
    // 10.0.0.0 to 10.255.255.255
    // 172.16.0.0 to 172.31.255.255  
    // 192.168.0.0 to 192.168.255.255
    return (a === 10) ||
           (a === 172 && b >= 16 && b <= 31) ||
           (a === 192 && b === 168);
  }

  return false;
};

/**
 * Optional: Check URL against external threat intelligence services
 * Requires API keys and service subscriptions
 * @param {string} url 
 * @returns {Promise<{safe: boolean, reason?: string}>}
 */
// eslint-disable-next-line no-unused-vars
const checkExternalThreatIntelligence = async (url) => {
  try {
    // Example: VirusTotal API integration
    // const response = await axios.post('https://www.virustotal.com/vtapi/v2/url/scan', {
    //   apikey: process.env.VIRUSTOTAL_API_KEY,
    //   url: url
    // });
    
    // Implement based on your chosen threat intelligence service
    
    return { safe: true };
  } catch (error) {
    console.error('External threat intelligence check failed:', error);
    // Fail open - don't block if external service is down
    return { safe: true };
  }
};

/**
 * Additional security: Check URL content type and size
 * @param {string} url 
 * @returns {Promise<{safe: boolean, reason?: string}>}
 */
export const validateUrlContent = async (url) => {
  try {
    // Make a HEAD request to check content without downloading
    const response = await axios.head(url, {
      timeout: 5000,
      maxRedirects: 3
    });

    // Check content type
    const contentType = response.headers['content-type'] || '';
    const suspiciousTypes = [
      'application/x-msdownload',
      'application/x-executable',
      'application/octet-stream'
    ];

    if (suspiciousTypes.some(type => contentType.includes(type))) {
      return { safe: false, reason: 'Suspicious content type detected' };
    }

    return { safe: true };

  } catch (error) {
    // If we can't check the content, don't block
    // This could be due to CORS, timeouts, etc.
    console.warn('Could not validate URL content:', error.message);
    return { safe: true };
  }
};
