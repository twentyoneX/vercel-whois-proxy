// File: api/proxy-check.js
const fetch = require('node-fetch');

// List of common proxy-related HTTP headers to check
const PROXY_HEADERS_TO_CHECK = [
  'via', 'x-forwarded-for', 'x-forwarded', 'forwarded-for', 'x-client-ip',
  'forwarded', 'client-ip', 'x-proxy-id', 'mt-proxy-id', 'x-tinyproxy',
  'proxy-agent', 'x-real-ip', // X-Real-IP can sometimes indicate a reverse proxy
  // Less common or sometimes misconfigured, but worth a look
  'http_via', 'http_x_forwarded_for', 'http_forwarded_for', 'http_x_forwarded',
  'http_forwarded', 'http_client_ip', 'http_forwarded_for_ip', 'x_forwarded_for',
  'forwarded_for_ip', 'http_proxy_connection'
];

module.exports = async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const clientIp = req.headers['x-forwarded-for']?.split(',').shift() || // Standard for proxies like Vercel
                   req.headers['x-real-ip'] || // Common for reverse proxies
                   req.socket?.remoteAddress || 
                   req.connection?.remoteAddress;

  if (!clientIp) {
    return res.status(500).json({ error: "Could not determine client IP address." });
  }

  let detectedProxyHeaders = {};
  let httpHeaderCheckResult = "No common proxy headers detected.";
  let foundProxyHeader = false;

  PROXY_HEADERS_TO_CHECK.forEach(headerKey => {
    const headerValue = req.headers[headerKey.toLowerCase()]; // Headers are case-insensitive
    if (headerValue) {
      detectedProxyHeaders[headerKey] = headerValue;
      foundProxyHeader = true;
    }
  });

  if (foundProxyHeader) {
    httpHeaderCheckResult = "Potential proxy headers detected.";
  }

  let ipDatabaseCheckResult = "No proxy status from database.";
  let proxyDbDetails = {};
  let fraudScore = null; // For services that provide it

  try {
    // Using ipwhois.app as it provides proxy/vpn/tor flags
    const ipDbResponse = await fetch(`https://ipwhois.app/json/${encodeURIComponent(clientIp)}`);
    if (!ipDbResponse.ok) {
      throw new Error(`IP database API error: ${ipDbResponse.status}`);
    }
    const ipDbData = await ipDbResponse.json();

    if (ipDbData.success) {
      proxyDbDetails.is_proxy = ipDbData.proxy || false; // ipwhois.app uses 'proxy'
      proxyDbDetails.is_vpn = ipDbData.vpn || false;     // 'vpn'
      proxyDbDetails.is_tor = ipDbData.tor || false;     // 'tor'
      proxyDbDetails.isp = ipDbData.isp || "N/A";
      proxyDbDetails.organization = ipDbData.org || "N/A";
      proxyDbDetails.country = ipDbData.country || "N/A";
      
      // Some APIs (like IPQualityScore, not directly ipwhois.app free tier) give fraud_score
      // We'll simulate this for now if proxy/vpn/tor is true
      if (proxyDbDetails.is_proxy || proxyDbDetails.is_vpn || proxyDbDetails.is_tor) {
        ipDatabaseCheckResult = "IP flagged as Proxy/VPN/Tor by database.";
        fraudScore = "High Risk (Simulated)"; // Placeholder
      } else {
        ipDatabaseCheckResult = "IP not flagged as Proxy/VPN/Tor by database.";
        fraudScore = "Low Risk (Simulated)"; // Placeholder
      }
    } else {
      ipDatabaseCheckResult = `Error querying IP database: ${ipDbData.message || 'Unknown error'}`;
    }

  } catch (error) {
    console.error("[Proxy Check] IP Database Error:", error);
    ipDatabaseCheckResult = `Failed to query IP database: ${error.message}`;
  }

  res.status(200).json({
    checkedIp: clientIp,
    httpHeaderTest: {
      result: httpHeaderCheckResult,
      detectedHeaders: foundProxyHeader ? detectedProxyHeaders : "None"
    },
    ipDatabaseTest: {
      source: "ipwhois.app (and simulated fraud score)",
      result: ipDatabaseCheckResult,
      details: proxyDbDetails,
      fraud_score: fraudScore 
    },
    notes: [
      "This check looks for common HTTP proxy headers and queries an IP database.",
      "Elite/High-anonymity proxies may not use detectable HTTP headers.",
      "IP databases may not list all or very new proxy servers.",
      "This tool does not perform port scanning and works for IPv4."
    ]
  });
};
