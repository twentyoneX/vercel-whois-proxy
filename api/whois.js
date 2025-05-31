// api/whois.js (Modified for ipwhois.app JSON)
const fetch = require('node-fetch');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { return res.status(200).end(); }

  const query = req.query.q;
  if (!query) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.status(400).send('Query parameter "q" is required.');
  }

  try {
    const targetApiUrl = `https://ipwhois.app/json/${encodeURIComponent(query)}`;
    console.log(`[Vercel Function] Proxying JSON request for ${query} to ${targetApiUrl}`);

    const apiResponse = await fetch(targetApiUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'Vercel-WHOIS-Proxy/1.0 (Node.js Fetch)' }
    });

    const data = await apiResponse.json(); // Expect JSON

    if (!apiResponse.ok || data.success === false) {
      console.error(`[Vercel Function] ipwhois.app returned error for query ${query}. Status: ${apiResponse.status}, Data:`, data);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.status(apiResponse.status).send(`Error from upstream provider: ${data.message || 'Failed to fetch data'}`);
    }

    // Format the JSON into a WHOIS-like text report
    let report = `WHOIS-like Report for: ${data.ip || query}\n`;
    report += `-------------------------------------------------\n`;
    if(data.type) report += `Type:            ${data.type}\n`;
    if(data.country) report += `Country:         ${data.country} (${data.country_code})\n`;
    if(data.region) report += `Region:          ${data.region}\n`;
    if(data.city) report += `City:            ${data.city}\n`;
    if(data.latitude) report += `Latitude:        ${data.latitude}\n`;
    if(data.longitude) report += `Longitude:       ${data.longitude}\n`;
    if(data.isp) report += `ISP:             ${data.isp}\n`;
    if(data.org) report += `Organization:    ${data.org}\n`;
    if(data.asn) report += `ASN:             ${data.asn}\n`;
    if(data.as) report +=  `AS Name:         ${data.as}\n`; // Sometimes 'as', sometimes 'asn_description' etc.
    // For domains, ipwhois.app is limited for deep WHOIS, but might have some info
    if(data.domain) report += `Domain Queried:  ${data.domain}\n`;
    if(data.domain_registrar && data.domain_registrar.name) report += `Registrar:       ${data.domain_registrar.name}\n`;

    // Add more fields as needed based on ipwhois.app's JSON structure

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(report);

  } catch (error) {
    console.error('[Vercel Function] Error in WHOIS proxy (JSON):', error.message, error.stack);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(500).send('Internal server error processing WHOIS request.');
  }
};
