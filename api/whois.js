// File: api/whois.js
const fetch = require('node-fetch');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const query = req.query.q;

  if (!query) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.status(400).send('Query parameter "q" is required.');
  }

  try {
    const targetApiUrl = `https://ip-api.com/whois/${encodeURIComponent(query)}`;
    console.log(`[Vercel Function] Proxying request for ${query} to ${targetApiUrl}`);

    const apiResponse = await fetch(targetApiUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'Vercel-WHOIS-Proxy/1.0 (Node.js Fetch)' }
    });

    const whoisText = await apiResponse.text();

    if (!apiResponse.ok) {
      console.error(`[Vercel Function] ip-api.com returned status ${apiResponse.status} for query ${query}. Response: ${whoisText.substring(0, 200)}`);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.status(apiResponse.status).send(`Error from upstream WHOIS provider (status ${apiResponse.status}): ${whoisText.substring(0, 500)}`);
    }

    if (whoisText && (whoisText.trim().toLowerCase().startsWith('<!doctype html') || whoisText.trim().toLowerCase().startsWith('<html'))) {
      console.warn(`[Vercel Function] ip-api.com returned HTML for query ${query}. HTML start: ${whoisText.substring(0, 200)}`);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.status(502).send('The upstream WHOIS provider (ip-api.com) returned an unexpected HTML page. This could be due to rate limits or an error on their end. Please try again later.');
    }
    
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(whoisText);

  } catch (error) {
    console.error('[Vercel Function] Error in WHOIS proxy:', error.message, error.stack);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(500).send('Internal server error processing WHOIS request. Check function logs for details.');
  }
};