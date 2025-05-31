// api/whois.js (Conceptual for direct RIPE query)
const net = require('net');

const RIPE_WHOIS_SERVER = 'whois.ripe.net';
const WHOIS_PORT = 43;

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

  // For this example, we assume the query is an IP that RIPE handles
  // In a real app, you'd need logic to determine the correct RIR
  // Or if it's a domain, use a different process.

  let whoisData = '';
  const client = new net.Socket();

  client.connect(WHOIS_PORT, RIPE_WHOIS_SERVER, () => {
    console.log(`[Vercel Function] Connected to RIPE WHOIS for query: ${query}`);
    client.write(`${query}\r\n`); // Send the query followed by CRLF
  });

  client.on('data', (data) => {
    whoisData += data.toString();
  });

  client.on('end', () => {
    console.log('[Vercel Function] RIPE WHOIS connection ended.');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    if (whoisData.trim() === "") {
        return res.status(200).send(`No WHOIS data found or an empty response was received from ${RIPE_WHOIS_SERVER} for ${query}.`);
    }
    res.status(200).send(whoisData);
    client.destroy(); // Ensure socket is destroyed
  });

  client.on('error', (err) => {
    console.error('[Vercel Function] RIPE WHOIS connection error:', err.message);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(502).send(`Error connecting to WHOIS server (${RIPE_WHOIS_SERVER}): ${err.message}`);
    client.destroy(); // Ensure socket is destroyed
  });

  client.on('timeout', () => {
    console.error('[Vercel Function] RIPE WHOIS connection timed out.');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(504).send(`Connection to WHOIS server (${RIPE_WHOIS_SERVER}) timed out for query ${query}.`);
    client.destroy();
  });
  
  // Set a timeout for the whole operation on Vercel (max execution time for Hobby plan is 10s-60s)
  // This client-side timeout is just for the socket connection itself.
  client.setTimeout(8000); // 8 seconds timeout for the socket
};
