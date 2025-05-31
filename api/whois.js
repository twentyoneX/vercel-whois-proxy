// File: api/whois.js (Queries IANA for IPs, then ALWAYS queries RIPE)
const net = require('net');

const IANA_WHOIS_SERVER = 'whois.iana.org';
const RIPE_WHOIS_SERVER = 'whois.ripe.net';
const WHOIS_PORT = 43;
const QUERY_TIMEOUT = 8000; // 8 seconds

// Helper function to perform a WHOIS query
function queryWhoisServer(server, port, queryText) {
  return new Promise((resolve, reject) => {
    let whoisData = '';
    const client = new net.Socket();
    let connected = false;
    let operationTimedOut = false;

    const timeoutId = setTimeout(() => {
      operationTimedOut = true;
      client.destroy(); 
      if (!connected) {
        reject(new Error(`Connection timeout to ${server}:${port} for query "${queryText}"`));
      } else {
        // If connected but no 'end' event, resolve with what we have.
        // 'end' might still fire after destroy if data was buffered.
        console.warn(`Data reception may have timed out from ${server}:${port} for query "${queryText}". Partial data might be returned.`);
        resolve(whoisData); 
      }
    }, QUERY_TIMEOUT);

    client.connect(port, server, () => {
      connected = true;
      console.log(`[WHOIS Client] Connected to ${server}:${port} for query: ${queryText}`);
      client.write(`${queryText}\r\n`);
    });

    client.on('data', (data) => {
      whoisData += data.toString();
    });

    client.on('end', () => {
      clearTimeout(timeoutId);
      if (!operationTimedOut) { // Don't resolve if timeout already handled it
        console.log(`[WHOIS Client] Connection ended with ${server}:${port}`);
        resolve(whoisData);
      }
      client.destroy(); // Ensure fully closed
    });

    client.on('error', (err) => {
      clearTimeout(timeoutId);
      if (!operationTimedOut) { // Don't reject if timeout already handled it
        console.error(`[WHOIS Client] Connection error with ${server}:${port}:`, err.message);
        reject(err);
      }
      client.destroy(); // Ensure fully closed
    });
  });
}

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

  let finalReport = `WHOIS Lookup for: ${query}\n`;
  finalReport += `-------------------------------------\n`;

  try {
    console.log(`[Vercel Function] Starting WHOIS process for: ${query}`);

    // 1. Query IANA if it's an IP address
    const isIpAddress = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(query);
    if (isIpAddress) {
      try {
        console.log(`[Vercel Function] Querying IANA (${IANA_WHOIS_SERVER}) for IP: ${query}`);
        const ianaData = await queryWhoisServer(IANA_WHOIS_SERVER, WHOIS_PORT, query);
        finalReport += `\n--- IANA Response (${IANA_WHOIS_SERVER}) ---\n`;
        finalReport += ianaData || "No data or empty response from IANA.";
        finalReport += `\n-----------------------------------------\n\n`;
      } catch (ianaError) {
        console.error(`[Vercel Function] Error querying IANA for ${query}:`, ianaError.message);
        finalReport += `\n--- Error Querying IANA ---\n${ianaError.message}\n---------------------------\n\n`;
      }
    } else {
      finalReport += `\n--- Query is not an IPv4 address. Skipping IANA lookup. ---\n\n`;
    }

    // 2. Always Query RIPE
    try {
      console.log(`[Vercel Function] Querying RIPE (${RIPE_WHOIS_SERVER}) for: ${query}`);
      const ripeData = await queryWhoisServer(RIPE_WHOIS_SERVER, WHOIS_PORT, query);
      finalReport += `\n--- RIPE NCC Response (${RIPE_WHOIS_SERVER}) ---\n`;
      finalReport += ripeData || "No data or empty response from RIPE NCC.";
      finalReport += `\n---------------------------------------------\n`;
    } catch (ripeError) {
      console.error(`[Vercel Function] Error querying RIPE for ${query}:`, ripeError.message);
      finalReport += `\n--- Error Querying RIPE NCC ---\n${ripeError.message}\n-------------------------------\n`;
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(finalReport.trim());

  } catch (error) { // Catch any unexpected errors from the main try block
    console.error('[Vercel Function] General error in WHOIS proxy:', error.message, error.stack);
    finalReport += `\n--- Unexpected Server Error ---\nAn internal error occurred: ${error.message}\n--------------------------------\n`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(500).send(finalReport.trim() + "\n\nInternal server error processing WHOIS request. Check function logs.");
  }
};
