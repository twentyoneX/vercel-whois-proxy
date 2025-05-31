// File: api/whois.js (With IANA referral attempt)
const net = require('net');

const IANA_WHOIS_SERVER = 'whois.iana.org';
const WHOIS_PORT = 43;
const QUERY_TIMEOUT = 8000; // 8 seconds

// Helper function to perform a WHOIS query
function queryWhoisServer(server, port, queryText) {
  return new Promise((resolve, reject) => {
    let whoisData = '';
    const client = new net.Socket();
    let connected = false;

    const timeoutId = setTimeout(() => {
      if (!connected) { // Timeout before connection
        client.destroy();
        reject(new Error(`Connection timeout to ${server}:${port}`));
      } else { // Timeout during data reception (less likely handled this way)
        client.destroy();
        // It might have partial data, or 'end' event might still fire
        // For simplicity, we'll let 'end' or 'error' handle final data.
        // console.warn(`Data reception timeout from ${server}:${port}`);
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
      console.log(`[WHOIS Client] Connection ended with ${server}:${port}`);
      client.destroy();
      resolve(whoisData);
    });

    client.on('error', (err) => {
      clearTimeout(timeoutId);
      console.error(`[WHOIS Client] Connection error with ${server}:${port}:`, err.message);
      client.destroy();
      reject(err);
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

  try {
    console.log(`[Vercel Function] Starting WHOIS for: ${query}`);
    let finalWhoisText = `WHOIS Lookup for: ${query}\n`;
    finalWhoisText += `-------------------------------------\n`;

    // 1. Query IANA first for IP addresses (simplistic check)
    // This is a very basic check, real IP validation is more complex
    const isIpAddress = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(query); 
    let authoritativeServer = null;
    let ianaData = '';

    if (isIpAddress) {
        try {
            console.log(`[Vercel Function] Querying IANA for ${query}`);
            ianaData = await queryWhoisServer(IANA_WHOIS_SERVER, WHOIS_PORT, query);
            finalWhoisText += `\n--- IANA Response ---\n${ianaData}\n---------------------\n\n`;

            // Simplistic parsing for referral (IANA often has "whois: whois.rir.net")
            const referralMatch = ianaData.match(/whois:\s*([A-Za-z0-9.-]+)/i);
            if (referralMatch && referralMatch[1]) {
                authoritativeServer = referralMatch[1].trim();
                console.log(`[Vercel Function] IANA referred to: ${authoritativeServer} for ${query}`);
            } else {
                console.log(`[Vercel Function] No clear WHOIS server referral from IANA for ${query}. Defaulting to RIPE (or displaying IANA only).`);
                // If no referral, for this example, we might just show IANA or try RIPE as a fallback for European IPs
                // For now, we'll just show IANA if no clear referral.
            }
        } catch (ianaError) {
            console.error(`[Vercel Function] Error querying IANA for ${query}:`, ianaError.message);
            finalWhoisText += `\n--- Error querying IANA ---\n${ianaError.message}\n---------------------------\n\n`;
        }
    } else {
        // For domain names, this simple IANA query isn't the right first step.
        // A proper domain WHOIS needs TLD server lookup, then registrar.
        // For now, we'll just try RIPE as if it were an IP, which will likely fail or give limited info.
        console.log(`[Vercel Function] Query is not an IP. For domains, full WHOIS is complex. Attempting RIPE as a fallback.`);
        // Or you could just state domains are not fully supported yet by this version.
    }


    // 2. Query the authoritative server (if found from IANA) or a default (e.g., RIPE)
    // If it's not an IP, or IANA didn't refer, 'authoritativeServer' will be null.
    // We'll fall back to trying RIPE if authoritativeServer is not set from IANA, 
    // or if the query was not an IP in the first place (RIPE might give some info or error).
    const serverToQuery = authoritativeServer || 'whois.ripe.net';
    
    // Avoid re-querying RIPE if IANA already pointed there AND we got IANA data.
    // Or if IANA was the one that already gave the detailed block info.
    let shouldQuerySpecificRir = true;
    if (authoritativeServer && authoritativeServer.toLowerCase() === IANA_WHOIS_SERVER.toLowerCase()) {
        // If IANA referred to itself, we already have its data.
        shouldQuerySpecificRir = false;
    }
    // A more robust check would be if ianaData already contains the full details.
    // For now, if an authoritative server was found (and it's not IANA itself), we query it.
    // If it's a domain, or no authoritative server, we try RIPE.

    if (shouldQuerySpecificRir || !isIpAddress || !authoritativeServer) {
        // If it's a domain OR (it's an IP AND no authoritative server was found from IANA OR IANA referred to someone else)
        try {
            console.log(`[Vercel Function] Querying ${serverToQuery} for ${query}`);
            const rirData = await queryWhoisServer(serverToQuery, WHOIS_PORT, query);
            if (authoritativeServer && authoritativeServer.toLowerCase() !== serverToQuery.toLowerCase()) {
                 finalWhoisText += `\n--- Response from ${serverToQuery} (referred by IANA) ---\n`;
            } else if (!authoritativeServer && isIpAddress) {
                 finalWhoisText += `\n--- Response from ${serverToQuery} (default/fallback for IP) ---\n`;
            } else if (!isIpAddress) {
                 finalWhoisText += `\n--- Response from ${serverToQuery} (attempt for domain/non-IP) ---\n`;
            }
            finalWhoisText += `${rirData}\n-------------------------------------------------\n`;
        } catch (rirError) {
            console.error(`[Vercel Function] Error querying ${serverToQuery} for ${query}:`, rirError.message);
            finalWhoisText += `\n--- Error querying ${serverToQuery} ---\n${rirError.message}\n--------------------------------------\n`;
        }
    }


    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(finalWhoisText.trim());

  } catch (error) {
    console.error('[Vercel Function] General error in WHOIS proxy:', error.message, error.stack);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(500).send(`Internal server error processing WHOIS request for ${query}. Check function logs.`);
  }
};
