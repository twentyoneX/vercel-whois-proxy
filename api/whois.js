// File: api/whois.js (IANA referral, then specific RIR like ARIN, APNIC, RIPE - CORRECTED)
const net = require('net');

const IANA_WHOIS_SERVER = 'whois.iana.org';
const WHOIS_PORT = 43;
const QUERY_TIMEOUT = 8000; // 8 seconds

// Known RIR WHOIS servers (add more if needed)
const RIR_SERVERS = {
  ARIN: 'whois.arin.net',
  RIPE: 'whois.ripe.net', // Ensure RIPE is here
  APNIC: 'whois.apnic.net',
  LACNIC: 'whois.lacnic.net',
  AFRINIC: 'whois.afrinic.net',
  "whois.verisign-grs.com": "whois.verisign-grs.com"
};

// Helper function to perform a WHOIS query (same as before)
function queryWhoisServer(server, port, queryText, serverFriendlyName) {
  return new Promise((resolve, reject) => {
    let whoisData = '';
    const client = new net.Socket();
    let connected = false;
    let operationTimedOut = false;
    const logPrefix = `[WHOIS Client for ${serverFriendlyName || server}]`;

    const timeoutId = setTimeout(() => {
      operationTimedOut = true;
      client.destroy();
      const errorMsg = `Connection/data timeout to ${serverFriendlyName || server}:${port} for query "${queryText}"`;
      console.warn(logPrefix, errorMsg);
      if (!connected) {
        reject(new Error(errorMsg));
      } else {
        resolve(whoisData + `\n\n--- Query to ${serverFriendlyName || server} timed out. Partial data above may be incomplete. ---\n`);
      }
    }, QUERY_TIMEOUT);

    client.connect(port, server, () => {
      connected = true;
      console.log(logPrefix, `Connected for query: ${queryText}`);
      client.write(`${queryText}\r\n`);
    });

    client.on('data', (data) => {
      whoisData += data.toString();
    });

    client.on('end', () => {
      clearTimeout(timeoutId);
      if (!operationTimedOut) {
        console.log(logPrefix, `Connection ended.`);
        resolve(whoisData);
      }
      client.destroy();
    });

    client.on('error', (err) => {
      clearTimeout(timeoutId);
      if (!operationTimedOut) {
        console.error(logPrefix, `Connection error:`, err.message);
        reject(err);
      }
      client.destroy();
    });
  });
}

// Function to parse referral from IANA data (same as before)
function parseReferral(ianaData) {
  if (!ianaData) return null;
  const patterns = [
    /whois:\s*([a-zA-Z0-9.-]+)/i,
    /refer:\s*([a-zA-Z0-9.-]+)/i
  ];
  for (const pattern of patterns) {
    const match = ianaData.match(pattern);
    if (match && match[1]) {
      const server = match[1].trim().toLowerCase();
      for (const rir in RIR_SERVERS) {
        if (RIR_SERVERS[rir].toLowerCase() === server) {
          return { name: rir, server: RIR_SERVERS[rir] };
        }
      }
      if (server !== IANA_WHOIS_SERVER.toLowerCase()){
          return { name: server, server: server }; 
      }
    }
  }
  return null;
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
    let authoritativeRir = null;

    const isIpAddress = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(query);
    if (isIpAddress) {
      try {
        console.log(`[Vercel Function] Querying IANA (${IANA_WHOIS_SERVER}) for IP: ${query}`);
        const ianaData = await queryWhoisServer(IANA_WHOIS_SERVER, WHOIS_PORT, query, "IANA");
        finalReport += `\n--- IANA Response (${IANA_WHOIS_SERVER}) ---\n`;
        finalReport += ianaData || "No data or empty response from IANA.";
        finalReport += `\n-----------------------------------------\n\n`;
        authoritativeRir = parseReferral(ianaData);
        if (authoritativeRir) {
          console.log(`[Vercel Function] IANA referred to ${authoritativeRir.name} (${authoritativeRir.server}) for ${query}`);
        } else {
          console.log(`[Vercel Function] No clear WHOIS server referral from IANA for ${query}. Will use default for specific RIR query.`);
        }
      } catch (ianaError) {
        console.error(`[Vercel Function] Error querying IANA for ${query}:`, ianaError.message);
        finalReport += `\n--- Error Querying IANA ---\n${ianaError.message}\n---------------------------\n\n`;
      }
    } else {
      finalReport += `\n--- Query '${query}' is not an IPv4 address. Skipping IANA pre-lookup. Attempting general WHOIS. ---\n\n`;
    }

    // === CORRECTED PART ===
    let serverToQuery = RIR_SERVERS.RIPE; // Default to RIPE from our RIR_SERVERS object
    let serverFriendlyName = "RIPE NCC (Default)";
    // === END CORRECTED PART ===

    if (authoritativeRir && authoritativeRir.server) {
      serverToQuery = authoritativeRir.server;
      serverFriendlyName = authoritativeRir.name;
    } else if (!isIpAddress) {
      if (query.toLowerCase().endsWith('.com') || query.toLowerCase().endsWith('.net')) {
        serverToQuery = RIR_SERVERS["whois.verisign-grs.com"]; 
        serverFriendlyName = "Verisign (.com/.net)";
      } else {
         // Keep default serverToQuery (RIPE) for other non-IPs or add more logic
         finalReport += `\n--- Full WHOIS for domain '${query}' is complex. Attempting query against ${serverFriendlyName} (${serverToQuery}). ---\n\n`;
      }
    }
    
    // Only query the specific RIR if it's different from IANA or if IANA query failed/skipped
    // Or if it's a domain name, in which case IANA wasn't queried for referral in the same way
    if (serverToQuery.toLowerCase() !== IANA_WHOIS_SERVER.toLowerCase() || !isIpAddress) {
        try {
            console.log(`[Vercel Function] Querying ${serverFriendlyName} (${serverToQuery}) for: ${query}`);
            const rirData = await queryWhoisServer(serverToQuery, WHOIS_PORT, query, serverFriendlyName);
            finalReport += `\n--- Response from ${serverFriendlyName} (${serverToQuery}) ---\n`;
            finalReport += rirData || `No data or empty response from ${serverFriendlyName}.`;
            finalReport += `\n-------------------------------------------------------------\n`;
        } catch (rirError) {
            console.error(`[Vercel Function] Error querying ${serverFriendlyName} (${serverToQuery}) for ${query}:`, rirError.message);
            finalReport += `\n--- Error Querying ${serverFriendlyName} (${serverToQuery}) ---\n${rirError.message}\n-----------------------------------------------------------\n`;
        }
    } else if (isIpAddress && authoritativeRir && serverToQuery.toLowerCase() === IANA_WHOIS_SERVER.toLowerCase()) {
        // This case means IANA referred to itself, so its initial response is considered authoritative.
        finalReport += `\n--- IANA response above is considered authoritative for IP '${query}'. ---\n`;
    }


    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(finalReport.trim());

  } catch (error) {
    console.error('[Vercel Function] General error in WHOIS proxy:', error.message, error.stack);
    finalReport += `\n--- Unexpected Server Error ---\nAn internal error occurred: ${error.message}\n--------------------------------\n`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(500).send(finalReport.trim() + "\n\nInternal server error processing WHOIS request.");
  }
};
