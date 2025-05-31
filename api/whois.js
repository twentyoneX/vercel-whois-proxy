// File: api/whois.js (IANA referral, then specific RIR like ARIN, APNIC, RIPE)
const net = require('net');

const IANA_WHOIS_SERVER = 'whois.iana.org';
const WHOIS_PORT = 43;
const QUERY_TIMEOUT = 8000; // 8 seconds

// Known RIR WHOIS servers (add more if needed)
const RIR_SERVERS = {
  ARIN: 'whois.arin.net',
  RIPE: 'whois.ripe.net',
  APNIC: 'whois.apnic.net',
  LACNIC: 'whois.lacnic.net',
  AFRINIC: 'whois.afrinic.net',
  // Add other common referral targets if IANA uses them
  "whois.verisign-grs.com": "whois.verisign-grs.com" // For .com/.net TLDs if query is a domain
};

// Helper function to perform a WHOIS query
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

// Function to parse referral from IANA data
function parseReferral(ianaData) {
  if (!ianaData) return null;
  // Look for "whois:" or "refer:" lines
  const patterns = [
    /whois:\s*([a-zA-Z0-9.-]+)/i,
    /refer:\s*([a-zA-Z0-9.-]+)/i
  ];
  for (const pattern of patterns) {
    const match = ianaData.match(pattern);
    if (match && match[1]) {
      const server = match[1].trim().toLowerCase();
      // Map known RIR server hostnames to a canonical name if needed, or just return the hostname
      for (const rir in RIR_SERVERS) {
        if (RIR_SERVERS[rir].toLowerCase() === server) {
          return { name: rir, server: RIR_SERVERS[rir] };
        }
      }
      // If not a known RIR, but still a referral, return it
      if (server !== IANA_WHOIS_SERVER.toLowerCase()){ // Avoid self-referral loop
          return { name: server, server: server }; // Use server hostname as name
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

    // 1. Query IANA if it's an IP address
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
          console.log(`[Vercel Function] No clear WHOIS server referral from IANA for ${query}.`);
        }
      } catch (ianaError) {
        console.error(`[Vercel Function] Error querying IANA for ${query}:`, ianaError.message);
        finalReport += `\n--- Error Querying IANA ---\n${ianaError.message}\n---------------------------\n\n`;
      }
    } else {
      finalReport += `\n--- Query '${query}' is not an IPv4 address. Skipping IANA pre-lookup. Attempting general WHOIS. ---\n\n`;
      // For non-IPs (domains), we could try a generic .com/.net server, or just a default.
      // For this example, we'll let it fall through to a default or specific logic later.
      // A more robust solution would check TLD and query appropriate TLD WHOIS server.
    }

    // 2. Query the specific RIR (if referred) or a default
    let serverToQuery = RIPE_WHOIS_SERVER; // Default if no other logic applies
    let serverFriendlyName = "RIPE NCC (Default)";

    if (authoritativeRir && authoritativeRir.server) {
      serverToQuery = authoritativeRir.server;
      serverFriendlyName = authoritativeRir.name;
    } else if (!isIpAddress) {
      // Rudimentary domain handling: if it's a .com or .net, try verisign.
      // This is VERY basic and not a full domain WHOIS solution.
      if (query.toLowerCase().endsWith('.com') || query.toLowerCase().endsWith('.net')) {
        serverToQuery = RIR_SERVERS["whois.verisign-grs.com"]; // Get from our RIR_SERVERS map
        serverFriendlyName = "Verisign (.com/.net)";
      } else {
         finalReport += `\n--- Full WHOIS for domain '${query}' is complex and may require multiple lookups not implemented here. Attempting query against ${serverFriendlyName}. ---\n\n`;
      }
    }
    
    // Only query the specific RIR if it's different from IANA or if IANA query failed/skipped
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
    } else if (authoritativeRir && serverToQuery.toLowerCase() === IANA_WHOIS_SERVER.toLowerCase()) {
        finalReport += `\n--- IANA response above is considered authoritative for ${query}. ---\n`;
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
