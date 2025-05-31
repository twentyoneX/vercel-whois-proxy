// File: api/whois.js (Handles IANA referral to any known RIR)
const net = require('net');

const IANA_WHOIS_SERVER = 'whois.iana.org';
const WHOIS_PORT = 43;
const QUERY_TIMEOUT = 8000; // 8 seconds

// Known RIR WHOIS servers
const RIR_SERVERS = {
  ARIN: 'whois.arin.net',
  RIPE: 'whois.ripe.net',
  APNIC: 'whois.apnic.net',
  LACNIC: 'whois.lacnic.net',
  AFRINIC: 'whois.afrinic.net',
  IANA: 'whois.iana.org', // If IANA itself is authoritative for some high-level blocks
  "whois.verisign-grs.com": "whois.verisign-grs.com" // Example for .com/.net domains
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
  const patterns = [
    /whois:\s*([a-zA-Z0-9.-]+)/i, // Standard referral
    /refer:\s*([a-zA-Z0-9.-]+)/i  // Common referral keyword
  ];
  for (const pattern of patterns) {
    const match = ianaData.match(pattern);
    if (match && match[1]) {
      const referredServerHost = match[1].trim().toLowerCase();
      // Check if this referred server is one of our known RIRs or IANA itself
      for (const rirKey in RIR_SERVERS) {
        if (RIR_SERVERS[rirKey].toLowerCase() === referredServerHost) {
          return { name: rirKey, server: RIR_SERVERS[rirKey] };
        }
      }
      // If not a primary RIR but still a valid server different from IANA (e.g. a national NIC)
      if (referredServerHost !== IANA_WHOIS_SERVER.toLowerCase()){
          console.log(`[Referral Parser] IANA referred to a non-primary RIR server: ${referredServerHost}`);
          return { name: referredServerHost, server: referredServerHost }; // Use hostname as name
      }
    }
  }
  return null; // No clear, actionable referral found
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
    let authoritativeRirInfo = null; // Will store { name, server }

    const isIpAddress = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(query);
    if (isIpAddress) {
      try {
        console.log(`[Vercel Function] Querying IANA (${IANA_WHOIS_SERVER}) for IP: ${query}`);
        const ianaData = await queryWhoisServer(IANA_WHOIS_SERVER, WHOIS_PORT, query, "IANA");
        finalReport += `\n--- IANA Response (${IANA_WHOIS_SERVER}) ---\n`;
        finalReport += ianaData || "No data or empty response from IANA.";
        finalReport += `\n-----------------------------------------\n\n`;
        authoritativeRirInfo = parseReferral(ianaData);
        if (authoritativeRirInfo) {
          console.log(`[Vercel Function] IANA referred to ${authoritativeRirInfo.name} (${authoritativeRirInfo.server}) for ${query}`);
        } else {
          console.log(`[Vercel Function] No clear WHOIS server referral from IANA for IP ${query}. Will use default RIR for specific query if applicable.`);
        }
      } catch (ianaError) {
        console.error(`[Vercel Function] Error querying IANA for ${query}:`, ianaError.message);
        finalReport += `\n--- Error Querying IANA ---\n${ianaError.message}\n---------------------------\n\n`;
      }
    } else {
      finalReport += `\n--- Query '${query}' is not an IPv4 address. Skipping IANA pre-lookup for IP referral. ---\n\n`;
    }

    let serverToQueryNext = null;
    let serverFriendlyNameToQueryNext = null;

    if (authoritativeRirInfo && authoritativeRirInfo.server) {
      // If IANA gave a referral for an IP
      if (authoritativeRirInfo.server.toLowerCase() !== IANA_WHOIS_SERVER.toLowerCase()) {
        serverToQueryNext = authoritativeRirInfo.server;
        serverFriendlyNameToQueryNext = authoritativeRirInfo.name;
      } else {
        // IANA referred to itself, meaning its response is considered authoritative for this query level
        finalReport += `\n--- IANA response above is considered authoritative for IP '${query}'. No further RIR query needed based on this referral. ---\n`;
      }
    } else if (!isIpAddress) {
      // Basic domain handling (very rudimentary)
      const lowerQuery = query.toLowerCase();
      if (lowerQuery.endsWith('.com') || lowerQuery.endsWith('.net')) {
        serverToQueryNext = RIR_SERVERS["whois.verisign-grs.com"];
        serverFriendlyNameToQueryNext = "Verisign (.com/.net)";
      } else {
        // For other domains or if no referral, we could try a default like RIPE,
        // or state that full domain WHOIS isn't supported.
        // For now, let's just try RIPE as a generic attempt for non-IPs if not .com/.net
        serverToQueryNext = RIR_SERVERS.RIPE;
        serverFriendlyNameToQueryNext = "RIPE NCC (Default for non-IP)";
        finalReport += `\n--- Attempting query for non-IP '${query}' against ${serverFriendlyNameToQueryNext}. Full domain WHOIS may require different servers. ---\n\n`;
      }
    } else if (isIpAddress && !authoritativeRirInfo) {
      // It's an IP, but IANA gave no clear referral (or IANA query failed)
      // Fallback to a default RIR, e.g., RIPE, or you could try querying all RIRs (not recommended for performance)
      serverToQueryNext = RIR_SERVERS.RIPE; // Default RIR to try
      serverFriendlyNameToQueryNext = "RIPE NCC (Default/Fallback)";
      finalReport += `\n--- No specific RIR referral from IANA for IP '${query}'. Attempting query against ${serverFriendlyNameToQueryNext}. ---\n\n`;
    }
    
    if (serverToQueryNext) {
        try {
            console.log(`[Vercel Function] Querying ${serverFriendlyNameToQueryNext} (${serverToQueryNext}) for: ${query}`);
            const rirData = await queryWhoisServer(serverToQueryNext, WHOIS_PORT, query, serverFriendlyNameToQueryNext);
            finalReport += `\n--- Response from ${serverFriendlyNameToQueryNext} (${serverToQueryNext}) ---\n`;
            finalReport += rirData || `No data or empty response from ${serverFriendlyNameToQueryNext}.`;
            finalReport += `\n----------------------------------------------------------------------\n`; // Consistent line length
        } catch (rirError) {
            console.error(`[Vercel Function] Error querying ${serverFriendlyNameToQueryNext} (${serverToQueryNext}) for ${query}:`, rirError.message);
            finalReport += `\n--- Error Querying ${serverFriendlyNameToQueryNext} (${serverToQueryNext}) ---\n${rirError.message}\n--------------------------------------------------------------------\n`;
        }
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
