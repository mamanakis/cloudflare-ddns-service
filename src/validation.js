export function validateHostname(hostname, config) {
    // 1. Check Domain Suffix and Extract Zone ID
    const allowedSuffixes = Object.keys(config.ALLOW_LIST_DOMAINS);
    const matchedSuffix = allowedSuffixes.find(domain => hostname.endsWith(domain));
    
    if (!matchedSuffix) return { error: "Forbidden: Domain not allowed", zoneId: null };
    const targetZoneId = config.ALLOW_LIST_DOMAINS[matchedSuffix];

    // 2. Extract Prefix (Handle wildcards like *.vault.mamanakis.net)
    const parts = hostname.split('.');
    const prefix = parts[0] === '*' ? parts[1] : parts[0];

    // 3. Check Allowlist Keywords
    const hasAllowedKeyword = config.ALLOW_LIST_PREFIXES.some(kw => prefix.includes(kw));
    if (!hasAllowedKeyword && prefix !== '*') return { error: "Forbidden: Prefix not permitted", zoneId: null };

    // 4. Check Blocklist
    const hasBlocklistWord = config.BLOCK_LIST.some(word => hostname.includes(word));
    if (hasBlocklistWord) return { error: "Forbidden: Blocked keyword detected", zoneId: null };

    return { error: null, zoneId: targetZoneId }; // Valid, return the target zone
}
