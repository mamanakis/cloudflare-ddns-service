export function validateHostname(hostname, config) {
    // 1. Check Domain Suffix
    const isValidDomain = config.ALLOW_LIST_DOMAINS.some(domain => hostname.endsWith(domain));
    if (!isValidDomain) return "Forbidden: Domain not allowed";

    // 2. Extract Prefix (Handle wildcards like *.vault.mamanakis.net)
    const parts = hostname.split('.');
    const prefix = parts[0] === '*' ? parts[1] : parts[0];

    // 3. Check Allowlist Keywords
    const hasAllowedKeyword = config.ALLOW_LIST_PREFIXES.some(kw => prefix.includes(kw));
    if (!hasAllowedKeyword && prefix !== '*') return "Forbidden: Prefix not permitted";

    // 4. Check Blocklist
    const hasBlocklistWord = config.BLOCK_LIST.some(word => hostname.includes(word));
    if (hasBlocklistWord) return "Forbidden: Blocked keyword detected";

    return null; // Valid
}
