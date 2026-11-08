export async function getConfig(env) {
    const dynamicConfig = await env.RATE_LIMIT_KV.get("ddns_config", "json");
    
    return dynamicConfig || {
        ALLOWED_TRIES: 3, 
        PENALTY_TYPE: 'logarithmic', 
        BASE_PENALTY_SECONDS: 3600,
        MAX_PENALTY_SECONDS: 3600 * 1000,
        ALLOW_CREATION: true,
        ALLOW_LIST_DOMAINS: [".example.net", ".example.com", ".example.org"],
        ALLOW_LIST_PREFIXES: ["router", "home", "vault"],
        BLOCK_LIST: ["admin", "root", "test"],
        MAX_ZONE_RECORDS: 150,
        ALERT_WEBHOOK_URL: "" 
    };
}
