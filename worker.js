export default {
    async fetch(request, env) {
        // --- DYNAMIC CONFIGURATION ---
        const dynamicConfig = await env.RATE_LIMIT_KV.get("ddns_config", "json");
        
        const CONFIG = dynamicConfig || {
            ALLOWED_TRIES: 3, 
            PENALTY_TYPE: 'logarithmic', 
            BASE_PENALTY_SECONDS: 3600,
            MAX_PENALTY_SECONDS: 3600 * 1000,
            ALLOW_CREATION: true,
            ALLOW_LIST_DOMAINS: [".example.com"],
            ALLOW_LIST_PREFIXES: ["router", "home"],
            BLOCK_LIST: ["admin", "root", "test"],
            MAX_ZONE_RECORDS: 150,
            ALERT_WEBHOOK_URL: "" 
        };

        const clientIP = request.headers.get("CF-Connecting-IP") || "Unknown IP";

        // 1. Rate Limiting Check
        const isBlocked = await env.RATE_LIMIT_KV.get(`block:${clientIP}`);
        if (isBlocked) {
            return new Response("Forbidden: IP temporarily banned.", { status: 403 });
        }

        // 2. Authentication
        const authHeader = request.headers.get("Authorization");
        const expectedAuth = btoa(`${env.USERNAME}:${env.PASSWORD}`);
        const providedAuth = authHeader ? authHeader.replace("Basic ", "") : "";

        if (!authHeader || !authHeader.startsWith("Basic ") || providedAuth !== expectedAuth) {
            let fails = parseInt(await env.RATE_LIMIT_KV.get(`fails:${clientIP}`) || "0") + 1;
            await env.RATE_LIMIT_KV.put(`fails:${clientIP}`, fails.toString(), { expirationTtl: 60 * 60 * 24 * 30 });

            if (fails >= CONFIG.ALLOWED_TRIES) {
                const tier = Math.floor(fails / CONFIG.ALLOWED_TRIES);
                let multiplier = CONFIG.PENALTY_TYPE === 'linear' ? tier : Math.pow(10, tier - 1);
                if (CONFIG.PENALTY_TYPE === 'flat') multiplier = 1;
                
                let penaltySeconds = Math.min(CONFIG.BASE_PENALTY_SECONDS * multiplier, CONFIG.MAX_PENALTY_SECONDS);
                await env.RATE_LIMIT_KV.put(`block:${clientIP}`, "true", { expirationTtl: penaltySeconds });
            }
            return new Response("Unauthorized", { status: 401 });
        }

        await env.RATE_LIMIT_KV.delete(`fails:${clientIP}`);

        // 3. Hostname Extraction & Validation
        const url = new URL(request.url);
        const hostname = url.searchParams.get("hostname")?.toLowerCase();
        
        if (!hostname) return new Response("badparam", { status: 400 });

        // Check Domain Suffix
        const isValidDomain = CONFIG.ALLOW_LIST_DOMAINS.some(domain => hostname.endsWith(domain));
        if (!isValidDomain) return new Response("Forbidden: Domain not allowed", { status: 403 });

        // Check Allowed Keywords in Prefix
        const prefix = hostname.split('.')[0];
        const hasAllowedKeyword = CONFIG.ALLOW_LIST_PREFIXES.some(kw => prefix.includes(kw));
        if (!hasAllowedKeyword) return new Response("Forbidden: Prefix not permitted", { status: 403 });

        // Check Blocklist
        const hasBlocklistWord = CONFIG.BLOCK_LIST.some(word => hostname.includes(word));
        if (hasBlocklistWord) return new Response("Forbidden: Blocked keyword detected", { status: 403 });

        // 4. IP Validation
        let dnsType = clientIP.includes(":") ? "AAAA" : "A";

        // 5. Check if Record Exists
        const getRecordUrl = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records?name=${hostname}&type=${dnsType}`;
        let dnsRecordId = null;
        let recordExists = false;

        try {
            const getResponse = await fetch(getRecordUrl, {
                method: "GET",
                headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" }
            });
            const getResult = await getResponse.json();
            
            if (getResult.success && getResult.result.length > 0) {
                dnsRecordId = getResult.result[0].id;
                recordExists = true;
            }
        } catch (error) {
            return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500 });
        }

        // 6. Creation Limits & Alerting
        if (!recordExists) {
            if (!CONFIG.ALLOW_CREATION) {
                return new Response("Forbidden: Creation of new records is disabled", { status: 403 });
            }

            const countUrl = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records?per_page=1`;
            const countResponse = await fetch(countUrl, {
                method: "GET",
                headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" }
            });
            const countResult = await countResponse.json();

            if (countResult.success && countResult.result_info.total_count >= CONFIG.MAX_ZONE_RECORDS) {
                if (CONFIG.ALERT_WEBHOOK_URL) {
                    await fetch(CONFIG.ALERT_WEBHOOK_URL, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ 
                            text: `🚨 DDNS Alert: Zone limit of ${CONFIG.MAX_ZONE_RECORDS} reached. Blocked creation of ${hostname}.` 
                        })
                    }).catch(() => {});
                }
                return new Response("Forbidden: Zone record limit reached", { status: 403 });
            }
        }

        // 7. Execute Update or Create
        const apiUrl = recordExists 
            ? `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records/${dnsRecordId}`
            : `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records`;
            
        const apiBody = JSON.stringify({ type: dnsType, name: hostname, content: clientIP, ttl: 3600, proxied: false });

        try {
            const apiResponse = await fetch(apiUrl, {
                method: recordExists ? "PUT" : "POST",
                headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" },
                body: apiBody,
            });
            const apiResult = await apiResponse.json();

            if (apiResult.success) {
                return new Response(`good ${clientIP}`, { status: 200 });
            } else {
                return new Response(JSON.stringify({ success: false, errors: apiResult.errors }), { status: 500 });
            }
        } catch (error) {
            return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500 });
        }
    }
};
