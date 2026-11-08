import { getConfig } from './config.js';
import { enforceRateLimit, validateAuth } from './security.js';
import { validateHostname } from './validation.js';
import { getDnsRecord, createDnsRecord, updateDnsRecord } from './cloudflare.js';

export default {
    async fetch(request, env) {
        const clientIP = request.headers.get("CF-Connecting-IP") || "Unknown IP";
        const config = await getConfig(env);

        // 1. Security & Auth
        const blockResponse = await enforceRateLimit(clientIP, env, config);
        if (blockResponse) return blockResponse;

        const authResponse = await validateAuth(request, env, clientIP, config);
        if (authResponse) return authResponse;

        // 2. Input Validation & Zone Mapping
        const url = new URL(request.url);
        const hostname = url.searchParams.get("hostname")?.toLowerCase();
        
        if (!hostname) return new Response("badparam", { status: 400 });

        const { error: validationError, zoneId } = validateHostname(hostname, config);
        if (validationError) return new Response(validationError, { status: 403 });

        // 3. DNS Logic
        const dnsType = clientIP.includes(":") ? "AAAA" : "A";
        
        // Pass zoneId explicitly, no longer relying on env.ZONE_ID
        const existingRecord = await getDnsRecord(hostname, dnsType, zoneId, env);

        if (existingRecord) {
            if (existingRecord.content === clientIP) {
                console.log(`No-op: ${hostname} is already ${clientIP}`);
                return new Response(`good ${clientIP}`, { status: 200 });
            }
            return await updateDnsRecord(existingRecord.id, hostname, clientIP, existingRecord.content, dnsType, zoneId, env, config);
        } else {
            if (!config.ALLOW_CREATION) {
                return new Response("Forbidden: Creation disabled", { status: 403 });
            }
            return await createDnsRecord(hostname, clientIP, dnsType, zoneId, env, config);
        }
    }
};
