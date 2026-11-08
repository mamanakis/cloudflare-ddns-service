import { getConfig } from './config.js';
import { enforceRateLimit, validateAuth } from './security.js';
import { validateHostname } from './validation.js';
import { getDnsRecord, createDnsRecord, updateDnsRecord } from './cloudflare.js';

export default {
    async fetch(request, env) {
        const clientIP = request.headers.get("CF-Connecting-IP") || "Unknown IP";
        const config = await getConfig(env);

        // 1. Security & Auth (Returns a 401/403 Response if blocked)
        const blockResponse = await enforceRateLimit(clientIP, env, config);
        if (blockResponse) return blockResponse;

        const authResponse = await validateAuth(request, env, clientIP, config);
        if (authResponse) return authResponse;

        // 2. Input Validation
        const url = new URL(request.url);
        const hostname = url.searchParams.get("hostname")?.toLowerCase();
        
        if (!hostname) return new Response("badparam", { status: 400 });

        const validationError = validateHostname(hostname, config);
        if (validationError) return new Response(validationError, { status: 403 });

        // 3. DNS Logic
        const dnsType = clientIP.includes(":") ? "AAAA" : "A";
        const existingRecord = await getDnsRecord(hostname, dnsType, env);

        if (existingRecord) {
            // IDEMPOTENCY CHECK: Do nothing if the IP hasn't changed
            if (existingRecord.content === clientIP) {
                console.log(`No-op: ${hostname} is already ${clientIP}`);
                return new Response(`good ${clientIP}`, { status: 200 });
            }
            // UPDATE: IP has changed
            return await updateDnsRecord(existingRecord.id, hostname, clientIP, existingRecord.content, dnsType, env, config);
        } else {
            // CREATE: Record does not exist
            if (!config.ALLOW_CREATION) {
                return new Response("Forbidden: Creation disabled", { status: 403 });
            }
            return await createDnsRecord(hostname, clientIP, dnsType, env, config);
        }
    }
};
