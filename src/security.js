export async function enforceRateLimit(clientIP, env, config) {
    const isBlocked = await env.RATE_LIMIT_KV.get(`block:${clientIP}`);
    if (isBlocked) {
        return new Response("Forbidden: IP temporarily banned.", { status: 403 });
    }
    return null;
}

export async function validateAuth(request, env, clientIP, config) {
    const authHeader = request.headers.get("Authorization");
    const expectedAuth = btoa(`${env.USERNAME}:${env.PASSWORD}`);
    const providedAuth = authHeader ? authHeader.replace("Basic ", "") : "";

    if (!authHeader || !authHeader.startsWith("Basic ") || providedAuth !== expectedAuth) {
        let fails = parseInt(await env.RATE_LIMIT_KV.get(`fails:${clientIP}`) || "0") + 1;
        await env.RATE_LIMIT_KV.put(`fails:${clientIP}`, fails.toString(), { expirationTtl: 60 * 60 * 24 * 30 });

        if (fails >= config.ALLOWED_TRIES) {
            const tier = Math.floor(fails / config.ALLOWED_TRIES);
            let multiplier = config.PENALTY_TYPE === 'linear' ? tier : Math.pow(10, tier - 1);
            if (config.PENALTY_TYPE === 'flat') multiplier = 1;
            
            let penaltySeconds = Math.min(config.BASE_PENALTY_SECONDS * multiplier, config.MAX_PENALTY_SECONDS);
            await env.RATE_LIMIT_KV.put(`block:${clientIP}`, "true", { expirationTtl: penaltySeconds });
        }
        return new Response("Unauthorized", { status: 401 });
    }

    // Success: clear failures
    await env.RATE_LIMIT_KV.delete(`fails:${clientIP}`);
    return null;
}
