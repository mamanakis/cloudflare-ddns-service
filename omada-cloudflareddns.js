export default {
    async fetch(request, env) {
        // 1. Basic Authentication
        const authHeader = request.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Basic ")) {
            return new Response("Unauthorized", { status: 401 });
        }

        const expectedAuth = btoa(`${env.USERNAME}:${env.PASSWORD}`);
        const providedAuth = authHeader.replace("Basic ", "");
        
        if (providedAuth !== expectedAuth) {
            return new Response("Unauthorized", { status: 401 });
        }

        // 2. Get hostname from request
        const url = new URL(request.url);
        const hostname = url.searchParams.get("hostname");
        
        if (!hostname) {
            return new Response("badparam", { status: 400 });
        }

        // 3. Determine Client IP and Protocol
        const clientIP = request.headers.get("CF-Connecting-IP");
        if (!clientIP) {
            return new Response("Could not determine client IP", { status: 500 });
        }

        let dnsType;
        if (clientIP.includes(".")) {
            dnsType = "A";
        } else if (clientIP.includes(":")) {
            dnsType = "AAAA";
        } else {
            return new Response("Client IP format error", { status: 500 });
        }

        // 4. DYNAMIC LOOKUP: Check if the record already exists
        const getRecordUrl = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records?name=${hostname}&type=${dnsType}`;
        let dnsRecordId = null;
        let recordExists = false;

        try {
            const getResponse = await fetch(getRecordUrl, {
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${env.API_TOKEN}`,
                    "Content-Type": "application/json",
                }
            });
            
            const getResult = await getResponse.json();
            
            if (getResult.success && getResult.result.length > 0) {
                dnsRecordId = getResult.result[0].id;
                recordExists = true;
            }
        } catch (error) {
            return new Response(JSON.stringify({ success: false, error: "Lookup failed: " + error.message }), { status: 500 });
        }

        // 5. UPDATE OR CREATE RECORD
        // If it exists, PUT to the specific ID. If it doesn't, POST to the base collection.
        const apiUrl = recordExists 
            ? `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records/${dnsRecordId}`
            : `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records`;
            
        const apiMethod = recordExists ? "PUT" : "POST";

        const apiBody = JSON.stringify({
            type: dnsType,
            name: hostname,
            content: clientIP,
            ttl: 3600, // 3600 is 1 hour; use 1 for 'Automatic'
            proxied: false,
        });

        try {
            const apiResponse = await fetch(apiUrl, {
                method: apiMethod,
                headers: {
                    "Authorization": `Bearer ${env.API_TOKEN}`,
                    "Content-Type": "application/json",
                },
                body: apiBody,
            });
            
            const apiResult = await apiResponse.json();

            if (apiResult.success) {
                // Return standard Omada success string
                return new Response(`good ${clientIP}`, { status: 200 });
            } else {
                return new Response(JSON.stringify({ 
                    success: false, 
                    errors: apiResult.errors 
                }), { status: 500, headers: { "Content-Type": "application/json" }});
            }
        } catch (error) {
            return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500 });
        }
    }
};
