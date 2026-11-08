async function sendWebhook(url, message) {
    if (!url) return;
    await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: message })
    }).catch(err => console.error("Webhook failed:", err));
}

export async function getDnsRecord(hostname, dnsType, env) {
    const url = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records?name=${hostname}&type=${dnsType}`;
    const response = await fetch(url, {
        headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" }
    });
    const result = await response.json();
    return (result.success && result.result.length > 0) ? result.result[0] : null;
}

export async function updateDnsRecord(id, hostname, newIP, oldIP, dnsType, env, config) {
    const url = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records/${id}`;
    const body = JSON.stringify({ type: dnsType, name: hostname, content: newIP, ttl: 3600, proxied: false });

    const response = await fetch(url, {
        method: "PUT",
        headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" },
        body: body,
    });
    const result = await response.json();

    if (result.success) {
        await sendWebhook(config.ALERT_WEBHOOK_URL, `🔄 DDNS Update: ${hostname} changed from ${oldIP} to ${newIP}`);
        return new Response(`good ${newIP}`, { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: result.errors }), { status: 500 });
}

export async function createDnsRecord(hostname, clientIP, dnsType, env, config) {
    // Check total zone records before creating
    const countUrl = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records?per_page=1`;
    const countResponse = await fetch(countUrl, {
        headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" }
    });
    const countResult = await countResponse.json();

    if (countResult.success && countResult.result_info.total_count >= config.MAX_ZONE_RECORDS) {
        await sendWebhook(config.ALERT_WEBHOOK_URL, `🚨 DDNS Alert: Zone limit of ${config.MAX_ZONE_RECORDS} reached. Blocked creation of ${hostname}.`);
        return new Response("Forbidden: Zone record limit reached", { status: 403 });
    }

    const url = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records`;
    const body = JSON.stringify({ type: dnsType, name: hostname, content: clientIP, ttl: 3600, proxied: false });

    const response = await fetch(url, {
        method: "POST",
        headers: { "Authorization": `Bearer ${env.API_TOKEN}`, "Content-Type": "application/json" },
        body: body,
    });
    const result = await response.json();

    if (result.success) {
        await sendWebhook(config.ALERT_WEBHOOK_URL, `✨ DDNS Created: New record ${hostname} registered to ${clientIP}`);
        return new Response(`good ${clientIP}`, { status: 200 });
    }
    return new Response(JSON.stringify({ success: false, errors: result.errors }), { status: 500 });
}
