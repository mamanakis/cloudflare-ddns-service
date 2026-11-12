export const ONBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DDNS Account Setup</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 2.5rem auto; padding: 0 1rem; line-height: 1.5; }
    .card { border: 1px solid #d1d5db; border-radius: 8px; padding: 1.5rem; }
    label { display: block; font-weight: 600; margin-top: 0.85rem; }
    input, select { width: 100%; padding: 0.55rem; margin-top: 0.25rem; box-sizing: border-box; font-size: 1rem; }
    button { margin-top: 1.1rem; padding: 0.65rem 1.1rem; font-size: 1rem; font-weight: 600; cursor: pointer; width: 100%; }
    .err { color: #b91c1c; margin-top: 0.75rem; font-weight: 600; }
    .warn { background: #fef3c7; border: 1px solid #f59e0b; padding: 0.75rem; border-radius: 6px; color: #92400e; font-size: 0.9rem; }
    .secret-box { font-family: monospace; font-size: 1.1rem; background: #f3f4f6; padding: 0.75rem; border-radius: 6px; text-align: center; letter-spacing: 0.05em; user-select: none; }
  </style>
</head>
<body>
  <h2>DDNS Credential Registration</h2>
  <div class="card" id="formCard">
    <label for="username">Username</label>
    <input id="username" autocomplete="off" />

    <label for="pin">8-Digit Invite PIN</label>
    <input id="pin" inputmode="numeric" maxlength="8" autocomplete="one-time-code" />

    <label for="mode">Credential Type</label>
    <select id="mode" onchange="toggleMode()">
      <option value="token">Generate 16-Char Router Token (Recommended)</option>
      <option value="password">Choose My Own Password</option>
    </select>

    <div id="pwGroup" style="display:none;">
      <label for="password">Password (12+ chars, upper, lower, number; no : or @)</label>
      <input id="password" type="password" autocomplete="new-password" />
    </div>

    <button type="button" onclick="submitForm()">Activate Credentials</button>
    <div class="err" id="errMsg"></div>
  </div>

  <div class="card" id="doneCard" style="display:none;">
    <div class="warn"><strong>Copy this secret right now.</strong> It has been hashed and cannot be viewed again.</div>
    <p><strong>Username:</strong> <span id="resUser"></span></p>
    <div class="secret-box" id="resSecret"></div>
    <button type="button" onclick="copySecret()" id="copyBtn">Copy Secret to Clipboard</button>
    <p style="font-size:0.9rem; color:#4b5563; margin-top:1rem;">Your account is active with an empty domain list. Let the admin know you registered so they can enable your subdomain(s).</p>
  </div>

  <script>
    let savedSecret = "";
    function toggleMode() {
      const isPw = document.getElementById("mode").value === "password";
      document.getElementById("pwGroup").style.display = isPw ? "block" : "none";
    }
    async function submitForm() {
      const errEl = document.getElementById("errMsg");
      errEl.textContent = "";
      const payload = {
        username: document.getElementById("username").value,
        pin: document.getElementById("pin").value,
        mode: document.getElementById("mode").value,
        password: document.getElementById("password").value
      };
      const res = await fetch("/onboard", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        errEl.textContent = data.error || "Registration failed.";
        return;
      }
      savedSecret = data.secret;
      document.getElementById("resUser").textContent = data.username;
      document.getElementById("resSecret").textContent = savedSecret;
      document.getElementById("formCard").style.display = "none";
      document.getElementById("doneCard").style.display = "block";
    }
    async function copySecret() {
      await navigator.clipboard.writeText(savedSecret);
      document.getElementById("copyBtn").textContent = "Copied!";
    }
  </script>
</body>
</html>`;