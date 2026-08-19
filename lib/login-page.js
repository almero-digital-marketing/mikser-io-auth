const escapeHtml = (value) => String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')

// The sign-in page.
//
// Deliberately identical to WhiteBox's — same layout, same type scale, same
// tokens, same pending state — because mikser and WhiteBox are the same
// company's products and a person who administers both should not have to
// wonder whether they are on the right one. The mark is the only difference.
//
// Two things the page must say, and WhiteBox learned the second the hard way:
//
//   appName — WHICH deployment. A page showing only a logo could be any
//             mikser, or a convincing copy of one.
//   client  — WHO gets your access. Without it, signing in to your own site
//             and handing an agent your permissions looked identical.
export function loginPage({ params, client, appName, logoUrl, error }) {
    const hidden = Object.entries(params)
        .filter(([, v]) => v != null)
        .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
        .join('\n')

    const subtitle = client
        ? `<p class="sub">to give <strong>${escapeHtml(client.name || client.clientId)}</strong> access</p>`
        : ''

    const notice = error ? `<p class="err">${escapeHtml(error)}</p>` : ''

    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>
/* Values measured off WhiteBox's running console login, not copied from its
   stylesheet fallbacks — its PrimeVue theme overrides --accent, --text and
   --radius at runtime, so the source would have produced a page that looked
   adjacent to it rather than identical.
   Light only, also deliberately: WhiteBox's login stays light under
   prefers-color-scheme: dark, so a dark block here would create exactly the
   mismatch it looks like it prevents. */
:root{
  --bg:#f1f5f9; --panel:#fff; --border:#e2e8f0; --border-2:#cbd5e1;
  --text:#334155; --text-strong:#0f172a; --accent:#09090b;
  --radius:6px; --shadow:0 6px 18px rgba(15,23,42,.10);
}
*{box-sizing:border-box}
body{
  margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg);
  color:var(--text); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
form{
  width:320px; padding:32px; display:flex; flex-direction:column; align-items:center; gap:10px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--radius); box-shadow:var(--shadow);
}
img{width:36px;height:36px;margin-bottom:2px}
h1{font-size:17px;font-weight:700;margin:0 0 6px;color:var(--text-strong)}
.sub{margin:-4px 0 4px;font-size:13px;text-align:center;opacity:.8}
.sub strong{color:var(--text-strong);font-weight:600}
.err{
  width:100%; margin:0 0 2px; padding:8px 10px; border-radius:8px; font-size:13px;
  background:#fef2f2; border:1px solid #fecaca; color:#b91c1c; text-align:center;
}
/* 8px on the fields against the card's 6px is WhiteBox's own combination, not a slip. */
input{
  width:100%; padding:9px 10px; border:1px solid var(--border-2); border-radius:8px;
  font-size:14px; background:var(--panel); color:var(--text);
}
input:focus{outline:2px solid color-mix(in srgb,var(--accent) 25%,transparent);border-color:var(--accent)}
button{
  width:100%; margin-top:6px; padding:9px; border:none; border-radius:8px;
  background:var(--accent); color:#fff; font-size:14px; font-weight:500; cursor:pointer;
}
button:hover{opacity:.92}
button[disabled]{opacity:.65;cursor:default}
</style>
</head><body>
<form method="post">
${hidden}
<img src="${escapeHtml(logoUrl)}" alt="" onerror="this.remove()">
<h1>Sign in${appName ? ` to ${escapeHtml(appName)}` : ''}</h1>
${subtitle}
${notice}
<!-- autocomplete hints are load-bearing: without them a password manager
     guesses, and a saved credential for a different app on the same host
     gets filled instead. -->
<input type="text" name="username" placeholder="Username" autocomplete="username" required autofocus>
<input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
<!-- Feedback while the POST is in flight, which is longer than it looks:
     bcrypt is deliberately slow, that being the point of a KDF, plus a round
     trip and a redirect. Without this the button does not move, the page
     looks inert, and the honest reading is "nothing happened" — so people
     click again.
     Progressive enhancement: with JS blocked the form still submits exactly
     as before, it just has no pending state. -->
<script>
(function () {
  var form = document.querySelector('form')
  var button = form.querySelector('button')
  form.addEventListener('submit', function () {
    // Runs AFTER the form data is collected, so disabling here cannot drop a
    // field. The button carries no name or value, so it has nothing of its
    // own to lose either.
    button.disabled = true
    button.textContent = 'Signing in…'
    form.setAttribute('aria-busy', 'true')
  })
})()
</script>
</body></html>`
}

export { escapeHtml }
