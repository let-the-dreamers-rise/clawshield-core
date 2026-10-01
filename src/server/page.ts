/**
 * The browser verifier: paste a receipt and its policy or trust anchor, get an answer.
 *
 * Self-contained, no external scripts or fonts. The inline script and style are allowed by
 * hash in the Content-Security-Policy, so nothing else can execute on the page.
 */

import { createHash } from "node:crypto";

const STYLE = `
:root{--bg:#f7f7f5;--fg:#18181b;--muted:#5f5f68;--card:#fff;--line:#dedee3;--ok:#0f7b45;--bad:#b42318;--accent:#3b3bd6}
@media (prefers-color-scheme: dark){:root{--bg:#111114;--fg:#ececf1;--muted:#a0a0ab;--card:#1a1a1f;--line:#2c2c34;--ok:#3ccf8e;--bad:#ff6b5e;--accent:#8c8cff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:880px;margin:0 auto;padding:32px 16px 64px}h1{font-size:24px;margin:0 0 4px}p{color:var(--muted);margin:0 0 24px}
label{display:block;font-weight:600;margin:16px 0 6px}textarea{width:100%;min-height:180px;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:13px/1.4 ui-monospace,Consolas,monospace}
.row{display:flex;gap:16px;flex-wrap:wrap;margin-top:12px}.row label{font-weight:400;margin:0}
button{margin-top:20px;padding:10px 20px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}
#out{margin-top:24px;padding:16px;border-radius:8px;border:1px solid var(--line);background:var(--card);white-space:pre-wrap;font:13px/1.5 ui-monospace,Consolas,monospace;display:none}
#out.ok{border-color:var(--ok)}#out.bad{border-color:var(--bad)}.v{font:600 16px system-ui;margin-bottom:8px}.ok .v{color:var(--ok)}.bad .v{color:var(--bad)}
`;

const SCRIPT = `
const $=(id)=>document.getElementById(id);
$('go').addEventListener('click',async()=>{
  const out=$('out');out.style.display='block';out.className='';
  let receipt,anchor;
  try{receipt=JSON.parse($('receipt').value);anchor=JSON.parse($('anchor').value);}catch(e){out.className='bad';out.textContent='Not valid JSON: '+e.message;return;}
  const mode=document.querySelector('input[name=mode]:checked').value;
  const body=JSON.stringify(mode==='sealed'?{receipt,trust:anchor}:{receipt,policy:anchor});
  try{
    const res=await fetch('/v1/receipts/verify',{method:'POST',headers:{'content-type':'application/json'},body});
    const json=await res.json();
    if(!json.success){out.className='bad';out.textContent=json.error;return;}
    const d=json.data;out.className=d.valid?'ok':'bad';out.textContent='';
    const v=document.createElement('div');v.className='v';v.textContent=d.valid?'Valid ('+d.mode+')':'Invalid ('+d.mode+')';out.appendChild(v);
    out.appendChild(document.createTextNode(d.valid?'Every check passed.':d.failures.join(', ')+'\\n\\n'+d.detail.join('\\n')));
  }catch(e){out.className='bad';out.textContent='Request failed: '+e.message;}
});
`;

const sha = (s: string) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;

export const PAGE_CSP = [
  "default-src 'none'",
  `script-src ${sha(SCRIPT)}`,
  `style-src ${sha(STYLE)}`,
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

export const PAGE_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GENKAI Verifier</title><style>${STYLE}</style></head>
<body><main>
<h1>GENKAI receipt verifier</h1>
<p>Check that an agent's action was decided by the policy its operator claims, without trusting the operator. Plaintext receipts are replayed; sealed receipts are checked against the pinned MXE attestation.</p>
<label for="receipt">Receipt (JSON)</label><textarea id="receipt" spellcheck="false"></textarea>
<div class="row"><label><input type="radio" name="mode" value="plaintext" checked> Plaintext policy</label><label><input type="radio" name="mode" value="sealed"> Sealed trust anchor</label></div>
<label for="anchor">Policy, or trust anchor {commitment, circuitId, clusterPublicKey}</label><textarea id="anchor" spellcheck="false"></textarea>
<button id="go" type="button">Verify</button>
<div id="out" role="status" aria-live="polite"></div>
</main><script>${SCRIPT}</script></body></html>`;
