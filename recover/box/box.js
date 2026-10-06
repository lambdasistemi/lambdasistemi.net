// recover-box: keep secrets behind a hardware key (FIDO2). Everything runs in the page; nothing is sent anywhere.
//
// The file (box.json) is public and holds:
//   keys:  one entry per enrolled hardware key. Each wraps the same random "data key" with a secret only that key
//          can recompute (WebAuthn PRF = the key's hmac-secret).
//   items: each is {iv, ct}: an AES-GCM box of {title, url, secret} under the data key. Titles are inside the box.
// One touch of any enrolled key opens every item.
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
// A credential belongs to one website name. Use the real name in production, localhost for rehearsal.
const RP = (typeof location !== 'undefined' && (location.hostname === 'localhost' || location.hostname === '127.0.0.1')) ? 'localhost' : 'lambdasistemi.net';
const SALT = enc.encode('recovery-v1');
const SECRET_KEY_RE = /A3-[A-Z0-9]{6}(-[A-Z0-9]{5,6}){5}/;

// ---------- core crypto (no browser needed; unit-tested) ----------
async function wrapKey(prf) {
  const base = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('recovery-wrap-v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const newDataKey = () => crypto.getRandomValues(new Uint8Array(32));
const aesKey = (data, usage) => crypto.subtle.importKey('raw', data, 'AES-GCM', false, usage);
const keysOf = (vault) => vault.keys || vault.entries || [];   // v1 files called them "entries"

async function wrapDataKey(data, prf) {
  const wiv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wiv }, await wrapKey(prf), data);
  return { wrapIv: b64(wiv), wrapped: b64(wrapped) };
}
async function unwrapDataKey(entry, prf) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(entry.wrapIv) }, await wrapKey(prf), unb64(entry.wrapped));
}
async function encryptItem(data, item) {                      // item = {title, url, secret}
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(data, ['encrypt']), enc.encode(JSON.stringify({ title: item.title, url: item.url, secret: item.secret })));
  return { iv: b64(iv), ct: b64(ct) };
}
async function decryptItem(data, it) {
  const text = dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(it.iv) }, await aesKey(data, ['decrypt']), unb64(it.ct)));
  return parseItem(text);
}
function parseItem(text) {
  try { const o = JSON.parse(text);
    if (o && typeof o.secret === 'string') return { title: typeof o.title === 'string' ? o.title : '', url: typeof o.url === 'string' ? o.url : '', secret: o.secret };
  } catch (e) {}
  const m = text.match(SECRET_KEY_RE);                         // older boxes: plain text, perhaps holding a Secret Key
  return { title: 'Secret', url: '', secret: m ? m[0] : text };
}
async function listItems(vault, data) {
  if (vault.v === 1) return [await decryptItem(data, { iv: vault.iv, ct: vault.ct })];   // v1: a single note
  return Promise.all((vault.items || []).map((it) => decryptItem(data, it)));
}
const emptyVault = () => ({ v: 2, rpId: RP, keys: [], items: [] });
async function addKeyEntry(vault, name, credId, prf, data) {
  return { ...vault, keys: [...keysOf(vault), { name, id: b64(credId), ...(await wrapDataKey(data, prf)) }] };
}
async function addItem(vault, data, item) {
  return { ...vault, items: [...(vault.items || []), await encryptItem(data, item)] };
}
// Turn a v1 box (one note) into v2 with the same data key and keys.
async function upgrade(vault, data) {
  if (vault.v !== 1) return vault;
  const [first] = await listItems(vault, data);
  return { v: 2, rpId: vault.rpId, keys: keysOf(vault), items: [await encryptItem(data, first)] };
}
// Only ever open https addresses (http only for rehearsal on this computer).
function safeUrl(u) {
  try { const x = new URL(u);
    return (x.protocol === 'https:' || (x.protocol === 'http:' && (x.hostname === 'localhost' || x.hostname === '127.0.0.1'))) ? x.href : '';
  } catch (e) { return ''; }
}

// ---------- browser parts: talking to the key ----------
async function prfFor(credId) {                       // browser shows PIN + touch
  const a = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: RP,
    allowCredentials: [{ type: 'public-key', id: credId }], userVerification: 'required',
    extensions: { prf: { eval: { first: SALT } } } } });
  const r = a.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) { const e = new Error('prf'); e.name = 'NoPrf'; throw e; }
  return r.results.first;
}
async function createCredential(name) {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: 'Recover box', id: RP },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
    extensions: { prf: {} } } });
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || !ext.prf.enabled) { const e = new Error('prf'); e.name = 'NoPrf'; throw e; }
  return cred.rawId;
}
async function loadBox(file) {
  try { const r = await fetch(file || 'box.json', { cache: 'no-store' }); if (!r.ok) return null; return await r.json(); }
  catch (e) { return null; }
}
async function unlockVault(vault) {                    // try each enrolled key until one answers (PIN + touch)
  let last = null;
  for (const e of keysOf(vault)) {
    try { return await unwrapDataKey(e, await prfFor(unb64(e.id))); } catch (x) { last = x; }
  }
  throw last || new Error('no enrolled key answered');
}
// Enrol the key that is plugged in: creates the credential (PIN + touch) and derives its secret (PIN + touch).
async function enrolKey(vault, name, data) {
  const id = await createCredential(name);
  return addKeyEntry(vault, name, id, await prfFor(id), data);
}
function niceError(e, L) {
  const n = e && e.name;
  if (n === 'NotAllowedError' || n === 'AbortError') return L.e_cancel;
  if (n === 'NoPrf' || n === 'NotSupportedError' || n === 'SecurityError') return L.e_nokey;
  return L.e_other + ((e && (e.message || n)) || '');
}
if (typeof module !== 'undefined') module.exports = { wrapDataKey, unwrapDataKey, encryptItem, decryptItem, parseItem, listItems, emptyVault, addKeyEntry, addItem, upgrade, safeUrl, newDataKey, keysOf, b64, unb64, enc };
