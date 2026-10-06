// Shared code for the browser route. Everything runs in the page; nothing is sent anywhere.
// The box: a random data key locks the note; the data key is locked once per hardware key,
// with a secret only that key can recompute (WebAuthn PRF = the key's hmac-secret).
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
// A credential belongs to one website name. Use the real name in production, localhost for rehearsal.
const RP = location.hostname === 'localhost' || location.hostname === '127.0.0.1' ? 'localhost' : 'lambdasistemi.net';
const SALT = enc.encode('recovery-v1');
const SECRET_KEY_RE = /A3-[A-Z0-9]{6}(-[A-Z0-9]{5,6}){5}/;

async function wrapKey(prf) {
  const base = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('recovery-wrap-v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function prfFor(credId) {                       // browser shows PIN + touch
  const a = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: RP,
    allowCredentials: [{ type: 'public-key', id: credId }], userVerification: 'required',
    extensions: { prf: { eval: { first: SALT } } } } });
  const r = a.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) { const e = new Error('prf'); e.name = 'NoPrf'; throw e; }
  return r.results.first;
}
async function loadBox(file) {
  try { const r = await fetch(file || 'box.json', { cache: 'no-store' }); if (!r.ok) return null; return await r.json(); }
  catch (e) { return null; }
}
async function unlockDataKey(box) {                    // try each enrolled key until one answers
  let last = null;
  for (const e of box.entries) {
    try { return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.wrapIv) }, await wrapKey(await prfFor(unb64(e.id))), unb64(e.wrapped)); }
    catch (x) { last = x; }
  }
  throw last || new Error('no enrolled key answered');
}
async function decryptNote(box, data) {
  const dk = await crypto.subtle.importKey('raw', data, 'AES-GCM', false, ['decrypt']);
  return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, dk, unb64(box.ct)));
}
async function createCredential(name) {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: 'Recovery', id: RP },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
    extensions: { prf: {} } } });
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || !ext.prf.enabled) { const e = new Error('prf'); e.name = 'NoPrf'; throw e; }
  return cred.rawId;
}
// Add one key to a box. For a new box pass note (the text to protect); for an existing one pass its data key.
async function addKey(box, name, noteOrNull, dataKeyOrNull) {
  const id = await createCredential(name);             // PIN + touch
  const prf = await prfFor(id);                        // PIN + touch again
  let data = dataKeyOrNull, out = box;
  if (!out) {
    data = crypto.getRandomValues(new Uint8Array(32));
    const dk = await crypto.subtle.importKey('raw', data, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    out = { v: 1, rpId: RP, entries: [], iv: b64(iv), ct: b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dk, enc.encode(noteOrNull))) };
  }
  const wiv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wiv }, await wrapKey(prf), data);
  out = { ...out, entries: [...out.entries, { name, id: b64(id), wrapIv: b64(wiv), wrapped: b64(wrapped) }] };
  return out;
}
function niceError(e, L) {
  const n = e && e.name;
  if (n === 'NotAllowedError' || n === 'AbortError') return L.e_cancel;
  if (n === 'NoPrf' || n === 'NotSupportedError' || n === 'SecurityError') return L.e_nokey;
  return L.e_other + ((e && (e.message || n)) || '');
}
