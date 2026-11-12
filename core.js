// UAVision Licencas (telemovel): a logica sem ecra. Corre igual no Safari e no Node (testes): so WebCrypto.
// Formato: ..\Shared\FORMATO.md. O mestre e o C# (UAVision.Licensing); isto tem de dar os mesmos bytes.
// 10/11/2026.
import * as noble from './vendor/noble-ed25519-2.3.0.js';

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();
export const utf8 = (s) => enc.encode(s);

export const PRODUCTS = { LINKMANAGER: 'LM', CAMVIEWER: 'CV' };   // o mesmo que o License Manager (1.0.7: + CamViewer)
export const DEMO_DAYS = 30;
export const ISSUED_BY = 'phone';

// 10/11/2026: a folha passou a ingles. Uma folha (Code.gs) antiga ainda pode responder em portugues: normalise() passa
// esses valores a ingles para a pagina comparar sempre em ingles.
export const STATE = { PENDING: 'Pending', APPROVED: 'Approved', REJECTED: 'Rejected', ISSUED: 'Issued', REMOVED: 'Removed' };
export const TYPE_PERPETUAL = 'Perpetual', TYPE_DEMO = '30-day demo', TYPE_YEAR = '1-year', YES = 'Yes';   // 1.0.8: 1-year
const OLD_PT = { 'Pendente': 'Pending', 'Aprovado': 'Approved', 'Rejeitado': 'Rejected', 'Emitido': 'Issued', 'Perpétua': 'Perpetual',
  'Demo 30 dias': '30-day demo', 'Sim': 'Yes', 'Não': 'No', 'telemóvel': 'phone', 'folha (à mão)': 'sheet (by hand)' };
export const normalise = (v) => (Object.prototype.hasOwnProperty.call(OLD_PT, String(v)) ? OLD_PT[String(v)] : v);
export function normaliseRow(r) {
  const o = Object.assign({}, r);
  for (const k of ['state', 'type', 'vm', 'decided_by', 'issued_by']) if (k in o) o[k] = normalise(o[k]);
  return o;
}
export const KDF_ITERATIONS = 600000;

// ---------------------------------------------------------------- base64 / hex

export function b64Encode(bytes) {
  let s = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64Decode(s) {
  const c = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/[\s=]+/g, '');
  const t = atob(c + '==='.slice((c.length + 3) % 4));
  const out = new Uint8Array(t.length);
  for (let i = 0; i < t.length; i++) out[i] = t.charCodeAt(i);
  return out;
}
export const b64uEncode = (bytes) => b64Encode(bytes).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
export const hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (h) => new Uint8Array((h.match(/../g) || []).map((x) => parseInt(x, 16)));
export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export async function sha256Hex(text) { return hex(new Uint8Array(await subtle.digest('SHA-256', utf8(text)))); }

// ---------------------------------------------------------------- JSON canonico da licenca (FORMATO.md sec. 1)

export function esc(s) {
  let o = '"';
  const t = String(s);
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);   // unidades UTF-16, como o C#
    if (c === 0x22) o += '\\"';
    else if (c === 0x5c) o += '\\\\';
    else if (c < 0x20 || c > 0x7e) o += '\\u' + c.toString(16).padStart(4, '0');
    else o += t[i];
  }
  return o + '"';
}

export function canonicalLicence(d) {
  const kv = (k, v) => esc(k) + ':' + v;
  const obj = (pairs) => '{' + pairs.join(',') + '}';
  const c = d.customer || {}, h = d.hwid || {};
  return obj([
    kv('format', esc('UAVLIC1')), kv('licence_id', esc(d.licence_id)), kv('key_id', esc(d.key_id)), kv('product', esc(d.product)),
    kv('type', esc(d.type)), kv('request_id', esc(d.request_id)),
    kv('customer', obj([kv('name', esc(c.name ?? '')), kv('company', esc(c.company ?? '')), kv('email', esc(c.email ?? '')), kv('country', esc(c.country ?? ''))])),
    kv('machine_name', esc(d.machine_name ?? '')),
    kv('hwid', obj([kv('uuid', esc(h.uuid ?? '')), kv('disk', esc(h.disk ?? '')), kv('cpu', esc(h.cpu ?? ''))])),
    kv('hwid_min_match', String(d.hwid_min_match)), kv('issued', esc(d.issued)),
    kv('expires', d.expires === null || d.expires === undefined || d.expires === '' ? 'null' : esc(d.expires)), kv('notes', esc(d.notes ?? ''))
  ]);
}

// "MAGIC.<b64url JSON>[.<b64url assinatura>]" -> { json, msg, sig } ou erro
export function decodeToken(token, magic, parts) {
  const p = String(token || '').trim().split('.');
  if (p.length !== parts || p[0] !== magic || !/^[A-Za-z0-9_-]+$/.test(p[1])) throw new Error('invalid ' + magic + ' text');
  const msg = b64Decode(p[1]);
  const json = JSON.parse(dec.decode(msg));
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('invalid ' + magic + ' text');
  return { json, msg, sig: parts === 3 ? b64Decode(p[2]) : null };
}

export const parseRequest = (token) => decodeToken(token, 'UAVREQ1', 2).json;

// O hash do PC que a folha usa (HwidSet.Hash no C#).
export const hwidHash = (h) => sha256Hex('UAVHWSET1|' + (h.uuid || '') + '|' + (h.disk || '') + '|' + (h.cpu || '')).then((x) => x.substring(0, 32));

// ---------------------------------------------------------------- Ed25519: WebCrypto ou, se faltar, noble-ed25519

const PKCS8_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
const pkcs8 = (seed) => new Uint8Array([...PKCS8_PREFIX, ...seed]);

const webcryptoEd = {
  name: 'WebCrypto',
  async publicKey(seed) {
    const k = await subtle.importKey('pkcs8', pkcs8(seed), { name: 'Ed25519' }, true, ['sign']);
    const jwk = await subtle.exportKey('jwk', k);
    return b64Decode(jwk.x);
  },
  async sign(msg, seed) {
    const k = await subtle.importKey('pkcs8', pkcs8(seed), { name: 'Ed25519' }, false, ['sign']);
    return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, k, msg));
  },
  async verify(sig, msg, pub) {
    const k = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    return subtle.verify({ name: 'Ed25519' }, k, sig, msg);
  }
};
const nobleEd = {
  name: 'noble-ed25519 2.3.0',
  publicKey: (seed) => noble.getPublicKeyAsync(seed),
  sign: (msg, seed) => noble.signAsync(msg, seed),
  verify: (sig, msg, pub) => noble.verifyAsync(sig, msg, pub)
};
export const ENGINES = { webcrypto: webcryptoEd, noble: nobleEd };

// RFC 8032 sec. 7.1, teste 2 (mensagem de 1 byte)
const RFC = {
  seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  pub: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  msg: '72',
  sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
};

// Autoteste de um motor: chave publica, assinatura e verificacao iguais ao RFC 8032. true/false, nunca rebenta.
export async function selfTest(engine) {
  try {
    const seed = fromHex(RFC.seed), msg = fromHex(RFC.msg);
    if (hex(await engine.publicKey(seed)) !== RFC.pub) return false;
    const sig = await engine.sign(msg, seed);
    if (hex(sig) !== RFC.sig) return false;
    if (!(await engine.verify(sig, msg, fromHex(RFC.pub)))) return false;
    const bad = sig.slice(); bad[5] ^= 1;
    return !(await engine.verify(bad, msg, fromHex(RFC.pub)));
  } catch (e) { return false; }
}

// O motor a usar: o WebCrypto se passar no autoteste, senao a noble. prefer = 'noble' so nos testes.
export async function pickEngine(prefer) {
  const order = prefer === 'noble' ? [nobleEd] : [webcryptoEd, nobleEd];
  for (const e of order) if (await selfTest(e)) return e;
  throw new Error('Ed25519 not available in this browser');
}

// ---------------------------------------------------------------- chave UAVKEY1 ("Export key for phone")

export function parseKeyFile(text) {
  let f;
  try { f = JSON.parse(String(text).replace(/^﻿/, '')); } catch (e) { throw new Error('The file is not a UAVision key (invalid JSON).'); }
  if (!f || f.format !== 'UAVKEY1' || f.kdf !== 'PBKDF2-SHA256' || f.cipher !== 'AES-256-GCM' || typeof f.public_key !== 'string' ||
      typeof f.salt !== 'string' || typeof f.iv !== 'string' || typeof f.ciphertext !== 'string' || !f.key_id)
    throw new Error('The file is not a UAVision key (UAVKEY1).');
  if (!(f.iterations >= 100000)) throw new Error('Key with too few iterations.');
  if (b64Decode(f.public_key).length !== 32) throw new Error('Invalid public key.');
  return f;
}

// -> semente (32 bytes). Confere que a chave publica tirada da semente e a do ficheiro.
export async function openKeyFile(f, password, engine) {
  const base = await subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64Decode(f.salt), iterations: f.iterations },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let seed;
  try {
    seed = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: b64Decode(f.iv), additionalData: utf8('UAVKEY1|' + f.key_id + '|' + f.public_key), tagLength: 128 },
      key, b64Decode(f.ciphertext)));
  } catch (e) { throw new Error('Wrong password (or the file was changed).'); }
  if (seed.length !== 32) throw new Error('Invalid key.');
  const pub = await engine.publicKey(seed);
  if (b64Encode(pub) !== b64Encode(b64Decode(f.public_key))) { seed.fill(0); throw new Error('The public key does not match the private key.'); }
  return seed;
}

// ---------------------------------------------------------------- cofre no telemovel (Face ID/PRF ou password)
//
// O cofre (JSON: semente, key_id, public_key, URL, ADMIN_KEY) fica cifrado com AES-256-GCM em duas copias:
//   wrap_prf: chave = HKDF-SHA256(saida PRF da passkey, info "UAVPHONE1 vault")   (Face ID)
//   wrap_pwd: chave = PBKDF2-SHA256(password, salt proprio, 600 000)               (alternativa)
// AAD = "UAVPHONE1|<key_id>|<public_key>": trocar a chave publica guardada invalida o cofre.

export const vaultAad = (cfg) => utf8('UAVPHONE1|' + cfg.key_id + '|' + cfg.public_key);

export async function keyFromPrf(prfBytes) {
  const b = new Uint8Array(prfBytes);
  if (b.length < 32) throw new Error('PRF output too short.');
  const base = await subtle.importKey('raw', b, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8('UAVPHONE1 vault') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function keyFromPassword(password, salt, iterations) {
  const base = await subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function sealVault(aesKey, vault, aad) {
  const iv = randomBytes(12);
  const pt = utf8(JSON.stringify(vault));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, aesKey, pt));
  pt.fill(0);
  return { iv: b64Encode(iv), ct: b64Encode(ct) };
}

export async function openVault(aesKey, wrap, aad) {
  let pt;
  try { pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: b64Decode(wrap.iv), additionalData: aad, tagLength: 128 }, aesKey, b64Decode(wrap.ct))); }
  catch (e) { throw new Error('Could not open the saved data (wrong password, or Face ID of another passkey).'); }
  const v = JSON.parse(dec.decode(pt));
  pt.fill(0);
  return v;
}

export async function passwordWrap(password, vault, aad, iterations = KDF_ITERATIONS) {
  const salt = randomBytes(16);
  const w = await sealVault(await keyFromPassword(password, salt, iterations), vault, aad);
  return Object.assign({ salt: b64Encode(salt), iterations }, w);
}
export async function passwordUnwrap(password, wrap, aad) {
  return openVault(await keyFromPassword(password, b64Decode(wrap.salt), wrap.iterations), wrap, aad);
}

// ---------------------------------------------------------------- servidor (1.0.4: Supabase; antes a folha Google)

// O URL do projeto Supabase: https://<projeto>.supabase.co (o mesmo que o License Manager). http so para
// 127.0.0.1/localhost e so se a propria pagina estiver em localhost (testes).
export function checkUrl(url, pageHost) {
  let u;
  try { u = new URL(String(url || '').trim()); } catch (e) { return 'Invalid URL.'; }
  const loop = (h) => h === '127.0.0.1' || h === 'localhost';
  if (u.protocol === 'http:' && loop(u.hostname) && loop(pageHost || '')) return null;
  if (u.hostname === 'script.google.com') return 'This is the old Google sheet URL. Use the Supabase project URL (https://<project>.supabase.co).';
  if (u.protocol !== 'https:' || !/^[a-z0-9]+\.supabase\.co$/.test(u.hostname)) return 'The URL must be the Supabase project URL: https://<project>.supabase.co';
  if (u.search || u.hash || !/^\/?(functions\/v1(\/uavision(\/admin)?)?\/?)?$/.test(u.pathname)) return 'Use only the project URL: https://<project>.supabase.co';
  return null;
}

// <projeto>/functions/v1/uavision/<route>
export function functionUrl(url, route) {
  const u = new URL(String(url).trim());
  return u.origin + '/functions/v1/uavision/' + route;
}

const ERRORS = {
  unauthorized: 'Wrong ADMIN_KEY (or the ADMIN_KEY is not set in the Supabase function secrets).',
  'not approved': 'The request is no longer Approved on the server.',
  'no such licence': 'The licence does not exist on the server.',
  'already issued': 'This request was already issued.',
  'licence does not match the request': 'The licence does not match the request.',
  'no such request': 'The request no longer exists on the server.',
  'secret-like field refused': 'The server refused the call (a field with a secret-like name).',
  'server error': 'Error on the server (Supabase).'
};
export const errorText = (e) => ERRORS[e] || String(e || 'unknown error');

// POST JSON a <projeto>/functions/v1/uavision/admin, com a ADMIN_KEY no cabecalho x-uav-key (nunca no corpo nem no
// URL). Tem preflight CORS: a funcao so responde a esta pagina se a origem dela estiver no segredo ALLOWED_ORIGIN.
// Sem cookies, sem redirecionamentos. A funcao responde sempre JSON {ok, ...}, tambem nos erros (4xx).
export async function callServer(url, adminKey, body, fetchImpl = globalThis.fetch) {
  let r;
  try {
    r = await fetchImpl(functionUrl(url, 'admin'), { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-uav-key': adminKey }, body: JSON.stringify(body),
      redirect: 'error', credentials: 'omit', cache: 'no-store', mode: 'cors' });
  } catch (e) { throw new Error('No connection to the server (' + (e && e.message ? e.message : 'network') + '). If the internet is fine: is this page address in ALLOWED_ORIGIN?'); }
  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch (e) { throw new Error('Invalid answer from the server (HTTP ' + r.status + '). Is the URL the Supabase project URL, and the function "uavision" deployed with Verify JWT off?'); }
  if (!j || j.ok !== true) throw new Error(errorText(j && j.error));
  return j;
}

export const listRequests = (url, adminKey, fetchImpl) => callServer(url, adminKey, { action: 'admin_requests' }, fetchImpl).then((j) => (j.rows || []).map(normaliseRow));

// ---------------------------------------------------------------- emitir

export function todayUtc(now = new Date()) { return now.toISOString().substring(0, 10); }
export function addDays(ymd, n) { const d = new Date(ymd + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().substring(0, 10); }

const isHex32 = (s) => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);

// Le e confere o pedido de uma linha da folha. Devolve o pedido (UAVREQ1) ou rebenta com o motivo.
export async function requestOfRow(row) {
  if (!row.request) throw new Error('The row has no request text.');
  const r = parseRequest(row.request);
  if (r.format !== 'UAVREQ1' || !isHex32(r.request_id)) throw new Error('Invalid request.');
  if (r.request_id !== row.request_id) throw new Error('The request text does not match the row.');
  if (!PRODUCTS[r.product]) throw new Error('Unknown program: ' + r.product + '.');
  const h = r.hwid || {};
  for (const k of ['uuid', 'disk', 'cpu']) if ((h[k] || '') !== '' && !isHex32(h[k])) throw new Error('Invalid HWID.');
  if (['uuid', 'disk', 'cpu'].filter((k) => (h[k] || '') !== '').length < 2) throw new Error('The request has fewer than 2 PC identifiers: the licence would never be valid.');
  if (row.hwid_hash && (await hwidHash(h)) !== row.hwid_hash) throw new Error('The HWID of the request does not match the one on the server.');
  return r;
}

// O numero da licenca: UAV-LM-<ano>-<8 hex do pedido>, e -2, -3 se ja existir (como o NewLicenceId do C#).
export function newLicenceId(product, requestId, issued, taken) {
  const base = 'UAV-' + (PRODUCTS[product] || product.substring(0, 2)) + '-' + issued.substring(0, 4) + '-' + requestId.substring(0, 8).toUpperCase();
  let id = base;
  for (let n = 2; taken.has(id); n++) id = base + '-' + n;
  return id;
}

// 1.0.8 (Shared\FORMATO.md 5.4): o tipo da licenca: 'perpetual', 'year' ou 'demo' (true/false antigos = demo/perpetual)
export function kindOf(k) { return k === true ? 'demo' : k === 'year' || k === 'demo' ? k : 'perpetual'; }
export const typeText = (k) => (k === 'demo' ? TYPE_DEMO : k === 'year' ? TYPE_YEAR : TYPE_PERPETUAL);

// O ultimo dia valido: 30 dias = emissao + 29; 1 ano = o mesmo dia e mes do ano seguinte menos um dia (29/2 conta como 28/2).
// Igual ao LicenceTypes.ExpiresFor do C#.
export function expiresFor(kind, issued) {
  if (kind === 'demo') return addDays(issued, DEMO_DAYS - 1);
  if (kind === 'year') {
    const y = +issued.substring(0, 4), m = +issued.substring(5, 7); let d = +issued.substring(8, 10);
    if (m === 2 && d === 29) d = 28;
    const next = String(y + 1).padStart(4, '0') + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
    return addDays(next, -1);
  }
  return null;
}

export function licenceFields(req, { demo, kind, issued, licenceId, keyId, notes = '' }) {
  const c = req.customer || {}, h = req.hwid || {};
  const k = kind ? kindOf(kind) : kindOf(!!demo);
  return {
    format: 'UAVLIC1', licence_id: licenceId, key_id: keyId, product: req.product, type: k,
    request_id: req.request_id,
    customer: { name: String(c.name || ''), company: String(c.company || ''), email: String(c.email || ''), country: String(c.country || '') },
    machine_name: String(req.machine_name || ''), hwid: { uuid: h.uuid || '', disk: h.disk || '', cpu: h.cpu || '' }, hwid_min_match: 2,
    issued, expires: expiresFor(k, issued), notes
  };
}

export async function signLicence(fields, seed, engine) {
  const msg = utf8(canonicalLicence(fields));
  const sig = await engine.sign(msg, seed);
  return 'UAVLIC1.' + b64uEncode(msg) + '.' + b64uEncode(sig);
}

// Confere uma licenca (como o programa do cliente: assinatura e JSON canonico). Devolve os campos.
export async function checkLicence(token, publicKeyB64, engine) {
  const t = decodeToken(token, 'UAVLIC1', 3);
  if (t.sig.length !== 64) throw new Error('signature with the wrong size');
  if (!(await engine.verify(t.sig, t.msg, b64Decode(publicKeyB64)))) throw new Error('invalid signature');
  if (dec.decode(t.msg) !== canonicalLicence(t.json)) throw new Error('JSON not canonical');
  return t.json;
}

// Tudo o que o botao Aceitar faz depois do Face ID: assina (ou reusa a licenca ja assinada neste telemovel se a
// publicacao anterior falhou), confere, Aprovado na folha, publica. Devolve { token, fields }.
//   ctx: { url, adminKey, seed, keyId, publicKey, engine, rows (todas, para os numeros ja usados), previous (token
//          ja assinado aqui para este pedido, ou null), takenIds, onSigned(token, fields), now, fetchImpl }
export async function approveAndIssue(row, demo, ctx) {
  const kind = kindOf(demo);   // 1.0.8: true / false / 'year' / 'demo' / 'perpetual'
  const req = await requestOfRow(row);
  if (normalise(row.state) === STATE.ISSUED) throw new Error('This request was already issued.');
  let token = ctx.previous || null, fields;
  if (token) {
    fields = await checkLicence(token, ctx.publicKey, ctx.engine);
    if (fields.request_id !== row.request_id) token = null;
  }
  if (!token) {
    const issued = todayUtc(ctx.now || new Date());
    const taken = new Set((ctx.rows || []).filter((r) => r.request_id !== row.request_id).map((r) => r.licence_id).filter(Boolean));
    for (const x of ctx.takenIds || []) taken.add(x);
    fields = licenceFields(req, { kind, issued, licenceId: newLicenceId(req.product, req.request_id, issued, taken), keyId: ctx.keyId });
    token = await signLicence(fields, ctx.seed, ctx.engine);
    const back = await checkLicence(token, ctx.publicKey, ctx.engine);   // nunca publicar uma licenca que nao verifica
    if (back.licence_id !== fields.licence_id) throw new Error('check failed');
    if (ctx.onSigned) await ctx.onSigned(token, fields);   // guardada antes da rede: se a publicacao falhar, repete-se a mesma
  }
  if (normalise(row.state) !== STATE.APPROVED)
    await callServer(ctx.url, ctx.adminKey, { action: 'admin_decide', request_id: row.request_id, decision: STATE.APPROVED, by: ISSUED_BY,
      type: typeText(fields.type) }, ctx.fetchImpl);
  await callServer(ctx.url, ctx.adminKey, { action: 'admin_publish', request_id: row.request_id, licence: token, licence_id: fields.licence_id,
    hwid_hash: row.hwid_hash, issued_by: ISSUED_BY }, ctx.fetchImpl);
  return { token, fields };
}

export const rejectRequest = (row, ctx) =>
  callServer(ctx.url, ctx.adminKey, { action: 'admin_decide', request_id: row.request_id, decision: STATE.REJECTED, by: ISSUED_BY }, ctx.fetchImpl);

// 1.0.6: remocao remota (Shared\FORMATO.md 5.1): o servidor marca a licenca como removida; o programa daquele PC apaga-a
// e volta a demo quando estiver ligado a internet. Diferente da anulacao (Revoke) do License Manager.
export function removeLicence(row, ctx, note = '') {
  if (!row.licence_id) return Promise.reject(new Error('This row has no licence number.'));
  return callServer(ctx.url, ctx.adminKey, { action: 'admin_remove', licence_id: row.licence_id, by: ISSUED_BY, note: String(note || '').substring(0, 300) }, ctx.fetchImpl);
}
