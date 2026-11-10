// UAVision Licencas (telemovel): o ecra. A logica (formato, assinatura, cofre, folha) esta em core.js.
// Os dados da folha so entram no ecra por textContent (nunca innerHTML): um nome de cliente nao corre codigo.
import * as C from './core.js';

const APP_VERSION = '1.0.5';
const IDLE_LOCK_MS = 3 * 60 * 1000;     // sem mexer
const HIDDEN_LOCK_MS = 30 * 1000;       // fora da app
const $ = (id) => document.getElementById(id);

let engine = null;      // Ed25519 (WebCrypto ou noble)
let cfg = null;         // o que fica guardado (cifrado) no IndexedDB
let session = null;     // { url, adminKey } so enquanto desbloqueado
let rows = [];
let localLog = [];      // licencas assinadas neste telemovel (para repetir uma publicacao falhada e para o historico)
let pending = null;     // durante a configuracao: { vault, pwd | keepPwdWrap, cred }
let lastActivity = Date.now(), hiddenAt = 0;

// ---------------------------------------------------------------- IndexedDB (so neste iPhone)

function db() {
  return new Promise((ok, ko) => {
    const r = indexedDB.open('uavision-licencas', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => ok(r.result);
    r.onerror = () => ko(r.error);
  });
}
async function dbGet(k) {
  const d = await db();
  try { return await new Promise((ok, ko) => { const q = d.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => ok(q.result); q.onerror = () => ko(q.error); }); }
  finally { d.close(); }
}
async function dbPut(k, v) {
  const d = await db();
  try { await new Promise((ok, ko) => { const t = d.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = ok; t.onerror = () => ko(t.error); }); }
  finally { d.close(); }
}
function dbWipe() {
  return new Promise((ok, ko) => { const r = indexedDB.deleteDatabase('uavision-licencas'); r.onsuccess = ok; r.onerror = () => ko(r.error); r.onblocked = ok; });
}

// ---------------------------------------------------------------- ecra: ajudas

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}
// Icone do sprite do index.html (SVG inline, sem bibliotecas).
function icon(name) {
  const NS = 'http://www.w3.org/2000/svg';
  const s = document.createElementNS(NS, 'svg'); s.setAttribute('class', 'ic'); s.setAttribute('aria-hidden', 'true');
  const u = document.createElementNS(NS, 'use'); u.setAttribute('href', '#i-' + name); s.append(u);
  return s;
}
// Mensagem em "toast": aparece e esconde-se sozinha (o texto fica no elemento, so deixa de se ver).
let msgTimer = 0;
function msg(text, kind) {
  const m = $('msg');
  m.textContent = text || '';
  m.className = 'msg' + (kind ? ' ' + kind : '') + (text ? ' show' : '');
  clearTimeout(msgTimer);
  if (text) msgTimer = setTimeout(() => m.classList.remove('show'), kind === 'err' ? 7000 : 4500);
}
function show(id) {
  for (const s of ['scrSetup', 'scrLocked', 'scrMain']) $(s).hidden = s !== id;
  $('btnLock').hidden = id !== 'scrMain';
  $('tabbar').hidden = id !== 'scrMain';
  document.body.classList.toggle('no-tabbar', id !== 'scrMain');
  $('boot').hidden = true;
}
function busy(on, ...buttons) { for (const b of buttons) if (b) b.disabled = on; }
const fmtUtc = (s) => { const d = new Date(s); return s && !isNaN(d) ? d.toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' }) : (s || ''); };
const errText = (e) => (e && e.name === 'NotAllowedError' ? 'Face ID cancelled (or it took too long).' : (e && e.message) || String(e));

// ---------------------------------------------------------------- Face ID: passkey com PRF

async function createPasskey() {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('This browser has no passkeys.');
  const salt = C.randomBytes(32);
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: 'UAVision Licences' },
    user: { id: C.randomBytes(16), name: 'UAVision Licences', displayName: 'UAVision Licences' },
    challenge: C.randomBytes(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }, { type: 'public-key', alg: -8 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    attestation: 'none', timeout: 120000,
    extensions: { prf: { eval: { first: salt } } }
  } });
  const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  if (!ext.prf || ext.prf.enabled === false) throw new Error('The passkey was created but this iPhone does not give the PRF secret (needs iOS 18 or newer). Use the password only.');
  const first = ext.prf.results && ext.prf.results.first;
  return { cred_id: C.b64uEncode(new Uint8Array(cred.rawId)), salt: C.b64Encode(salt), prf: first ? new Uint8Array(first) : null };
}

// Face ID -> segredo PRF (32 bytes). Tem de ser o primeiro "await" depois do toque (o Safari exige o gesto).
async function prfAssert(p) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: C.randomBytes(32), allowCredentials: [{ type: 'public-key', id: C.b64Decode(p.cred_id) }],
    userVerification: 'required', timeout: 120000, extensions: { prf: { eval: { first: C.b64Decode(p.salt) } } }
  } });
  const flags = new Uint8Array(a.response.authenticatorData)[32];
  if (!(flags & 0x04)) throw new Error('Face ID was not confirmed.');
  const r = a.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) throw new Error('The passkey did not return the PRF secret.');
  return new Uint8Array(r.results.first);
}

const openWithFace = async () => { const prf = await prfAssert(cfg.prf); try { return await C.openVault(await C.keyFromPrf(prf), cfg.wrap_prf, C.vaultAad(cfg)); } finally { prf.fill(0); } };
const openWithPassword = (pwd) => C.passwordUnwrap(pwd, cfg.wrap_pwd, C.vaultAad(cfg));

// ---------------------------------------------------------------- 1.a configuracao

async function onCheck() {
  const b = $('btnCheck');
  busy(true, b);
  let seed = null;
  try {
    let text = $('keyText').value.trim();
    const f = $('keyFile').files && $('keyFile').files[0];
    if (!text && f) text = await f.text();
    if (!text) throw new Error('Choose the key file (or paste its contents).');
    const kf = C.parseKeyFile(text);
    const pwd = $('keyPwd').value;
    if (!pwd) throw new Error('The export password is missing.');
    const url = $('sheetUrl').value.trim(), adminKey = $('adminKey').value.trim();
    const bad = C.checkUrl(url, location.hostname);
    if (bad) throw new Error(bad);
    if (adminKey.length < 16) throw new Error('The ADMIN_KEY has at least 16 characters.');
    msg('Opening the key (a few seconds)...');
    seed = await C.openKeyFile(kf, pwd, engine);
    msg('Connecting to the server...');
    const list = await C.listRequests(url, adminKey);
    pending = { vault: { seed: C.b64Encode(seed), key_id: kf.key_id, public_key: kf.public_key, url, admin_key: adminKey }, pwd };
    $('setupOkText').textContent = 'Key ' + kf.key_id + ' opened (' + await fingerprint(kf.public_key) + '). Server connected: ' + list.length + ' request(s).';
    for (const id of ['keyText', 'keyPwd', 'adminKey']) $(id).value = '';
    $('keyFile').value = '';
    $('setupStep1').hidden = true; $('setupStep2').hidden = false;
    msg('');
  } catch (e) { msg(errText(e), 'err'); }
  finally { if (seed) seed.fill(0); busy(false, b); }
}

async function onPasskey() {
  const b = $('btnPasskey');
  busy(true, b, $('btnNoPasskey'));
  try {
    let prf;
    if (!pending.cred) {
      const c = await createPasskey();
      pending.cred = { cred_id: c.cred_id, salt: c.salt };
      prf = c.prf;
      if (!prf) {   // o Safari nem sempre da o segredo ao criar: falta um Face ID (outro toque)
        b.textContent = 'Confirm Face ID (step 2)';
        msg('Passkey created. Tap again to confirm with Face ID.');
        return;
      }
    } else prf = await prfAssert(pending.cred);
    await finishSetup(prf);
  } catch (e) { msg(errText(e), 'err'); }
  finally { busy(false, b, $('btnNoPasskey')); }
}

async function finishSetup(prf) {
  const v = pending.vault;
  const c = { v: 1, app: APP_VERSION, key_id: v.key_id, public_key: v.public_key, created_utc: new Date().toISOString(), prf: null, wrap_prf: null, wrap_pwd: null };
  const aad = C.vaultAad(c);
  if (prf) {
    c.prf = pending.cred;
    c.wrap_prf = await C.sealVault(await C.keyFromPrf(prf), v, aad);
    prf.fill(0);
  }
  if (pending.keepPwdWrap) c.wrap_pwd = pending.keepPwdWrap;
  else { msg('Saving (a few seconds)...'); c.wrap_pwd = await C.passwordWrap(pending.pwd, v, aad); }
  if (cfg && cfg.created_utc && pending.keepPwdWrap) c.created_utc = cfg.created_utc;
  await dbPut('config', c);
  cfg = c;
  try { if (navigator.storage && navigator.storage.persist) await navigator.storage.persist(); } catch (e) { }
  startSession(v);
  pending = null;
  $('btnPasskey').textContent = 'Turn on Face ID';
  $('btnNoPasskey').hidden = false; $('setupStep1').hidden = false; $('setupStep2').hidden = true;
  msg(prf ? 'Done. Face ID is on.' : 'Done. Unlock with the password only.', 'good');
}

// ---------------------------------------------------------------- bloquear / desbloquear

function startSession(vault) {
  session = { url: vault.url, adminKey: vault.admin_key };
  lastActivity = Date.now();
  show('scrMain');
  selectTab('pend');
  refresh();
}

function lock(why) {
  session = null; rows = []; pending = null;
  closeModal();
  for (const id of ['tabPend', 'tabHist', 'confInfo']) $(id).replaceChildren();
  for (const id of ['unlockPwd', 'mPwd', 'wipeConfirm']) $(id).value = '';
  $('cntPend').textContent = ''; $('lastRefresh').textContent = '';
  if (!cfg) { show('scrSetup'); return; }
  $('btnUnlockFace').hidden = !cfg.prf;
  $('pwdBox').open = !cfg.prf;
  show('scrLocked');
  msg(why || '');
}

async function onUnlockFace() {
  try { startSession(await openWithFace()); msg(''); } catch (e) { msg(errText(e), 'err'); }
}
async function onUnlockPwd() {
  const b = $('btnUnlockPwd'); busy(true, b);
  try { msg('Opening...'); const v = await openWithPassword($('unlockPwd').value); $('unlockPwd').value = ''; startSession(v); msg(''); }
  catch (e) { msg(errText(e), 'err'); }
  finally { busy(false, b); }
}

// ---------------------------------------------------------------- lista

async function refresh() {
  if (!session) return;
  const b = $('btnRefresh'); busy(true, b);
  try {
    rows = await C.listRequests(session.url, session.adminKey);
    $('lastRefresh').textContent = 'Updated ' + new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    render();
  } catch (e) { msg(errText(e), 'err'); }
  finally { busy(false, b); }
}

const waiting = () => rows.filter((r) => r.state === C.STATE.PENDING || (r.state === C.STATE.APPROVED && !r.licence_id));

function render() {
  if (!session) return;
  const w = waiting().sort((a, b) => String(b.received_utc).localeCompare(String(a.received_utc)));
  $('cntPend').textContent = w.length ? String(w.length) : '';
  $('tabPend').replaceChildren(...(w.length ? w.map(requestCard)
    : [emptyState('inbox', 'No pending requests', 'New licence requests from the Link Manager appear here.')]));
  renderHistory();
  renderConf();
}

function emptyState(ic, title, text) {
  return el('div', { class: 'empty' }, el('div', { class: 'empty-ic' }, icon(ic)), el('div', { class: 'empty-t', text: title }), el('div', { class: 'empty-s', text }));
}

// Lista "rotulo / valor" (linhas como nas Definicoes do iOS). So textContent.
function info(pairs) {
  const dl = el('dl');
  for (const [k, v, cls] of pairs) if (v !== undefined && v !== null && v !== '') dl.append(el('div', {}, el('dt', { text: k }), el('dd', { text: String(v), class: cls || '' })));
  return dl;
}

function requestInfo(r) {
  return info([['Name', r.name || '(empty)'], ['Company', r.company], ['Email', r.email], ['Country', r.country], ['PC', r.pc],
    ['Program', (r.product || '') + (r.version ? ' ' + r.version : '')], ['Received', fmtUtc(r.received_utc)], ['Note', r.note],
    ['Request', r.request_id, 'mono']]);
}

const banner = (kind, ic, text) => el('p', { class: 'banner ' + kind }, icon(ic), el('span', { text }));

function warnings(r) {
  const out = [];
  if (r.vm === C.YES) out.push(banner('bad', 'warn', 'Virtual machine: the licence will NOT work there.'));
  const same = rows.filter((x) => x !== r && x.hwid_hash && x.hwid_hash === r.hwid_hash && x.state === C.STATE.ISSUED);
  if (same.length) out.push(banner('', 'info', 'This PC already has a licence: ' + same.map((x) => x.licence_id).join(', ') + '.'));
  if (!r.name && !r.company) out.push(banner('muted', 'info', 'The customer has not filled in the name or company yet.'));
  return out;
}

function requestCard(r) {
  const title = r.company || r.name || r.pc || 'Request';
  const person = [r.company ? r.name : '', r.country].filter(Boolean).join(' · ');
  const acts = el('div', { class: 'actions' });
  if (r.state === C.STATE.APPROVED) {
    const demo = r.type === C.TYPE_DEMO;
    acts.append(el('button', { class: 'btn primary wide', text: 'Sign and publish (' + (demo ? '30-day' : 'perpetual') + ')', onclick: () => askAccept(r, demo) }));
  } else {
    acts.append(el('button', { class: 'btn primary', text: 'Approve', onclick: () => askAccept(r, false) }),
      el('button', { class: 'btn tinted', text: '30-day', onclick: () => askAccept(r, true) }));
  }
  acts.append(el('button', { class: 'btn text-red wide', text: 'Reject', onclick: () => askReject(r) }));
  const details = el('details', { class: 'details' }, el('summary', {}, el('span', { text: 'Details' }), icon('chev')),
    info([['PC', r.pc], ['Program', (r.product || '') + (r.version ? ' ' + r.version : '')], ['Email', r.email], ['Received', fmtUtc(r.received_utc)],
      ['Note', r.note], ['Request', r.request_id, 'mono']]));
  return el('div', { class: 'card', 'data-request': r.request_id },
    el('div', { class: 'head' },
      el('div', { class: 'who' }, el('div', { class: 'company', text: title }), person ? el('div', { class: 'person', text: person }) : null),
      el('span', { class: 'state ' + r.state, text: r.state })),
    el('div', { class: 'meta' }, el('span', { class: 'chip', text: r.pc || 'PC ?' }), el('span', { class: 'chip', text: fmtUtc(r.received_utc) })),
    ...warnings(r), details, acts);
}

// ---------------------------------------------------------------- aceitar / rejeitar

// Resumo do pedido no "bottom sheet": so o que interessa para decidir.
function summary(r, typeText) {
  return el('div', { class: 'summary' }, info([['Company', r.company || '(empty)'], ['Name', r.name || '(empty)'], ['Country', r.country], ['PC', r.pc],
    ['Program', (r.product || '') + (r.version ? ' ' + r.version : '')], ['Licence', typeText]]));
}

function askAccept(r, demo) {
  const vm = r.vm === C.YES;
  openModal({
    title: demo ? '30-day licence' : 'Perpetual licence',
    body: [el('p', { class: 'sheet-sub', text: demo ? 'Valid for 30 days from today (warning 7 days before; then it goes to demo mode).' : 'For this PC, for all versions.' }),
      summary(r, demo ? '30-day' : 'Perpetual')],
    warn: vm ? 'Virtual machine: the licence will not work there. Sign anyway?' : '',
    secret: true,
    run: async (vault) => {
      const seed = C.b64Decode(vault.seed);
      try {
        const prev = localLog.find((x) => x.request_id === r.request_id && !x.published);
        const res = await C.approveAndIssue(r, demo, {
          url: session.url, adminKey: session.adminKey, seed, keyId: cfg.key_id, publicKey: cfg.public_key, engine, rows,
          previous: prev ? prev.token : null, takenIds: localLog.map((x) => x.licence_id),
          onSigned: async (token, f) => { addLog({ licence_id: f.licence_id, request_id: f.request_id, company: f.customer.company, name: f.customer.name,
            pc: f.machine_name, type: f.type, issued: f.issued, expires: f.expires, token, published: false }); }
        });
        markPublished(res.fields.licence_id);
        msg('Issued ' + res.fields.licence_id + ' (' + (res.fields.type === 'demo' ? '30-day, until ' + res.fields.expires : 'perpetual') + '). The customer program installs it by itself.', 'good');
      } finally { seed.fill(0); }
      await refresh();
    }
  });
}

function askReject(r) {
  openModal({
    title: 'Reject the request?', secret: false, okText: 'Reject', okClass: 'btn destructive block xl',
    body: [el('p', { class: 'sheet-sub', text: 'No licence is issued. The customer program shows that the request was rejected.' }), summary(r, 'none')],
    run: async () => { await C.rejectRequest(r, { url: session.url, adminKey: session.adminKey }); msg('Request rejected.', 'good'); await refresh(); }
  });
}

async function addLog(x) { localLog = localLog.filter((y) => y.licence_id !== x.licence_id); localLog.push(x); await dbPut('log', localLog); }
async function markPublished(id) { for (const x of localLog) if (x.licence_id === id) x.published = true; await dbPut('log', localLog); }

// ---------------------------------------------------------------- confirmacao (Face ID ou password)

let modalJob = null;
function openModal(job) {
  modalJob = job;
  $('mTitle').textContent = job.title;
  $('mBody').replaceChildren(...job.body);
  $('mWarn').textContent = job.warn || ''; $('mWarn').hidden = !job.warn;
  $('mFace').hidden = !job.secret || !cfg.prf;
  $('mPwdBox').hidden = !job.secret;
  $('mOk').hidden = !!job.secret;
  $('mOk').textContent = job.okText || 'Confirm';
  $('mOk').className = job.okClass || 'btn primary block xl';
  $('mPwd').value = '';
  $('msg').classList.remove('show');
  $('modal').hidden = false;
}
function closeModal() { modalJob = null; $('modal').hidden = true; $('mPwd').value = ''; }
const modalButtons = () => ['mFace', 'mPwdBtn', 'mOk', 'mCancel'].map($);

async function runModal(getVault) {
  const job = modalJob;
  if (!job) return;
  busy(true, ...modalButtons());
  try {
    const vault = getVault ? await getVault() : null;   // o Face ID tem de ser o primeiro await (gesto)
    msg('Working...');
    await job.run(vault);
    if (modalJob === job) closeModal();
  } catch (e) { msg(errText(e), 'err'); }
  finally { busy(false, ...modalButtons()); }
}

// ---------------------------------------------------------------- historico

function renderHistory() {
  const done = rows.filter((r) => r.state === C.STATE.ISSUED).sort((a, b) => String(b.decided_utc).localeCompare(String(a.decided_utc)));
  const cards = [];
  for (const r of done) {
    let f = null;
    try { f = C.decodeToken(r.licence, 'UAVLIC1', 3).json; } catch (e) { }
    const demo = f && f.type === 'demo';
    const c = el('div', { class: 'card' },
      el('div', { class: 'head' },
        el('div', { class: 'who' }, el('div', { class: 'company', text: r.company || r.name || '(no company)' }),
          el('div', { class: 'person', text: [r.company ? r.name : '', r.pc].filter(Boolean).join(' · ') })),
        el('span', { class: 'state Issued', text: demo ? '30-day' : 'Perpetual' })),
      el('div', { class: 'meta' }, el('span', { class: 'chip mono', text: r.licence_id || '(no number)' })),
      info([['Issued', f ? f.issued : ''], ['Valid until', demo && f.expires ? f.expires : ''], ['Issued by', r.issued_by], ['Decided by', r.decided_by]]));
    const chk = el('p', { class: 'sig' }, icon('seal'), el('span', { text: 'Signature: checking...' }));
    c.append(chk);
    C.checkLicence(r.licence, cfg.public_key, engine).then(() => { chk.className = 'sig ok'; chk.lastChild.textContent = 'Signature: matches this key.'; },
      (e) => { chk.className = 'sig bad'; chk.lastChild.textContent = 'Signature does NOT match this key (' + e.message + ').'; });
    cards.push(c);
  }
  const unpublished = localLog.filter((x) => !x.published);
  for (const x of unpublished)
    cards.unshift(el('div', { class: 'card' },
      el('div', { class: 'head' }, el('div', { class: 'who' }, el('div', { class: 'company', text: x.company || x.licence_id }), el('div', { class: 'person', text: x.pc || '' })),
        el('span', { class: 'state Unpublished', text: 'Not published' })),
      el('div', { class: 'meta' }, el('span', { class: 'chip mono', text: x.licence_id })),
      info([['Signed', x.issued]]),
      banner('', 'warn', 'Signed on this iPhone but publishing failed. Tap Sign and publish on the request again.')));
  $('tabHist').replaceChildren(...(cards.length ? cards : [emptyState('seal', 'No licences yet', 'Licences issued here or on the PC appear here, with their signature checked.')]));
}

// ---------------------------------------------------------------- definicoes

async function fingerprint(pubB64) { const h = await C.sha256Hex(C.b64Encode(C.b64Decode(pubB64))); return h.substring(0, 16).replace(/(....)(?=.)/g, '$1 '); }

async function renderConf() {
  if (!session) return;
  let host = '';
  try { host = new URL(session.url).host; } catch (e) { }
  const fp = await fingerprint(cfg.public_key);
  $('confInfo').replaceChildren(...info([['Key', cfg.key_id], ['Fingerprint', fp, 'mono'], ['Face ID', cfg.prf ? 'on' : 'off (password only)'],
    ['Ed25519', engine.name], ['Server', host, 'mono'], ['Set up', fmtUtc(cfg.created_utc)], ['Page', APP_VERSION]]).childNodes);
  $('btnAddPasskey').hidden = !!cfg.prf;
}

function onAddPasskey() {
  openModal({ title: 'Turn on Face ID', body: [el('p', { class: 'sheet-sub', text: 'First the export password; then the passkey is created.' })], secret: true,
    run: async (vault) => {
      pending = { vault, keepPwdWrap: cfg.wrap_pwd };
      closeModal();
      show('scrSetup'); $('setupStep1').hidden = true; $('setupStep2').hidden = false; $('btnNoPasskey').hidden = true;
      $('setupOkText').textContent = 'Password correct.';
      msg('Tap Turn on Face ID.');
    } });
}

async function onWipe() {
  if ($('wipeConfirm').value.trim().toUpperCase() !== 'DELETE') { msg('Type DELETE to confirm.', 'err'); return; }
  try {
    await dbWipe();
    if (window.caches) for (const k of await caches.keys()) await caches.delete(k);
    if (navigator.serviceWorker) for (const r of await navigator.serviceWorker.getRegistrations()) await r.unregister();
  } catch (e) { }
  cfg = null; localLog = [];
  location.reload();
}

function selectTab(t) {
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('on', b.dataset.tab === t);
  $('tabPend').hidden = t !== 'pend'; $('tabHist').hidden = t !== 'hist'; $('tabConf').hidden = t !== 'conf';
  $('btnRefresh').parentElement.hidden = t === 'conf';
  $('mainTitle').textContent = { pend: 'Requests', hist: 'Issued', conf: 'Settings' }[t];
  window.scrollTo(0, 0);
  $('msg').classList.remove('show');
}

// ---------------------------------------------------------------- arranque

function wire() {
  $('btnCheck').addEventListener('click', onCheck);
  $('btnPasskey').addEventListener('click', onPasskey);
  $('btnNoPasskey').addEventListener('click', async () => { busy(true, $('btnNoPasskey')); try { await finishSetup(null); } catch (e) { msg(errText(e), 'err'); } finally { busy(false, $('btnNoPasskey')); } });
  $('btnUnlockFace').addEventListener('click', onUnlockFace);
  $('btnUnlockPwd').addEventListener('click', onUnlockPwd);
  $('unlockPwd').addEventListener('keydown', (e) => { if (e.key === 'Enter') onUnlockPwd(); });
  $('btnLock').addEventListener('click', () => lock('Locked.'));
  $('btnRefresh').addEventListener('click', refresh);
  $('btnAddPasskey').addEventListener('click', onAddPasskey);
  $('btnWipe').addEventListener('click', onWipe);
  for (const b of document.querySelectorAll('.tab')) b.addEventListener('click', () => selectTab(b.dataset.tab));
  $('mFace').addEventListener('click', () => runModal(openWithFace));
  $('mPwdBtn').addEventListener('click', () => runModal(() => openWithPassword($('mPwd').value)));
  $('mOk').addEventListener('click', () => runModal(null));
  $('mCancel').addEventListener('click', () => { closeModal(); msg(''); });
  for (const ev of ['pointerdown', 'keydown', 'touchstart']) document.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hiddenAt = Date.now();
    else if (session && hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS) lock('Locked (you left the app).');
  });
  setInterval(() => { if (session && Date.now() - lastActivity > IDLE_LOCK_MS) lock('Locked (3 minutes without use).'); }, 5000);
}

(async () => {
  wire();
  try { engine = await C.pickEngine(); }
  catch (e) { $('boot').textContent = 'This browser cannot sign (Ed25519). ' + errText(e); return; }
  try {
    cfg = (await dbGet('config')) || null;
    localLog = (await dbGet('log')) || [];
  } catch (e) { $('boot').textContent = 'No access to the browser storage (private mode?). ' + errText(e); return; }
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) navigator.serviceWorker.register('sw.js').catch(() => { });
  if (!cfg) { show('scrSetup'); return; }
  lock('');
})();
