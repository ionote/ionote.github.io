(() => {
"use strict";

const STORE_KEY = "notes_v3_enc";
const SETTINGS_KEY = "notes_settings_v3";
const ITER = 600000;
const CHECK = "ionote";

const $ = s => document.querySelector(s);
const te = new TextEncoder();
const td = new TextDecoder();

/* ── Crypto: AES-GCM, key from passphrase via PBKDF2 ── */
function b64(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function fromB64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(pass, salt, iter = ITER) {
  const base = await crypto.subtle.importKey("raw", te.encode(pass.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(plain, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(plain));
  return b64(iv) + ":" + b64(ct);
}

async function decryptText(payload, key) {
  const [ivB, ctB] = payload.split(":");
  if (!ivB || !ctB) throw new Error("bad payload");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(ivB) }, key, fromB64(ctB));
  return td.decode(pt);
}

async function checkKey(key, check) {
  try { return (await decryptText(check, key)) === CHECK; } catch { return false; }
}

async function decryptItems(items, key) {
  const out = [];
  for (const n of items) {
    try {
      out.push({ id: n.id, d: n.d, pinned: !!n.pinned, t: await decryptText(n.t, key), b: await decryptText(n.b, key) });
    } catch {}
  }
  return out;
}

const toUrl = u8 => b64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromUrl = s => fromB64(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));

async function zip(bytes) {
  const s = new Blob([bytes]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

async function unzip(bytes, max = 1 << 20) {
  const r = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const out = [];
  let n = 0;
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    n += value.length;
    if (n > max) { r.cancel(); throw new Error("too big"); }
    out.push(value);
  }
  return new Blob(out).text();
}

async function sealLink(n, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass, salt);
  const body = await zip(te.encode(JSON.stringify({ t: n.t, b: n.b })));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, body));
  const out = new Uint8Array(29 + ct.length);
  out[0] = 1;
  out.set(salt, 1);
  out.set(iv, 17);
  out.set(ct, 29);
  return location.origin + location.pathname + "#s=" + toUrl(out);
}

async function openLink(token, pass) {
  const d = fromUrl(token);
  if (d.length < 45 || d[0] !== 1) throw new Error("bad link");
  const key = await deriveKey(pass, d.slice(1, 17));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: d.slice(17, 29) }, key, d.slice(29));
  const o = JSON.parse(await unzip(new Uint8Array(pt)));
  if (!o || typeof o !== "object") throw new Error("bad note");
  return o;
}

async function sendLink(url) {
  if (navigator.share) {
    try { await navigator.share({ url }); return; }
    catch (e) { if (e.name === "AbortError") return; }
  }
  try { await navigator.clipboard.writeText(url); toast("Link copied"); }
  catch { prompt("Copy this link", url); }
}

/* ── Storage ── */
function loadRaw(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}
function saveRaw(key, data) {
  try { localStorage.setItem(key, JSON.stringify(data)); }
  catch { toast("Couldn't save. Free up space on your device and try again."); }
}

let settings = {
  theme: "system", autoLock: 5, lastBackup: null, lockEnabled: false, salt: null, iter: null, check: null,
  ...loadRaw(SETTINGS_KEY, {})
};

let notes = [];          // plaintext in memory only while unlocked
let cryptoKey = null;    // AES key while unlocked
let cur = null;
let saveTimer = null;
let lockMode = "unlock";
let importData = null;
let hiddenAt = 0;
let holdLock = 0;
let menuNote = null;
let menuAt = 0;
let popGuard = 0;
let lpTimer = null;
let lpFired = false;
let lpX = 0;
let lpY = 0;
let deferredPrompt = null;
let toastTimer = null;

const DAY = 864e5;
const MAX_BODY = 2100;
let pendingShare = null;
let pendingLink = null;
let shareNote = null;

function readUrl() {
  const sp = new URLSearchParams(location.search);
  const text = sp.get("text") || "";
  const url = sp.get("url") || "";
  const title = sp.get("title") || "";
  const body = url && !text.includes(url) ? (text ? text + "\n" + url : url) : text;
  const m = /^#s=([\w-]+)$/.exec(location.hash);
  if (title || body) pendingShare = { t: title.slice(0, 200), b: body };
  if (m && m[1].length < 100000) pendingLink = m[1];
  if (title || body || m) history.replaceState(null, "", location.pathname);
  return !!(pendingShare || pendingLink);
}
readUrl();

const list = $("#list");
const ed = $("#ed");
const q = $("#q");

const fold = s => s.normalize("NFKC").toLowerCase()
  .replace(/[\u064B-\u065F\u0670\u0640\u200C]/g, "")
  .replace(/[\u0649\u06CC]/g, "\u064A")
  .replace(/\u06A9/g, "\u0643")
  .replace(/[\u0622\u0623\u0625\u0671]/g, "\u0627")
  .replace(/[\u0660-\u0669\u06F0-\u06F9]/g, c => String(c.charCodeAt(0) & 15));

const uid = () => crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const fmtDate = d => {
  const now = new Date(), dt = new Date(d), diff = (now - dt) / 864e5;
  if (diff < 1 && now.getDate() === dt.getDate()) return dt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  if (diff < 2) return "Yesterday";
  if (diff < 7) return dt.toLocaleDateString(undefined, { weekday: "long" });
  return dt.toLocaleDateString(undefined, { month: "short", day: "numeric", year: now.getFullYear() !== dt.getFullYear() ? "numeric" : undefined });
};

/* ── Toast ── */
function hideToast() { $("#toast").classList.remove("show"); }
function toast(msg, act, fn, ms = 2600) {
  $("#toastMsg").textContent = msg;
  const b = $("#toastAct");
  b.hidden = !act;
  b.textContent = act || "";
  b.onclick = () => { hideToast(); if (fn) fn(); };
  $("#toast").classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, act ? 5000 : ms);
}

/* ── Theme ── */
const mq = matchMedia("(prefers-color-scheme: dark)");
function applyTheme() {
  const dark = settings.theme === "dark" || (settings.theme === "system" && mq.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $("#metaTheme").content = dark ? "#101110" : "#FDFDFD";
  document.querySelectorAll("#seg button").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.v === settings.theme)));
}
mq.addEventListener("change", applyTheme);

/* ── Persist ── */
async function persistNotes() {
  if (settings.lockEnabled && !cryptoKey) return;
  if (settings.lockEnabled) {
    const packed = [];
    for (const n of notes) {
      packed.push({
        id: n.id,
        d: n.d,
        pinned: !!n.pinned,
        t: await encryptText(n.t || "", cryptoKey),
        b: await encryptText(n.b || "", cryptoKey)
      });
    }
    saveRaw(STORE_KEY, { enc: true, items: packed });
  } else {
    saveRaw(STORE_KEY, { enc: false, items: notes.map(n => ({ id: n.id, t: n.t, b: n.b, d: n.d, pinned: !!n.pinned })) });
  }
}

async function loadNotes() {
  const data = loadRaw(STORE_KEY, { enc: false, items: [] });
  if (!Array.isArray(data.items)) return [];
  if (!data.enc) return data.items.map(n => ({ id: n.id, t: n.t || "", b: n.b || "", d: n.d || Date.now(), pinned: !!n.pinned }));
  return cryptoKey ? decryptItems(data.items, cryptoKey) : null;
}

/* ── List ── */
const IC = id => `<svg class="ic" aria-hidden="true" focusable="false"><use href="#${id}"/></svg>`;

const WELCOME = `<div class="welcome">
  <img src="icons/icon-192.png" width="56" height="56" alt="">
  <h2>No notes yet</h2>
  <p>Tap + to write your first note.</p>
  <p class="small">Notes stay on this device.</p>
</div>`;

function render() {
  const term = fold(q.value.trim());
  $("#btnSearch").hidden = notes.length <= 8;
  const items = notes
    .filter(n => !term || fold(n.t + "\n" + n.b).includes(term))
    .sort((a, b) => (b.pinned - a.pinned) || (b.d - a.d));

  if (!items.length) {
    list.innerHTML = term ? `<div class="empty">${IC("i-note")}<b>No results</b><span>Try a different word</span></div>` : WELCOME;
    return;
  }
  list.innerHTML = items.map(n => {
    const lines = n.b.trim().split("\n");
    const title = n.t.trim() || lines[0] || "Untitled";
    const preview = (n.t.trim() ? lines : lines.slice(1)).join(" ").trim().slice(0, 200);
    return `<button class="note${cur && cur.id === n.id ? " sel" : ""}" data-id="${esc(n.id)}"><span class="nt" dir="auto">${esc(title)}</span>${preview ? `<span class="np" dir="auto">${esc(preview)}</span>` : ""}<span class="nm">${n.pinned ? `<span class="pinchip">${IC("i-pin")}</span>` : ""}<span>${fmtDate(n.d)}</span></span></button>`;
  }).join("");
}

function closeSearch() {
  q.value = "";
  $("#sbar").hidden = true;
  render();
}

function refreshBackupInfo() {
  $("#bkInfo").textContent = settings.lastBackup
    ? "Last backup: " + new Date(settings.lastBackup).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })
    : "No backup yet. Notes live only in this browser.";
}

/* ── Editor ── */
function pinUI() { $("#btnPin").setAttribute("aria-pressed", String(!!(cur && cur.pinned))); }
function stampUI() { $("#stamp").textContent = cur && (cur.t || cur.b) ? "Edited " + fmtDate(cur.d) : "New note"; }

function markSelected() {
  list.querySelectorAll(".note").forEach(el => { el.classList.toggle("sel", !!cur && el.dataset.id === cur.id); });
}

function finishCurrent() {
  clearTimeout(saveTimer);
  saveTimer = null;
  if (cur && !cur.t.trim() && !cur.b.trim()) notes = notes.filter(x => x !== cur);
  cur = null;
}

function openNote(n) {
  const wasOpen = ed.classList.contains("open");
  if (cur && cur !== n) { finishCurrent(); persistNotes(); render(); }
  cur = n;
  $("#t").value = n.t;
  $("#b").value = n.b;
  pinUI();
  stampUI();
  $("#settings").classList.remove("open");
  $("#about").classList.remove("open");
  ed.classList.add("open");
  if (wasOpen) history.replaceState({ v: "ed" }, ""); else history.pushState({ v: "ed" }, "");
  markSelected();
}

function closeNote() {
  ed.classList.remove("open");
  if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
  finishCurrent();
  persistNotes();
  render();
}

function flushSave() {
  if (!saveTimer) return;
  clearTimeout(saveTimer);
  saveTimer = null;
  persistNotes();
}

function scheduleSave() {
  if (!cur) return;
  cur.t = $("#t").value;
  cur.b = $("#b").value;
  cur.d = Date.now();
  stampUI();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { saveTimer = null; persistNotes(); }, 400);
}

async function togglePin() {
  if (!cur) return;
  cur.pinned = !cur.pinned;
  cur.d = Date.now();
  const on = cur.pinned;
  pinUI();
  stampUI();
  await persistNotes();
  toast(on ? "Pinned" : "Unpinned");
}

async function removeNote(n) {
  const i = notes.indexOf(n);
  if (i < 0) return;
  notes.splice(i, 1);
  await persistNotes();
  render();
  toast("Note deleted", "Undo", async () => {
    notes.splice(Math.min(i, notes.length), 0, n);
    await persistNotes();
    render();
  });
}

function deleteCurrent() {
  if (!cur) return;
  const n = cur;
  cur = null;
  clearTimeout(saveTimer);
  saveTimer = null;
  removeNote(n);
  history.back();
}

/* ── Note actions: press and hold, or right-click ── */
function openActions(n) {
  if (menuNote) return;
  menuNote = n;
  menuAt = Date.now();
  $("#actTitle").textContent = n.t.trim() || n.b.trim().split("\n")[0] || "Untitled";
  $("#actPin b").textContent = n.pinned ? "Unpin" : "Pin";
  $("#actions").classList.add("show");
  setInert(true);
  history.pushState({ v: "menu" }, "");
  $("#actPin").focus();
}

function closeActions(viaPop) {
  if (!menuNote) return;
  menuNote = null;
  $("#actions").classList.remove("show");
  setInert(false);
  if (!viaPop) { popGuard++; history.back(); }
}

/* ── Lock ── */
const LOCK_UI = {
  unlock: { t: "Notes are locked", p: "Enter your passphrase to open them.", ok: "Unlock", two: false, cancel: false, input: true },
  set: { t: "Encrypt notes", p: "Choose a passphrase of at least 12 characters. If you forget it, your notes cannot be recovered.", ok: "Encrypt", two: true, cancel: true, input: true },
  change: { t: "Change passphrase", p: "Choose a new passphrase of at least 12 characters. If you forget it, your notes cannot be recovered.", ok: "Change", two: true, cancel: true, input: true },
  import: { t: "Encrypted backup", p: "Enter the passphrase this backup was made with.", ok: "Import", two: false, cancel: true, input: true },
  legacy: { t: "Old lock format", p: "These notes were locked with a PIN by an older version and can't be opened here. Erase them to start fresh.", ok: "Erase old notes", two: false, cancel: false, input: false },
  share: { t: "Share as link", p: "Choose a passphrase of at least 12 characters. Send it by a different route than the link.", ok: "Create link", two: true, cancel: true, input: true },
  shared: { t: "Shared note", p: "Enter the passphrase that came with this link.", ok: "Open", two: false, cancel: true, input: true }
};

const BG = "#list,#dock,#add,#ed,#settings,#about,#sbar";
const setInert = v => document.querySelectorAll(BG).forEach(el => { el.inert = v; });

function showLock(mode) {
  lockMode = mode;
  const u = LOCK_UI[mode];
  $("#lockTitle").textContent = u.t;
  $("#lockText").textContent = u.p;
  $("#lockOk").textContent = u.ok;
  $("#lockPass").style.display = u.input ? "" : "none";
  $("#lockPass2").style.display = u.two ? "" : "none";
  $("#lockCancel").style.display = u.cancel ? "" : "none";
  $("#lockPass").value = "";
  $("#lockPass2").value = "";
  $("#lockErr").textContent = "";
  $("#lock").classList.add("show");
  setInert(true);
  if (u.input) $("#lockPass").focus();
}

function hideLock() {
  $("#lockPass").value = "";
  $("#lockPass2").value = "";
  $("#lock").classList.remove("show");
  setInert(false);
}

function refreshSecurityUI() {
  const on = settings.lockEnabled && !!settings.check;
  $("#togLock .toggle").classList.toggle("on", on);
  $("#togLock").setAttribute("aria-checked", String(on));
  ["#rowAuto", "#btnChangePass", "#btnLock"].forEach(s => { $(s).hidden = !on; });
  $("#selAuto").value = String(settings.autoLock);
}

async function submitLock() {
  const pass = $("#lockPass").value;
  const fail = (m, el = $("#lockPass")) => { $("#lockErr").textContent = m; el.focus(); if (el.select) el.select(); };
  $("#lockOk").disabled = true;
  try {
    if (lockMode === "legacy") {
      if (!confirm("Erase the old locked notes permanently?")) return;
      localStorage.removeItem(STORE_KEY);
      Object.assign(settings, { lockEnabled: false, salt: null, iter: null, check: null });
      delete settings.pinHash;
      saveRaw(SETTINGS_KEY, settings);
      notes = [];
      refreshSecurityUI();
      hideLock();
      render();
      return;
    }
    if (lockMode === "unlock") {
      const key = await deriveKey(pass, fromB64(settings.salt), settings.iter);
      if (!(await checkKey(key, settings.check))) return fail("Wrong passphrase. Check for typos and try again.");
      cryptoKey = key;
      notes = (await loadNotes()) || [];
      hideLock();
      render();
      afterLoad();
      return;
    }
    if (lockMode === "import") {
      const d = importData;
      const key = await deriveKey(pass, fromB64(d.salt), d.iter);
      if (!(await checkKey(key, d.check))) return fail("Wrong passphrase for this backup. Try the one you had when you saved it.");
      const items = await decryptItems(d.items, key);
      importData = null;
      hideLock();
      await mergeNotes(items);
      return;
    }
    if (lockMode === "shared") {
      let o;
      try { o = await openLink(pendingLink, pass); } catch { return fail("Wrong passphrase, or the link is damaged."); }
      const n = clean([o])[0];
      if (!n) return fail("This link doesn't hold a note.");
      pendingLink = null;
      hideLock();
      notes.unshift(n);
      await persistNotes();
      render();
      openNote(n);
      return;
    }
    if (pass.length < 12) return fail("Use at least 12 characters. A few random words work well.");
    if (pass !== $("#lockPass2").value) return fail("The two passphrases differ. Retype the second one.", $("#lockPass2"));
    if (lockMode === "share") {
      const url = await sealLink(shareNote, pass);
      shareNote = null;
      hideLock();
      await sendLink(url);
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pass, salt);
    settings.salt = b64(salt);
    settings.iter = ITER;
    settings.check = await encryptText(CHECK, key);
    settings.lockEnabled = true;
    cryptoKey = key;
    saveRaw(SETTINGS_KEY, settings);
    await persistNotes();
    refreshSecurityUI();
    hideLock();
    toast(lockMode === "set" ? "Encryption on" : "Passphrase changed");
  } catch {
    fail("Couldn't finish that. Try again.");
  } finally {
    $("#lockOk").disabled = false;
  }
}

async function lockApp() {
  if (!settings.lockEnabled || !cryptoKey) return;
  clearTimeout(saveTimer);
  if (cur && !cur.t.trim() && !cur.b.trim()) notes = notes.filter(x => x !== cur);
  await persistNotes();
  cryptoKey = null;
  notes = [];
  cur = null;
  importData = null;
  shareNote = null;
  menuNote = null;
  $("#actions").classList.remove("show");
  q.value = "";
  $("#sbar").hidden = true;
  $("#t").value = "";
  $("#b").value = "";
  ed.classList.remove("open");
  $("#settings").classList.remove("open");
  $("#installGuide").classList.remove("show");
  $("#settings").inert = false;
  hideToast();
  list.innerHTML = "";
  showLock("unlock");
}

/* ── Backup ── */
async function mergeNotes(items) {
  let added = 0, updated = 0;
  for (const n of items) {
    const have = notes.find(x => x.id === n.id);
    if (!have) { notes.unshift(n); added++; }
    else if (n.d > have.d) { Object.assign(have, n); updated++; }
  }
  await persistNotes();
  render();
  toast(`Imported ${added} new, ${updated} updated`);
}

const clean = arr => arr
  .filter(n => n && typeof n === "object")
  .map(n => ({
    id: String(n.id || uid()),
    t: String(n.t ?? n.title ?? ""),
    b: String(n.b ?? n.body ?? n.content ?? ""),
    d: Number(n.d ?? n.date) || Date.now(),
    pinned: !!n.pinned
  }));

async function backupFile() {
  await persistNotes();
  const out = settings.lockEnabled
    ? { app: "ionote", v: 1, enc: true, salt: settings.salt, iter: settings.iter, check: settings.check, items: loadRaw(STORE_KEY, { items: [] }).items }
    : { app: "ionote", v: 1, enc: false, items: notes.map(n => ({ id: n.id, t: n.t, b: n.b, d: n.d, pinned: !!n.pinned })) };
  return new File([JSON.stringify(out)], `ionote-backup-${new Date().toISOString().slice(0, 10)}.json`, { type: "application/json" });
}

function applyShare() {
  const n = { id: uid(), t: pendingShare.t, b: pendingShare.b, d: Date.now(), pinned: false };
  pendingShare = null;
  notes.unshift(n);
  persistNotes();
  render();
  openNote(n);
}

function backupNudge() {
  if (!notes.length) return;
  const now = Date.now();
  const last = settings.lastBackup || Math.min(...notes.map(n => n.d));
  if (now - last < 14 * DAY || now - (settings.nudgedAt || 0) < 3 * DAY) return;
  settings.nudgedAt = now;
  saveRaw(SETTINGS_KEY, settings);
  toast("Back up your notes? They only live in this browser.", "Back up", exportBackup);
}

function afterLoad() {
  if (pendingShare) applyShare();
  else if (pendingLink) showLock("shared");
  else backupNudge();
}

/* ── Install ── */
function isStandalone() {
  return matchMedia("(display-mode: standalone)").matches
    || navigator.standalone === true
    || document.referrer.includes("android-app://");
}

function getPlatform() {
  const ua = navigator.userAgent || "";
  if (/iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)) return "ios";
  if (/Android/i.test(ua)) return "android";
  return "desktop";
}

function showInstallGuide() {
  const ua = navigator.userAgent || "";
  const p = getPlatform();
  let s;
  if (p === "ios") {
    s = ["Open the <b>Share</b> menu", "Tap <b>Add to Home Screen</b>", "Tap <b>Add</b>"];
  } else if (p === "android") {
    const other = /Firefox|EdgA|OPR|Opera|SamsungBrowser/.test(ua) || navigator.brave;
    s = other
      ? ["This browser can only add a shortcut, not a real app", "Open this page in <b>Chrome</b> and follow the install steps there"]
      : ["Use the page for 30 seconds and tap once", "Tap <b>⋮</b>, then <b>Install and create shortcut</b>", "Tap <b>Install</b>, not <b>Create shortcut</b>", "If <b>Install</b> is greyed out, this phone can't install apps from Chrome (it needs Google Play Services and Play Store access)"];
  } else if (/Firefox/.test(ua)) {
    s = ["Firefox on desktop can't install web apps", "Open this page in <b>Chrome</b> or <b>Edge</b>"];
  } else if (/^((?!chrome|android).)*safari/i.test(ua)) {
    s = ["In Safari, choose <b>File</b>, then <b>Add to Dock</b>"];
  } else {
    s = ["Click the <b>install icon</b> in the address bar", "Or open the browser menu and choose <b>Install ioNote</b>"];
  }
  $("#guideSteps").innerHTML = s.map(x => `<li>${x}</li>`).join("");
  $("#installGuide").classList.add("show");
  $("#settings").inert = true;
  $("#guideClose").focus();
}

function closeGuide() {
  $("#installGuide").classList.remove("show");
  $("#settings").inert = false;
  $("#btnInstall").focus({ preventScroll: true });
}

async function triggerInstall() {
  if (deferredPrompt) {
    try {
      deferredPrompt.prompt();
      await deferredPrompt.userChoice;
    } catch {}
    deferredPrompt = null;
    return;
  }
  showInstallGuide();
}

addEventListener("beforeinstallprompt", e => { e.preventDefault(); deferredPrompt = e; });
addEventListener("appinstalled", () => { deferredPrompt = null; $("#btnInstall").hidden = true; toast("App installed"); });

/* ── Events ── */
$("#add").onclick = () => {
  const n = { id: uid(), t: "", b: "", d: Date.now(), pinned: false };
  notes.unshift(n);
  openNote(n);
  setTimeout(() => $("#t").focus(), 300);
};
$("#btnSearch").onclick = () => { $("#sbar").hidden = false; history.pushState({ v: "q" }, ""); q.focus(); };
q.oninput = render;
q.onkeydown = e => { if (e.key === "Enter") q.blur(); };
$("#qClose").onclick = () => history.back();
const noteFor = el => notes.find(x => x.id === el.dataset.id);
const cancelLp = () => clearTimeout(lpTimer);
list.addEventListener("pointerdown", e => {
  const el = e.target.closest(".note");
  if (!el || e.pointerType === "mouse") return;
  lpX = e.clientX;
  lpY = e.clientY;
  clearTimeout(lpTimer);
  lpTimer = setTimeout(() => {
    const n = noteFor(el);
    if (!n) return;
    lpFired = true;
    if (navigator.vibrate) navigator.vibrate(12);
    openActions(n);
  }, 450);
});
list.addEventListener("pointermove", e => { if (Math.abs(e.clientX - lpX) > 8 || Math.abs(e.clientY - lpY) > 8) cancelLp(); });
["pointerup", "pointercancel", "pointerleave"].forEach(t => list.addEventListener(t, cancelLp));
list.addEventListener("contextmenu", e => {
  const el = e.target.closest(".note");
  if (!el) return;
  e.preventDefault();
  const n = noteFor(el);
  if (n) openActions(n);
});

$("#actPin").onclick = async () => {
  if (Date.now() - menuAt < 350) return;
  const n = menuNote;
  closeActions();
  n.pinned = !n.pinned;
  n.d = Date.now();
  if (cur === n) { pinUI(); stampUI(); }
  await persistNotes();
  render();
};
$("#actDel").onclick = () => {
  if (Date.now() - menuAt < 350) return;
  const n = menuNote;
  closeActions();
  if (cur === n) deleteCurrent(); else removeNote(n);
};
$("#actCancel").onclick = () => closeActions();
$("#actions").onclick = e => { if (e.target === $("#actions") && Date.now() - menuAt >= 350) closeActions(); };

list.onclick = e => {
  if (lpFired) { lpFired = false; return; }
  const el = e.target.closest(".note");
  const n = el && notes.find(x => x.id === el.dataset.id);
  if (n) openNote(n);
};

$("#t").oninput = scheduleSave;
$("#b").oninput = scheduleSave;
$("#t").onkeydown = e => { if (e.key === "Enter") { e.preventDefault(); $("#b").focus(); } };
$("#back").onclick = () => history.back();
$("#btnPin").onclick = togglePin;
$("#btnDel").onclick = deleteCurrent;

$("#btnSettings").onclick = () => { $("#settings").classList.add("open"); history.pushState({ v: "set" }, ""); $("#setBack").focus({ preventScroll: true }); };
$("#setBack").onclick = () => history.back();
$("#btnAbout").onclick = () => { $("#about").classList.add("open"); history.pushState({ v: "about" }, ""); $("#abBack").focus({ preventScroll: true }); };
$("#abBack").onclick = () => history.back();
$("#btnLock").onclick = lockApp;

$("#seg").onclick = e => {
  const b = e.target.closest("button");
  if (!b) return;
  settings.theme = b.dataset.v;
  saveRaw(SETTINGS_KEY, settings);
  applyTheme();
};

$("#togLock").onclick = async () => {
  if (!settings.lockEnabled) { showLock("set"); return; }
  if (!confirm("Turn off encryption? Notes will be stored unencrypted.")) return;
  Object.assign(settings, { lockEnabled: false, salt: null, iter: null, check: null });
  cryptoKey = null;
  saveRaw(SETTINGS_KEY, settings);
  await persistNotes();
  refreshSecurityUI();
  toast("Encryption off");
};
$("#btnChangePass").onclick = () => showLock("change");
$("#selAuto").onchange = e => { settings.autoLock = Number(e.target.value); saveRaw(SETTINGS_KEY, settings); };

$("#lockOk").onclick = submitLock;
$("#lockCancel").onclick = () => { importData = null; shareNote = null; pendingLink = null; hideLock(); };
$("#lock").addEventListener("keydown", e => { if (e.key === "Enter") submitLock(); });

async function exportBackup() {
  const f = await backupFile();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(f);
  a.download = f.name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  settings.lastBackup = Date.now();
  saveRaw(SETTINGS_KEY, settings);
  refreshBackupInfo();
  toast("Backup saved");
}
$("#btnExport").onclick = exportBackup;

$("#btnShare").onclick = async () => {
  const n = cur;
  if (!n || !(n.t.trim() || n.b.trim())) return toast("Write something first");
  if (typeof CompressionStream === "undefined") return toast("This browser can't make share links");
  const size = (await zip(te.encode(JSON.stringify({ t: n.t, b: n.b })))).length;
  if (size > MAX_BODY) return toast("Too long for a link. Use Save backup instead.");
  shareNote = n;
  showLock("share");
};

addEventListener("hashchange", () => {
  if (readUrl() && (!settings.lockEnabled || cryptoKey)) afterLoad();
});

$("#btnImport").onclick = () => { holdLock = Date.now() + 120000; $("#importFile").click(); };
$("#importFile").onchange = e => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const data = JSON.parse(reader.result);
      if (Array.isArray(data)) await mergeNotes(clean(data));
      else if (!Array.isArray(data.items)) throw new Error("invalid");
      else if (!data.enc) await mergeNotes(clean(data.items));
      else if (!data.salt || !data.iter || !data.check) throw new Error("invalid");
      else { importData = data; showLock("import"); }
    } catch { toast("That isn't an ioNote backup. Pick a .json file saved from ioNote."); }
    e.target.value = "";
  };
  reader.readAsText(file);
};

$("#btnInstall").onclick = triggerInstall;
$("#guideClose").onclick = closeGuide;
$("#installGuide").onclick = e => { if (e.target === $("#installGuide")) closeGuide(); };

$("#btnClearAll").onclick = async () => {
  if (!confirm("Delete all notes permanently? This can't be undone.")) return;
  notes = [];
  await persistNotes();
  render();
  history.back();
  toast("All notes deleted");
};

addEventListener("popstate", () => {
  if (popGuard) { popGuard--; return; }
  if (menuNote) { closeActions(true); return; }
  if ($("#installGuide").classList.contains("show")) { closeGuide(); history.pushState({ v: "set" }, ""); return; }
  if ($("#about").classList.contains("open")) { $("#about").classList.remove("open"); $("#btnAbout").focus({ preventScroll: true }); return; }
  if ($("#settings").classList.contains("open")) { $("#settings").classList.remove("open"); $("#btnSettings").focus({ preventScroll: true }); return; }
  if (ed.classList.contains("open")) { closeNote(); return; }
  if (!$("#sbar").hidden) closeSearch();
});

addEventListener("keydown", e => {
  if (e.key === "Escape") {
    if (menuNote) closeActions();
    else if ($("#installGuide").classList.contains("show")) closeGuide();
    else if (document.querySelector(".page.open")) history.back();
    return;
  }
  const tag = document.activeElement && document.activeElement.tagName;
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag) || e.ctrlKey || e.metaKey || e.altKey || $("#lock").classList.contains("show")) return;
  if (e.key === "n") { e.preventDefault(); $("#add").click(); }
  else if (e.key === "/" && !$("#btnSearch").hidden) { e.preventDefault(); $("#btnSearch").click(); }
});

addEventListener("pagehide", flushSave);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) flushSave();
  if (Date.now() < holdLock) return;
  if (document.hidden) {
    hiddenAt = Date.now();
    if (settings.autoLock === 0) lockApp();
    return;
  }
  if (hiddenAt && settings.lockEnabled && cryptoKey && Date.now() - hiddenAt >= settings.autoLock * 60000) lockApp();
  hiddenAt = 0;
});

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});

/* ── Init ── */
(async () => {
  $("#appVersion").textContent = "Version " + VERSION;
  applyTheme();
  refreshSecurityUI();
  refreshBackupInfo();
  $("#btnInstall").hidden = isStandalone();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist();

  if (settings.lockEnabled) {
    showLock(settings.check ? "unlock" : "legacy");
    return;
  }
  notes = (await loadNotes()) || [];
  render();
  afterLoad();
})();
})();
