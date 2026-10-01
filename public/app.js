// -------------------------------------------------------------
// NoteDealer — Cloud Sync Vault (app.js)
// Features added:
// - Theme panel + more themes
// - Phone optimized (no soft keyboard for PIN on mobile)
// - Sound effects on PIN type / unlock / error
// - Change PIN (moves vault to new PIN)
// - Admin panel (/admin) shows vault count (needs ADMIN_KEY on server)
// -------------------------------------------------------------

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const LS_THEME = "notedealer:theme";

// Keep 6 digits if you want. (Security tip: 8+ digits is stronger)
const PIN_LEN = 6;
const PBKDF2_ITERS = 250_000;

// Detect mobile-ish pointer to avoid opening soft keyboard
const IS_COARSE_POINTER = window.matchMedia?.("(pointer: coarse)")?.matches ?? false;

const state = {
  pin: "",
  vaultId: null,
  passcode: null,
  vault: { notes: [] },
  activeNoteId: null,
  isAdminPage: false,
};

// ---------------- Base64 Helpers ----------------
function bytesToB64(bytes) {
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64Url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fmtDate(ms) {
  return new Date(ms).toLocaleString();
}
function uid() {
  return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

// ---------------- Sound (Web Audio) ----------------
const sound = {
  ctx: null,
  enabled: true,
  ensure() {
    if (!this.enabled) return null;
    if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    // resume required in some browsers
    if (this.ctx.state === "suspended") this.ctx.resume().catch(()=>{});
    return this.ctx;
  },
  beep(freq = 880, dur = 0.03, type = "sine", gain = 0.04) {
    const ctx = this.ensure();
    if (!ctx) return;
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.type = type;
    o.frequency.value = freq;
    g.gain.value = gain;
    o.connect(g);
    g.connect(ctx.destination);
    o.start();
    o.stop(ctx.currentTime + dur);
  },
  success() {
    // little chime
    this.beep(523.25, 0.06, "triangle", 0.05);
    setTimeout(() => this.beep(659.25, 0.08, "triangle", 0.05), 70);
  },
  error() {
    this.beep(180, 0.10, "square", 0.03);
  }
};

// ---------------- Crypto (Web Crypto API) ----------------
async function deriveKey(passcode, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passcode), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJSON(passcode, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passcode, salt);

  const enc = new TextEncoder();
  const pt = enc.encode(JSON.stringify(obj));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);

  return { salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ctBuf)) };
}

async function decryptJSON(passcode, record) {
  const salt = b64ToBytes(record.salt);
  const iv = b64ToBytes(record.iv);
  const ct = b64ToBytes(record.ct);

  const key = await deriveKey(passcode, salt);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);

  return JSON.parse(new TextDecoder().decode(ptBuf));
}

// PIN -> deterministic vaultId (so any device can open same vault)
async function vaultIdFromPin(pin) {
  const bytes = new TextEncoder().encode("notedealer-seed:" + pin);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return b64Url(digest.slice(0, 18)); // 24-ish chars
}

// ---------------- API Calls ----------------
async function apiGetVault(vaultId) {
  const res = await fetch(`/api/vault/${vaultId}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GET error: ${res.status}`);
  return res.json();
}
async function apiPutVault(vaultId, record) {
  const res = await fetch(`/api/vault/${vaultId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(record),
  });
  if (!res.ok) throw new Error(`PUT error: ${res.status}`);
  return res.json();
}
async function apiDeleteVault(vaultId) {
  const res = await fetch(`/api/vault/${vaultId}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`DELETE error: ${res.status}`);
  return res.json();
}
async function apiAdminStats(adminKey) {
  const res = await fetch(`/api/admin/stats`, {
    headers: { "Authorization": `Bearer ${adminKey}` },
    cache: "no-store"
  });
  if (res.status === 401) throw new Error("Unauthorized");
  if (!res.ok) throw new Error(`Admin stats error: ${res.status}`);
  return res.json();
}

// ---------------- UI Elements ----------------
const viewLock = $("#viewLock");
const viewVault = $("#viewVault");
const viewAdmin = $("#viewAdmin");

const brandHome = $("#brandHome");
const pinArea = $("#pinArea");
const pinInput = $("#pinInput");
const pinBoxes = $("#pinBoxes");
const lockError = $("#lockError");
const btnClear = $("#btnClear");
const btnGo = $("#btnGo");
const btnLock = $("#btnLock");

const vaultTitle = $("#vaultTitle");
const vaultMeta = $("#vaultMeta");
const btnNewNote = $("#btnNewNote");
const btnSwitchLocker = $("#btnSwitchLocker");
const btnChangePin = $("#btnChangePin");

const noteList = $("#noteList");
const search = $("#search");
const noteTitle = $("#noteTitle");
const noteBody = $("#noteBody");
const btnSave = $("#btnSave");
const btnDelete = $("#btnDelete");
const editStatus = $("#editStatus");

// Admin UI
const adminKey = $("#adminKey");
const btnAdminLoad = $("#btnAdminLoad");
const adminStats = $("#adminStats");

// Theme UI
const btnTheme = $("#btnTheme");
const themePanel = $("#themePanel");
const btnThemeClose = $("#btnThemeClose");
const themeList = $("#themeList");

// ---------------- Themes ----------------
const themes = [
  { id: "midnight", name: "Midnight", desc: "Deep neon", a: "#7c5cff", b: "#ff4d9d" },
  { id: "aurora",   name: "Aurora",   desc: "Green glow", a: "#5cffc6", b: "#7c5cff" },
  { id: "ocean",    name: "Ocean",    desc: "Aqua glass", a: "#26d0ce", b: "#7c5cff" },
  { id: "sakura",   name: "Sakura",   desc: "Pink night", a: "#ff4d9d", b: "#7c5cff" },
  { id: "desert",   name: "Desert",   desc: "Warm dusk",  a: "#ffb703", b: "#fb5607" },

  { id: "dark",     name: "Dark",     desc: "Pure dark",     a: "#111111", b: "#ffffff" },
  { id: "mono",     name: "Mono",     desc: "Black & White", a: "#e6e6e6", b: "#9c9c9c" },
  { id: "graphite", name: "Graphite", desc: "Dark tech",     a: "#a1a7ff", b: "#7c5cff" },
  { id: "ice",      name: "Ice",      desc: "Cool frost",    a: "#b8f3ff", b: "#26d0ce" },
  { id: "ember",    name: "Ember",    desc: "Hot glow",      a: "#ff7a18", b: "#fb5607" },
];

function applyTheme(id) {
  document.body.dataset.theme = id;
  localStorage.setItem(LS_THEME, id);
}
function initThemes() {
  applyTheme(localStorage.getItem(LS_THEME) || "midnight");

  if (!themeList || !btnTheme || !themePanel || !btnThemeClose) return;

  themeList.innerHTML = "";
  for (const t of themes) {
    const el = document.createElement("div");
    el.className = "themeCard";
    el.innerHTML = `
      <div class="swatch" style="--a:${t.a}; --b:${t.b}"></div>
      <div class="tname">${t.name}</div>
      <div class="tdesc">${t.desc}</div>
    `;
    el.addEventListener("click", () => applyTheme(t.id));
    themeList.appendChild(el);
  }

  btnTheme.addEventListener("click", (e) => {
    e.stopPropagation();
    themePanel.classList.toggle("hidden");
  });
  btnThemeClose.addEventListener("click", () => themePanel.classList.add("hidden"));
  document.addEventListener("click", (e) => {
    const fab = document.querySelector(".themeFab");
    if (!fab) return;
    if (!fab.contains(e.target)) themePanel.classList.add("hidden");
  });
}

// ---------------- PIN Logic ----------------
function buildPinBoxes() {
  pinBoxes.innerHTML = "";
  for (let i = 0; i < PIN_LEN; i++) {
    const b = document.createElement("div");
    b.className = "pinBox";
    pinBoxes.appendChild(b);
  }
}
function renderPin() {
  const boxes = $$(".pinBox", pinBoxes);
  boxes.forEach((b, i) => b.classList.toggle("filled", i < state.pin.length));
}

function setPin(v) {
  const digits = String(v).replace(/\D/g, "").slice(0, PIN_LEN);
  state.pin = digits;
  if (pinInput) pinInput.value = digits;
  renderPin();

  if (digits.length === PIN_LEN) {
    setTimeout(() => handleGo(), 140);
  }
}
function clearPin() { setPin(""); }
function backspace() { setPin(state.pin.slice(0, -1)); }
function pushDigit(d) {
  if (/^\d$/.test(d) && state.pin.length < PIN_LEN) {
    sound.beep(950, 0.02, "sine", 0.03);
    setPin(state.pin + d);
  }
}

function shake(msg) {
  lockError.textContent = msg;
  lockError.classList.remove("hidden");
  pinBoxes.classList.remove("shake");
  void pinBoxes.offsetWidth;
  pinBoxes.classList.add("shake");
}

function showOnly(view) {
  viewLock.classList.toggle("hidden", view !== "lock");
  viewVault.classList.toggle("hidden", view !== "vault");
  viewAdmin.classList.toggle("hidden", view !== "admin");
}

function showLock() {
  showOnly("lock");
  if (btnLock) btnLock.disabled = true;
  lockError.classList.add("hidden");
  state.vaultId = null;
  state.passcode = null;
  state.vault = { notes: [] };
  state.activeNoteId = null;
  clearPin();
}

function showVault(updatedAt) {
  showOnly("vault");
  if (btnLock) btnLock.disabled = false;
  vaultTitle.textContent = "Vault Locker";
  vaultMeta.textContent = `Cloud sync • Updated: ${fmtDate(updatedAt || Date.now())}`;
  renderNotes();
  selectNote(null);
}

// Disable mobile keyboard for PIN input
function lockMobileKeyboard() {
  if (!pinInput) return;
  if (IS_COARSE_POINTER) {
    pinInput.setAttribute("readonly", "readonly");
    pinInput.setAttribute("inputmode", "none");
    pinInput.tabIndex = -1;
    pinInput.addEventListener("focus", () => pinInput.blur());
  }
}

// ---------------- Notes Logic ----------------
function renderNotes() {
  const q = (search.value || "").trim().toLowerCase();
  const notes = (state.vault?.notes || []).slice().sort((a, b) => b.updatedAt - a.updatedAt);
  const list = q
    ? notes.filter(n => (n.title || "").toLowerCase().includes(q) || (n.body || "").toLowerCase().includes(q))
    : notes;

  noteList.innerHTML = "";
  if (!list.length) {
    const d = document.createElement("div");
    d.className = "muted small";
    d.textContent = q ? "No notes matched." : "No notes yet. Click “New Note”.";
    noteList.appendChild(d);
    return;
  }

  for (const n of list) {
    const item = document.createElement("div");
    item.className = "noteItem" + (n.id === state.activeNoteId ? " active" : "");
    item.innerHTML = `
      <div class="noteTitle">${escapeHtml(n.title || "Untitled")}</div>
      <div class="noteMeta">Updated: ${fmtDate(n.updatedAt)}</div>
    `;
    item.onclick = () => selectNote(n.id);
    noteList.appendChild(item);
  }
}

function selectNote(id) {
  state.activeNoteId = id;
  const n = (state.vault?.notes || []).find(x => x.id === id) || null;
  const has = !!n;

  noteTitle.disabled = !has;
  noteBody.disabled = !has;
  btnSave.disabled = !has;
  btnDelete.disabled = !has;

  if (!has) {
    noteTitle.value = "";
    noteBody.value = "";
    editStatus.textContent = "No note selected";
  } else {
    noteTitle.value = n.title || "";
    noteBody.value = n.body || "";
    editStatus.textContent = `Editing • ${fmtDate(n.updatedAt)}`;
  }

  renderNotes();
}

async function persistVault() {
  const payload = { data: state.vault, updatedAt: Date.now() };
  const enc = await encryptJSON(state.passcode, payload);
  const record = { ...enc, updatedAt: payload.updatedAt };

  await apiPutVault(state.vaultId, record);
  vaultMeta.textContent = `Cloud sync • Updated: ${fmtDate(payload.updatedAt)}`;
}

// ---------------- Unlock / Create ----------------
async function handleGo() {
  lockError.classList.add("hidden");

  if (!crypto?.subtle) {
    sound.error();
    shake("Crypto not available in this browser.");
    return;
  }

  if (state.pin.length !== PIN_LEN) {
    sound.error();
    shake(`Enter full ${PIN_LEN}-digit PIN.`);
    return;
  }

  try {
    const pin = state.pin;
    const vaultId = await vaultIdFromPin(pin);

    const record = await apiGetVault(vaultId);

    state.vaultId = vaultId;
    state.passcode = pin;

    if (!record) {
      // Create new vault for this PIN
      const ok = confirm("No vault exists for this PIN.\nCreate new vault?");
      if (!ok) { clearPin(); return; }

      state.vault = { notes: [] };
      await persistVault();
      clearPin();
      sound.success();
      showVault(Date.now());
      return;
    }

    const payload = await decryptJSON(pin, record);
    state.vault = payload.data || { notes: [] };

    clearPin();
    sound.success();
    showVault(payload.updatedAt || record.updatedAt);
  } catch (e) {
    console.error(e);
    sound.error();
    shake("Wrong PIN or server error.");
    clearPin();
  }
}

// ---------------- Change PIN / Password ----------------
async function changePinFlow() {
  if (!state.vaultId || !state.passcode) return;

  const newPinRaw = prompt(`Enter NEW ${PIN_LEN}-digit PIN:`);
  if (!newPinRaw) return;

  const newPin = String(newPinRaw).replace(/\D/g, "").slice(0, PIN_LEN);
  if (newPin.length !== PIN_LEN) {
    alert(`PIN must be exactly ${PIN_LEN} digits.`);
    return;
  }
  if (newPin === state.passcode) {
    alert("New PIN is same as current PIN.");
    return;
  }

  const ok = confirm(
    "Change PIN will MOVE your vault to the new PIN.\n\nOld PIN vault will be deleted.\nContinue?"
  );
  if (!ok) return;

  try {
    // Encrypt same vault content with new PIN
    const newVaultId = await vaultIdFromPin(newPin);

    // If target exists, ask overwrite
    const existing = await apiGetVault(newVaultId);
    if (existing) {
      const ow = confirm("A vault already exists for NEW PIN.\nOverwrite it?");
      if (!ow) return;
    }

    const payload = { data: state.vault, updatedAt: Date.now() };
    const enc = await encryptJSON(newPin, payload);
    const newRecord = { ...enc, updatedAt: payload.updatedAt };

    // Save to new vault id
    await apiPutVault(newVaultId, newRecord);

    // Delete old vault id
    try {
      await apiDeleteVault(state.vaultId);
    } catch (delErr) {
      console.warn("Old vault delete failed:", delErr);
      // Not fatal. New vault still works.
    }

    // Update state
    state.vaultId = newVaultId;
    state.passcode = newPin;

    alert("PIN changed successfully.");
    vaultMeta.textContent = `Cloud sync • Updated: ${fmtDate(payload.updatedAt)}`;
  } catch (e) {
    console.error(e);
    alert("PIN change failed (server/network). Try again.");
  }
}

// ---------------- Notes actions ----------------
function newNote() {
  const n = { id: uid(), title: "New note", body: "", updatedAt: Date.now() };
  state.vault.notes = [n, ...(state.vault.notes || [])];
  renderNotes();
  selectNote(n.id);
}

async function saveNote() {
  const n = (state.vault?.notes || []).find(x => x.id === state.activeNoteId);
  if (!n) return;

  n.title = noteTitle.value.trim() || "Untitled";
  n.body = noteBody.value || "";
  n.updatedAt = Date.now();

  editStatus.textContent = "Saving...";
  try {
    await persistVault();
    editStatus.textContent = `Saved • ${fmtDate(n.updatedAt)}`;
  } catch (e) {
    console.error(e);
    editStatus.textContent = "Save failed";
    alert("Could not save (network/server).");
  }

  renderNotes();
}

async function deleteNote() {
  const n = (state.vault?.notes || []).find(x => x.id === state.activeNoteId);
  if (!n) return;

  if (!confirm(`Delete "${n.title}"?`)) return;

  state.vault.notes = state.vault.notes.filter(x => x.id !== n.id);
  selectNote(null);
  try {
    await persistVault();
  } catch (e) {
    console.error(e);
    alert("Delete save failed.");
  }
  renderNotes();
}

// ---------------- Admin page ----------------
async function initAdminPage() {
  showOnly("admin");
  if (btnLock) btnLock.disabled = true;

  btnAdminLoad?.addEventListener("click", async () => {
    const key = adminKey.value.trim();
    if (!key) {
      alert("Enter admin key.");
      return;
    }
    adminStats.innerHTML = `<div class="muted small">Loading...</div>`;
    try {
      const data = await apiAdminStats(key);
      adminStats.innerHTML = `
        <div style="font-weight:900; font-size:18px;">Vaults: ${Number(data.vaultCount || 0)}</div>
        <div class="muted small">Server time: ${escapeHtml(data.serverTime || "")}</div>
      `;
    } catch (e) {
      console.error(e);
      adminStats.innerHTML = `<div class="error">Admin auth failed or server error.</div>`;
    }
  });
}

// ---------------- Init ----------------
function init() {
  state.isAdminPage = location.pathname === "/admin";

  initThemes();
  buildPinBoxes();
  lockMobileKeyboard();

  // Brand click to go home
  brandHome?.addEventListener("click", () => { location.href = "/"; });

  // Keypad
  $$(".key").forEach(b => {
    b.addEventListener("click", () => {
      // user interaction => allow audio
      sound.ensure();

      const k = b.dataset.key;
      const act = b.dataset.action;
      if (k != null) pushDigit(k);
      if (act === "back") { sound.beep(420, 0.02, "sine", 0.03); backspace(); }
    });
  });

  btnClear?.addEventListener("click", () => { sound.ensure(); sound.beep(300, 0.03, "sine", 0.03); clearPin(); });
  btnGo?.addEventListener("click", () => { sound.ensure(); handleGo(); });

  btnLock?.addEventListener("click", showLock);
  btnSwitchLocker?.addEventListener("click", showLock);

  // Desktop keyboard support (mobile keyboard disabled)
  document.addEventListener("keydown", (e) => {
    if (viewLock.classList.contains("hidden")) return;

    if (e.key >= "0" && e.key <= "9") {
      sound.ensure();
      pushDigit(e.key);
    } else if (e.key === "Backspace") {
      sound.ensure();
      backspace();
    } else if (e.key === "Enter") {
      sound.ensure();
      handleGo();
    } else if (e.key === "Escape") {
      clearPin();
    }
  });

  // Notes
  btnNewNote?.addEventListener("click", newNote);
  btnSave?.addEventListener("click", saveNote);
  btnDelete?.addEventListener("click", deleteNote);
  btnChangePin?.addEventListener("click", changePinFlow);

  search?.addEventListener("input", renderNotes);
  noteTitle?.addEventListener("input", () => (btnSave.disabled = !state.activeNoteId));
  noteBody?.addEventListener("input", () => (btnSave.disabled = !state.activeNoteId));

  // Admin page
  if (state.isAdminPage) {
    initAdminPage();
    return;
  }

  showLock();
}

init();
