// -------------------------------------------------------------
// NoteDealer — Cloud Sync Vault (app.js)
// Client-side AES-GCM + PBKDF2 with Cloud Storage
// -------------------------------------------------------------

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const LS_THEME = "notedealer:theme";

// PIN Length (6 digit by default)
const PIN_LEN = 6;
const PBKDF2_ITERS = 250_000;

const state = {
  pin: "",
  vaultId: null,
  passcode: null,
  vault: { notes: [] },
  activeNoteId: null,
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
  return bytesToB64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fmtDate(ms) {
  return new Date(ms).toLocaleString();
}

function uid() {
  return (
    crypto.randomUUID?.() ??
    `${Date.now()}-${Math.random().toString(16).slice(2)}`
  );
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

// ---------------- Crypto (Web Crypto API) ----------------
async function deriveKey(passcode, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passcode),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERS,
      hash: "SHA-256",
    },
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

  return {
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ct: bytesToB64(new Uint8Array(ctBuf)),
  };
}

async function decryptJSON(passcode, record) {
  const salt = b64ToBytes(record.salt);
  const iv = b64ToBytes(record.iv);
  const ct = b64ToBytes(record.ct);

  const key = await deriveKey(passcode, salt);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);

  return JSON.parse(new TextDecoder().decode(ptBuf));
}

// PIN se deterministic ID banti hai taaki har device same vault pe connect ho
async function vaultIdFromPin(pin) {
  const bytes = new TextEncoder().encode("notedealer-seed:" + pin);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return b64Url(digest.slice(0, 18));
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

// ---------------- UI Elements ----------------
const viewLock = $("#viewLock");
const viewVault = $("#viewVault");

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

const noteList = $("#noteList");
const search = $("#search");
const noteTitle = $("#noteTitle");
const noteBody = $("#noteBody");
const btnSave = $("#btnSave");
const btnDelete = $("#btnDelete");
const editStatus = $("#editStatus");

// Theme
const btnTheme = $("#btnTheme");
const themePanel = $("#themePanel");
const btnThemeClose = $("#btnThemeClose");
const themeList = $("#themeList");

const themes = [
  { id: "midnight", name: "Midnight", desc: "Deep neon", a: "#7c5cff", b: "#ff4d9d" },
  { id: "aurora", name: "Aurora", desc: "Green glow", a: "#5cffc6", b: "#7c5cff" },
  { id: "ocean", name: "Ocean", desc: "Aqua glass", a: "#26d0ce", b: "#7c5cff" },
  { id: "sakura", name: "Sakura", desc: "Pink night", a: "#ff4d9d", b: "#7c5cff" },
  { id: "desert", name: "Desert", desc: "Warm dusk", a: "#ffb703", b: "#fb5607" },
];

function applyTheme(id) {
  document.body.dataset.theme = id;
  localStorage.setItem(LS_THEME, id);
}

function initThemes() {
  applyTheme(localStorage.getItem(LS_THEME) || "midnight");
  if (!themeList) return;

  themeList.innerHTML = "";
  for (const t of themes) {
    const el = document.createElement("div");
    el.className = "themeCard";
    el.innerHTML = `
      <div class="swatch" style="--a:${t.a}; --b:${t.b}"></div>
      <div class="tname">${t.name}</div>
      <div class="tdesc">${t.desc}</div>
    `;
    el.onclick = () => applyTheme(t.id);
    themeList.appendChild(el);
  }

  if (btnTheme) btnTheme.onclick = () => themePanel.classList.toggle("hidden");
  if (btnThemeClose) btnThemeClose.onclick = () => themePanel.classList.add("hidden");
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

  // Auto trigger when PIN is full
  if (digits.length === PIN_LEN) {
    setTimeout(() => handleGo(), 150);
  }
}

function clearPin() {
  setPin("");
}

function backspace() {
  setPin(state.pin.slice(0, -1));
}

function pushDigit(d) {
  if (/^\d$/.test(d) && state.pin.length < PIN_LEN) {
    setPin(state.pin + d);
  }
}

function focusPin() {
  if (pinInput) pinInput.focus({ preventScroll: true });
}

function shake(msg) {
  lockError.textContent = msg;
  lockError.classList.remove("hidden");
  pinBoxes.classList.remove("shake");
  void pinBoxes.offsetWidth; // restart animation
  pinBoxes.classList.add("shake");
}

function showLock() {
  viewVault.classList.add("hidden");
  viewLock.classList.remove("hidden");
  if (btnLock) btnLock.disabled = true;
  lockError.classList.add("hidden");
  state.vaultId = null;
  state.passcode = null;
  state.vault = { notes: [] };
  state.activeNoteId = null;
  clearPin();
  focusPin();
}

function showVault(updatedAt) {
  viewLock.classList.add("hidden");
  viewVault.classList.remove("hidden");
  if (btnLock) btnLock.disabled = false;
  vaultTitle.textContent = "Vault Locker";
  vaultMeta.textContent = `Cloud sync • Updated: ${fmtDate(updatedAt || Date.now())}`;
  renderNotes();
  selectNote(null);
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
    shake("Crypto is not available in this browser context.");
    return;
  }

  if (state.pin.length !== PIN_LEN) {
    shake(`Please enter full ${PIN_LEN}-digit PIN.`);
    return;
  }

  try {
    const pin = state.pin;
    const vaultId = await vaultIdFromPin(pin);

    // Server se record fetch karo
    const record = await apiGetVault(vaultId);

    state.vaultId = vaultId;
    state.passcode = pin;

    // Agar server pe vault nahi mila => naya banayenge
    if (!record) {
      const ok = confirm("No vault exists for this PIN yet.\nDo you want to create a new vault?");
      if (!ok) {
        clearPin();
        return;
      }

      state.vault = { notes: [] };
      await persistVault();
      clearPin();
      showVault(Date.now());
      return;
    }

    // Vault mil gaya => decrypt karo
    const payload = await decryptJSON(pin, record);
    state.vault = payload.data || { notes: [] };

    clearPin();
    showVault(payload.updatedAt || record.updatedAt);
  } catch (e) {
    console.error(e);
    shake("Wrong PIN or server connection error.");
    clearPin();
  }
}

function newNote() {
  const n = {
    id: uid(),
    title: "New note",
    body: "",
    updatedAt: Date.now(),
  };
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
  } catch {
    editStatus.textContent = "Save failed";
    alert("Could not save to cloud. Check internet connection.");
  }
  renderNotes();
}

async function deleteNote() {
  const n = (state.vault?.notes || []).find(x => x.id === state.activeNoteId);
  if (!n) return;
  if (!confirm(`Delete "${n.title}"?`)) return;

  state.vault.notes = state.vault.notes.filter(x => x.id !== n.id);
  selectNote(null);
  await persistVault();
  renderNotes();
}

// ---------------- Init Events ----------------
function init() {
  initThemes();
  buildPinBoxes();

  if (btnClear) btnClear.onclick = () => { clearPin(); focusPin(); };
  if (btnGo) btnGo.onclick = handleGo;
  if (btnLock) btnLock.onclick = showLock;
  if (btnSwitchLocker) btnSwitchLocker.onclick = showLock;

  if (pinArea) pinArea.onclick = focusPin;
  if (pinBoxes) pinBoxes.onclick = focusPin;

  if (pinInput) {
    pinInput.addEventListener("input", () => setPin(pinInput.value));
    pinInput.addEventListener("paste", e => {
      const t = (e.clipboardData?.getData("text") || "").replace(/\D/g, "");
      if (!t) return;
      e.preventDefault();
      setPin(t);
    });
  }

  $$(".key").forEach(b => {
    b.onclick = () => {
      const k = b.dataset.key;
      const act = b.dataset.action;
      if (k != null) pushDigit(k);
      if (act === "back") backspace();
      focusPin();
    };
  });

  document.addEventListener("keydown", e => {
    if (viewLock.classList.contains("hidden")) return;
    if (e.key === "Enter") handleGo();
    if (e.key === "Escape") clearPin();
  });

  if (btnNewNote) btnNewNote.onclick = newNote;
  if (btnSave) btnSave.onclick = saveNote;
  if (btnDelete) btnDelete.onclick = deleteNote;

  if (search) search.oninput = renderNotes;
  if (noteTitle) noteTitle.oninput = () => (btnSave.disabled = !state.activeNoteId);
  if (noteBody) noteBody.oninput = () => (btnSave.disabled = !state.activeNoteId);

  showLock();
}

init();
