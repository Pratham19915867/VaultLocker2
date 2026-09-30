// NoteDealer - app.js (updated)
// Changes:
// - Create Locker allowed ONLY if no locker exists yet (first-time setup)
// - Better code entry: hidden input supports typing + paste + mobile keypad
// - PIN boxes generated from PIN_LEN (easy to increase digits)

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const LS_INDEX = "notedealer:lockersIndex";
const LS_THEME = "notedealer:theme";
const LOCKER_PREFIX = "notedealer:locker:";

const PIN_LEN = 6;              // Want more digits? change to 8/10 etc.
const PBKDF2_ITERS = 250_000;
const VERSION = 1;

const state = {
  mode: "unlock",               // unlock | create
  pin: "",
  selectedLockerId: null,
  currentLockerId: null,
  currentPasscode: null,
  vault: null,
  activeNoteId: null,
};

const uiPolicy = {
  allowCreate: false,           // computed at runtime: only if no lockers exist
};

const themes = [
  { id: "midnight", name: "Midnight", desc: "Deep neon", a: "#7c5cff", b: "#ff4d9d" },
  { id: "aurora",   name: "Aurora",   desc: "Green glow", a: "#5cffc6", b: "#7c5cff" },
  { id: "ocean",    name: "Ocean",    desc: "Aqua glass", a: "#26d0ce", b: "#7c5cff" },
  { id: "sakura",   name: "Sakura",   desc: "Pink night", a: "#ff4d9d", b: "#7c5cff" },
  { id: "desert",   name: "Desert",   desc: "Warm dusk",  a: "#ffb703", b: "#fb5607" },
];

// -------------------- Base64 helpers --------------------
function bytesToB64(bytes) {
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function fmtDate(ms) {
  const d = new Date(ms);
  return d.toLocaleString();
}
function uid() {
  return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

// -------------------- Crypto --------------------
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
  const plaintext = enc.encode(JSON.stringify(obj));

  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

  return {
    v: VERSION,
    kdf: { name: "PBKDF2", iter: PBKDF2_ITERS, hash: "SHA-256" },
    alg: { name: "AES-GCM" },
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ct: bytesToB64(new Uint8Array(cipherBuf)),
  };
}

async function decryptJSON(passcode, record) {
  const salt = b64ToBytes(record.salt);
  const iv = b64ToBytes(record.iv);
  const ct = b64ToBytes(record.ct);

  const key = await deriveKey(passcode, salt);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);

  const dec = new TextDecoder();
  return JSON.parse(dec.decode(plainBuf));
}

// -------------------- Storage --------------------
function loadIndex() {
  try { return JSON.parse(localStorage.getItem(LS_INDEX) || "[]"); }
  catch { return []; }
}
function saveIndex(arr) {
  localStorage.setItem(LS_INDEX, JSON.stringify(arr));
}
function getLockerRecord(id) {
  const raw = localStorage.getItem(LOCKER_PREFIX + id);
  return raw ? JSON.parse(raw) : null;
}
function setLockerRecord(id, record) {
  localStorage.setItem(LOCKER_PREFIX + id, JSON.stringify(record));
}

// -------------------- UI elements --------------------
const viewLock = $("#viewLock");
const viewVault = $("#viewVault");

const tabUnlock = $("#tabUnlock");
const tabCreate = $("#tabCreate");
const createFields = $("#createFields");
const lockerName = $("#lockerName");

const pinArea = $("#pinArea");
const pinInput = $("#pinInput");
const pinBoxes = $("#pinBoxes");
const pinHint = $("#pinHint");
const lockError = $("#lockError");

const btnClear = $("#btnClear");
const btnGo = $("#btnGo");
const lockerList = $("#lockerList");

const btnLock = $("#btnLock");
const btnExport = $("#btnExport");
const fileImport = $("#fileImport");

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

// Theme UI
const btnTheme = $("#btnTheme");
const themePanel = $("#themePanel");
const btnThemeClose = $("#btnThemeClose");
const themeList = $("#themeList");

// -------------------- Theme --------------------
function applyTheme(id) {
  document.body.dataset.theme = id;
  localStorage.setItem(LS_THEME, id);
}
function initThemes() {
  const saved = localStorage.getItem(LS_THEME) || "midnight";
  applyTheme(saved);

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

  btnTheme.addEventListener("click", () => themePanel.classList.toggle("hidden"));
  btnThemeClose.addEventListener("click", () => themePanel.classList.add("hidden"));
  document.addEventListener("click", (e) => {
    if (themePanel.classList.contains("hidden")) return;
    const fab = $(".themeFab");
    if (!fab.contains(e.target)) themePanel.classList.add("hidden");
  });
}

// -------------------- Lock screen --------------------
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
function setPin(next) {
  const digits = String(next).replace(/\D/g, "").slice(0, PIN_LEN);
  state.pin = digits;
  pinInput.value = digits;       // keep synced
  renderPin();

  if (digits.length === PIN_LEN) {
    setTimeout(() => handleGo(), 120);
  }
}
function clearPin() { setPin(""); }
function backspace() { setPin(state.pin.slice(0, -1)); }
function pushDigit(d) {
  if (!/^\d$/.test(d)) return;
  if (state.pin.length >= PIN_LEN) return;
  setPin(state.pin + d);
}

function shakePin(message) {
  lockError.textContent = message;
  lockError.classList.remove("hidden");
  pinBoxes.classList.remove("shake");
  void pinBoxes.offsetWidth;
  pinBoxes.classList.add("shake");
}

function computePolicy() {
  const idx = loadIndex();
  uiPolicy.allowCreate = idx.length === 0;         // ONLY first time
  tabCreate.classList.toggle("hidden", !uiPolicy.allowCreate);

  // If create is not allowed, force unlock mode
  if (!uiPolicy.allowCreate && state.mode === "create") setMode("unlock");
}

function setMode(mode) {
  state.mode = mode;

  tabUnlock.classList.toggle("active", mode === "unlock");
  tabCreate.classList.toggle("active", mode === "create");

  createFields.classList.toggle("hidden", mode !== "create");
  lockError.classList.add("hidden");

  pinHint.textContent =
    mode === "create"
      ? `First-time setup: choose a ${PIN_LEN}-digit code`
      : "Type code, paste, or use keypad";

  clearPin();
  focusPin();
}

function focusPin() {
  // focus hidden input so typing/paste works
  pinInput.focus({ preventScroll: true });
}

// Locker list
function renderLockerList() {
  const idx = loadIndex().sort((a,b) => b.createdAt - a.createdAt);
  lockerList.innerHTML = "";

  if (!idx.length) {
    const empty = document.createElement("div");
    empty.className = "muted small";
    empty.textContent = "No locker yet. Create your first locker (setup).";
    lockerList.appendChild(empty);
    return;
  }

  // Auto select first if none selected
  if (!state.selectedLockerId) state.selectedLockerId = idx[0].id;

  for (const item of idx) {
    const row = document.createElement("div");
    row.className = "lockerItem";

    const left = document.createElement("div");
    left.innerHTML = `
      <div class="name">${escapeHtml(item.name)}</div>
      <div class="meta">Created: ${fmtDate(item.createdAt)}</div>
    `;

    const right = document.createElement("div");
    right.className = "right";

    const pick = document.createElement("button");
    pick.className = "btn tiny ghost";
    pick.textContent = (state.selectedLockerId === item.id) ? "Selected" : "Select";
    pick.addEventListener("click", () => {
      state.selectedLockerId = item.id;
      renderLockerList();
      focusPin();
    });

    right.appendChild(pick);

    row.appendChild(left);
    row.appendChild(right);
    lockerList.appendChild(row);
  }
}

function selectedLockerIdOrFirst() {
  const idx = loadIndex();
  if (!idx.length) return null;
  return state.selectedLockerId ?? idx[0].id;
}

// Views
function showLockView() {
  viewVault.classList.add("hidden");
  viewLock.classList.remove("hidden");

  btnLock.disabled = true;
  btnExport.disabled = true;

  state.currentLockerId = null;
  state.currentPasscode = null;
  state.vault = null;
  state.activeNoteId = null;

  noteTitle.value = "";
  noteBody.value = "";
  noteTitle.disabled = true;
  noteBody.disabled = true;
  btnSave.disabled = true;
  btnDelete.disabled = true;
  editStatus.textContent = "No note selected";

  computePolicy();
  renderLockerList();
  if (uiPolicy.allowCreate) setMode("create"); else setMode("unlock");
}

// -------------------- Vault --------------------
function showVaultView(lockerName, updatedAt) {
  viewLock.classList.add("hidden");
  viewVault.classList.remove("hidden");

  btnLock.disabled = false;
  btnExport.disabled = false;

  vaultTitle.textContent = lockerName || "Locker";
  vaultMeta.textContent = `Encrypted • Updated: ${fmtDate(updatedAt || Date.now())}`;

  renderNotes();
  selectNote(null);
}

function renderNotes() {
  const q = (search.value || "").trim().toLowerCase();
  const notes = (state.vault?.notes || []).slice().sort((a,b) => b.updatedAt - a.updatedAt);

  const filtered = q
    ? notes.filter(n =>
        (n.title || "").toLowerCase().includes(q) ||
        (n.body || "").toLowerCase().includes(q)
      )
    : notes;

  noteList.innerHTML = "";
  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.className = "muted small";
    empty.textContent = q ? "No matches." : "No notes yet. Click “New Note”.";
    noteList.appendChild(empty);
    return;
  }

  for (const n of filtered) {
    const item = document.createElement("div");
    item.className = "noteItem" + (n.id === state.activeNoteId ? " active" : "");
    item.innerHTML = `
      <div class="noteTitle">${escapeHtml(n.title || "Untitled")}</div>
      <div class="noteMeta">Updated: ${fmtDate(n.updatedAt)}</div>
    `;
    item.addEventListener("click", () => selectNote(n.id));
    noteList.appendChild(item);
  }
}

function selectNote(noteId) {
  state.activeNoteId = noteId;
  const n = (state.vault?.notes || []).find(x => x.id === noteId) || null;

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
  const idx = loadIndex();
  const meta = idx.find(x => x.id === state.currentLockerId);
  if (!meta) throw new Error("Locker index missing.");

  const payload = {
    lockerId: meta.id,
    lockerName: meta.name,
    createdAt: meta.createdAt,
    updatedAt: Date.now(),
    data: state.vault,
  };

  const encrypted = await encryptJSON(state.currentPasscode, payload);
  const record = { ...encrypted, id: meta.id, name: meta.name, createdAt: meta.createdAt, updatedAt: payload.updatedAt };
  setLockerRecord(meta.id, record);

  // Update updatedAt in index
  saveIndex(idx.map(x => x.id === meta.id ? ({...x, updatedAt: payload.updatedAt}) : x));

  vaultMeta.textContent = `Encrypted • Updated: ${fmtDate(payload.updatedAt)}`;
}

// -------------------- Unlock / Create --------------------
async function unlockLocker(lockerId, passcode) {
  const record = getLockerRecord(lockerId);
  if (!record) throw new Error("Locker record missing.");

  const payload = await decryptJSON(passcode, record);
  if (!payload?.data || !payload?.lockerId) throw new Error("Bad payload");

  state.currentLockerId = lockerId;
  state.currentPasscode = passcode;
  state.vault = payload.data;

  clearPin();
  showVaultView(payload.lockerName, payload.updatedAt || record.updatedAt);
}

async function createFirstLocker(passcode) {
  const name = (lockerName.value || "").trim();
  if (!name) {
    shakePin("Please enter a locker name.");
    lockerName.focus();
    return;
  }

  const idx = loadIndex();
  if (idx.length > 0) {
    shakePin("Create is disabled. A locker already exists.");
    return;
  }

  const id = uid();
  const createdAt = Date.now();

  const payload = {
    lockerId: id,
    lockerName: name,
    createdAt,
    updatedAt: createdAt,
    data: { notes: [] },
  };

  const encrypted = await encryptJSON(passcode, payload);
  const record = { ...encrypted, id, name, createdAt, updatedAt: createdAt };
  setLockerRecord(id, record);

  idx.push({ id, name, createdAt, updatedAt: createdAt });
  saveIndex(idx);

  state.selectedLockerId = id;
  lockerName.value = "";

  computePolicy();
  renderLockerList();

  // Auto unlock after create
  await unlockLocker(id, passcode);
}

async function handleGo() {
  lockError.classList.add("hidden");

  if (!crypto?.subtle) {
    shakePin("Web Crypto is not available. Run this site on https or localhost (Live Server).");
    return;
  }

  if (state.pin.length !== PIN_LEN) {
    shakePin(`Enter a ${PIN_LEN}-digit code.`);
    return;
  }

  try {
    if (state.mode === "create") {
      if (!uiPolicy.allowCreate) {
        shakePin("You don’t have permission to create more lockers.");
        return;
      }
      const pass = state.pin;
      await createFirstLocker(pass);
      return;
    }

    const lockerId = selectedLockerIdOrFirst();
    if (!lockerId) {
      shakePin("No locker found. First-time setup: create one locker.");
      computePolicy();
      if (uiPolicy.allowCreate) setMode("create");
      return;
    }

    await unlockLocker(lockerId, state.pin);
  } catch (e) {
    console.error(e);
    shakePin("Wrong code or corrupted locker data.");
    clearPin();
  }
}

// -------------------- Export / Import --------------------
function downloadJSON(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function currentLockerMeta() {
  const idx = loadIndex();
  return idx.find(x => x.id === state.currentLockerId) || null;
}

function doExport() {
  const meta = currentLockerMeta();
  if (!meta) return;
  const record = getLockerRecord(meta.id);
  if (!record) return;
  const filename = `NoteDealer_${meta.name.replace(/\s+/g, "_")}_${meta.id}.json`;
  downloadJSON(filename, record);
}

async function doImport(file) {
  const text = await file.text();
  let record;
  try { record = JSON.parse(text); }
  catch { alert("Invalid JSON file."); return; }

  if (!record?.ct || !record?.iv || !record?.salt) {
    alert("This file does not look like a NoteDealer locker export.");
    return;
  }

  // In this “no-permission-to-create-more” logic:
  // If a locker already exists, import should REPLACE it (not create another one).
  const idx = loadIndex();
  if (idx.length > 0) {
    const ok = confirm("A locker already exists on this device.\n\nDo you want to REPLACE it with this imported locker?");
    if (!ok) return;

    // Replace the first locker record
    const target = idx[0];
    const name = prompt("Locker name:", target.name) || target.name;

    const stored = { ...record, id: target.id, name, createdAt: target.createdAt, updatedAt: Date.now() };
    setLockerRecord(target.id, stored);
    saveIndex([{ ...target, name, updatedAt: stored.updatedAt }]);

    state.selectedLockerId = target.id;
    renderLockerList();
    alert("Imported (replaced). Now unlock using the same code.");
    return;
  }

  // If no locker exists, import acts like setup
  const name = prompt("Name for this locker:", record.name || "Imported Locker");
  if (!name) return;

  const id = uid();
  const createdAt = Date.now();
  const stored = { ...record, id, name, createdAt, updatedAt: Date.now() };
  setLockerRecord(id, stored);
  saveIndex([{ id, name, createdAt, updatedAt: stored.updatedAt }]);

  state.selectedLockerId = id;
  computePolicy();
  renderLockerList();
  alert("Imported. Unlock using the same code used to encrypt it.");
}

// -------------------- Vault actions --------------------
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

  editStatus.textContent = `Saving...`;
  btnSave.disabled = true;

  try {
    await persistVault();
    editStatus.textContent = `Saved • ${fmtDate(n.updatedAt)}`;
  } catch (e) {
    console.error(e);
    editStatus.textContent = `Save failed`;
    alert("Save failed. Check console.");
  } finally {
    btnSave.disabled = false;
    renderNotes();
  }
}

async function deleteNote() {
  const n = (state.vault?.notes || []).find(x => x.id === state.activeNoteId);
  if (!n) return;
  const ok = confirm(`Delete "${n.title}"?`);
  if (!ok) return;

  state.vault.notes = state.vault.notes.filter(x => x.id !== n.id);
  selectNote(null);

  try { await persistVault(); }
  catch (e) { console.error(e); alert("Delete save failed."); }

  renderNotes();
}

function switchLocker() {
  showLockView();
}

// -------------------- Events --------------------
function initEvents() {
  tabUnlock.addEventListener("click", () => setMode("unlock"));
  tabCreate.addEventListener("click", () => {
    if (!uiPolicy.allowCreate) {
      shakePin("You don’t have permission to create more lockers.");
      return;
    }
    setMode("create");
  });

  btnClear.addEventListener("click", () => { clearPin(); focusPin(); });
  btnGo.addEventListener("click", handleGo);

  // Focus typing when user clicks the boxes area
  pinArea.addEventListener("click", () => focusPin());
  pinBoxes.addEventListener("click", () => focusPin());

  // Typing + paste support
  pinInput.addEventListener("input", () => setPin(pinInput.value));
  pinInput.addEventListener("paste", (e) => {
    const text = (e.clipboardData?.getData("text") || "").replace(/\D/g, "");
    if (!text) return;
    e.preventDefault();
    setPin(text);
  });

  // keypad buttons
  $$(".key").forEach(btn => {
    btn.addEventListener("click", () => {
      const k = btn.dataset.key;
      const act = btn.dataset.action;
      if (k != null) pushDigit(k);
      if (act === "back") backspace();
      focusPin();
    });
  });

  // keyboard backspace/enter for desktop (when hidden input is focused)
  document.addEventListener("keydown", (e) => {
    if (viewLock.classList.contains("hidden")) return;
    if (e.key === "Enter") handleGo();
    if (e.key === "Escape") clearPin();
  });

  btnLock.addEventListener("click", () => showLockView());
  btnSwitchLocker.addEventListener("click", switchLocker);

  btnNewNote.addEventListener("click", newNote);
  btnSave.addEventListener("click", saveNote);
  btnDelete.addEventListener("click", deleteNote);

  search.addEventListener("input", renderNotes);

  noteTitle.addEventListener("input", () => btnSave.disabled = !state.activeNoteId);
  noteBody.addEventListener("input", () => btnSave.disabled = !state.activeNoteId);

  btnExport.addEventListener("click", doExport);

  fileImport.addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    await doImport(file);
    computePolicy();
  });
}

// -------------------- Init --------------------
function init() {
  initThemes();
  buildPinBoxes();
  initEvents();
  showLockView();
  focusPin();
}
init();