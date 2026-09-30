import express from "express";
import compression from "compression";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(compression());
app.use(express.json({ limit: "2mb" }));

// Local me ./data, Render me persistent disk ke liye /var/data set karo
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "notedealer.db");

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    record TEXT NOT NULL,
    updatedAt INTEGER NOT NULL
  );
`);

function validId(id) {
  return /^[A-Za-z0-9_-]{16,64}$/.test(id);
}

// (optional) small rate limit to slow brute force
const hits = new Map();
setInterval(() => hits.clear(), 60_000);
function limit(req, res, next) {
  const key = req.ip;
  const n = (hits.get(key) || 0) + 1;
  hits.set(key, n);
  if (n > 120) return res.status(429).json({ error: "Too many requests" });
  next();
}

app.get("/api/vault/:id", limit, (req, res) => {
  const { id } = req.params;
  if (!validId(id)) return res.status(400).json({ error: "Bad id" });

  const row = db.prepare("SELECT record FROM vaults WHERE id=?").get(id);
  if (!row) return res.status(404).json({ error: "Not found" });

  res.setHeader("Cache-Control", "no-store");
  res.json(JSON.parse(row.record));
});

app.put("/api/vault/:id", limit, (req, res) => {
  const { id } = req.params;
  if (!validId(id)) return res.status(400).json({ error: "Bad id" });

  const record = req.body;
  if (!record || !record.ct || !record.iv || !record.salt) {
    return res.status(400).json({ error: "Bad record" });
  }

  const updatedAt = Date.now();
  const stored = { ...record, updatedAt };

  db.prepare(`
    INSERT INTO vaults (id, record, updatedAt)
    VALUES (?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET record=excluded.record, updatedAt=excluded.updatedAt
  `).run(id, JSON.stringify(stored), updatedAt);

  res.json({ ok: true, updatedAt });
});

// Serve frontend from /public
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Running on", port));
