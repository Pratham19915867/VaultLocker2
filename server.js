import express from "express";
import compression from "compression";
import path from "path";
import { fileURLToPath } from "url";
import { createClient } from "@supabase/supabase-js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(compression());
app.use(express.json({ limit: "2mb" }));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_KEY = process.env.ADMIN_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

function validId(id) {
  return /^[A-Za-z0-9_-]{16,64}$/.test(id);
}

// Basic rate limit (per minute)
const hits = new Map();
setInterval(() => hits.clear(), 60_000);

function limit(req, res, next) {
  const key = req.ip || "unknown";
  const n = (hits.get(key) || 0) + 1;
  hits.set(key, n);
  if (n > 200) return res.status(429).json({ error: "Too many requests" });
  next();
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

// Get vault record
app.get("/api/vault/:id", limit, async (req, res) => {
  const { id } = req.params;
  if (!validId(id)) return res.status(400).json({ error: "Bad id" });

  const { data, error } = await supabase
    .from("vaults")
    .select("record")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    console.error("Supabase GET error:", error);
    return res.status(500).json({ error: "Database error" });
  }
  if (!data) return res.status(404).json({ error: "Not found" });

  res.setHeader("Cache-Control", "no-store");
  res.json(data.record);
});

// Put (create/update) vault record
app.put("/api/vault/:id", limit, async (req, res) => {
  const { id } = req.params;
  if (!validId(id)) return res.status(400).json({ error: "Bad id" });

  const record = req.body;
  if (!record || !record.ct || !record.iv || !record.salt) {
    return res.status(400).json({ error: "Bad record" });
  }

  const updatedAt = Date.now();
  const stored = { ...record, updatedAt };

  const { error } = await supabase
    .from("vaults")
    .upsert({ id, record: stored, updated_at: updatedAt });

  if (error) {
    console.error("Supabase PUT error:", error);
    return res.status(500).json({ error: "Database error" });
  }

  res.json({ ok: true, updatedAt });
});

// Delete vault (used by Change PIN flow)
app.delete("/api/vault/:id", limit, async (req, res) => {
  const { id } = req.params;
  if (!validId(id)) return res.status(400).json({ error: "Bad id" });

  const { error } = await supabase.from("vaults").delete().eq("id", id);

  if (error) {
    console.error("Supabase DELETE error:", error);
    return res.status(500).json({ error: "Database error" });
  }

  res.json({ ok: true });
});

// Admin stats: vault count
app.get("/api/admin/stats", limit, async (req, res) => {
  if (!ADMIN_KEY) return res.status(500).json({ error: "Admin not configured" });

  const auth = req.headers.authorization || "";
  if (auth !== `Bearer ${ADMIN_KEY}`) return res.status(401).json({ error: "Unauthorized" });

  const { count, error } = await supabase
    .from("vaults")
    .select("id", { count: "exact", head: true });

  if (error) {
    console.error("Supabase COUNT error:", error);
    return res.status(500).json({ error: "Database error" });
  }

  res.setHeader("Cache-Control", "no-store");
  res.json({
    vaultCount: count ?? 0,
    serverTime: new Date().toISOString()
  });
});

// Frontend
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("NoteDealer running on port", port));
