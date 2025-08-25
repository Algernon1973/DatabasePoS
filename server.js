// Proxy CORS minimal + sicuro (Node 18+)
import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

// Consenti solo questi host di destinazione (evita open-proxy)
const ALLOWLIST = (process.env.ALLOWLIST_HOSTS || "script.google.com").split(",").map(s => s.trim());

// Accetta body “grezzi” di dimensione ampia (puoi aumentare se necessario)
app.use(express.raw({ type: "*/*", limit: process.env.BODY_LIMIT || "15mb" }));

// Preflight CORS
app.options("*", (req, res) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "*",
  });
  return res.sendStatus(204);
});

app.all("/", async (req, res) => {
  try {
    const target = req.query.url;
    if (!target) return res.status(400).send("Missing url");

    const url = new URL(target);
    if (!["http:", "https:"].includes(url.protocol)) {
      return res.status(400).send("Invalid protocol");
    }
    if (!ALLOWLIST.includes(url.hostname)) {
      return res.status(403).send("Target host not allowed");
    }

    // Copia/filtra header in uscita
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (!v) continue;
      const key = k.toLowerCase();
      // rimuovi hop-by-hop/origin
      if (["host","origin","referer","connection","accept-encoding","content-length"].includes(key)) continue;
      headers.set(key, Array.isArray(v) ? v.join(", ") : v);
    }

    const init = {
      method: req.method,
      headers,
      body: (req.method === "GET" || req.method === "HEAD") ? undefined : req.body
    };

    const resp = await fetch(target, init);
    const buf = Buffer.from(await resp.arrayBuffer());

    // Copia content-type se presente
    const outHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    };
    const ct = resp.headers.get("content-type");
    if (ct) outHeaders["Content-Type"] = ct;

    res.status(resp.status).set(outHeaders).send(buf);
  } catch (err) {
    res.status(500).send(String(err));
  }
});

app.listen(PORT, () => console.log(`CORS proxy on :${PORT}`));
