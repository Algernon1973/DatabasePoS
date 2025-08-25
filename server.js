import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

// Body grande: invieremo foto in base64
app.use(express.raw({ type: "*/*", limit: process.env.BODY_LIMIT || "25mb" }));

// Preflight CORS
app.options("*", (req, res) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "*",
  });
  res.sendStatus(204);
});

const ALLOW = (process.env.ALLOWLIST_HOSTS ||
  "script.google.com,script.googleusercontent.com"
).split(",").map(s => s.trim());

app.all("/", async (req, res) => {
  try {
    const target = req.query.url;
    if (!target) return res.status(400).send("Missing url");

    const url = new URL(target);
    if (!["http:", "https:"].includes(url.protocol)) {
      return res.status(400).send("Invalid protocol");
    }
    if (!ALLOW.includes(url.hostname)) {
      console.log("Blocked host:", url.hostname, "ALLOW:", ALLOW);
      return res.status(403).send("Target host not allowed");
    }

    // copia header in uscita (no origin/referer/host)
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      const key = k.toLowerCase();
      if (["host","origin","referer","connection","accept-encoding","content-length"].includes(key)) continue;
      if (v) headers.set(key, Array.isArray(v) ? v.join(", ") : v);
    }

    const resp = await fetch(target, {
      method: req.method,
      headers,
      body: (req.method === "GET" || req.method === "HEAD") ? undefined : req.body
    });

    const buf = await resp.arrayBuffer();
    const h = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    };
    const ct = resp.headers.get("content-type"); if (ct) h["Content-Type"] = ct;

    res.status(resp.status).set(h).send(Buffer.from(buf));
  } catch (e) {
    console.error(e);
    res.status(500).send(String(e));
  }
});

app.listen(PORT, () => console.log("CORS proxy up on :" + PORT));
