// Sample file store: content-addressed by sha256, so a file is uploaded once per session no
// matter how many projects or channel states reference it. Plain HTTP next to the WebSocket:
//   POST /blobs/missing   body: sha256 hex per line  -> the ones not stored, one per line
//   HEAD /blob/<sha256>   200 + content-length | 404
//   GET  /blob/<sha256>   the file
//   PUT  /blob/<sha256>   store (streamed to disk; rejected if the content doesn't hash to <sha256>)
// Auth: header x-flim-key = the session's blob key (sent in `welcome`). Every session has its own
// folder under FLIM_BLOB_DIR (default: <tmp>/flim-blobs), deleted when the session ends: a
// session can neither see, fetch nor evict another session's files. Per session the oldest files
// are evicted above FLIM_BLOB_SESSION_MAX bytes; uploads are refused (507) while all sessions
// together hold FLIM_BLOB_STORE_MAX. On Fly that disk resets when the machine stops: fine,
// clients re-upload what is missing.
import crypto from "crypto";
import fs from "fs";
import http from "http";
import os from "os";
import path from "path";
import { addEgress, egressRefusal } from "./egress";

const ROOT = process.env.FLIM_BLOB_DIR ?? path.join(os.tmpdir(), "flim-blobs");
const FILE_MAX = Number(process.env.FLIM_BLOB_FILE_MAX ?? 2000 * 1024 * 1024);
const SESSION_MAX = Number(process.env.FLIM_BLOB_SESSION_MAX ?? 2500 * 1024 * 1024);
const STORE_MAX = Number(process.env.FLIM_BLOB_STORE_MAX ?? 5 * 1024 * 1024 * 1024);
const HEX = /^[0-9a-f]{64}$/;

// Nothing survives a restart: sessions don't either.
fs.rmSync(ROOT, { recursive: true, force: true });
fs.mkdirSync(ROOT, { recursive: true });

// The session's folder. Named by a hash of its key, so it can't be guessed from anything sent.
export function blobDir(blobKey: string): string {
  return path.join(ROOT, crypto.createHash("sha256").update(blobKey).digest("hex").slice(0, 32));
}

// Session ended: its files go with it.
export function dropBlobs(blobKey: string): void {
  fs.rm(blobDir(blobKey), { recursive: true, force: true }, () => {});
}

function dirSize(dir: string): number {
  let total = 0;
  try {
    for (const name of fs.readdirSync(dir)) {
      try {
        total += fs.statSync(path.join(dir, name)).size;
      } catch {
        /* raced with a delete */
      }
    }
  } catch {
    /* no folder yet */
  }
  return total;
}

function storeSize(): number {
  let total = 0;
  for (const d of fs.readdirSync(ROOT)) total += dirSize(path.join(ROOT, d));
  return total;
}

// Keep one session's folder under SESSION_MAX: drop its least recently used files.
function evict(DIR: string): void {
  let entries: { p: string; size: number; t: number }[] = [];
  for (const name of fs.readdirSync(DIR)) {
    if (!HEX.test(name)) continue;
    try {
      const st = fs.statSync(path.join(DIR, name));
      entries.push({ p: path.join(DIR, name), size: st.size, t: st.atimeMs });
    } catch {
      /* raced with a delete */
    }
  }
  let total = entries.reduce((a, e) => a + e.size, 0);
  if (total <= SESSION_MAX) return;
  entries = entries.sort((a, b) => a.t - b.t);
  for (const e of entries) {
    if (total <= SESSION_MAX) break;
    try {
      fs.unlinkSync(e.p);
      total -= e.size;
      console.log(`[blob] evicted ${path.basename(e.p).slice(0, 12)} (${e.size} B)`);
    } catch {
      /* ignore */
    }
  }
}

function readBody(req: http.IncomingMessage, max: number): Promise<string | null> {
  return new Promise((resolve) => {
    let n = 0;
    const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > max) {
        resolve(null);
        req.destroy();
      } else parts.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
    req.on("error", () => resolve(null));
  });
}

// Returns true if the request was a blob request (handled). `sessionKeyOk` says whether the
// x-flim-key belongs to a running session.
export function handleBlob(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  sessionKeyOk: (key: string) => boolean,
  ip: string,
): boolean {
  const url = (req.url ?? "").split("?")[0];
  const m = /^\/blob\/([0-9a-f]{64})$/.exec(url);
  const isMissing = url === "/blobs/missing";
  if (!m && !isMissing) return false;
  const key = String(req.headers["x-flim-key"] ?? "");
  if (!HEX.test(key) || !sessionKeyOk(key)) {
    res.writeHead(401);
    res.end();
    req.resume();
    return true;
  }
  const DIR = blobDir(key);
  const file = (hex: string) => path.join(DIR, hex);
  const exists = (hex: string): fs.Stats | null => {
    try {
      return fs.statSync(file(hex));
    } catch {
      return null;
    }
  };

  if (isMissing) {
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end();
      return true;
    }
    readBody(req, 1024 * 1024).then((body) => {
      if (body === null) {
        res.writeHead(413);
        res.end();
        return;
      }
      const missing = body
        .split(/\s+/)
        .filter((h) => HEX.test(h) && !exists(h));
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(missing.join("\n"));
    });
    return true;
  }

  const hex = m![1];
  if (req.method === "HEAD" || req.method === "GET") {
    const st = exists(hex);
    if (!st) {
      res.writeHead(404);
      res.end();
      return true;
    }
    if (req.method === "GET") {
      const why = egressRefusal(ip); // data budget (egress.ts)
      if (why) {
        console.log(`[blob] download refused (${ip}): ${why}`);
        res.writeHead(429, { "content-type": "text/plain" });
        res.end(why);
        return true;
      }
      addEgress(ip, st.size);
    }
    res.writeHead(200, { "content-type": "application/octet-stream", "content-length": st.size });
    if (req.method === "HEAD") {
      res.end();
      return true;
    }
    const now = new Date();
    fs.utimes(file(hex), now, st.mtime, () => {}); // LRU: recently fetched files stay
    fs.createReadStream(file(hex)).pipe(res);
    return true;
  }

  if (req.method === "PUT") {
    const len = Number(req.headers["content-length"] ?? -1);
    if (!(len >= 0) || len > FILE_MAX) {
      res.writeHead(413);
      res.end();
      req.resume();
      return true;
    }
    if (exists(hex)) {
      res.writeHead(200);
      res.end();
      req.resume();
      return true;
    }
    if (storeSize() + len > STORE_MAX) {
      console.log(`[blob] store full: refused ${hex.slice(0, 12)} (${len} B)`);
      res.writeHead(507);
      res.end();
      req.resume();
      return true;
    }
    fs.mkdirSync(DIR, { recursive: true });
    const tmp = path.join(DIR, `.${hex}.${process.pid}.${Math.random().toString(36).slice(2)}`);
    const out = fs.createWriteStream(tmp);
    const hash = crypto.createHash("sha256");
    let got = 0;
    let failed = false;
    const fail = (code: number) => {
      if (failed) return;
      failed = true;
      out.destroy();
      fs.unlink(tmp, () => {});
      if (!res.headersSent) {
        res.writeHead(code);
        res.end();
      }
    };
    req.on("data", (c: Buffer) => {
      got += c.length;
      if (got > len) return fail(400);
      hash.update(c);
    });
    req.on("error", () => fail(400));
    req.pipe(out);
    out.on("error", () => fail(500));
    out.on("finish", () => {
      if (failed) return;
      if (got !== len || hash.digest("hex") !== hex) {
        console.log(`[blob] rejected ${hex.slice(0, 12)}: content does not match`);
        return fail(400);
      }
      if (!sessionKeyOk(key)) return fail(410); // the session ended during the upload
      fs.rename(tmp, file(hex), (err) => {
        if (err) return fail(500);
        console.log(`[blob] stored ${hex.slice(0, 12)} (${got} B)`);
        res.writeHead(201);
        res.end();
        try {
          evict(DIR);
        } catch {
          /* ignore */
        }
      });
    });
    return true;
  }

  res.writeHead(405);
  res.end();
  return true;
}
