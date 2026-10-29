import crypto from "crypto";
import http from "http";
import { WebSocketServer, WebSocket } from "ws";
import { dropBlobs, handleBlob } from "./blobs";
import { egressLimits, egressRefusal, setWsIp } from "./egress";
import { CAP_NOTES_MERGE, ClientMsg, NotesMode, PING_INTERVAL_MS, UserInfo } from "./protocol";
import { Client, Session, send } from "./session";

const PORT = Number(process.env.PORT ?? 8080);
const MAX_PAYLOAD = 64 * 1024 * 1024; // 64 MB — an .flp snapshot in base64

// Two modes.
// Public (FLIM_PUBLIC=1, flim.fly.dev's fly.toml): anyone may host 01..08 (first free one). 00 is
//   the owner's: only a host that sends the owner key gets it (`fly secrets set FLIM_OWNER_KEY=...`;
//   FLIM_PASSWORD works too; no key = 00 off). Sessions 01..08 end after SESSION_MS and everyone who
//   was in one may not host or join another one for COOLDOWN_MS (testing: nobody hogs a slot); idle
//   sessions close after IDLE_MS. Slot 00 has no time limit and no cooldown.
// Self-hosted (default): one session (01), no time limit, no cooldown, no idle close. With
//   FLIM_PASSWORD (or FLIM_OWNER_KEY) set, only a host that sends it as the owner key may host.
const PUBLIC = process.env.FLIM_PUBLIC === "1";
const PUBLIC_SLOTS = PUBLIC ? ["01", "02", "03", "04", "05", "06", "07", "08"] : ["01"];
const OWNER_SLOT = "00"; // public mode only
const OWNER_KEY = process.env.FLIM_OWNER_KEY || process.env.FLIM_PASSWORD || "";
if (PUBLIC && !OWNER_KEY) console.warn("FLIM_OWNER_KEY is not set: slot 00 can't be hosted.");
if (!PUBLIC && !OWNER_KEY) console.warn("FLIM_PASSWORD is not set: anyone who knows the address can host.");

const IDLE_MS = PUBLIC ? Number(process.env.FLIM_IDLE_MS ?? 5 * 60_000) : 0; // no message from anyone -> closed
const SESSION_MS = PUBLIC ? Number(process.env.FLIM_SESSION_MS ?? 15 * 60_000) : 0;
const COOLDOWN_MS = PUBLIC ? Number(process.env.FLIM_COOLDOWN_MS ?? 5 * 60_000) : 0;
const JOIN_TIMEOUT_MS = 20_000; // a connection must host/join this soon
const MAX_MEMBERS = 8; // people per session (host included)
const MAX_CONNS_PER_IP = Number(process.env.FLIM_MAX_CONNS_PER_IP ?? 12); // open WebSockets per IP: one visitor can't fill the machine
const PW_MAX = 128;
// Wrong passwords / owner keys per IP: after FAIL_MAX in FAIL_WINDOW_MS that IP is refused
// until the window has passed.
const FAIL_MAX = 8;
const FAIL_WINDOW_MS = 10 * 60_000;
// Messages per connection: a token bucket (RATE_PER_S, burst RATE_BURST). Beyond it the
// connection is closed, so one session can't slow the others down.
const RATE_PER_S = 400;
const RATE_BURST = 4000;

const sha = (v: string) => crypto.createHash("sha256").update(v, "utf8").digest();
function ownerKeyOk(given: unknown): boolean {
  if (!OWNER_KEY || typeof given !== "string" || !given) return false;
  return crypto.timingSafeEqual(sha(given), sha(OWNER_KEY));
}

const sessions = new Map<string, Session>(); // slot -> session
const blobKeys = new Map<string, Session>(); // blob key -> session

function openSession(slot: string, password: string, leader: Client, notes: NotesMode): Session {
  const endsAt = slot === OWNER_SLOT || !SESSION_MS ? null : Date.now() + SESSION_MS;
  const session: Session = new Session(slot, password, leader, endsAt, () => {
    // only the session that holds the slot may free it (a stale one must not drop its successor)
    if (sessions.get(slot) === session) sessions.delete(slot);
    blobKeys.delete(session.blobKey);
    dropBlobs(session.blobKey);
    console.log(`[${slot}] session ended`);
  }, notes);
  sessions.set(slot, session);
  blobKeys.set(session.blobKey, session);
  return session;
}

// "3", "03" -> "03"; anything else -> null
function slotId(v: unknown): string | null {
  const s = String(v ?? "").trim();
  if (!/^\d{1,2}$/.test(s)) return null;
  const id = s.padStart(2, "0");
  return (PUBLIC && id === OWNER_SLOT) || PUBLIC_SLOTS.includes(id) ? id : null;
}

const cooldowns = new Map<string, number>(); // ip -> until (ms)
function cooldownLeft(ip: string): number {
  return Math.max(0, (cooldowns.get(ip) ?? 0) - Date.now());
}
const mmss = (ms: number) => {
  const s = Math.ceil(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};

const fails = new Map<string, { n: number; since: number }>();
function failCount(ip: string): number {
  const f = fails.get(ip);
  if (!f) return 0;
  if (Date.now() - f.since > FAIL_WINDOW_MS) {
    fails.delete(ip);
    return 0;
  }
  return f.n;
}
function addFail(ip: string): void {
  const f = fails.get(ip);
  if (!f || Date.now() - f.since > FAIL_WINDOW_MS) fails.set(ip, { n: 1, since: Date.now() });
  else f.n += 1;
}

function clientIp(req: http.IncomingMessage): string {
  return String(req.headers["fly-client-ip"] ?? req.socket.remoteAddress ?? "?");
}

// What a browser sees when someone opens a session link.
const LINK_PAGE = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>flim session</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 16px">
<h1 style="font-size:1.4rem">This is a flim session link</h1>
<p>Open FL Studio through flim, click <b>Connect</b> in the toolbar, paste this link and enter the
session password the host gave you.</p></body>`;

// Health check for the Fly proxy (TCP connect here also wakes a stopped machine), the sample
// file store (blobs.ts), and a short page for session links opened in a browser.
const httpServer = http.createServer((req, res) => {
  if (handleBlob(req, res, (key) => blobKeys.has(key), clientIp(req))) return;
  const url = (req.url ?? "").split("?")[0];
  if (url === "/health" || url === "/") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("flim-server ok\n");
  } else if (req.method === "GET" && slotId(url.slice(1)) && url.length === 3) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(LINK_PAGE);
  } else {
    res.writeHead(404);
    res.end();
  }
});

const wss = new WebSocketServer({ server: httpServer, maxPayload: MAX_PAYLOAD });

// Per-connection bookkeeping.
interface Conn {
  ip: string;
  client?: Client;
  session?: Session;
  tokens: number;
  tokensAt: number;
  refused?: boolean; // hanging up: nothing more is read from it
}
const conns = new WeakMap<WebSocket, Conn>();
const connsPerIp = new Map<string, number>();

function fail(ws: WebSocket, code: string, msg: string): void {
  send(ws, { t: "error", code, msg });
}
// Refuse and hang up (pre-session errors).
function refuse(ws: WebSocket, code: string, msg: string, delayMs = 0, retryIn?: number): void {
  const conn = conns.get(ws);
  if (conn) conn.refused = true;
  send(ws, { t: "error", code, msg, ...(retryIn ? { retry_in: retryIn } : {}) });
  setTimeout(() => ws.close(4001, code), delayMs);
}

function rateOk(conn: Conn): boolean {
  const now = Date.now();
  conn.tokens = Math.min(RATE_BURST, conn.tokens + ((now - conn.tokensAt) / 1000) * RATE_PER_S);
  conn.tokensAt = now;
  if (conn.tokens < 1) return false;
  conn.tokens -= 1;
  return true;
}

function handlePreSession(ws: WebSocket, conn: Conn, msg: ClientMsg): void {
  if (msg.t !== "host" && msg.t !== "join") return fail(ws, "not_joined", "Host or join a session first.");
  const budget = egressRefusal(conn.ip); // data budget (egress.ts): no new sessions / members
  if (budget) return refuse(ws, "data_limit", budget);
  if (failCount(conn.ip) >= FAIL_MAX) {
    return refuse(ws, "too_many_attempts", "Too many wrong passwords. Try again in a few minutes.");
  }
  const user = sanitizeUser(msg.user);
  const password = typeof msg.password === "string" ? msg.password : "";
  if (!password || password.length > PW_MAX) {
    return refuse(ws, "bad_request", `The session password must be 1 to ${PW_MAX} characters.`);
  }

  if (msg.t === "host") {
    let slot: string | undefined;
    if (!PUBLIC) {
      // self-hosted: the one session, for whoever has the server's password (if it has one)
      if (OWNER_KEY && !ownerKeyOk(msg.owner)) {
        if (!msg.owner) {
          return refuse(ws, "owner_required", "This server needs its password to host: Ctrl+click Host and enter it.");
        }
        addFail(conn.ip);
        console.log(`[auth] wrong server password from ${user.name} (${conn.ip})`);
        return refuse(ws, "bad_owner", "Wrong server password.", 1000);
      }
      slot = PUBLIC_SLOTS[0];
      if (sessions.has(slot)) return refuse(ws, "full", "A session is already running on this server.");
    } else if (msg.owner !== undefined && msg.owner !== "") {
      if (!ownerKeyOk(msg.owner)) {
        addFail(conn.ip);
        console.log(`[auth] wrong owner key from ${user.name} (${conn.ip})`);
        return refuse(ws, "bad_owner", "Wrong owner key.", 1000);
      }
      if (sessions.has(OWNER_SLOT)) return refuse(ws, "in_use", `Session ${OWNER_SLOT} is already running.`);
      slot = OWNER_SLOT;
    } else {
      const cool = cooldownLeft(conn.ip);
      if (cool) return refuse(ws, "cooldown", `Cooldown: you can host again in ${mmss(cool)}.`, 0, cool);
      slot = PUBLIC_SLOTS.find((s) => !sessions.has(s));
      if (!slot) return refuse(ws, "full", `All ${PUBLIC_SLOTS.length} sessions are in use. Try again later.`);
    }
    const client: Client = { ws, user, role: "leader", alive: true, ip: conn.ip };
    conn.client = client;
    const notes: NotesMode = msg.notes === "merge" ? "merge" : "lock";
    conn.session = openSession(slot, password, client, notes);
    console.log(`[${slot}] hosted by ${user.name} (notes: ${notes})`);
    return;
  }

  const slot = slotId(msg.session);
  const session = slot ? sessions.get(slot) : undefined;
  if (!slot || !session) return refuse(ws, "no_session", "That session isn't running (check the link).");
  const cool = slot === OWNER_SLOT ? 0 : cooldownLeft(conn.ip);
  if (cool) return refuse(ws, "cooldown", `Cooldown: you can join again in ${mmss(cool)}.`, 0, cool);
  if (!session.passwordOk(password)) {
    addFail(conn.ip);
    console.log(`[${slot}] wrong password from ${user.name} (${conn.ip})`);
    return refuse(ws, "bad_password", "Wrong session password.", 1000);
  }
  if (session.hasUser(user.id)) return refuse(ws, "id_in_use", "You are already in this session.");
  if (session.size >= MAX_MEMBERS) return refuse(ws, "session_full", `That session already has ${MAX_MEMBERS} people.`);
  if (session.notesMode === "merge" && !(Array.isArray(msg.caps) && msg.caps.includes(CAP_NOTES_MERGE))) {
    return refuse(ws, "notes_merge", "This session merges simultaneous note edits, which your flim can't do yet. Update flim to join.");
  }
  const client: Client = { ws, user, role: "member", alive: true, ip: conn.ip };
  conn.client = client;
  conn.session = session;
  session.touch();
  session.add(client);
  console.log(`[${slot}] ${user.name} joined; peers=${session.size}`);
}

function handleInSession(ws: WebSocket, client: Client, session: Session, msg: ClientMsg): void {
  if (msg.t !== "bye") session.touch();
  switch (msg.t) {
    case "snapshot":
      session.setSnapshot(client, msg.flp);
      break;
    case "project_swap":
      session.projectSwap(client, msg.flp);
      break;
    case "op":
      if (!msg.op || typeof msg.op !== "object") return fail(ws, "bad_request", "Malformed op.");
      if (msg.op.kind === "cur") { session.relayOp(client, msg.op); break; } // mouse position: frequent, not an edit
      session.touchLocksOf(client.user.id); // editing keeps the user's locks fresh
      session.relayOp(client, msg.op);
      console.log(`[${session.code} op] ${client.user.name}: ${JSON.stringify(msg.op).slice(0, 120)}`);
      break;
    case "lock_acquire":
      session.acquire(client, msg.key);
      break;
    case "lock_release":
      session.release(client, msg.key);
      break;
    case "bye":
      ws.close(1000, "bye");
      break;
    default:
      fail(ws, "unknown", `Unknown message type.`);
  }
}

wss.on("connection", (ws, req) => {
  const conn: Conn = { ip: clientIp(req), tokens: RATE_BURST, tokensAt: Date.now() };
  setWsIp(ws, conn.ip);
  conns.set(ws, conn);
  const n = (connsPerIp.get(conn.ip) ?? 0) + 1;
  connsPerIp.set(conn.ip, n);
  if (n > MAX_CONNS_PER_IP) {
    console.log(`[conn] too many connections from ${conn.ip}`);
    refuse(ws, "too_many_connections", "Too many connections from your network.");
  }
  (ws as any).isAlive = true;
  ws.on("pong", () => ((ws as any).isAlive = true));
  const joinTimer = setTimeout(() => {
    if (!conn.session) ws.close(4003, "join_timeout");
  }, JOIN_TIMEOUT_MS);

  ws.on("message", (raw) => {
    if (conn.refused) return;
    if (!rateOk(conn)) {
      console.log(`[rate] ${conn.client?.user.name ?? conn.ip} sent too fast: closed`);
      ws.close(4008, "rate");
      return;
    }
    let msg: ClientMsg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return fail(ws, "bad_json", "Malformed message.");
    }
    if (!msg || typeof msg !== "object") return fail(ws, "bad_json", "Malformed message.");
    try {
      if (!conn.session || !conn.client) handlePreSession(ws, conn, msg);
      else handleInSession(ws, conn.client, conn.session, msg);
    } catch (e) {
      // a bad message only fails itself: every other session keeps running
      console.error(`[error] ${conn.session?.code ?? "--"}: ${(e as Error)?.stack ?? e}`);
    }
  });

  ws.on("close", () => {
    clearTimeout(joinTimer);
    const left = (connsPerIp.get(conn.ip) ?? 1) - 1;
    if (left > 0) connsPerIp.set(conn.ip, left);
    else connsPerIp.delete(conn.ip);
    if (conn.client) console.log(`[${conn.session?.code ?? "--"}] ${conn.client.user.name} disconnected`);
    conn.session?.remove(ws);
    conns.delete(ws);
  });

  ws.on("error", () => {
    /* close handler does cleanup */
  });
});

// Names are shown to peers (and in FL's hint bar): the client already restricts them to
// letters/digits/space/-_. ; the server only strips control and quote-ish characters.
function sanitizeUser(u: UserInfo | undefined): UserInfo {
  const clean = (v: unknown, max: number) =>
    String(v ?? "").replace(/[\u0000-\u001f\u007f"\\<>]/g, "").trim().slice(0, max);
  const id = clean(u?.id, 64) || `anon-${Math.random().toString(36).slice(2, 8)}`;
  const name = clean(u?.name, 24) || "Anonymous";
  return { id, name };
}

// Liveness: ping clients; terminate dead ones (triggers close → lock release / session end).
const ping = setInterval(() => {
  for (const ws of wss.clients) {
    if ((ws as any).isAlive === false) {
      ws.terminate();
      continue;
    }
    (ws as any).isAlive = false;
    try {
      ws.ping();
    } catch {
      /* ignore */
    }
  }
}, PING_INTERVAL_MS);

// Lock TTL safety sweep + time limit + idle sessions (frees their slot).
const sweep = setInterval(() => {
  const now = Date.now();
  for (const s of [...sessions.values()]) {
    if (s.endsAt !== null && now >= s.endsAt) {
      console.log(`[${s.code}] time limit reached: closing`);
      for (const ip of s.ips()) cooldowns.set(ip, now + COOLDOWN_MS);
      s.end("time_up", `Time's up: sessions are limited to ${Math.round(SESSION_MS / 60_000)} minutes.`, COOLDOWN_MS);
    } else if (IDLE_MS && now - s.lastActive >= IDLE_MS) {
      console.log(`[${s.code}] idle for ${Math.round(IDLE_MS / 60_000)} min: closing`);
      s.end("idle", `Session closed after ${Math.round(IDLE_MS / 60_000)} minutes without activity.`);
    } else s.sweepLocks();
  }
  for (const [ip, f] of fails) if (now - f.since > FAIL_WINDOW_MS) fails.delete(ip);
  for (const [ip, until] of cooldowns) if (now >= until) cooldowns.delete(ip);
}, 1_000);

wss.on("close", () => {
  clearInterval(ping);
  clearInterval(sweep);
});

httpServer.listen(PORT, () => {
  console.log(
    PUBLIC
      ? `flim-server listening on :${PORT} (public: slots ${OWNER_SLOT}, ${PUBLIC_SLOTS.join(" ")}; ` +
          `${SESSION_MS / 60_000} min sessions, ${COOLDOWN_MS / 60_000} min cooldown)`
      : `flim-server listening on :${PORT} (self-hosted: one session)`,
    `| ${egressLimits()}`,
  );
});
