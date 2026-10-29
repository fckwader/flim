// Session isolation / slot tests. Starts servers from dist/ (npm run build first): public mode
// :8099 (owner key "ownerk", idle 4 s, no per-IP cap), :8098 (defaults, for the per-IP cap),
// :8097 (3 s sessions, 4 s cooldown); self-hosted :8096 (FLIM_PASSWORD "hk") and :8095 (no password).
// usage (in server/):  npm run build && node test/slots_test.js
const WebSocket = require("ws");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const servers = [
  { PORT: "8099", FLIM_PUBLIC: "1", FLIM_OWNER_KEY: "ownerk", FLIM_IDLE_MS: "4000", FLIM_MAX_CONNS_PER_IP: "500" },
  { PORT: "8098", FLIM_PUBLIC: "1" },
  { PORT: "8097", FLIM_PUBLIC: "1", FLIM_OWNER_KEY: "ownerk", FLIM_SESSION_MS: "3000", FLIM_COOLDOWN_MS: "4000", FLIM_MAX_CONNS_PER_IP: "500" },
  { PORT: "8096", FLIM_PASSWORD: "hk", FLIM_SESSION_MS: "1000", FLIM_IDLE_MS: "1000" },
  { PORT: "8095" },
  { PORT: "8094", FLIM_PUBLIC: "1", FLIM_EGRESS_IP_DAY_GB: String(3000 / 2 ** 30), FLIM_BLOB_FILE_MAX: "1000",
    FLIM_MAX_CONNS_PER_IP: "500" },
  { PORT: "8093", FLIM_PUBLIC: "1", FLIM_MAX_CONNS_PER_IP: "500" },
].map((env, i) =>
  spawn(process.execPath, [path.join(__dirname, "..", "dist", "server.js")], {
    env: { ...process.env, FLIM_OWNER_KEY: "", FLIM_PASSWORD: "", ...env,
           FLIM_BLOB_DIR: path.join(os.tmpdir(), `flim-slots-test-${i}`) },
    stdio: "ignore",
  }));
process.on("exit", () => servers.forEach((s) => s.kill()));
const crypto = require("crypto");
const http = require("http");
const BASE = "ws://localhost:8099";
let failed = 0;
const ok = (c, what) => { console.log(`${c ? "PASS" : "FAIL"}  ${what}`); if (!c) failed++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function client(name, base = BASE) {
  const ws = new WebSocket(base);
  const c = { ws, name, msgs: [], closed: null };
  ws.on("message", (m) => c.msgs.push(JSON.parse(m.toString())));
  ws.on("close", (code) => (c.closed = code));
  c.open = new Promise((r) => ws.on("open", r));
  c.send = (o) => ws.send(JSON.stringify(o));
  c.user = { id: "id-" + name, name };
  c.wait = async (pred, ms = 3000) => {
    const t = Date.now();
    while (Date.now() - t < ms) { const m = c.msgs.find(pred); if (m) return m; await sleep(20); }
    return null;
  };
  return c;
}
async function host(name, pw, owner, base) {
  const c = client(name, base); await c.open;
  c.send({ t: "host", user: c.user, password: pw, ...(owner !== undefined ? { owner } : {}) });
  c.welcome = await c.wait((m) => m.t === "welcome" || m.t === "error");
  return c;
}
async function join(name, session, pw, id, base) {
  const c = client(name, base); await c.open;
  if (id) c.user.id = id;
  c.send({ t: "join", user: c.user, session, password: pw });
  c.welcome = await c.wait((m) => m.t === "welcome" || m.t === "error");
  return c;
}
function req(method, path, key, body, port = 8099) {
  return new Promise((res) => {
    const r = http.request({ host: "localhost", port, method, path, headers: { "x-flim-key": key, ...(body ? { "content-length": body.length } : {}) } },
      (resp) => { let d = ""; resp.on("data", (x) => (d += x)); resp.on("end", () => res({ status: resp.statusCode, body: d })); });
    if (body) r.write(body);
    r.end();
  });
}

(async () => {
  await sleep(1500); // servers starting
  // hosting public slots
  const h1 = await host("H1", "pw1");
  ok(h1.welcome.t === "welcome" && h1.welcome.session === "01" && /^[0-9a-f]{64}$/.test(h1.welcome.blob), "first host gets 01 + blob key");
  const h2 = await host("H2", "pw2");
  ok(h2.welcome.session === "02", "second host gets 02");
  ok(h1.welcome.ends_in > 14 * 60_000 && h1.welcome.ends_in <= 15 * 60_000, "public session: ends_in ~15 min");
  ok(h1.welcome.blob !== h2.welcome.blob, "blob keys differ per session");

  // owner slot
  const bad = await host("X", "pw", "nope");
  ok(bad.welcome.t === "error" && bad.welcome.code === "bad_owner", "wrong owner key refused");
  const own = await host("OWN", "pw0", "ownerk");
  ok(own.welcome.session === "00", "owner key gets 00");
  ok(own.welcome.ends_in === 0, "00 has no time limit");
  const own2 = await host("OWN2", "pw0", "ownerk");
  ok(own2.welcome.t === "error" && own2.welcome.code === "in_use", "second owner host: 00 in use");
  const j00 = await join("X0", "00", "pw0");
  ok(j00.welcome.t === "welcome" && j00.welcome.session === "00", "anyone can JOIN 00 with its password");

  // joining
  const wrong = await join("W", "01", "pw2");
  ok(wrong.welcome.t === "error" && wrong.welcome.code === "bad_password", "02's password doesn't open 01");
  const nos = await join("N", "05", "x");
  ok(nos.welcome.code === "no_session", "unknown slot: no_session");
  const j1 = await join("J1", "1", "pw1");
  ok(j1.welcome.session === "01", "join '1' = 01");
  const j2 = await join("J2", "02", "pw2");
  const dup = await join("D", "01", "pw1", "id-H1");
  ok(dup.welcome.code === "id_in_use", "duplicate user id refused (can't impersonate the leader)");

  // ops / locks / snapshots stay in their session
  for (const c of [h1, h2, j1, j2, own, j00]) c.msgs.length = 0;
  h1.send({ t: "op", op: { kind: "param.set", id: 1, v: 111 } });
  h1.send({ t: "lock_acquire", key: "chan:1" });
  h1.send({ t: "snapshot", flp: "SESSION1" });
  h1.send({ t: "project_swap", flp: "SWAP1" });
  await sleep(400);
  ok(j1.msgs.some((m) => m.t === "op" && m.op.v === 111), "op reaches own session's member");
  const leaked = [h2, j2, own, j00].some((c) => c.msgs.some((m) => JSON.stringify(m).includes("111") || JSON.stringify(m).includes("SESSION1") || JSON.stringify(m).includes("SWAP1") || m.t === "lock"));
  ok(!leaked, "nothing from 01 (op, lock, snapshot, swap) reaches 02 or 00");
  j2.send({ t: "lock_acquire", key: "chan:1" });
  const l = await j2.wait((m) => m.t === "lock");
  ok(l && l.granted === true, "same lock key in 02 is independent of 01");
  const j1b = await join("J1b", "01", "pw1");
  const snap = j1b.msgs.find((m) => m.t === "snapshot");
  ok(snap && snap.flp === "SWAP1", "late joiner of 01 gets 01's snapshot");
  const j2b = await join("J2b", "02", "pw2");
  const snap2 = j2b.msgs.find((m) => m.t === "snapshot");
  ok(snap2 && snap2.flp === null, "late joiner of 02 doesn't get 01's snapshot");

  // blobs
  const data = Buffer.from("sample data of session 01");
  const hex = crypto.createHash("sha256").update(data).digest("hex");
  ok((await req("PUT", "/blob/" + hex, h1.welcome.blob, data)).status === 201, "01 uploads a blob");
  ok((await req("GET", "/blob/" + hex, j1.welcome.blob)).body === data.toString(), "01 member fetches it");
  ok((await req("HEAD", "/blob/" + hex, h2.welcome.blob)).status === 404, "02 can't see 01's blob (HEAD 404)");
  ok((await req("GET", "/blob/" + hex, h2.welcome.blob)).status === 404, "02 can't fetch 01's blob");
  ok((await req("POST", "/blobs/missing", h2.welcome.blob, Buffer.from(hex))).body.trim() === hex, "02's missing-list says 01's blob is missing");
  ok((await req("GET", "/blob/" + hex, "0".repeat(64))).status === 401, "unknown key: 401");
  ok((await req("GET", "/blob/" + hex, "")).status === 401, "no key: 401");

  // fill up the public slots
  const more = [];
  for (let i = 3; i <= 8; i++) more.push(await host("H" + i, "p"));
  ok(more.map((c) => c.welcome.session).join(",") === "03,04,05,06,07,08", "slots 03..08 handed out");
  const full = await host("H9", "p");
  ok(full.welcome.code === "full", "ninth host: full");

  // slot reuse: leader of 03 leaves, slot frees; the stale session must not drop the new one
  more[0].ws.close();
  await sleep(300);
  const re = await host("R3", "new3");
  ok(re.welcome.session === "03", "freed slot 03 is reused");
  const oldpw = await join("Z", "03", "p");
  ok(oldpw.welcome.code === "bad_password", "old 03 password doesn't open the new 03");

  // leader of 01 leaves -> members dropped, 01's blobs deleted
  h1.ws.close();
  await sleep(400);
  ok(j1.closed === 4000, "01 member closed when leader left");
  ok((await req("GET", "/blob/" + hex, j1.welcome.blob)).status === 401, "01's blob key dead after the session ended");
  const new1 = await host("NEW1", "q");
  ok(new1.welcome.session === "01", "01 reused");
  ok((await req("HEAD", "/blob/" + hex, new1.welcome.blob)).status === 404, "new 01 can't see old 01's blobs");

  // member cap: new01 + 7 members = 8; the 9th is refused
  const mem = [];
  for (let i = 0; i < 7; i++) mem.push(await join("M" + i, "01", "q"));
  ok(mem.every((c) => c.welcome.t === "welcome"), "7 members join 01 (8 people)");
  const ninth = await join("M9", "01", "q");
  ok(ninth.welcome.code === "session_full", "9th person: session_full");

  // brute force limit
  let last;
  for (let i = 0; i < 9; i++) last = await join("BF" + i, "02", "guess" + i);
  ok(last.welcome.code === "too_many_attempts", "9th wrong password from one IP: too_many_attempts");

  // idle: only h2/j2 keep talking; everything else goes idle (FLIM_IDLE_MS=4000)
  const keep = setInterval(() => j2.send({ t: "op", op: { kind: "cur", x: 1 } }), 500);
  await sleep(10000);
  clearInterval(keep);
  ok(re.closed === 4002 && re.msgs.some((m) => m.code === "idle"), "idle session closed with 'idle'");
  ok(own.closed === 4002, "idle 00 closed too");
  ok(h2.closed === null, "active session 02 still open");

  // per-IP connection cap: second server with the default cap of 12
  {
    const cs = [];
    for (let i = 0; i < 13; i++) {
      const w = new WebSocket("ws://localhost:8098");
      const c = { msgs: [], closed: null };
      w.on("message", (m) => c.msgs.push(JSON.parse(m.toString())));
      w.on("close", (code) => (c.closed = code));
      await new Promise((r) => w.on("open", r));
      cs.push(c);
    }
    await sleep(300);
    ok(cs.slice(0, 12).every((c) => c.closed === null), "12 connections from one IP stay open");
    ok(cs[12].closed === 4001 && cs[12].msgs.some((m) => m.code === "too_many_connections"), "13th: too_many_connections");
  }

  // time limit + cooldown (:8097: 3 s sessions, 4 s cooldown)
  {
    const T = "ws://localhost:8097";
    const th = await host("TH", "tp", undefined, T);
    const tj = await join("TJ", th.welcome.session, "tp", undefined, T);
    ok(th.welcome.ends_in > 0 && th.welcome.ends_in <= 3000, "short session: ends_in <= 3 s");
    ok(tj.welcome.ends_in > 0 && tj.welcome.ends_in <= th.welcome.ends_in, "member gets the remaining time");
    const to = await host("TO", "op", "ownerk", T);
    await sleep(4600); // 3 s + up to 1 s until the server's once-a-second sweep
    const up = (c) => c.msgs.find((m) => m.code === "time_up");
    ok(up(th) && up(th).cooldown === 4000 && th.closed === 4002, "host kicked with time_up + cooldown");
    ok(up(tj) && tj.closed === 4002, "member kicked with time_up");
    ok(to.closed === null, "00 not ended by the time limit");
    const again = await host("TH2", "tp", undefined, T);
    ok(again.welcome.code === "cooldown" && again.welcome.retry_in > 0, "hosting during cooldown refused (retry_in)");
    const own2 = await join("TJ2", "00", "op", undefined, T);
    ok(own2.welcome.t === "welcome", "joining 00 is allowed during cooldown");
    await sleep(4200);
    const after = await host("TH3", "tp", undefined, T);
    ok(after.welcome.t === "welcome", "after the cooldown hosting works again");
  }

  // self-hosted: one session, no limits; FLIM_SESSION_MS / FLIM_IDLE_MS are ignored there
  {
    const P = "ws://localhost:8096";
    const nok = await host("S0", "sp", undefined, P);
    ok(nok.welcome.code === "owner_required", "self-hosted with password: hosting without it refused");
    const bad = await host("S1", "sp", "nope", P);
    ok(bad.welcome.code === "bad_owner", "self-hosted: wrong server password refused");
    const sh = await host("S2", "sp", "hk", P);
    ok(sh.welcome.session === "01" && sh.welcome.ends_in === 0, "self-hosted: the server password hosts 01, no time limit");
    const second = await host("S3", "sp", "hk", P);
    ok(second.welcome.code === "full", "self-hosted: only one session");
    const sj = await join("SJ", "01", "sp", undefined, P);
    ok(sj.welcome.t === "welcome", "self-hosted: join with the session password");
    ok((await join("SX", "00", "sp", undefined, P)).welcome.code === "no_session", "self-hosted: no slot 00");
    ok((await join("SY", "02", "sp", undefined, P)).welcome.code === "no_session", "self-hosted: no slot 02");
    await sleep(2500);
    ok(sh.closed === null && sj.closed === null, "self-hosted: no time limit / idle close");
    const Q = "ws://localhost:8095";
    const open = await host("O1", "op", undefined, Q);
    ok(open.welcome.session === "01", "self-hosted without password: anyone hosts 01");
  }

  // data budget + upload size (:8094: ~3000 bytes per IP per day, files up to 1000 bytes)
  {
    const D = "ws://localhost:8094";
    const dh = await host("DH", "dp", undefined, D);
    ok(dh.welcome.t === "welcome", "budget server: hosting works while under budget");
    const big = Buffer.alloc(2000, 1), small = Buffer.alloc(900, 2);
    const hb = crypto.createHash("sha256").update(big).digest("hex"), hs = crypto.createHash("sha256").update(small).digest("hex");
    ok((await req("PUT", "/blob/" + hb, dh.welcome.blob, big, 8094)).status === 413, "file over the upload limit refused (413)");
    ok((await req("PUT", "/blob/" + hs, dh.welcome.blob, small, 8094)).status === 201, "file under the limit stored");
    let st = [];
    for (let i = 0; i < 5; i++) st.push((await req("GET", "/blob/" + hs, dh.welcome.blob, undefined, 8094)).status);
    ok(st.includes(200) && st[st.length - 1] === 429, "downloads refused once the IP's budget is used (" + st.join(",") + ")");
    const dj = await join("DJ", dh.welcome.session, "dp", undefined, D);
    ok(dj.welcome.code === "data_limit", "joining refused over budget (data_limit)");
    ok(dh.closed === null, "the running session keeps going");
  }

  // note editing mode (:8093): the host picks lock (default) or merge; merge needs members that can merge
  {
    const N = "ws://localhost:8093";
    const lh = await host("NL", "np", undefined, N);
    ok(lh.welcome.t === "welcome" && lh.welcome.notes === "lock", "notes: lock by default");
    ok((await join("NL2", lh.welcome.session, "np", undefined, N)).welcome.notes === "lock", "notes: lock session, plain member joins");
    const mc = client("NM", N); await mc.open;
    mc.send({ t: "host", user: mc.user, password: "mp", notes: "merge" });
    mc.welcome = await mc.wait((m) => m.t === "welcome" || m.t === "error");
    ok(mc.welcome.notes === "merge", "notes: host picks merge");
    const old = await join("NO", mc.welcome.session, "mp", undefined, N);
    ok(old.welcome.code === "notes_merge", "notes: merge session refuses a member that can't merge");
    const nj = client("NJ", N); await nj.open;
    nj.send({ t: "join", user: nj.user, session: mc.welcome.session, password: "mp", caps: ["notes.merge"] });
    nj.welcome = await nj.wait((m) => m.t === "welcome" || m.t === "error");
    ok(nj.welcome.t === "welcome" && nj.welcome.notes === "merge", "notes: merge-capable member joins and is told the mode");
    const odd = client("NX", N); await odd.open;
    odd.send({ t: "host", user: odd.user, password: "xp", notes: "nonsense" });
    odd.welcome = await odd.wait((m) => m.t === "welcome" || m.t === "error");
    ok(odd.welcome.notes === "lock", "notes: unknown mode falls back to lock");
  }

  console.log(failed ? `\n${failed} FAILED` : "\nall passed");
  process.exit(failed ? 1 : 0);
})();
