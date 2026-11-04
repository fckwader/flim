'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const {randomBytes, randomUUID} = require('node:crypto');
const {WebSocket} = require('ws');
const path = require('node:path');
const {sameMetadata} = require('./local-file.cjs');

const HASH = /^[a-f0-9]{64}$/;
const LIMIT = 90_000_000;
const CHUNK = 32 * 1024;
const json = (res, status, body = {}) => {res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'}); res.end(JSON.stringify(body));};
async function body(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) {size += chunk.length; if (size > 32768) throw new Error('body_limit'); chunks.push(chunk);}
  const value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks)));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_body');
  return value;
}
async function abortable(promise, signal) {
  let cancel;
  try {
    return await Promise.race([promise, new Promise((_resolve, reject) => {
      cancel = () => reject(new Error('transfer_canceled'));
      signal.addEventListener('abort', cancel, {once: true}); if (signal.aborted) cancel();
    })]);
  } finally {signal.removeEventListener('abort', cancel);}
}

class PeerFiles {
  constructor({relay, transport, record = () => {}, alive = pid => {try {process.kill(pid, 0); return true;} catch {return false;}}, idle = () => {}, connect = url => new WebSocket(url, {maxPayload: 65536, handshakeTimeout: 5000})}) {
    this.relay = relay; this.transport = transport; this.record = record; this.alive = alive; this.idle = idle; this.connect = connect;
    this.sessions = new Map(); this.transfers = new Map(); this.jobs = new Set(); this.server = null; this.starting = null; this.closed = false;
  }
  get active() {return [...this.sessions.values()].some(s => s.pid && this.alive(s.pid));}
  async listen() {
    if (this.server) return;
    if (this.starting) return this.starting;
    this.starting = (async () => {
      const server = http.createServer((req, res) => {void this.request(req, res).catch(() => {if (!res.headersSent) json(res, 400); else res.destroy();});});
      server.requestTimeout = 15000; server.headersTimeout = 10000; server.maxConnections = 16;
      server.on('clientError', (_error, socket) => socket.destroy());
      await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
      this.server = server;
      this.timer = setInterval(() => {
        for (const s of this.sessions.values()) if (s.pid ? !this.alive(s.pid) : Date.now() - s.created > 120000) this.drop(s);
      }, 3000); this.timer.unref();
    })().finally(() => {this.starting = null;});
    return this.starting;
  }
  async prepare(code) {
    if (this.closed || !/^\d{8}$/.test(code) || this.sessions.size >= 8) throw new Error('peer_capacity');
    await this.listen();
    if (this.closed || this.sessions.size >= 8) throw new Error('peer_capacity');
    const token = randomBytes(32).toString('hex');
    const s = {id: randomUUID(), token, code, created: Date.now(), generation: 0, offers: new Map(), ready: new Set(), pid: 0, incoming: 0, outgoing: 0, serving: new Map(), reconnects: 0};
    this.sessions.set(token, s);
    return {env: {FLIM_PEER_URL: `http://127.0.0.1:${this.server.address().port}`, FLIM_PEER_TOKEN: token},
      launched: pid => {if (!Number.isSafeInteger(pid) || pid < 1 || pid > 0xffffffff) throw new Error('invalid_pid'); s.pid = pid;}, cancel: () => this.drop(s)};
  }
  drop(s) {
    if (!this.sessions.delete(s.token)) return;
    clearTimeout(s.reconnect); clearTimeout(s.admission); const ws = s.ws; s.ws = null; ws?.close(); this.reset(s);
    s.offers.clear(); s.ready.clear(); this.idle();
  }
  reset(s) {
    this.transport.send({type: 'reset', session: s.id});
    for (const [id, t] of this.transfers) if (t.session === s) this.finish(id, new Error('session_changed'));
    for (const controller of s.serving.values()) controller.abort();
    s.ready.clear(); s.id = randomUUID();
  }
  retry(s) {
    clearTimeout(s.reconnect);
    const delay = Math.min(30000, 1000 * 2 ** Math.min(s.reconnects++, 5));
    s.reconnect = setTimeout(() => this.attach(s), delay); s.reconnect.unref?.();
  }
  log(event, fields) {try {Promise.resolve(this.record(event, fields)).catch(() => {});} catch {}}
  signal(s, message) {
    const ws = s.ws;
    if (ws?.readyState !== 1) return;
    try {if (ws.bufferedAmount > 65536) {ws.close(); return;} ws.send(JSON.stringify(message));}
    catch {try {ws.close();} catch {}}
  }
  async request(req, res) {
    if (req.headers.origin || req.headers.host !== `127.0.0.1:${this.server?.address()?.port}`) return json(res, 403);
    const s = this.sessions.get(req.headers['x-flim-key']);
    if (!s) return json(res, 403);
    if (!req.url.startsWith('/') || req.url.startsWith('//')) return json(res, 400);
    const u = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && u.pathname === '/connect') {
      const data = await body(req);
      if (!this.sessions.has(s.token)) return json(res, 403);
      if (!HASH.test(data.token) || !Number.isSafeInteger(data.generation) || data.generation < 1 || data.generation > 0x7fffffff || data.generation <= s.generation) return json(res, 409);
      s.generation = data.generation; s.credential = data.token;
      clearTimeout(s.reconnect); clearTimeout(s.admission); const ws = s.ws; s.ws = null; ws?.close(); s.offers.clear(); s.reconnects = 0;
      this.reset(s); this.attach(s); return json(res, 200);
    }
    if (req.method === 'POST' && u.pathname === '/offer') {
      const data = await body(req);
      if (!s.generation || data.generation !== s.generation || !HASH.test(data.h) || !Number.isSafeInteger(data.s) || data.s < 1 || data.s > LIMIT || typeof data.p !== 'string' || data.p.length > 22000) return json(res, 400);
      const decoded = Buffer.from(data.p, 'base64');
      if (decoded.length % 2 || decoded.toString('base64') !== data.p) return json(res, 400);
      const file = decoded.toString('utf16le');
      if (!path.isAbsolute(file) || file.includes('\0') || !file.isWellFormed()) return json(res, 400);
      const stat = await fs.stat(file);
      if (!this.sessions.has(s.token) || data.generation !== s.generation) return json(res, 409);
      if (!stat.isFile() || stat.size !== data.s || s.offers.size >= 2000 && !s.offers.has(data.h)) return json(res, 409);
      s.offers.set(data.h, {file, bytes: stat.size, metadata: stat}); return json(res, 200);
    }
    const hash = u.pathname.slice(6), bytes = Number(u.searchParams.get('bytes'));
    if (req.method !== 'GET' || !u.pathname.startsWith('/blob/') || !HASH.test(hash) || !/^\d{1,9}$/.test(u.searchParams.get('bytes') || '') || !Number.isSafeInteger(bytes) || bytes < 1 || bytes > LIMIT || !s.generation || !/^\d{1,10}$/.test(u.searchParams.get('generation') || '') || Number(u.searchParams.get('generation')) !== s.generation) return json(res, 400);
    if (!s.ready.size || s.incoming >= 2) return json(res, 404);
    s.incoming++;
    const id = randomUUID();
    try {
      await new Promise((resolve, reject) => {
        const t = {session: s, worker: s.id, res, bytes, done: 0, resolve, reject};
        t.timer = setTimeout(() => this.finish(id, new Error('peer_timeout')), 120000);
        t.first = setTimeout(() => this.finish(id, new Error('peer_unavailable')), Math.min(10000, 1500 + Math.max(0, s.ready.size - 1) * 1100));
        this.transfers.set(id, t);
        res.once('close', () => {if (this.transfers.has(id)) this.finish(id, new Error('receiver_closed'));});
        this.transport.send({type: 'get', session: s.id, id, hash, bytes});
      });
      this.log('peer_download', {bytes});
    } catch {if (!res.headersSent) json(res, 404); else res.destroy();}
    finally {s.incoming--;}
  }
  attach(s) {
    if (!this.sessions.has(s.token)) return;
    const endpoint = new URL(`/peer/${s.code}`, this.relay); endpoint.protocol = endpoint.protocol === 'https:' ? 'wss:' : 'ws:';
    let ws;
    try {ws = this.connect(endpoint.href);} catch {this.retry(s); return;}
    s.ws = ws;
    s.admission = setTimeout(() => {if (s.ws === ws) ws.close();}, 10000); s.admission.unref?.();
    ws.on('open', () => {if (s.ws === ws) this.signal(s, {t: 'files.hello', token: s.credential});});
    ws.on('message', raw => {
      if (s.ws !== ws || !this.sessions.has(s.token)) return;
      try {
        const m = JSON.parse(String(raw));
        if (m.t === 'files.peers' && typeof m.you === 'string' && /^[\w-]{1,64}$/.test(m.you) && Array.isArray(m.peers) && m.peers.length <= 8 && new Set(m.peers).size === m.peers.length && m.peers.includes(m.you) && m.peers.every(p => typeof p === 'string' && /^[\w-]{1,64}$/.test(p))) {clearTimeout(s.admission); s.reconnects = 0; for (const id of s.ready) if (!m.peers.includes(id)) s.ready.delete(id); this.transport.send({type: 'peers', session: s.id, you: m.you, peers: m.peers});}
        else if (m.t === 'files.signal') this.transport.send({type: 'signal', session: s.id, from: m.from, signal: m.signal});
      } catch {}
    });
    ws.on('error', () => {});
    ws.on('close', (code) => {
      if (s.ws !== ws || !this.sessions.has(s.token)) return;
      clearTimeout(s.admission);
      s.ws = null; this.reset(s);
      if (code !== 4000 && code !== 4001) this.retry(s);
    });
  }
  finish(id, error) {
    const t = this.transfers.get(id); if (!t) return;
    this.transfers.delete(id); clearTimeout(t.timer); clearTimeout(t.first);
    this.transport.send({type: 'cancel', session: t.worker, id});
    if (error) t.reject(error); else {t.res.end(); t.resolve();}
  }
  async event(m) {
    const s = [...this.sessions.values()].find(s => s.id === m?.session); if (!s) return;
    if (m.type === 'signal') this.signal(s, {t: 'files.signal', to: m.to, signal: m.signal});
    else if (m.type === 'ready') {if (m.ready) s.ready.add(m.peer); else s.ready.delete(m.peer);}
    else if (m.type === 'served_closed') s.serving.get(m.id)?.abort();
    else if (m.type === 'serve') {
      if (s.outgoing >= 2 || !HASH.test(m.hash) || typeof m.id !== 'string' || m.id.length > 64 || s.serving.has(m.id)) return false;
      const offer = s.offers.get(m.hash); if (!offer || offer.bytes !== m.bytes) return false;
      s.outgoing++;
      const id = m.id, generation = s.generation, worker = s.id, controller = new AbortController();
      s.serving.set(id, controller);
      const current = () => !controller.signal.aborted && this.sessions.has(s.token) && generation === s.generation && worker === s.id;
      let file;
      try {
        file = await fs.open(offer.file, 'r');
        const stat = await file.stat();
        if (!current() || !stat.isFile() || !sameMetadata(stat, offer.metadata)) throw new Error('source_changed');
      } catch {if (s.offers.get(m.hash) === offer) s.offers.delete(m.hash); s.outgoing--; s.serving.delete(id); await file?.close().catch(() => {}); return false;}
      const job = (async () => {
        try {
          this.transport.send({type: 'start', session: worker, id, bytes: offer.bytes});
          let offset = 0;
          while (offset < offer.bytes && current()) {
            const chunk = Buffer.allocUnsafe(Math.min(CHUNK, offer.bytes - offset));
            const {bytesRead} = await file.read(chunk, 0, chunk.length, offset); if (!bytesRead) throw new Error('source_changed');
            if (!current()) throw new Error('session_ended');
            await abortable(this.transport.chunk({type: 'chunk', session: worker, id, data: chunk.subarray(0, bytesRead)}, controller.signal), controller.signal); offset += bytesRead;
          }
          const after = await file.stat();
          if (offset !== offer.bytes || !current() || !sameMetadata(after, offer.metadata)) throw new Error('source_changed');
          this.transport.send({type: 'end', session: worker, id});
        } catch {this.transport.send({type: 'cancel', session: worker, id});}
        finally {s.outgoing--; s.serving.delete(id); await file.close().catch(() => {});}
      })();
      this.jobs.add(job); void job.finally(() => this.jobs.delete(job)).catch(() => {});
      return true;
    } else {
      const t = this.transfers.get(m.id); if (!t || t.session !== s) return;
      if (m.type === 'start' && m.bytes === t.bytes && !t.started) {clearTimeout(t.first); t.started = true; t.res.writeHead(200, {'content-type': 'application/octet-stream', 'content-length': t.bytes, 'cache-control': 'no-store'});}
      else if (m.type === 'chunk' && t.started) {
        const data = Buffer.from(m.data); if (!data.length || data.length > CHUNK || t.done + data.length > t.bytes) return this.finish(m.id, new Error('invalid_length'));
        t.done += data.length;
        if (!t.res.write(data)) await new Promise(resolve => {
          const done = () => {t.res.off('drain', done); t.res.off('close', done); resolve();};
          t.res.once('drain', done); t.res.once('close', done);
        });
      } else if (m.type === 'end' && t.started && t.done === t.bytes) this.finish(m.id);
      else if (m.type === 'failed') this.finish(m.id, new Error('peer_failed'));
      else this.finish(m.id, new Error('invalid_transfer'));
    }
  }
  async close() {this.closed = true; await this.starting; clearInterval(this.timer); for (const s of [...this.sessions.values()]) this.drop(s); await Promise.allSettled([...this.jobs]); if (this.server) {this.server.closeAllConnections(); await new Promise(resolve => this.server.close(resolve)); this.server = null;}}
}
module.exports = {PeerFiles, CHUNK};
