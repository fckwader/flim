'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const assert = require('node:assert/strict');
const {WebSocket} = require('ws');
const {fetch} = require('../../../server/cloudflare/node_modules/undici');
const {Miniflare} = require('../../../server/cloudflare/node_modules/miniflare');
const ownerFixture = 'peer-test-host-key-never-deploy-this';
async function native(url, hello) {
  const ws = new WebSocket(url), pending = [];
  ws.on('message', data => pending.push(JSON.parse(String(data))));
  await new Promise((resolve, reject) => {ws.once('open', resolve); ws.once('error', reject);});
  ws.send(JSON.stringify(hello));
  const until = Date.now() + 5000;
  for (;;) {const m = pending.find(m => m.t === 'welcome'); if (m) return {ws, welcome: m}; if (pending.some(m => m.t === 'error') || Date.now() > until) throw new Error('Native fixture admission failed'); await new Promise(r => setTimeout(r, 20));}
}
(async () => {
  const root = path.resolve(__dirname, '..'), tmpRoot = path.join(__dirname, '.tmp'); await fs.mkdir(tmpRoot, {recursive: true});
  const tmp = await fs.mkdtemp(path.join(tmpRoot, 'peer-files-'));
  const live = process.env.FLIM_PEER_TEST_RELAY;
  if (live && live !== 'https://flim-relay.cashflowbeatz.workers.dev/') throw new Error('Unexpected live test endpoint');
  const owner = live ? (await fs.readFile(process.env.FLIM_PEER_OWNER_KEY_FILE, 'utf8')).trim() : ownerFixture;
  process.chdir(path.resolve(root, '../../server/cloudflare'));
  const mf = live ? null : new Miniflare({rootPath: path.resolve(root, '../../server/cloudflare'), modules: true, scriptPath: path.resolve(root, '../../server/cloudflare/test/fixture.mjs'), compatibilityDate: '2026-07-30', durableObjects: {ROOM: {className: 'TestRoom', useSQLite: true}}, r2Buckets: ['FILES'], bindings: {HOST_KEY: owner}});
  const sockets = [];
  try {
    const relay = live || (await mf.ready).href;
    const before = await (await fetch(relay + 'usage', {headers: {'x-flim-owner': owner}})).json();
    const room = await (await fetch(relay + 'rooms', {method: 'POST', headers: {'content-type': 'application/json'}, body: '{}'})).json();
    const hello = {password: room.password, session: room.room, transport: 2, notes_crdt: 1, portable_sync: 1};
    const wsRelay = relay.replace(/^http/, 'ws');
    const host = await native(wsRelay + `room/${room.room}`, {...hello, t: 'host', owner: room.hostToken, user: {id: 'peer-a', name: 'Fixture A'}, compat: {protocol: 1, wire: 'flim-25-26-v1', fl: '24.2.2.4597'}}); sockets.push(host.ws);
    const member = await native(wsRelay + `room/${room.room}`, {...hello, t: 'join', user: {id: 'peer-b', name: 'Fixture B'}, compat: {protocol: 1, wire: 'flim-25-26-v1', fl: '26.1.7.5654'}}); sockets.push(member.ws);
    const third = await native(wsRelay + `room/${room.room}`, {...hello, t: 'join', user: {id: 'peer-c', name: 'Fixture C'}, compat: {protocol: 1, wire: 'flim-25-26-v1', fl: '25.2.5.5319'}}); sockets.push(third.ws);
    const bytes = Buffer.alloc(2 * 1024 * 1024 + 19); for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
    const hash = createHash('sha256').update(bytes).digest('hex'), source = path.join(tmp, 'kick.wav'); await fs.writeFile(source, bytes);
    const uploaded = await (mf ? mf.dispatchFetch.bind(mf) : fetch)(relay + 'blob/' + hash, {method: 'PUT', headers: {'x-flim-key': host.welcome.blob, 'content-length': String(bytes.length)}, body: bytes}); assert.equal(uploaded.status, 201);
    const result = path.join(__dirname, 'evidence', require('../package.json').version, live ? 'peer-live.json' : 'peer-electron.json'); await fs.mkdir(path.dirname(result), {recursive: true});
    await fs.rm(result, {force: true});
    const config = path.join(tmp, 'config.json'); await fs.writeFile(config, JSON.stringify({relay, live: !!live, room: room.room, tokens: [host.welcome.file_peer, member.welcome.file_peer, third.welcome.file_peer], blob: host.welcome.blob, source, result}));
    const child = spawn(path.join(root, 'node_modules/electron/dist/electron.exe'), [path.join(__dirname, 'peer-electron-fixture.cjs'), '--user-data-dir=' + path.join(tmp, 'profile')], {cwd: root, env: {...process.env, FLIM_PEER_TEST_CONFIG: config}, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', data => process.stdout.write(data)); child.stderr.on('data', data => process.stderr.write(data));
    const timer = setTimeout(() => child.kill(), 60000);
    let code; try {code = await new Promise((resolve, reject) => {child.once('exit', resolve); child.once('error', reject);});} finally {clearTimeout(timer);}
    assert.equal(code, 0);
    const usage = await (await fetch(relay + 'usage', {headers: {'x-flim-owner': owner}})).json();
    const downloads = usage.downloads.used - before.downloads.used;
    assert.equal(downloads, 1, 'Only the deliberately forced R2 fallback should read R2');
    const evidence = JSON.parse(await fs.readFile(result, 'utf8')); evidence.r2Downloads = downloads; evidence.signaling = live ? 'Deployed Cloudflare Worker' : 'Local Cloudflare emulator'; await fs.writeFile(result, JSON.stringify(evidence, null, 2));
    console.log('PASS actual Electron direct files, concurrent transfers and R2 fallback; no FL instance launched');
  } finally {sockets.forEach(ws => ws.close()); await mf?.dispose(); assert.ok(tmp.startsWith(tmpRoot + path.sep)); await fs.rm(tmp, {recursive: true, force: true, maxRetries: 5, retryDelay: 200});}
})().catch(error => {console.error(error); process.exitCode = 1;});
