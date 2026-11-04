'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { pathToFileURL } = require('node:url');
const { DesktopBridge, BridgeError, RELAY, displayName, roomCode, childEnvironment, trustedSender } = require('../electron/bridge-core.cjs');

const PASSWORD = 'a'.repeat(64), TICKET = 'b'.repeat(64);
const roomReply = { room: '12345678', password: PASSWORD, hostToken: TICKET, websocket: '/room/12345678', maxParticipants: 8, expiresAt: '2099-01-01T00:00:00.000Z' };
const activeStatus = fl => ({room: roomReply.room, state: 'active', maxParticipants: 8, peers: [{id: 'host', name: 'Host', role: 'leader', fl}]});
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

test('confirmed FL launches stay confirmed when optional peer lifetime tracking throws', async t => {
  const f = await fixture(t, {peerFiles: {prepare: async () => ({launched() {throw new Error('tracking');}})}});
  await f.bridge.createRoom(f.input); await f.bridge.launchFL(); assert.equal(f.bridge.room.state, 'launched');
});
test('optional cancellation cannot mask a definite launch failure and attempted folders are released', async t => {
  const f = await fixture(t, {peerFiles: {prepare: async () => ({cancel() {throw new Error('cancel');}})}, launch: async () => {throw new BridgeError('launcher refused', 'native_failed');}});
  await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.launchFL(), /launcher refused/);
  assert.equal(f.bridge.room.state, 'ready'); assert.equal(f.bridge.room.sampleDirectory, undefined);
});
test('reservation expiry during direct-file preparation prevents launch and cancels preparation', async t => {
  let canceled = 0; const f = await fixture(t);
  f.bridge.peerFiles = {prepare: async () => {f.bridge.room.expiresAt = new Date(99_000).toISOString(); return {cancel() {canceled++;}};}};
  await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.launchFL(), /reservation expired/);
  assert.equal(canceled, 1); assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
});
test('reinitialization detects removed native files instead of retaining an earlier ready flag', async t => {
  const f = await fixture(t); assert.equal(f.bridge.nativeReady, true);
  await fs.unlink(path.join(f.nativeDir, 'flim_engine.dll')); await f.bridge.initialize(); assert.equal(f.bridge.nativeReady, false);
});
test('failed diagnostics availability cannot stop state, room setup or recovery', async t => {
  const f = await fixture(t); f.bridge.diagnosticsStatus = () => {throw new Error('disk');};
  assert.equal(f.bridge.state().diagnosticsAvailable, false); await f.bridge.createRoom(f.input);
});
test('installation chooser absence gives an actionable error and releases busy state', async t => {
  const f = await fixture(t); f.bridge.chooseDirectory = undefined;
  await assert.rejects(f.bridge.chooseInstall(), /complete flim app/); assert.equal(f.bridge.busy, false);
});
test('a slower installation scan cannot overwrite the latest completed scan', async t => {
  const f = await fixture(t); let release, first = true;
  const inspect = f.bridge.inspect.bind(f.bridge);
  f.bridge.inspect = async dir => {if (first) {first = false; await new Promise(resolve => {release = resolve;});} return inspect(dir);};
  const earlier = f.bridge.scanInstalls(); while (!release) await new Promise(resolve => setImmediate(resolve));
  await f.bridge.scanInstalls(); const latest = f.bridge.installs; release(); await earlier;
  assert.equal(f.bridge.installs, latest);
});
test('participant names remove invisible formatting and repair malformed Unicode', async t => {
  const f = await fixture(t, {fetch: async url => response(url.endsWith('/status') ? {...activeStatus('26.1.7.5654'), peers: [{id: 'host', role: 'leader', fl: '26.1.7.5654', name: '\u200b\ufeff\u2060'}]} : roomReply)});
  await f.bridge.createRoom(f.input); await f.bridge.refreshRoom(); assert.equal(f.bridge.room.peers[0].name, 'Participant');
});

test('canonically equivalent accented names retain their accent in preferences and the FL environment', async t => {
  const f = await fixture(t); const name = 'Jose\u0301';
  assert.equal(displayName(name), 'José');
  assert.equal((await import('../src/utils/roomUI.js')).validateName(name), '');
  await f.bridge.createRoom({...f.input, name}); await f.bridge.launchFL();
  assert.equal(f.calls.at(-1).settings.env.FLIM_NAME, 'José');
  assert.equal(JSON.parse(await fs.readFile(f.bridge.preferencesFile, 'utf8')).name, 'José');
});

test('expired unused reservations are neither copied nor polled as live rooms', async t => {
  const f = await fixture(t); await f.bridge.createRoom(f.input); f.bridge.room.expiresAt = new Date(99_000).toISOString();
  await assert.rejects(f.bridge.copyInvite(), /reservation expired/); assert.deepEqual(f.copied, []);
  await f.bridge.leaveRoom(); await f.bridge.createRoom(f.input); f.bridge.room.expiresAt = new Date(99_000).toISOString();
  const before = f.requests.length;
  assert.equal((await f.bridge.refreshRoom()).room.status, 'ended'); assert.equal(f.requests.length, before);
});

test('status failures back off automatically and a successful read restores the normal cadence', async t => {
  let fail = true;
  const f = await fixture(t, {fetch: async url => !url.endsWith('/status') ? response(roomReply) : fail ? response({}, 429) : response(activeStatus('26.1.7.5654'))});
  await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.refreshRoom());
  f.advance(5000); await assert.rejects(f.bridge.refreshRoom());
  f.advance(5000); await assert.rejects(f.bridge.refreshRoom());
  assert.equal(f.requests.length, 3);
  f.advance(5000); fail = false; assert.equal((await f.bridge.refreshRoom()).room.status, 'active');
  assert.equal(f.bridge.statusFailures, 0); f.advance(10_000); await f.bridge.refreshRoom(); assert.equal(f.requests.length, 5);
});

test('server Retry-After pauses forced as well as automatic status checks, with bounded seconds and HTTP dates', async t => {
  for (const header of ['20', new Date(120_000).toUTCString()]) {
    let fail = true;
    const f = await fixture(t, {fetch: async url => !url.endsWith('/status') ? response(roomReply) : fail ? new Response('{}', {status: 503, headers: {'retry-after': header}}) : response(activeStatus('26.1.7.5654'))});
    await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.refreshRoom()); assert.equal(f.requests.length, 2);
    f.advance(19_000); fail = false; await assert.rejects(f.bridge.refreshRoom({force: true})); assert.equal(f.requests.length, 2);
    f.advance(1000); assert.equal((await f.bridge.refreshRoom({force: true})).room.status, 'active');
  }
  const f = await fixture(t, {fetch: async url => !url.endsWith('/status') ? response(roomReply) : new Response('{}', {status: 429, headers: {'retry-after': '99999999999'}})});
  await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.refreshRoom()); assert.equal(f.bridge.serverRetryAt, 400_000);
});

test('backwards clocks release failure backoff and a new room never inherits its old cooldown', async t => {
  const f = await fixture(t, {fetch: async url => !url.endsWith('/status') ? response(roomReply) : response({}, 429)});
  await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.refreshRoom()); f.advance(-10_000);
  await assert.rejects(f.bridge.refreshRoom()); assert.equal(f.requests.length, 3);
  await f.bridge.leaveRoom(); await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.refreshRoom());
  assert.equal(f.requests.length, 6);
});

test('settings failures retain actionable OS codes without including private paths', async t => {
  const f = await fixture(t); const events = []; f.bridge.record = (event, fields) => events.push({event, fields});
  f.bridge.io = {...fs, open: async () => {throw Object.assign(new Error('private file path'), {code: 'ENOSPC'});}};
  assert.equal(await f.bridge.persist(), false);
  const saved = events.find(item => item.event === 'settings_failed');
  assert.equal(saved.fields.code, 'ENOSPC'); assert.equal(saved.fields.operation, 'save'); assert.ok(!JSON.stringify(saved).includes('private'));
});

async function fixture(t, options = {}) {
  const testRoot = path.resolve(__dirname, '.tmp');
  await fs.mkdir(testRoot, { recursive: true });
  const root = await fs.mkdtemp(path.join(testRoot, 'bridge-'));
  t.after(() => { assert.ok(path.resolve(root).startsWith(`${testRoot}${path.sep}`)); return fs.rm(root, { recursive: true, force: true }); });
  const nativeDir = path.join(root, 'native'), installDir = path.join(root, 'Image-Line', 'FL Studio 2026');
  await fs.mkdir(nativeDir); await fs.mkdir(installDir, { recursive: true });
  await fs.writeFile(path.join(nativeDir, 'flim.exe'), 'test fixture');
  await fs.writeFile(path.join(nativeDir, 'flim_engine.dll'), 'test fixture');
  const calls = [], requests = [], copied = [], scanned = [];
  let supported = true, tick = 100_000;
  const bridge = new DesktopBridge({
    nativeDir, preferencesFile: path.join(root, 'settings', 'preferences.json'), platform: 'win32',
    defaultSampleDirectory: path.join(root, 'samples'), peerFiles: options.peerFiles,
    environment: { ProgramFiles: root, ProgramW6432: root, SystemRoot: 'C:\\Windows', PATH: 'C:\\Windows', FLIM_OWNER_KEY: 'global-secret', FLIM_AUTOCONNECT: 'wss://evil.invalid', CLOUDFLARE_API_TOKEN: 'never-inherit', NODE_OPTIONS: '--require injected.cjs' },
    io: {...fs, readdir: async (...args) => { scanned.push(args[0]); return fs.readdir(...args); }},
    run: async (file, args, settings) => {
      calls.push({ file, args, settings });
      if (args[0] === '--desktop' && options.launch) return options.launch(file, args, settings);
      if (args[0] === '--inspect-json' && options.inspect) return options.inspect(args[1]);
      return JSON.stringify(args[0] === '--inspect-json' ? { path: args[1], version: '26.1.7.5654', supported, reason: supported ? '' : 'Build has no verified profile.' } : { launched: true, pid: 321 });
    },
    fetch: async (url, settings) => { requests.push({ url, settings }); return options.fetch ? options.fetch(url, settings) : response(url.endsWith('/status') ? activeStatus('26.1.7.5654') : roomReply); },
    chooseDirectory: async () => installDir,
    copyText: text => copied.push(text),
    now: () => tick,
  });
  await bridge.initialize();
  const input = { name: 'Producer', installId: bridge.state().selectedInstallId };
  return { bridge, input, root, nativeDir, installDir, calls, requests, copied, scanned, support: value => { supported = value; }, advance: value => { tick += value; } };
}

test('direct file session credentials are per launch and the confirmed FL pid keeps its broker alive', async t => {
  let prepared, launched;
  const env = {FLIM_PEER_URL: 'http://127.0.0.1:12345', FLIM_PEER_TOKEN: 'c'.repeat(64)};
  const f = await fixture(t, {peerFiles: {prepare: async code => {prepared = code; return {env, launched: pid => {launched = pid;}};}}});
  await f.bridge.createRoom(f.input); await f.bridge.launchFL();
  assert.equal(prepared, '12345678'); assert.equal(launched, 321);
  assert.equal(f.calls.at(-1).settings.env.FLIM_PEER_TOKEN, env.FLIM_PEER_TOKEN);
  assert.equal(f.calls.at(-1).settings.env.FLIM_PEER_URL, env.FLIM_PEER_URL);
  assert.ok(!JSON.stringify(f.bridge.state()).includes(env.FLIM_PEER_TOKEN));
});
test('unavailable direct file service leaves normal R2-backed native launch usable', async t => {
  const f = await fixture(t, {peerFiles: {prepare: async () => {throw new Error('Unavailable');}}});
  await f.bridge.createRoom(f.input); await f.bridge.launchFL(); assert.equal(f.bridge.room.state, 'launched');
  assert.equal(f.calls.at(-1).settings.env.FLIM_PEER_TOKEN, undefined);
});
test('confirmed native launch failure cancels the staged peer session while uncertain launch retains it', async t => {
  for (const code of ['native_failed', 'native_uncertain']) {
    let canceled = 0;
    const f = await fixture(t, {launch: async () => {throw new BridgeError('Failed', code);}, peerFiles: {prepare: async () => ({env: {}, cancel: () => {canceled++;}})}});
    await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.launchFL()); assert.equal(canceled, code === 'native_failed' ? 1 : 0);
  }
});
test('launch binds the chosen sample folder to its FL process without inheriting an environment override', async t => {
  const f = await fixture(t); const directory = path.join(f.root, 'received'); await fs.mkdir(directory);
  f.bridge.chooseSampleDirectory = async () => directory; f.bridge.environment.FLIM_SAMPLE_DIR = 'D:\\untrusted';
  await f.bridge.changeSampleLocation(); await f.bridge.createRoom(f.input); await f.bridge.launchFL();
  const launch = f.calls.find(call => call.args[0] === '--desktop');
  assert.equal(launch.settings.env.FLIM_SAMPLE_DIR, await fs.realpath(directory));
  assert.equal(f.calls[0].settings.env.FLIM_SAMPLE_DIR, undefined);
  assert.equal(f.bridge.room.sampleDirectory, await fs.realpath(directory));
  assert.equal(Object.hasOwn(f.bridge.state().room, 'sampleDirectory'), false);
});
test('unavailable chosen storage prevents starting FL without marking its launch uncertain or ending its room', async t => {
  const f = await fixture(t); f.bridge.sampleDirectory = path.join(f.root, 'missing'); await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.launchFL(), /samples folder or its drive is no longer available/);
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
  assert.equal(f.bridge.room.state, 'ready'); assert.equal(f.bridge.room.status, 'waiting'); assert.equal(f.bridge.busy, false);
});
test('a failed launch retains its prepared folder so opening the folder matches the pending FL session', async t => {
  const f = await fixture(t, {launch: async () => {throw new BridgeError('Launch failed', 'native_failed');}});
  await f.bridge.createRoom(f.input); await assert.rejects(f.bridge.launchFL(), /Launch failed/);
  assert.equal(f.bridge.getSampleLocation().path, f.calls.at(-1).settings.env.FLIM_SAMPLE_DIR);
  assert.equal(f.bridge.room.state, 'ready');
});
test('status retries one temporary transport or service failure without creating another room', async t => {
  for (const failure of ['network', 502, 503, 504]) {
    let attempts = 0;
    const f = await fixture(t, {fetch: async url => {
      if (!url.endsWith('/status')) return response(roomReply);
      if (++attempts === 1) { if (failure === 'network') throw new TypeError('connection reset'); return new Response('<html>Temporary outage</html>', {status: failure}); }
      return response(activeStatus('26.1.7.5654'));
    }});
    await f.bridge.createRoom(f.input);
    assert.equal((await f.bridge.refreshRoom()).room.status, 'active');
    assert.equal(attempts, 2); assert.equal(f.requests.filter(request => request.url.endsWith('/rooms')).length, 1);
  }
});

test('retries remain bounded and do not retry room creation, unavailable rooms or quota responses', async t => {
  for (const status of [404, 429, 503]) {
    const f = await fixture(t, {fetch: async () => response({code: status === 404 ? 'room_unavailable' : status === 429 ? 'room_rate_limit' : 'unknown'}, status)});
    await assert.rejects(f.bridge.createRoom(f.input)); assert.equal(f.requests.length, 1);
  }
  const f = await fixture(t, {fetch: async url => url.endsWith('/status') ? new Response('unavailable', {status: 503}) : response(roomReply)});
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.refreshRoom(), /relay is unavailable/);
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 2);
  assert.equal(f.bridge.state().room.status, 'waiting');
});

test('leaving during retry backoff cancels the next status request', async t => {
  let first;
  const received = new Promise(resolve => { first = resolve; });
  const f = await fixture(t, {fetch: async url => {
    if (!url.endsWith('/status')) return response(roomReply);
    first(); return response({}, 503);
  }});
  await f.bridge.createRoom(f.input);
  const refresh = f.bridge.refreshRoom(); await received;
  await f.bridge.leaveRoom(); await refresh;
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 1);
  assert.equal(f.bridge.state().room, null);
});

test('room number normalization matches the renderer without accepting extra text', async () => {
  const {validateCode, cleanCodeInput} = await import('../src/utils/roomUI.js');
  for (const value of ['１２３４ ５６７８', '١٢٣٤-٥٦٧٨', '۱۲۳۴–۵۶۷۸', '\n1234\u00a05678\t', '1234\u20095678']) {
    assert.equal(validateCode(value), ''); assert.equal(roomCode(value), '12345678');
    assert.equal(cleanCodeInput(value).replace(/\D/g, ''), '12345678');
  }
  for (const value of ['abc12345678', '123456789', '1234567']) {
    assert.notEqual(validateCode(value), ''); assert.throws(() => roomCode(value));
  }
});

test('discovery scans aliased Program Files roots only once', async t => {
  const f = await fixture(t);
  assert.deepEqual(f.scanned, [path.join(f.root, 'Image-Line')]);
  assert.equal(f.calls.filter(call=>call.args[0]==='--inspect-json').length, 1);
});

test('rescanning rechecks updated files without changing the selected folder or installation ID', async t => {
  const f = await fixture(t);
  f.support(false);
  const unsupported = await f.bridge.rescanInstalls(f.input.installId);
  assert.equal(unsupported.selectedInstallId, f.input.installId);
  assert.equal(unsupported.installs[0].supported, false);
  f.support(true);
  assert.equal((await f.bridge.rescanInstalls(f.input.installId)).installs[0].supported, true);
  assert.equal(f.requests.length, 0);
});

test('rescanning discovers new copies, removes unreadable ones and explains a lost selection', async t => {
  const f = await fixture(t);
  await fs.mkdir(path.join(f.root, 'Image-Line', 'FL Studio 2025'));
  f.bridge.run = async (_file, args) => {
    if (sameDirectory(args[1], f.installDir)) throw new Error('Installation is gone');
    return JSON.stringify({path: args[1], version: '25.2.5.5319', supported: true, reason: ''});
  };
  const state = await f.bridge.rescanInstalls(f.input.installId);
  assert.equal(state.installs.length, 1);
  assert.equal(state.installs[0].version, '25.2.5.5319');
  assert.notEqual(state.selectedInstallId, f.input.installId);
  assert.match(state.notice, /could no longer be checked/);
  function sameDirectory(a, b) { return path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase(); }
});

test('rescanning retains an unsaved form selection and is blocked during a room', async t => {
  const f = await fixture(t);
  const other = path.join(f.root, 'Image-Line', 'FL Studio 2025');
  await fs.mkdir(other);
  let state = await f.bridge.rescanInstalls();
  const chosen = state.installs.find(install => install.path === other);
  state = await f.bridge.rescanInstalls(chosen.id);
  assert.equal(state.selectedInstallId, chosen.id);
  await f.bridge.createRoom({...f.input, installId: chosen.id});
  await assert.rejects(f.bridge.rescanInstalls(), /Return to start/);
  assert.equal(f.bridge.state().room.code, roomReply.room);
});

test('folder dialog starts at the form selection even when it is canceled', async t => {
  const f = await fixture(t);
  let suggested;
  f.bridge.chooseDirectory = async directory => { suggested = directory; return null; };
  await f.bridge.chooseInstall(f.input.installId);
  assert.equal(suggested, f.installDir);
});

test('manual status retry bypasses the automatic cache after one second while deduplicating bursts', async t => {
  let fail = true;
  const f = await fixture(t, {fetch: async url => !url.endsWith('/status') ? response(roomReply)
    : fail ? response({code: 'room_rate_limit'}, 429) : response(activeStatus('26.1.7.5654'))});
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  fail = false;
  await assert.rejects(f.bridge.refreshRoom({force: true}), /wait a little/);
  f.advance(1000);
  assert.equal((await f.bridge.refreshRoom({force: true})).room.status, 'active');
  await f.bridge.refreshRoom({force: true});
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 2);
});

test('people freshness records successful responses rather than cached attempts or failed requests', async t => {
  let fail = false;
  const f = await fixture(t, {fetch: async url => !url.endsWith('/status') ? response(roomReply)
    : fail ? response({code: 'room_rate_limit'}, 429) : response(activeStatus('26.1.7.5654'))});
  await f.bridge.createRoom(f.input);
  assert.equal(f.bridge.state().room.statusUpdatedAt, null);
  assert.equal((await f.bridge.refreshRoom()).room.statusUpdatedAt, 100_000);
  f.advance(1000);
  assert.equal((await f.bridge.refreshRoom()).room.statusUpdatedAt, 100_000);
  f.advance(10_000); fail = true;
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  assert.equal(f.bridge.state().room.statusUpdatedAt, 100_000);
});

test('launch invalidates a pending lookup before it can falsely end the current room', async t => {
  let finish, signal;
  const f = await fixture(t, {fetch: async (url, settings) => {
    if (!url.endsWith('/status')) return response(roomReply);
    signal = settings.signal;
    return new Promise(resolve => { finish = () => resolve(response({code: 'room_unavailable'}, 404)); });
  }});
  await f.bridge.createRoom(f.input);
  const pending = f.bridge.refreshRoom();
  await f.bridge.launchFL();
  assert.equal(signal.aborted, true);
  finish(); await pending;
  assert.equal(f.bridge.state().room.status, 'waiting');
  assert.equal(f.bridge.state().room.state, 'launched');
});

test('clipboard paste reads only on request, validates bounded room numbers and hides invalid clipboard text', async t => {
  const f = await fixture(t);
  let reads = 0, contents = ' 1234-5678\n';
  f.bridge.readText = () => { reads++; return contents; };
  assert.equal(reads, 0);
  assert.deepEqual(await f.bridge.pasteRoomCode(), {code: '12345678'});
  assert.equal(reads, 1);
  for (contents of ['private contents', '1234567', '123456789', '9'.repeat(100_000)])
    await assert.rejects(f.bridge.pasteRoomCode(), error => error.message === 'Copy an eight-digit room number, then paste again.');
  assert.equal(f.requests.length, 0);
});

test('clipboard copy failure is awaited without making the bridge busy or canceling a people request', async t => {
  const f = await fixture(t);
  await f.bridge.createRoom(f.input);
  f.bridge.copyText = async () => { throw new Error('Clipboard is unavailable'); };
  await assert.rejects(f.bridge.copyInvite(), /Select and copy the room number/);
  assert.equal(f.bridge.state().busy, false);
  assert.equal((await f.bridge.refreshRoom()).room.status, 'active');
});

test('discovery checks installations concurrently within a fixed limit and retains order', async t => {
  let active = 0, peak = 0;
  const f = await fixture(t, { inspect: async directory => {
    active++; peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, directory.endsWith('2026') ? 30 : 5));
    active--;
    if(directory.endsWith('Broken')) throw new Error('Broken installation');
    return JSON.stringify({path:directory,version:'26.1.7.5654',supported:true,reason:''});
  }});
  for(const name of ['FL Studio 2024','FL Studio 2025','FL Studio 2027','FL Studio Broken'])
    await fs.mkdir(path.join(f.root,'Image-Line',name));
  const state = await f.bridge.initialize();
  assert.equal(peak,3); assert.equal(active,0); assert.equal(state.installs.length,4);
  assert.equal(state.selectedInstallId,f.input.installId);
  assert.deepEqual(f.scanned,[path.join(f.root,'Image-Line'),path.join(f.root,'Image-Line')]);
  assert.equal(f.calls.filter(call=>call.args[0]==='--inspect-json').length,6);
});

test('a throttled retry preserves the failure until a real status lookup succeeds', async t => {
  let fail = true;
  const f = await fixture(t, { fetch: async url => !url.endsWith('/status') ? response(roomReply) : fail
    ? response({code:'room_rate_limit'},429)
    : response({room:roomReply.room,state:'active',peers:[],maxParticipants:8}) });
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  fail = false;
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  assert.equal(f.requests.length,2);
  f.advance(5000);
  assert.equal((await f.bridge.refreshRoom()).room.status,'active');
  assert.equal(f.requests.length,3);
});

test('a backwards system-clock change does not freeze room status polling', async t => {
  const f = await fixture(t, { fetch: async url => response(url.endsWith('/status')
    ? {room: roomReply.room, state: 'active', peers: [], maxParticipants: 8} : roomReply) });
  await f.bridge.createRoom(f.input);
  await f.bridge.refreshRoom();
  f.advance(-60_000);
  await f.bridge.refreshRoom();
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 2);
  await f.bridge.refreshRoom();
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 2);
});

test('canceling the folder picker preserves the installation selected in the form', async t => {
  const f = await fixture(t);
  const other = {...f.bridge.installs.get(f.input.installId), id: 'other-install', path: path.join(f.root, 'other')};
  f.bridge.installs.set(other.id, other);
  f.bridge.chooseDirectory = async () => null;
  assert.equal((await f.bridge.chooseInstall(other.id)).selectedInstallId, other.id);
  assert.equal((await f.bridge.chooseInstall('unknown-id')).selectedInstallId, other.id);
  assert.equal(f.requests.length, 0);
});

test('settings-write failures preserve the previous file and allow the room session to continue', async t => {
  const f = await fixture(t);
  await f.bridge.savePreferences(f.input);
  const previous = await fs.readFile(f.bridge.preferencesFile, 'utf8');
  const rename = f.bridge.io.rename;
  f.bridge.io = {...f.bridge.io, rename: async () => { throw new Error('disk unavailable'); }};
  const room = await f.bridge.createRoom({...f.input, name: 'Changed name'});
  assert.match(room.notice, /settings could not be saved/);
  assert.equal(room.room.code, roomReply.room);
  assert.equal(await fs.readFile(f.bridge.preferencesFile, 'utf8'), previous);
  await assert.rejects(fs.stat(`${f.bridge.preferencesFile}.tmp`), {code: 'ENOENT'});
  assert.match((await f.bridge.launchFL()).notice, /settings could not be saved/);
  await f.bridge.leaveRoom();
  f.bridge.io = {...f.bridge.io, rename};
  assert.equal((await f.bridge.savePreferences({...f.input, name: 'Changed name'})).notice, '');
  assert.equal(JSON.parse(await fs.readFile(f.bridge.preferencesFile, 'utf8')).name, 'Changed name');
});

test('oversized declared responses stop the body download before parsing', async t => {
  let canceled = 0;
  const f = await fixture(t, { fetch: async () => new Response(new ReadableStream({
    cancel() { canceled++; },
  }), {headers: {'content-length': '10000000'}}) });
  await assert.rejects(f.bridge.createRoom(f.input), /invalid response/);
  assert.equal(canceled, 1);
  assert.equal(f.bridge.state().room, null);
});

test('leaving aborts the old status lookup and a new room can refresh immediately', async t => {
  let finishOld, finishNew, oldSignal;
  const second = {...roomReply,room:'87654321',websocket:'/room/87654321'};
  let created = 0;
  const f = await fixture(t,{fetch:async (url,settings)=>{
    if(url.endsWith('/cancel')) return response({released:true});
    if(!url.endsWith('/status')) return response(created++ ? second : roomReply);
    const code = JSON.parse(settings.body).room;
    return new Promise(resolve=>{
      if(code===roomReply.room) {oldSignal=settings.signal;finishOld=()=>resolve(response({room:code,state:'active',peers:[],maxParticipants:8}));}
      else finishNew=()=>resolve(response({room:code,state:'active',peers:[],maxParticipants:8}));
    });
  }});
  await f.bridge.createRoom(f.input);
  const old = f.bridge.refreshRoom();
  await f.bridge.leaveRoom();
  assert.equal(oldSignal.aborted,true);
  await f.bridge.createRoom(f.input);
  const current = f.bridge.refreshRoom();
  assert.equal(typeof finishNew,'function');
  finishOld(); await old;
  const overlapping = f.bridge.refreshRoom();
  assert.equal(f.requests.filter(request=>request.url.endsWith('/status')).length,2);
  finishNew();
  assert.equal((await current).room.code,second.room);
  assert.equal((await overlapping).room.status,'active');
});

test('returning after a failed launch releases only the host pending reservation', async t => {
  const f = await fixture(t, { launch: async () => { throw new BridgeError('Failed safely', 'native_failed'); } });
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.launchFL(), /Failed safely/);
  await f.bridge.leaveRoom();
  const cancel = f.requests.find(request => request.url.endsWith('/cancel'));
  assert.deepEqual(JSON.parse(cancel.settings.body), { room: roomReply.room, hostToken: TICKET });
  assert.equal(f.bridge.state().room, null);
  assert.equal(f.bridge.state().notice, '');
  assert.ok(!JSON.stringify(f.bridge.state()).includes(TICKET));
});

for (const kind of ['member', 'launched', 'uncertain']) test(`returning from ${kind} does not cancel the FL session`, async t => {
  const f = await fixture(t, { launch: kind === 'uncertain' ? async () => { throw new BridgeError('Unknown startup'); } : undefined });
  if (kind === 'member') await f.bridge.joinRoom({ ...f.input, code: roomReply.room });
  else {
    await f.bridge.createRoom(f.input);
    if (kind === 'uncertain') await assert.rejects(f.bridge.launchFL());
    else await f.bridge.launchFL();
  }
  await f.bridge.leaveRoom();
  assert.equal(f.requests.filter(request => request.url.endsWith('/cancel')).length, 0);
});

test('offline cancellation returns to start with an expiry notice and clears it on the next action', async t => {
  const f = await fixture(t, { fetch: async url => { if(url.endsWith('/cancel')) throw new Error('offline'); return response(roomReply); } });
  await f.bridge.createRoom(f.input);
  const state = await f.bridge.leaveRoom();
  assert.equal(state.room, null);
  assert.match(state.notice, /expire automatically/);
  assert.equal((await f.bridge.createRoom(f.input)).notice, '');
});

test('malformed status peers cannot replace a previously verified participant list', async t => {
  let peers = [{id:'host',name:'Producer',role:'leader',fl:'26.1.7.5654'}];
  const f = await fixture(t,{fetch:async url=>response(url.endsWith('/status') ? {room:roomReply.room,state:'active',peers,maxParticipants:8} : roomReply)});
  await f.bridge.createRoom(f.input); await f.bridge.refreshRoom();
  for(const invalid of [[null],[{...peers[0],role:'fake'}],[peers[0],peers[0]]]) {
    peers=invalid; f.advance(10_000);
    await assert.rejects(f.bridge.refreshRoom(),/invalid room status/);
    assert.equal(f.bridge.state().room.peers[0].name,'Producer');
    assert.equal(f.bridge.state().room.peers.length,1);
  }
});

test('a response stream failure produces a useful connection error', async t => {
  const f=await fixture(t,{fetch:async()=>new Response(new ReadableStream({start(controller){controller.error(new Error('socket reset'));}}))});
  await assert.rejects(f.bridge.createRoom(f.input),/Check your connection/);
  assert.equal(f.bridge.state().room,null);
});

test('names and room numbers are bounded and cannot become paths or command arguments', () => {
  assert.equal(displayName('  Cashflow  🎹 Beatz  '), 'Cashflow Beatz');
  assert.equal(displayName('Музыка 12'), 'Музыка 12');
  assert.equal(roomCode('1234 5678'), '12345678');
  assert.equal(roomCode('1234-5678'), '12345678');
  for (const value of ['../../01', '1234567', '123456789', 'https://evil/12345678', 12345678]) assert.throws(() => roomCode(value));
  assert.throws(() => displayName(' 🎹 !!! '));
  assert.throws(() => displayName('a'.repeat(129)));
});

test('only the owning window main frame may invoke the bridge', () => {
  const frame = { url: 'file:///app/dist/index.html' }, contents = { mainFrame: frame };
  assert.equal(trustedSender({ sender: contents, senderFrame: frame }, contents, frame.url), true);
  assert.equal(trustedSender({ sender: contents, senderFrame: { url: frame.url } }, contents, frame.url), false);
  assert.equal(trustedSender({ sender: {}, senderFrame: frame }, contents, frame.url), false);
  assert.equal(trustedSender({ sender: contents, senderFrame: frame }, contents, 'https://evil.invalid'), false);
});

test('launch environment excludes global keys and process injection settings', () => {
  const environment = childEnvironment({ Path: 'C:\\Windows', FLIM_OWNER_KEY: 'global', FLIM_PASSWORD: 'old', NODE_OPTIONS: 'bad', OPENAI_API_KEY: 'bad' },
    { code: '12345678', role: 'member', password: PASSWORD }, 'Player');
  assert.deepEqual(environment, { Path: 'C:\\Windows', FLIM_NAME: 'Player', FLIM_AUTOCONNECT: 'wss://flim-relay.cashflowbeatz.workers.dev/room/12345678', FLIM_PASSWORD: PASSWORD, FLIM_HOST: '0' });
});

test('host credentials stay in memory and only a bundled strict launcher gets them', async t => {
  const f = await fixture(t);
  const state = await f.bridge.createRoom({ ...f.input, executable: 'evil.exe', url: 'https://evil.invalid' });
  assert.equal(state.room.code, '12345678');
  assert.equal(state.room.role, 'host');
  assert.equal(state.room.expiresAt, roomReply.expiresAt);
  assert.ok(!JSON.stringify(state).includes(PASSWORD)); assert.ok(!JSON.stringify(state).includes(TICKET));
  assert.deepEqual(JSON.parse(await fs.readFile(f.bridge.preferencesFile, 'utf8')), { name: 'Producer', flPath: f.installDir, flPaths: [] });
  assert.equal(f.requests[0].url, `${RELAY}/rooms`);
  assert.equal(f.requests[0].settings.redirect, 'error');
  assert.deepEqual(JSON.parse(f.requests[0].settings.body), {});
  await f.bridge.copyInvite(); assert.deepEqual(f.copied, ['12345678']);
  const launched = await f.bridge.launchFL();
  assert.equal(launched.room.state, 'launched');
  const command = f.calls.at(-1);
  assert.equal(command.file, path.join(f.nativeDir, 'flim.exe'));
  assert.deepEqual(command.args, ['--desktop', '--fl-dir', f.installDir]);
  assert.equal(command.settings.env.FLIM_OWNER_KEY, TICKET);
  assert.equal(command.settings.env.FLIM_PASSWORD, PASSWORD);
  assert.equal(command.settings.env.CLOUDFLARE_API_TOKEN, undefined);
  assert.equal(command.settings.env.NODE_OPTIONS, undefined);
  assert.equal(command.settings.shell, false);
  assert.equal(command.settings.timeout, 0);
  assert.ok(!JSON.stringify(command.args).includes(PASSWORD));
  await assert.rejects(f.bridge.launchFL(), /already been opened/);
});

test('members receive no hosting capability and join through a normalized room number', async t => {
  const f = await fixture(t);
  const state = await f.bridge.joinRoom({ ...f.input, code: '1234 5678' });
  assert.equal(state.room.role, 'member');
  assert.equal(f.requests[0].url, `${RELAY}/rooms/join`);
  assert.deepEqual(JSON.parse(f.requests[0].settings.body), { room: '12345678' });
  await f.bridge.launchFL();
  assert.equal(f.calls.at(-1).settings.env.FLIM_OWNER_KEY, undefined);
  assert.equal(f.calls.at(-1).settings.env.FLIM_HOST, '0');
});

test('renderer cannot supply a custom executable or unregistered FL path', async t => {
  const f = await fixture(t);
  await assert.rejects(f.bridge.createRoom({ name: 'Producer', installId: 'C:\\evil.exe', flPath: f.installDir }), /Choose your FL Studio/);
  assert.equal(f.requests.length, 0);
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
});

test('a changed or unsupported installation is rejected before room allocation and again before launch', async t => {
  const f = await fixture(t); f.support(false);
  await assert.rejects(f.bridge.createRoom(f.input), /verified profile/);
  assert.equal(f.requests.length, 0);
  f.support(true); await f.bridge.createRoom(f.input); f.support(false);
  await assert.rejects(f.bridge.launchFL(), /verified profile/);
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
});

test('overlapping actions allocate only one room and cannot change identity midway', async t => {
  let release;
  const f = await fixture(t, { fetch: () => new Promise(resolve => { release = () => resolve(response(roomReply)); }) });
  const first = f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.createRoom(f.input), /current step/);
  await assert.rejects(f.bridge.savePreferences({ ...f.input, name: 'Changed' }), /current step/);
  for (let attempt = 0; !release && attempt < 100; attempt++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(typeof release, 'function');
  release(); await first;
  assert.equal(f.requests.length, 1);
  await assert.rejects(f.bridge.savePreferences({ ...f.input, name: 'Changed' }), /Leave this room/);
});

test('malformed relay paths, wrong rooms, and oversized responses never become launch capabilities', async t => {
  for (const reply of [{ ...roomReply, websocket: 'wss://evil.invalid/room/12345678' }, { ...roomReply, room: '87654321' }, { ...roomReply, password: 'x'.repeat(20000) }]) {
    const f = await fixture(t, { fetch: async () => response(reply) });
    await assert.rejects(f.bridge.joinRoom({ ...f.input, code: '12345678' }));
    assert.equal(f.bridge.state().room, null);
    await assert.rejects(f.bridge.launchFL(), /Create or join/);
  }
});

test('server errors are translated without displaying response secrets', async t => {
  const f = await fixture(t, { fetch: async () => response({ code: 'room_not_ready', error: `secret ${TICKET}` }, 409) });
  await assert.rejects(f.bridge.joinRoom({ ...f.input, code: '12345678' }), error => /still opening FL Studio/.test(error.message) && !error.message.includes(TICKET));
  assert.equal(f.bridge.state().room, null);
});

test('status polling is authenticated, throttled and excluded from persistent preferences', async t => {
  const f = await fixture(t, { fetch: async url => url.endsWith('/status')
    ? response({ room: '12345678', state: 'active', maxParticipants: 8, peers: [{ id: 'host', name: 'Producer', role: 'leader', fl: '26.1.7.5654' }] })
    : response(roomReply) });
  await f.bridge.createRoom(f.input);
  const result = await f.bridge.refreshRoom();
  assert.equal(result.room.status, 'active');
  assert.equal(result.room.peers[0].role, 'host');
  assert.equal(result.room.peers[0].name, 'Producer');
  assert.deepEqual(JSON.parse(f.requests.at(-1).settings.body), { room: '12345678', password: PASSWORD });
  await f.bridge.refreshRoom(); assert.equal(f.requests.length, 2);
  f.advance(10_000); await f.bridge.refreshRoom(); assert.equal(f.requests.length, 3);
  await f.bridge.leaveRoom(); assert.equal(f.bridge.state().room, null);
  await assert.rejects(f.bridge.copyInvite(), /Create or join/);
  assert.ok(!(await fs.readFile(f.bridge.preferencesFile, 'utf8')).includes(PASSWORD));
});

test('an old status reply cannot restore a room after the user leaves', async t => {
  let release;
  const f = await fixture(t, { fetch: async url => url.endsWith('/status') ? new Promise(resolve => { release = () => resolve(response({ room: '12345678', state: 'active', peers: [] })); }) : response(roomReply) });
  await f.bridge.createRoom(f.input);
  const pending = f.bridge.refreshRoom();
  await f.bridge.leaveRoom(); release(); await pending;
  assert.equal(f.bridge.state().room, null);
});

test('a pending room with no peers stays ready and keeps its ISO expiration', async t => {
  const f = await fixture(t, { fetch: async url => url.endsWith('/status') ? response({ room: roomReply.room, state: 'waiting', peers: [], maxParticipants: 8, expiresAt: roomReply.expiresAt }) : response(roomReply) });
  await f.bridge.createRoom(f.input);
  const state = await f.bridge.refreshRoom();
  assert.equal(state.room.state, 'ready'); assert.equal(state.room.status, 'waiting');
  assert.equal(state.room.expiresAt, roomReply.expiresAt); assert.deepEqual(state.room.peers, []);
});

test('expired reservations are explained before starting a process', async t => {
  const f = await fixture(t, { fetch: async () => response({ ...roomReply, expiresAt: '1970-01-01T00:00:01.000Z' }) });
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.launchFL(), /reservation expired/);
  assert.equal(f.bridge.state().room.status, 'ended');
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
});

test('ended status clears peers and stops automatic lookups', async t => {
  const f = await fixture(t, { fetch: async url => url.endsWith('/status') ? response({ code: 'room_unavailable' }, 404) : response(roomReply) });
  await f.bridge.createRoom(f.input);
  const state = await f.bridge.refreshRoom();
  assert.equal(state.room.status, 'ended'); assert.deepEqual(state.room.peers, []);
  f.advance(30_000); await f.bridge.refreshRoom(); assert.equal(f.requests.length, 2);
  await assert.rejects(f.bridge.launchFL(), /room has ended/);
});

test('failed status lookup does not falsely report that the live room ended', async t => {
  const f = await fixture(t, { fetch: async url => url.endsWith('/status') ? response({ code: 'room_rate_limit' }, 429) : response(roomReply) });
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  assert.equal(f.bridge.state().room.status, 'waiting');
  assert.equal(f.bridge.state().room.state, 'ready');
});

test('launch waits for native completion and blocks simultaneous duplicate launches', async t => {
  let finish;
  const f = await fixture(t, { launch: () => new Promise(resolve => { finish = () => resolve(JSON.stringify({ launched: true, pid: 123 })); }) });
  await f.bridge.createRoom(f.input);
  const pending = f.bridge.launchFL();
  for (let attempt = 0; !finish && attempt < 100; attempt++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(typeof finish, 'function');
  assert.equal(f.bridge.state().busy, true); assert.equal(f.bridge.state().room.state, 'ready');
  await assert.rejects(f.bridge.launchFL(), /current step/);
  finish(); const state = await pending;
  assert.equal(state.busy, false); assert.equal(state.room.state, 'launched');
  assert.equal(state.room.status, 'waiting');
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 1);
});

test('unconfirmed launches cannot silently start another FL instance', async t => {
  const f = await fixture(t, { launch: async () => 'truncated response' });
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.launchFL(), /did not confirm/);
  assert.equal(f.bridge.state().room.state, 'uncertain');
  await assert.rejects(f.bridge.launchFL(), /previous launch/);
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 1);
});

test('a confirmed native failure can be retried after correction', async t => {
  const f = await fixture(t, { launch: async () => { throw new BridgeError('The selected installation was removed.', 'native_failed'); } });
  await f.bridge.createRoom(f.input);
  await assert.rejects(f.bridge.launchFL(), /installation was removed/);
  assert.equal(f.bridge.state().room.state, 'ready');
  assert.equal(f.bridge.state().busy, false);
});

test('preload exposes only explicit methods and normalizes Electron error messages', async () => {
  let exposed, exposedName;
  const invocations = [];
  vm.runInNewContext(await fs.readFile(path.join(__dirname, '../electron/preload.cjs'), 'utf8'), {
    require: name => {
      assert.equal(name, 'electron');
      return {
        contextBridge: { exposeInMainWorld: (name, api) => { exposedName = name; exposed = api; } },
        ipcRenderer: { send: (channel, input) => invocations.push({channel, input}), invoke: async (channel, input) => {
          invocations.push({ channel, input });
          if (channel === 'flim:join-room') throw new Error("Error invoking remote method 'flim:join-room': Error: The host is still opening FL Studio.");
          return { platform: 'win32' };
        } },
      };
    },
  });
  assert.equal(exposedName, 'flimDesktop');
  assert.deepEqual(Object.keys(exposed).sort(), ['getSampleLocation', 'chooseSampleLocation', 'resetSampleLocation', 'chooseInstall', 'rescanInstalls', 'copyInvite', 'pasteRoomCode', 'createRoom', 'getState', 'getFileTransfers', 'openSampleFolder', 'joinRoom', 'launchFL', 'leaveRoom', 'refreshRoom', 'savePreferences', 'openLogs', 'reloadControls', 'reportError', 'fitWindow'].sort());
  assert.equal(Object.isFrozen(exposed), true);
  assert.equal((await exposed.getState()).platform, 'win32');
  await assert.rejects(exposed.joinRoom({ code: '12345678' }), error => error.message === 'The host is still opening FL Studio.');
  assert.equal(invocations[0].channel, 'flim:get-state');
  assert.equal(invocations[1].channel, 'flim:join-room');
  exposed.reportError({message: 'x'.repeat(5000), stack: 'y'.repeat(9000), token: PASSWORD});
  assert.equal(invocations[2].channel, 'flim:renderer-error');
  assert.equal(invocations[2].input.message.length, 2048);
  assert.equal(invocations[2].input.stack.length, 4096);
  assert.equal(invocations[2].input.token, undefined);
  for (const height of [null, undefined, '500', 0, -1, NaN, Infinity, 8193]) exposed.fitWindow(height);
  assert.equal(invocations.length, 3);
  exposed.fitWindow(600);
  assert.equal(invocations[3].channel, 'flim:fit-window');
  assert.equal(invocations[3].input, 600);
});

test('packaged main uses local renderer and external native resources with a locked-down window', async () => {
  const peer = {active: false, close: async () => {}}, peerOptions = {};
  const resources = path.resolve(__dirname, 'packaged resources');
  const directory = path.join(resources, 'app.asar', 'electron');
  const windows = [], handlers = new Map(), listeners = new Map(), events = [], opened = [], createdFolders = [];
  let bridgeOptions, permissionHandler, permissionCheck, headersHandler, stallLogs = false, initializeCalls = 0;
  const scheduledDelays = [];
  class FakeWindow extends EventEmitter {
    constructor(options) { super(); this.options = options; this.webContents = new EventEmitter(); this.webContents.mainFrame = { url: pathToFileURL(path.join(directory, '../dist/index.html')).href }; this.webContents.setWindowOpenHandler = callback => { this.openHandler = callback; }; windows.push(this); }
    removeMenu() { this.noMenu = true; }
    async loadURL(url) { this.url = url; }
    getBounds() {return this.bounds || {x: 100, y: 100, width: 536, height: 600};}
    getContentSize() {return [520, 561];}
    setBounds(bounds) {this.bounds = bounds;}
    isDestroyed() {return false;}
    isMinimized() {return true;}
    restore() {this.restored = true;}
    show() {this.shown = true; this.hidden = false;}
    hide() {this.hidden = true;}
    isVisible() {return !this.hidden;}
    focus() {this.focused = true;}
  }
  const fakeApp = new EventEmitter();
  Object.assign(fakeApp, { isPackaged: true, requestSingleInstanceLock: () => true, whenReady: async () => {}, getPath: () => path.join(resources, 'user-data'), getVersion: () => '0.2.6', quit: () => {} });
  class FakeBridge { constructor(options) { bridgeOptions = options; } async initialize() {if (++initializeCalls <= 2) throw new Error('private setup failure');} state() { return { nativeReady: true }; } async checkedSampleDirectory() {const directory = bridgeOptions.defaultSampleDirectory; createdFolders.push(directory); return directory;} }
  vm.runInNewContext(await fs.readFile(path.join(__dirname, '../electron/main.cjs'), 'utf8'), {
    __dirname: directory,
    setTimeout: (callback, delay) => {scheduledDelays.push(delay); return setTimeout(callback, 5);}, clearTimeout,
    process: { resourcesPath: resources, env: { FLIM_DESKTOP_DEV: '1' }, pid: 123, on() {} },
    require: name => {
      if (name === 'electron') return { app: fakeApp, BrowserWindow: FakeWindow, screen: {getPrimaryDisplay: () => ({workArea: {x:0,y:0,width:1920,height:1040}}), getDisplayMatching: () => ({workArea: {x:0,y:0,width:1920,height:1040}})}, clipboard: { writeText() {} }, shell: {openPath: async directory => {opened.push(directory); return '';}}, dialog: { showErrorBox: () => assert.fail('main startup failed') }, ipcMain: { on: (channel, fn) => listeners.set(channel, fn), handle: (channel, fn) => handlers.set(channel, fn) }, session: { defaultSession: {
        setPermissionRequestHandler: fn => { permissionHandler = fn; }, setPermissionCheckHandler: fn => { permissionCheck = fn; }, webRequest: { onHeadersReceived: fn => { headersHandler = fn; } },
      } } };
      if (name === './bridge-core.cjs') return { DesktopBridge: FakeBridge, BridgeError, trustedSender, RELAY };
      if (name === './window-fit.cjs') return require('../electron/window-fit.cjs');
      if (name === './renderer-recovery.cjs') return require('../electron/renderer-recovery.cjs');
      if (name === './file-transfers.cjs') return require('../electron/file-transfers.cjs');
      if (name === './setup.cjs') return require('../electron/setup.cjs');
      if (name === './single-flight.cjs') return require('../electron/single-flight.cjs');
      if (name === './peer-electron.cjs') return {createPeerFiles: options => {Object.assign(peerOptions, options); return peer;}};
      if (name === 'node:fs/promises') return {readFile: async () => Buffer.from('fixture'), mkdir: async directory => {createdFolders.push(directory);}};
      if (name === './diagnostics.cjs') return {createDiagnostics: async () => ({available: true, directory: 'owned-logs', nativeDirectory: 'owned-logs', record: (event, fields) => {events.push({event, fields});}, flush: () => stallLogs ? new Promise(() => {}) : Promise.resolve()})};
      return require(name);
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  const window = windows[0];
  fakeApp.emit('second-instance');
  assert.equal(window.restored, true); assert.equal(window.shown, true); assert.equal(window.focused, true);
  assert.equal(window.url, pathToFileURL(path.join(directory, '../dist/index.html')).href);
  assert.equal(bridgeOptions.nativeDir, path.join(resources, 'native'));
  assert.equal(window.options.webPreferences.preload, path.join(directory, 'preload.cjs'));
  assert.equal(window.options.webPreferences.contextIsolation, true);
  assert.equal(window.options.webPreferences.sandbox, true);
  assert.equal(window.options.webPreferences.nodeIntegration, false);
  assert.equal(window.options.webPreferences.devTools, false);
  assert.equal(window.noMenu, true);
  assert.equal(window.openHandler().action, 'deny');
  assert.equal(permissionCheck(), false);
  permissionHandler(null, 'media', approved => assert.equal(approved, false));
  headersHandler({ responseHeaders: {} }, result => assert.match(result.responseHeaders['Content-Security-Policy'][0], /connect-src 'none'/));
  const event = { sender: window.webContents, senderFrame: window.webContents.mainFrame };
  window.webContents.getZoomFactor = () => 1;
  assert.equal(window.options.maximizable, false);
  listeners.get('flim:fit-window')({...event, senderFrame: {url: window.url}}, 800);
  assert.equal(window.bounds, undefined);
  listeners.get('flim:fit-window')(event, '800');
  assert.equal(window.bounds, undefined);
  listeners.get('flim:fit-window')(event, 400);
  assert.equal(window.bounds.height, 439);
  await handlers.get('flim:open-logs')(event);
  assert.deepEqual(opened, ['owned-logs']); opened.length = 0; scheduledDelays.length = 0;
  assert.equal(initializeCalls, 1);
  await assert.rejects(handlers.get('flim:get-state')(event), error => error.message === 'That step could not be completed. Please try again.');
  assert.ok(events.some(entry => entry.event === 'ipc_error' && entry.fields.operation === 'get-state'));
  assert.equal((await handlers.get('flim:get-state')(event)).nativeReady, true);
  assert.equal(initializeCalls, 3);
  await assert.rejects(handlers.get('flim:get-state')({ sender: window.webContents, senderFrame: { url: window.url } }), /did not come from/);
  assert.deepEqual((await handlers.get('flim:get-file-transfers')(event)).items, []);
  for (const channel of ['flim:get-file-transfers', 'flim:open-sample-folder']) {
    await assert.rejects(handlers.get(channel)({sender: window.webContents, senderFrame: {url: window.url}}), /did not come from/);
  }
  await handlers.get('flim:open-sample-folder')(event, 'untrusted-path');
  const samplesFolder = path.join(resources, 'user-data', 'flim', 'samples');
  assert.deepEqual(createdFolders, [samplesFolder]); assert.deepEqual(opened, [samplesFolder]); opened.length = 0;
  await handlers.get('flim:open-logs')(event, 'untrusted-path');
  assert.deepEqual(opened, ['owned-logs']);
  stallLogs = true;
  await handlers.get('flim:open-logs')(event);
  assert.deepEqual(opened, ['owned-logs', 'owned-logs']);
  assert.deepEqual(scheduledDelays, [2000, 2000]);
  listeners.get('flim:renderer-error')(event, {message:'test failure',stack:'test stack'});
  const count = events.length;
  listeners.get('flim:renderer-error')({sender:window.webContents,senderFrame:{url:window.url}}, {message:'untrusted'});
  assert.equal(events.length, count);
  assert.equal(events.at(-1).event, 'renderer_error');
  assert.equal(bridgeOptions.nativeLogDir, 'owned-logs');
  assert.equal(peerOptions.relay, RELAY);
  let prevented = 0, quit = 0; fakeApp.quit = () => {quit++;};
  peer.active = true; window.emit('close', {preventDefault: () => {prevented++;}});
  assert.equal(prevented, 1); assert.equal(window.hidden, true); assert.equal(quit, 0);
  fakeApp.emit('second-instance'); assert.equal(window.hidden, false);
  window.hide(); peer.active = false; peerOptions.idle(); assert.equal(quit, 1);
  window.emit('close', {preventDefault: () => {prevented++;}}); assert.equal(prevented, 1);
});

test('explicit experimental candidates keep their opt-in separate from supported FL24', async t => {
  const f = await fixture(t, {inspect: directory => JSON.stringify({path:directory,version:'26.9.0.9999',supported:true,experimental:true,reason:'Test only'})});
  const events = []; f.bridge.record = (event, fields) => events.push({event, fields});
  f.bridge.nativeLogDir = path.join(f.root, 'owned-logs');
  f.bridge.environment.FLIM_LOG_DIR = 'untrusted-inherited';
  assert.equal(f.bridge.state().installs[0].experimental, true);
  await f.bridge.createRoom(f.input); await f.bridge.launchFL();
  assert.ok(f.calls.at(-1).args.includes('--allow-experimental'));
  assert.equal(f.calls.at(-1).settings.env.FLIM_LOG_DIR, f.bridge.nativeLogDir);
  assert.ok(events.some(item=>item.event==='launch_confirmed' && item.fields.pid===321 && item.fields.flVersion==='26.9.0.9999'));
  assert.ok(!JSON.stringify(events).includes(PASSWORD) && !JSON.stringify(events).includes(TICKET));
  assert.ok(!JSON.stringify(events).includes('12345678'));
});

test('supported FL24 launches without experimental flags', async t => {
  const f = await fixture(t, {inspect: directory => JSON.stringify({path:directory,version:'24.2.2.4597',supported:true,experimental:false,reason:''})});
  assert.equal(f.bridge.state().installs[0].experimental, false);
  await f.bridge.createRoom(f.input); await f.bridge.launchFL();
  assert.ok(!f.calls.at(-1).args.includes('--allow-experimental'));
  assert.equal(f.bridge.state().room.state, 'launched');
});

test('custom installations remain discoverable after choosing a different version', async t => {
  const f = await fixture(t);
  const other = path.join(f.root, 'custom-fl24'); await fs.mkdir(other);
  f.bridge.chooseDirectory = async () => other;
  await f.bridge.chooseInstall(); await f.bridge.savePreferences(f.input);
  assert.deepEqual(JSON.parse(await fs.readFile(f.bridge.preferencesFile,'utf8')).flPaths,[other]);
  const state = await f.bridge.initialize();
  assert.ok(state.installs.some(install=>install.path===other));
  assert.equal(state.selectedInstallId, f.input.installId);
});

test('diagnostic failures never block a room or native launch', async t => {
  const f = await fixture(t);
  f.bridge.record = () => {throw new Error('Disk is full');};
  await f.bridge.createRoom(f.input); await f.bridge.launchFL();
  assert.equal(f.bridge.state().room.state,'launched');
  f.bridge.record = () => Promise.reject(new Error('Disk is full'));
  f.bridge.log('test', {}); await new Promise(resolve=>setImmediate(resolve));
});

const versions = ['24.2.2.4597', '25.2.5.5319', '26.1.7.5654'];
for (const host of versions) for (const member of versions) {
  test(`portable member launch: FL${member} joining FL${host}`,async t=>{
    const f=await fixture(t,{
      inspect:directory=>JSON.stringify({path:directory,version:member,supported:true,experimental:false}),
      fetch:async url=>response(url.endsWith('/status')?{...activeStatus(host),portable_sync:1}:roomReply),
    });
    await f.bridge.joinRoom({...f.input,code:roomReply.room});
    await f.bridge.launchFL();
    assert.equal(f.bridge.state().room.state,'launched');
    assert.equal(f.calls.filter(call=>call.args[0]==='--desktop').length,1);
  });
}
for (const [hi, host] of versions.entries()) for (const [mi, member] of versions.entries()) {
  test(`member launch preflight: FL${member} joining FL${host}`, async t => {
    const f = await fixture(t, {
      inspect: directory => JSON.stringify({path: directory, version: member, supported: true, experimental: false, reason: ''}),
      fetch: async url => response(url.endsWith('/status') ? activeStatus(host) : roomReply),
    });
    await f.bridge.joinRoom({...f.input, code: roomReply.room});
    if (mi >= hi) { await f.bridge.launchFL(); assert.equal(f.bridge.state().room.state, 'launched'); }
    else {
      await assert.rejects(f.bridge.launchFL(), error => error.code === 'compatibility' && /update.*relay/i.test(error.message));
      assert.equal(f.bridge.state().room.state, 'ready');
    }
    assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, mi >= hi ? 1 : 0);
    const status = f.requests.find(request => request.url.endsWith('/status'));
    assert.deepEqual(JSON.parse(status.settings.body), {room: roomReply.room, password: PASSWORD});
  });
}

test('preflight compares patch/build numbers numerically and retries without opening a duplicate window', async t => {
  let host = '26.1.10.9';
  const f = await fixture(t, {
    inspect: directory => JSON.stringify({path: directory, version: '26.1.9.100', supported: true}),
    fetch: async url => response(url.endsWith('/status') ? activeStatus(host) : roomReply),
  });
  await f.bridge.joinRoom({...f.input, code: roomReply.room});
  await assert.rejects(f.bridge.launchFL(), /Update flim/);
  assert.equal(f.bridge.state().room.state, 'ready');
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
  host = '26.1.8.999';
  await f.bridge.launchFL();
  assert.equal(f.bridge.state().room.state, 'launched');
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 2);
});

test('preflight fails closed on unavailable, malformed, waiting and ambiguous-host rooms', async t => {
  let reply;
  const f = await fixture(t, {fetch: async url => url.endsWith('/status') ? reply() : response(roomReply)});
  const valid = activeStatus('25.2.5.5319');
  await f.bridge.joinRoom({...f.input, code: roomReply.room});
  const cases = [
    () => {throw new Error('offline');},
    () => response({...valid, room: '87654321'}),
    () => response({...valid, state: 'ended'}),
    () => response({...valid, state: 'waiting'}),
    () => response({...valid, peers: []}),
    () => response({...valid, peers: [valid.peers[0], {...valid.peers[0], id: 'other'}]}),
    ...['025.2.5.5319', '25.2.5.65536', '25.2.5', null].map(fl => () => response(activeStatus(fl))),
  ];
  for (reply of cases) {
    await assert.rejects(f.bridge.launchFL());
    assert.equal(f.bridge.state().room.state, 'ready');
    assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
  }
  reply = () => response({code: 'room_unavailable'}, 404);
  await assert.rejects(f.bridge.launchFL(), /closed/);
  assert.equal(f.bridge.state().room.status, 'ended');
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
});

test('preflight rechecks the host even when the people list is cached', async t => {
  let host = '25.2.5.5319';
  const f = await fixture(t, {fetch: async url => response(url.endsWith('/status') ? activeStatus(host) : roomReply)});
  await f.bridge.joinRoom({...f.input, code: roomReply.room});
  await f.bridge.refreshRoom();
  host = '26.1.8.5655';
  await assert.rejects(f.bridge.launchFL(), /Update flim/);
  assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
  assert.equal(f.bridge.state().room.state, 'ready');
});

test('successful relay responses must be objects with complete canonical room data', async t => {
  const f = await fixture(t);
  for (const data of [null, [], 'hello', 12, true, {}, {...roomReply, room: '1234 5678'}, {...roomReply, expiresAt: 'invalid'}, {...roomReply, expiresAt: null}]) {
    f.bridge.fetch = async () => response(data);
    await assert.rejects(f.bridge.createRoom(f.input), error => error instanceof BridgeError && /relay returned/.test(error.message));
    assert.equal(f.bridge.state().room, null);
  }
});

test('malformed UTF-8 and empty relay streams have useful errors without allocating a room', async t => {
  const f = await fixture(t);
  const prefix = JSON.stringify({...roomReply, extra: 'REPLACE'});
  const malformed = Buffer.concat([Buffer.from(prefix.slice(0, prefix.indexOf('REPLACE'))), Buffer.from([0xff]), Buffer.from(prefix.slice(prefix.indexOf('REPLACE') + 7))]);
  f.bridge.fetch = async () => new Response(malformed);
  await assert.rejects(f.bridge.createRoom(f.input), /invalid response/);
  f.bridge.fetch = async () => new Response('');
  await assert.rejects(f.bridge.createRoom(f.input), /empty response/);
  assert.equal(f.bridge.state().room, null);
});

test('oversized relay streams preserve their validation error even when cancellation fails', async t => {
  const f = await fixture(t);
  f.bridge.fetch = async () => new Response(new ReadableStream({
    start(controller) {controller.enqueue(new Uint8Array(17000));},
    cancel() {throw new Error('private cancel failure');},
  }));
  await assert.rejects(f.bridge.createRoom(f.input), error => error instanceof BridgeError && error.message === 'The relay returned an invalid response.');
});

test('inspection rejects noncanonical and overflowing native versions', async t => {
  const f = await fixture(t);
  for (const version of ['026.1.7.5654', '26.1.7.65536', '26.1.7.999999999999999', '26.1.7.1e3', '26.1.7']) {
    f.bridge.run = async () => JSON.stringify({path: f.installDir, version, supported: true});
    await assert.rejects(f.bridge.inspect(f.installDir), error => error instanceof BridgeError);
  }
});

test('null, primitive and out-of-range launch confirmations preserve the duplicate-launch guard', async t => {
  for (const result of [null, [], 'ok', {launched: true, pid: 0x100000000}, {launched: true, pid: 1.5}]) {
    const f = await fixture(t, {launch: async () => JSON.stringify(result)});
    await f.bridge.createRoom(f.input);
    await assert.rejects(f.bridge.launchFL(), error => error instanceof BridgeError && error.code === 'native_uncertain');
    assert.equal(f.bridge.state().room.state, 'uncertain');
    await assert.rejects(f.bridge.launchFL(), /previous launch/);
    assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 1);
  }
});

test('reservations expiring during inspection or file-status setup never start a process', async t => {
  for (const phase of ['inspection', 'files']) {
    const f = await fixture(t);
    await f.bridge.createRoom(f.input);
    f.bridge.room.expiresAt = new Date(100_500).toISOString();
    if (phase === 'inspection') {
      const original = f.bridge.run;
      f.bridge.run = async (...args) => {f.advance(1000); return original(...args);};
    } else f.bridge.fileTransfers = {start: async () => {f.advance(1000); return f.root;}};
    await assert.rejects(f.bridge.launchFL(), /reservation expired/);
    assert.equal(f.bridge.state().room.status, 'ended');
    assert.equal(f.bridge.state().room.state, 'ready');
    assert.equal(f.calls.filter(call => call.args[0] === '--desktop').length, 0);
  }
});

test('member launch uses its confirmed preflight people and freshness immediately', async t => {
  const f = await fixture(t);
  await f.bridge.joinRoom({...f.input, code: roomReply.room});
  f.advance(2500);
  const launched = await f.bridge.launchFL();
  assert.equal(launched.room.status, 'active');
  assert.equal(launched.room.peers[0].fl, '26.1.7.5654');
  assert.equal(launched.room.statusUpdatedAt, 102500);
  await f.bridge.refreshRoom();
  assert.equal(f.requests.filter(request => request.url.endsWith('/status')).length, 1);
});

test('slow success and failure throttle the next status lookup from completion', async t => {
  const f = await fixture(t);
  await f.bridge.createRoom(f.input);
  let attempts = 0, failing = false;
  f.bridge.fetch = async () => {attempts++; f.advance(15000); return failing ? response({code: 'room_rate_limit'}, 429) : response(activeStatus('26.1.7.5654'));};
  await f.bridge.refreshRoom();
  await f.bridge.refreshRoom(); assert.equal(attempts, 1);
  f.advance(10000); failing = true;
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  await assert.rejects(f.bridge.refreshRoom(), /wait a little/);
  assert.equal(attempts, 2);
});

test('people changes at the same headcount are logged while order-only changes are quiet', async t => {
  const f = await fixture(t), events = [];
  f.bridge.record = (event, fields) => events.push({event, fields});
  let peers = [...activeStatus('26.1.7.5654').peers, {id: 'member', name: 'Friend', role: 'member', fl: '25.2.5.5319'}];
  f.bridge.fetch = async url => response(url.endsWith('/status') ? {...activeStatus('26.1.7.5654'), peers} : roomReply);
  await f.bridge.createRoom(f.input); await f.bridge.refreshRoom();
  const count = () => events.filter(entry => entry.event === 'room_status').length;
  const original = count();
  peers.reverse(); f.advance(10000); await f.bridge.refreshRoom(); assert.equal(count(), original);
  peers[0] = {...peers[0], id: 'replacement'}; f.advance(10000); await f.bridge.refreshRoom(); assert.equal(count(), original + 1);
  peers[0] = {...peers[0], fl: '26.1.7.5654'}; f.advance(10000); await f.bridge.refreshRoom(); assert.equal(count(), original + 2);
  assert.ok(!JSON.stringify(events).includes('Friend'));
});

test('inconsistent leader and waiting-room data cannot replace confirmed people', async t => {
  const f = await fixture(t);
  await f.bridge.createRoom(f.input); await f.bridge.refreshRoom();
  for (const data of [{...activeStatus('26.1.7.5654'), state: 'waiting'}, {...activeStatus('26.1.7.5654'), peers: [activeStatus('26.1.7.5654').peers[0], {...activeStatus('26.1.7.5654').peers[0], id: 'other'}]}]) {
    f.advance(10000); f.bridge.fetch = async () => response(data);
    await assert.rejects(f.bridge.refreshRoom(), /invalid room status/);
    assert.equal(f.bridge.state().room.peers.length, 1);
  }
});

test('displayed peer names remove controls and keep whole Unicode characters at the boundary', async t => {
  const f = await fixture(t);
  await f.bridge.createRoom(f.input);
  for (const [name, expected] of [['\u202eHost\u2069\n', 'Host'], ['\u202e\u2069', 'Participant'], ['a'.repeat(23) + '𝄞', 'a'.repeat(23)], ['Cafe\u0301', 'Café']]) {
    f.bridge.fetch = async () => response({...activeStatus('26.1.7.5654'), peers: [{...activeStatus('26.1.7.5654').peers[0], name}]});
    f.advance(10000); assert.equal((await f.bridge.refreshRoom()).room.peers[0].name, expected);
  }
});

test('saved primary custom folders survive a missing installation and are rediscovered later', async t => {
  const f = await fixture(t), custom = path.join(f.root, 'custom FL');
  await fs.mkdir(custom);
  await fs.mkdir(path.dirname(f.bridge.preferencesFile));
  await fs.writeFile(f.bridge.preferencesFile, JSON.stringify({name: 'Saved', flPath: custom}));
  const run = f.bridge.run;
  f.bridge.run = async (...args) => {if (args[1][1] === custom) throw new Error('Drive offline'); return run(...args);};
  await f.bridge.initialize();
  await f.bridge.savePreferences({name: 'Saved', installId: f.bridge.selectedInstallId});
  assert.ok(JSON.parse(await fs.readFile(f.bridge.preferencesFile, 'utf8')).flPaths.includes(custom));
  f.bridge.run = run;
  assert.ok((await f.bridge.rescanInstalls()).installs.some(install => install.path === custom));
});

test('stored paths share validation and case deduplication while a bad name preserves good folders', async t => {
  const f = await fixture(t), custom = path.join(f.root, 'custom FL');
  await fs.mkdir(path.dirname(f.bridge.preferencesFile));
  await fs.writeFile(f.bridge.preferencesFile, JSON.stringify({name: '---', flPath: custom, flPaths: [custom.toUpperCase(), custom, 'relative', custom + '\u0000', custom + '\u007f']}));
  const state = await f.bridge.initialize();
  assert.equal(f.bridge.extraPaths.size, 1); assert.equal([...f.bridge.extraPaths][0], custom);
  assert.match(state.notice, /saved name could not be used/);
  assert.ok(state.installs.some(install => install.path === custom));
});

test('corrupt, oversized and unreadable saved settings explain recovery without blocking discovery', async t => {
  const f = await fixture(t);
  await fs.mkdir(path.dirname(f.bridge.preferencesFile));
  for (const source of ['{broken', '[]', 'x'.repeat(17000)]) {
    await fs.writeFile(f.bridge.preferencesFile, source);
    const state = await f.bridge.initialize();
    assert.match(state.notice, /Saved settings could not be loaded/); assert.equal(state.installs.length, 1);
  }
  f.bridge.io = {...f.bridge.io, lstat: async file => {if (file === f.bridge.preferencesFile) throw new Error('Access denied'); return fs.lstat(file);}};
  assert.match((await f.bridge.initialize()).notice, /Saved settings could not be loaded/);
  f.bridge.io = {...f.bridge.io, lstat: fs.lstat};
  await f.bridge.changeSampleLocation(true);
  assert.equal((await f.bridge.savePreferences(f.input)).notice, '');
});

test('deliberately canceled status checks log cancellation rather than a connection failure', async t => {
  const f = await fixture(t), events = [], controller = new AbortController();
  f.bridge.record = (event, fields) => events.push({event, fields});
  controller.abort();
  await assert.rejects(f.bridge.request('/rooms/status', {}, controller.signal), error => error.code === 'request_canceled');
  assert.equal(f.requests.length, 0);
  assert.deepEqual(events.map(entry => entry.event), ['request_canceled']);
});

test('relay deadlines report timeout separately from an unreachable relay', async t => {
  const f = await fixture(t), events = [];
  f.bridge.record = (event, fields) => events.push({event, fields});
  f.bridge.fetch = async (_url, options) => new Promise((_resolve, reject) => {options.signal.addEventListener('abort', () => reject(options.signal.reason), {once: true});});
  const keepAlive = setTimeout(() => {}, 500);
  try { await assert.rejects(f.bridge.request('/rooms/status', {}, undefined, 5), error => error.code === 'timeout' && /too long/.test(error.message)); }
  finally {clearTimeout(keepAlive);}
  assert.equal(events.at(-1).fields.code, 'timeout');
});
