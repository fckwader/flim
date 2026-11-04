'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {EventEmitter} = require('node:events');
const http = require('node:http');
const {PeerFiles} = require('../electron/peer-core.cjs');
const HASH = 'a'.repeat(64);

test('native generation overflow and invalid launched process IDs are rejected', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('/connect', {token: 'b'.repeat(64), generation: 0x80000000})).status, 409);
  for (const pid of [0, -1, 1.5, '123', 0x100000000]) assert.throws(() => f.client.launched(pid), /invalid_pid/);
});
test('replaced source files with matching size and mtime are declined and stale registrations removed', async t => {
  const f = await fixture(t); await f.connect(1); const data = await f.offer(); await f.call('/offer', data);
  const file = Buffer.from(data.p, 'base64').toString('utf16le'), stat = await fs.stat(file);
  await fs.rename(file, file + '.old'); await fs.writeFile(file, 'other!'); await fs.utimes(file, stat.atime, stat.mtime);
  assert.equal(await f.core.event({type: 'serve', session: f.s.id, id: 'replaced', hash: HASH, bytes: 6}), false);
  assert.equal(f.s.offers.has(HASH), false);
});
test('signaling send failures and excessive queued signaling cannot reject worker events', async t => {
  const f = await fixture(t); await f.connect(1); const socket = f.sockets[0]; let closed = 0;
  socket.close = () => {closed++;}; socket.send = () => {throw new Error('network');};
  await f.core.event({type: 'signal', session: f.s.id, to: 'other', signal: {type: 'answer', sdp: 'sdp'}}); assert.equal(closed, 1);
  socket.bufferedAmount = 70000; socket.send = () => {throw new Error('must not send');};
  await f.core.event({type: 'signal', session: f.s.id, to: 'other', signal: {type: 'ice'}}); assert.equal(closed, 2);
});
test('participant updates immediately remove departed ready peers and clear admission timeout', async t => {
  const f = await fixture(t); await f.connect(1); f.s.ready.add('departed');
  f.sockets[0].emit('message', JSON.stringify({t: 'files.peers', you: 'me', peers: ['me', 'other']}));
  assert.equal(f.s.ready.size, 0); assert.equal(f.s.admission._destroyed, true);
});
test('shutdown waits for outgoing handles and canceled streaming jobs to finish', async t => {
  const f = await fixture(t); await f.connect(1); await f.call('/offer', await f.offer()); f.setChunks(() => new Promise(() => {}));
  assert.equal(await f.core.event({type: 'serve', session: f.s.id, id: 'close', hash: HASH, bytes: 6}), true);
  await f.core.close(); assert.equal(f.core.jobs.size, 0); assert.equal(f.s.outgoing, 0);
});
test('malformed UTF-8 native JSON is rejected instead of silently replacing its bytes', async t => {
  const f = await fixture(t);
  const response = await fetch(f.client.env.FLIM_PEER_URL + '/connect', {method: 'POST', headers: {'x-flim-key': f.client.env.FLIM_PEER_TOKEN}, body: Buffer.from('{"x":"\xff"}', 'latin1')});
  assert.equal(response.status, 400); assert.equal(f.s.generation, 0);
});
test('later direct sources have enough first-byte time before cloud fallback', async t => {
  const f = await fixture(t); await f.connect(1); f.s.ready.add('first'); f.s.ready.add('second');
  f.setSend(m => {if (m.type === 'get') setTimeout(() => {void (async () => {
    await f.core.event({type: 'start', session: f.s.id, id: m.id, bytes: 6});
    await f.core.event({type: 'chunk', session: f.s.id, id: m.id, data: Buffer.from('sample')});
    await f.core.event({type: 'end', session: f.s.id, id: m.id});
  })();}, 1800);});
  const response = await f.call(`/blob/${HASH}?bytes=6&generation=1`); assert.equal(response.status, 200); assert.equal(await response.text(), 'sample');
});
test('absolute-form and authority-form local requests cannot register a session', async t => {
  const f = await fixture(t); const endpoint = new URL(f.client.env.FLIM_PEER_URL);
  for (const route of ['http://elsewhere.invalid/connect', '//elsewhere.invalid/connect']) {
    const status = await new Promise((resolve, reject) => {
      const req = http.request({hostname: endpoint.hostname, port: endpoint.port, path: route, method: 'POST', headers: {'x-flim-key': f.client.env.FLIM_PEER_TOKEN}}, response => {response.resume(); resolve(response.statusCode);});
      req.on('error', reject); req.end(JSON.stringify({generation: 1, token: 'b'.repeat(64)}));
    }); assert.equal(status, 400);
  } assert.equal(f.s.generation, 0);
});
test('a signaling connection that never supplies admission closes for retry', async t => {
  const f = await fixture(t); await f.connect(1); let closed = 0; f.sockets[0].close = () => {closed++;};
  f.s.admission._onTimeout(); assert.equal(closed, 1);
});
async function fixture(t) {
  const root = path.join(__dirname, '.tmp'); await fs.mkdir(root, {recursive: true});
  const dir = await fs.mkdtemp(path.join(root, 'peer-unit-')), commands = [], sockets = [];
  let send = () => {}, chunks = async () => {};
  const core = new PeerFiles({relay: 'https://relay.invalid', transport: {send: m => {commands.push(m); send(m);}, chunk: m => chunks(m)}, alive: pid => pid === 123,
    connect: () => {const ws = new EventEmitter(); ws.readyState = 1; ws.send = () => {}; ws.close = () => {}; sockets.push(ws); return ws;}});
  t.after(async () => {await core.close(); assert.ok(dir.startsWith(root + path.sep)); await fs.rm(dir, {recursive: true, force: true});});
  const client = await core.prepare('12345678'), s = [...core.sessions.values()][0];
  const call = (route, data, headers = {}) => fetch(client.env.FLIM_PEER_URL + route, {method: data === undefined ? 'GET' : 'POST', headers: {'x-flim-key': client.env.FLIM_PEER_TOKEN, ...headers}, ...(data === undefined ? {} : {body: JSON.stringify(data)})});
  const connect = async generation => assert.equal((await call('/connect', {generation, token: 'b'.repeat(64)})).status, 200);
  const offer = async () => {const file = path.join(dir, 'kick.wav'); await fs.writeFile(file, 'sample'); return {generation: s.generation, h: HASH, s: 6, p: Buffer.from(file, 'utf16le').toString('base64')};};
  return {core, client, s, call, connect, offer, commands, sockets, setSend: fn => {send = fn;}, setChunks: fn => {chunks = fn;}};
}
test('broker rejects browser origins, wrong capabilities and malformed native generations', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('/connect', {}, {'x-flim-key': 'wrong'})).status, 403);
  assert.equal((await f.call('/connect', {}, {origin: 'https://foreign.invalid'})).status, 403);
  for (const generation of [0, -1, 1.1, '1']) assert.equal((await f.call('/connect', {generation, token: 'b'.repeat(64)})).status, 409);
  await f.connect(1); assert.equal((await f.call('/connect', {generation: 1, token: 'b'.repeat(64)})).status, 409);
});
test('parallel preparations cannot exceed eight launch sessions and closed brokers cannot reopen', async t => {
  const f = await fixture(t);
  const results = await Promise.allSettled(Array.from({length: 12}, () => f.core.prepare('12345678')));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 7); assert.equal(f.core.sessions.size, 8);
  await f.core.close(); await assert.rejects(f.core.prepare('12345678')); assert.equal(f.core.server, null);
});
test('source registration rejects relative paths, noncanonical base64, size mismatches and stale sessions', async t => {
  const f = await fixture(t); await f.connect(1); const data = await f.offer();
  for (const bad of [{...data, p: Buffer.from('relative.wav', 'utf16le').toString('base64')}, {...data, p: data.p + '\n'}, {...data, s: 5}, {...data, generation: 0}]) assert.notEqual((await f.call('/offer', bad)).status, 200);
  assert.equal((await f.call('/offer', data)).status, 200); await f.connect(2); assert.equal(f.s.offers.size, 0);
});
test('serving reserves concurrency before opening files and releases it after cancellation', async t => {
  const f = await fixture(t); await f.connect(1); await f.call('/offer', await f.offer());
  const pending = []; f.setChunks(() => new Promise(resolve => pending.push(resolve)));
  const serve = id => f.core.event({type: 'serve', session: f.s.id, id, hash: HASH, bytes: 6});
  const results = await Promise.all([serve('a'), serve('b'), serve('c')]); assert.deepEqual(results, [true, true, false]);
  assert.equal(f.s.outgoing, 2);
  while (pending.length < 2) await new Promise(r => setTimeout(r, 5));
  f.client.cancel(); pending.forEach(resolve => resolve());
  for (let i = 0; f.s.outgoing && i < 100; i++) await new Promise(r => setTimeout(r, 5));
  assert.equal(f.s.outgoing, 0);
});
test('changed or deleted registered sources decline direct serving without leaking slots', async t => {
  const f = await fixture(t); await f.connect(1); const data = await f.offer(); await f.call('/offer', data);
  const file = Buffer.from(data.p, 'base64').toString('utf16le'); await fs.appendFile(file, '!');
  assert.equal(await f.core.event({type: 'serve', session: f.s.id, id: 'a', hash: HASH, bytes: 6}), false);
  await fs.unlink(file); assert.equal(await f.core.event({type: 'serve', session: f.s.id, id: 'b', hash: HASH, bytes: 6}), false); assert.equal(f.s.outgoing, 0);
});
test('direct broker download streams exact bytes and cleans transfer resources', async t => {
  const f = await fixture(t); await f.connect(1); f.s.ready.add('other');
  f.setSend(m => {if (m.type === 'get') void (async () => {
    await f.core.event({type: 'start', session: f.s.id, id: m.id, bytes: 6});
    await f.core.event({type: 'chunk', session: f.s.id, id: m.id, data: Buffer.from('sample')});
    await f.core.event({type: 'end', session: f.s.id, id: m.id});
  })();});
  const response = await f.call(`/blob/${HASH}?bytes=6&generation=1`); assert.equal(response.status, 200); assert.equal(await response.text(), 'sample');
  assert.equal(f.core.transfers.size, 0); assert.equal(f.s.incoming, 0);
});
test('oversized chunks abort a direct download instead of accepting partial content', async t => {
  const f = await fixture(t); await f.connect(1); f.s.ready.add('other');
  f.setSend(m => {if (m.type === 'get') void (async () => {
    await f.core.event({type: 'start', session: f.s.id, id: m.id, bytes: 6});
    await f.core.event({type: 'chunk', session: f.s.id, id: m.id, data: Buffer.alloc(7)});
  })();});
  await assert.rejects(async () => {const response = await f.call(`/blob/${HASH}?bytes=6&generation=1`); await response.arrayBuffer();});
  assert.equal(f.core.transfers.size, 0); assert.equal(f.s.incoming, 0);
});
test('new native generations and signaling loss clear ready peers and pending downloads', async t => {
  const f = await fixture(t); await f.connect(1); f.s.ready.add('other');
  const response = f.call(`/blob/${HASH}?bytes=6&generation=1`);
  while (!f.core.transfers.size) await new Promise(r => setTimeout(r, 5));
  await f.connect(2); assert.equal((await response).status, 404); assert.equal(f.s.ready.size, 0); assert.equal(f.core.transfers.size, 0);
  f.s.ready.add('other'); f.s.ws.emit('close', 4000); assert.equal(f.s.ready.size, 0); assert.equal(f.s.ws, null);
});
test('unavailable peers, invalid generations and incoming capacity return promptly', async t => {
  const f = await fixture(t); await f.connect(1);
  assert.equal((await f.call(`/blob/${HASH}?bytes=6&generation=1`)).status, 404);
  assert.equal((await f.call(`/blob/${HASH}?bytes=6&generation=0`)).status, 400);
  f.s.ready.add('other'); f.s.incoming = 2;
  assert.equal((await f.call(`/blob/${HASH}?bytes=6&generation=1`)).status, 404);
});
test('only launched living FL processes keep the companion active', async t => {
  const f = await fixture(t); assert.equal(f.core.active, false); f.client.launched(123); assert.equal(f.core.active, true);
  f.client.launched(456); assert.equal(f.core.active, false); f.client.cancel(); assert.equal(f.core.sessions.size, 0);
});
test('canceling a serving request releases its slot without waiting for a stuck worker acknowledgment', async t => {
  const f = await fixture(t); await f.connect(1); await f.call('/offer', await f.offer()); f.setChunks(() => new Promise(() => {}));
  assert.equal(await f.core.event({type: 'serve', session: f.s.id, id: 'stuck', hash: HASH, bytes: 6}), true);
  await f.core.event({type: 'served_closed', session: f.s.id, id: 'stuck'});
  for (let i = 0; f.s.outgoing && i < 100; i++) await new Promise(r => setTimeout(r, 5));
  assert.equal(f.s.outgoing, 0); assert.equal(f.s.serving.size, 0);
});
test('duplicate serving IDs cannot open the same outgoing transfer twice', async t => {
  const f = await fixture(t); await f.connect(1); await f.call('/offer', await f.offer()); f.setChunks(() => new Promise(() => {}));
  const m = {type: 'serve', session: f.s.id, id: 'duplicate', hash: HASH, bytes: 6};
  const result = await Promise.all([f.core.event(m), f.core.event(m)]); assert.deepEqual(result, [true, false]); f.client.cancel();
});
test('late worker events cannot set readiness or serve files in a replacement native connection', async t => {
  const f = await fixture(t); await f.connect(1); const previous = f.s.id; await f.connect(2);
  assert.notEqual(previous, f.s.id);
  await f.core.event({type: 'ready', session: previous, peer: 'old', ready: true});
  assert.equal(f.s.ready.size, 0); assert.equal(await f.core.event({type: 'serve', session: previous, id: 'old', hash: HASH, bytes: 6}), undefined);
});
test('signaling reconnection invalidates old worker messages and backs off repeated failures', async t => {
  const f = await fixture(t); await f.connect(1); const previous = f.s.id;
  f.s.ws.emit('close', 1006); assert.notEqual(f.s.id, previous); assert.equal(f.s.reconnect._idleTimeout, 1000);
  clearTimeout(f.s.reconnect); f.core.attach(f.s); f.s.ws.emit('close', 1006); assert.equal(f.s.reconnect._idleTimeout, 2000);
  clearTimeout(f.s.reconnect); f.core.attach(f.s); f.s.ws.emit('message', JSON.stringify({t: 'files.peers', you: 'a', peers: ['a','b']}));
  f.s.ws.emit('close', 1006); assert.equal(f.s.reconnect._idleTimeout, 1000);
});
test('sources require a negotiated session and malformed JSON shapes are rejected', async t => {
  const f = await fixture(t); assert.equal((await f.call('/offer', await f.offer())).status, 400);
  for (const value of [null, [], true, 'text']) assert.equal((await f.call('/connect', value)).status, 400);
  await f.connect(1);
  for (const route of [`/blob/${HASH}?bytes=6e0&generation=1`, `/blob/${HASH}?bytes=6&generation=1e0`, `/blob/${HASH}?bytes=6`]) assert.equal((await f.call(route)).status, 400);
});
test('a partial connect body cannot revive a dropped session', async t => {
  const f = await fixture(t), data = JSON.stringify({token: 'b'.repeat(64), generation: 1});
  let sent;
  const started = new Promise(resolve => {sent = resolve;});
  const status = new Promise((resolve, reject) => {
    const req = http.request(f.client.env.FLIM_PEER_URL + '/connect', {method: 'POST', headers: {'x-flim-key': f.client.env.FLIM_PEER_TOKEN, 'content-length': Buffer.byteLength(data)}}, res => {res.resume(); resolve(res.statusCode);});
    req.on('error', reject); req.flushHeaders(); req.write(data.slice(0, 10)); sent(req);
  });
  const req = await started; f.client.cancel(); req.end(data.slice(10)); assert.equal(await status, 403); assert.equal(f.sockets.length, 0);
});
test('diagnostic exceptions and rejected writes cannot turn a completed download into a failure', async t => {
  for (const record of [() => {throw new Error('disk');}, () => Promise.reject(new Error('disk'))]) {
    const f = await fixture(t); f.core.record = record; await f.connect(1); f.s.ready.add('other');
    f.setSend(m => {if (m.type === 'get') void (async () => {
      await f.core.event({type: 'start', session: f.s.id, id: m.id, bytes: 6});
      await f.core.event({type: 'chunk', session: f.s.id, id: m.id, data: Buffer.from('sample')});
      await f.core.event({type: 'end', session: f.s.id, id: m.id});
    })();});
    const response = await f.call(`/blob/${HASH}?bytes=6&generation=1`); assert.equal(await response.text(), 'sample'); await new Promise(r => setImmediate(r));
  }
});
test('duplicate transfer start cancels the download without writing a second set of headers', async t => {
  const f = await fixture(t); await f.connect(1); f.s.ready.add('other');
  f.setSend(m => {if (m.type === 'get') void (async () => {
    await f.core.event({type: 'start', session: f.s.id, id: m.id, bytes: 6});
    await f.core.event({type: 'start', session: f.s.id, id: m.id, bytes: 6});
  })();});
  await assert.rejects(async () => {const response = await f.call(`/blob/${HASH}?bytes=6&generation=1`); await response.arrayBuffer();}); assert.equal(f.core.transfers.size, 0);
});
