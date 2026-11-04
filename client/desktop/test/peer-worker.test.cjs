'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
const flush = async () => {for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve));};
async function fixture() {
  const events = [], replies = [], pcs = [], timers = new Map(); let command, now = 0, serial = 0, handle = async () => true;
  class Channel {
    constructor(label) {this.label = label; this.readyState = 'open'; this.bufferedAmount = 0; this.sent = [];}
    send(data) {if (this.readyState !== 'open') throw new Error('closed'); this.sent.push(data);}
    close() {if (this.readyState === 'closed') return; this.readyState = 'closed'; const late = this.onclose; queueMicrotask(() => late?.());}
    message(data) {this.onmessage?.({data: typeof data === 'object' && !(data instanceof ArrayBuffer) ? JSON.stringify(data) : data});}
  }
  class PC {
    constructor() {this.connectionState = 'connected'; this.channels = []; this.ice = []; this.offers = []; pcs.push(this);}
    createDataChannel(label) {if (this.throwChannel) throw new Error('channel failed'); const ch = new Channel(label); this.channels.push(ch); return ch;}
    async createOffer(options) {this.offers.push(options); return {type: 'offer', sdp: 'fixture-offer'};}
    async createAnswer() {return {type: 'answer', sdp: 'fixture-answer'};}
    async setLocalDescription(value) {this.localDescription = value;}
    async setRemoteDescription(value) {this.remoteDescription = value;}
    async addIceCandidate(value) {assert.ok(this.remoteDescription); this.ice.push(value);}
    close() {this.connectionState = 'closed'; for (const ch of this.channels) ch.close(); this.onconnectionstatechange?.();}
  }
  const context = vm.createContext({window: {peerTransport: {event: async m => {events.push(m); return handle(m);}, reply: (...args) => replies.push(args), onCommand: fn => {command = fn;}}},
    RTCPeerConnection: PC, crypto: {randomUUID}, ArrayBuffer, Uint8Array,
    setTimeout: (fn, delay) => {const id = ++serial; timers.set(id, {fn, at: now + delay}); return id;}, clearTimeout: id => timers.delete(id)});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../electron/peer-worker.js'), 'utf8'), context);
  const send = async m => {command({session: 's', ...m}); await flush();};
  const tick = async ms => {now += ms; for (let i = 0; i < 20; i++) {const due = [...timers].filter(([,t]) => t.at <= now); if (!due.length) break; for (const [id,t] of due) {timers.delete(id); t.fn();} await flush();}};
  await send({type: 'peers', you: 'a', peers: ['a', 'b', 'c']});
  const get = async (bytes = 3) => {await send({type: 'get', id: 'download', hash: 'a'.repeat(64), bytes}); const ch = pcs[0].channels.at(-1); ch.onopen?.(); await flush(); return ch;};
  const incoming = () => {const ch = new Channel('flim-file-v1'); pcs[0].ondatachannel({channel: ch}); return ch;};
  return {events, replies, pcs, timers, context, send, tick, get, incoming, handle: fn => {handle = fn;}, read: code => vm.runInContext(code, context), Channel};
}
test('trying the next direct source cannot be canceled by the previous channel closing late', async () => {
  const f = await fixture(), first = await f.get(); const late = first.onclose;
  first.message({t: 'missing'}); await flush(); const next = f.pcs[1].channels.at(-1); next.onopen?.(); await flush();
  late(); await flush(); assert.equal(next.readyState, 'open');
  next.message({t: 'start', bytes: 3}); next.message(new Uint8Array([1,2,3]).buffer); next.message({t: 'end'}); await flush();
  assert.equal(f.events.filter(m => m.type === 'end').length, 1); assert.equal(f.events.filter(m => m.type === 'failed').length, 0);
});
test('the last missing source reports failure once and frees all channel timers', async () => {
  const f = await fixture(), first = await f.get(); first.message({t: 'missing'}); await flush();
  f.pcs[1].channels.at(-1).message({t: 'missing'}); await flush();
  assert.equal(f.events.filter(m => m.type === 'failed').length, 1); assert.equal(f.timers.size, 0);
});
test('canceling a serving channel notifies the broker while source admission is still pending', async () => {
  const f = await fixture(); let release; f.handle(m => m.type === 'serve' ? new Promise(resolve => {release = resolve;}) : true);
  const ch = f.incoming(); ch.message({t: 'want', hash: 'a'.repeat(64), bytes: 3}); await flush(); ch.close(); await flush();
  assert.equal(f.events.filter(m => m.type === 'served_closed').length, 1); release(true); await flush(); assert.equal(ch.sent.length, 0);
});
test('declining an unavailable source clears both the transfer timer and short close timer', async () => {
  const f = await fixture(); f.handle(m => m.type !== 'serve');
  const ch = f.incoming(); ch.message({t: 'want', hash: 'a'.repeat(64), bytes: 3}); await flush();
  assert.ok(ch.sent.some(value => JSON.parse(value).t === 'missing')); await f.tick(200);
  assert.equal(ch.readyState, 'closed'); assert.equal(f.timers.size, 0);
});
for (const [name, bytes, data] of [['empty',3,new ArrayBuffer(0)], ['oversized chunk',40000,new ArrayBuffer(32769)], ['beyond file size',3,new ArrayBuffer(4)]]) {
  test(`${name} direct content is rejected before forwarding it to the broker`, async () => {
    const f = await fixture(), ch = await f.get(bytes); ch.message({t: 'start', bytes}); await flush(); ch.message(data); await flush();
    assert.equal(f.events.filter(m => m.type === 'chunk').length, 0); assert.equal(f.events.filter(m => m.type === 'failed').length, 1);
  });
}
test('early end cannot complete a short file', async () => {
  const f = await fixture(), ch = await f.get(); ch.message({t: 'start', bytes: 3}); ch.message({t: 'end'}); await flush();
  assert.equal(f.events.filter(m => m.type === 'end').length, 0); assert.equal(f.events.filter(m => m.type === 'failed').length, 1);
});
test('a flood of queued tiny messages is bounded by count as well as bytes', async () => {
  const f = await fixture(), ch = f.incoming(); for (let i = 0; i < 65; i++) ch.message('{}'); await flush();
  assert.equal(ch.readyState, 'closed'); assert.equal(f.read('transfers.size'), 0);
});
test('backpressure wakes when the browser send buffer drains without another acknowledgment', async () => {
  const f = await fixture(), ch = f.incoming(); ch.message({t: 'want', hash: 'a'.repeat(64), bytes: 3}); await flush();
  const id = f.events.find(m => m.type === 'serve').id; ch.bufferedAmount = 600000;
  await f.send({type: 'chunk', id, data: new Uint8Array([1,2,3]).buffer, reply: 'chunk'}); assert.equal(f.replies.length, 0);
  ch.bufferedAmount = 0; ch.onbufferedamountlow(); await flush(); assert.deepEqual(f.replies, [['chunk', true]]);
  ch.message({t: 'ack', bytes: 3}); await flush(); await f.send({type: 'end', id}); await f.tick(8000); assert.equal(f.timers.size, 0);
});
test('a timed-out blocked write closes the sender and rejects its IPC acknowledgment', async () => {
  const f = await fixture(), ch = f.incoming(); ch.message({t: 'want', hash: 'a'.repeat(64), bytes: 3}); await flush();
  const id = f.events.find(m => m.type === 'serve').id; ch.bufferedAmount = 600000;
  await f.send({type: 'chunk', id, data: new ArrayBuffer(3), reply: 'chunk'}); await f.tick(8000);
  assert.equal(ch.readyState, 'closed'); assert.deepEqual(f.replies, [['chunk', false]]); assert.equal(f.events.filter(m => m.type === 'served_closed').length, 1);
});
test('late completion after session reset cannot acknowledge or revive an old channel', async () => {
  const f = await fixture(); let release; f.handle(m => m.type === 'chunk' ? new Promise(resolve => {release = resolve;}) : true);
  const ch = await f.get(); ch.message({t: 'start', bytes: 3}); await flush(); ch.message(new ArrayBuffer(3)); await flush();
  await f.send({type: 'reset'}); release(); await flush(); assert.equal(ch.sent.filter(m => typeof m === 'string' && m.includes('ack')).length, 0); assert.equal(f.read('transfers.size'), 0);
});
test('ICE candidates arriving before the session description wait for that description', async () => {
  const f = await fixture(); await f.send({type: 'signal', from: 'b', signal: {type: 'ice', candidate: {candidate: 'early'}}});
  assert.equal(f.pcs[0].ice.length, 0); assert.equal(f.pcs[0].connectionState, 'connected');
  await f.send({type: 'signal', from: 'b', signal: {type: 'answer', sdp: 'answer'}}); assert.equal(f.pcs[0].ice[0].candidate, 'early');
});
test('an unbounded early ICE backlog is rejected', async () => {
  const f = await fixture(); for (let i = 0; i < 65; i++) await f.send({type: 'signal', from: 'b', signal: {type: 'ice', candidate: {candidate: String(i)}}});
  assert.equal(f.pcs[0].connectionState, 'closed');
});
test('a disconnected connection restarts ICE and removing a peer cancels future recovery', async () => {
  const f = await fixture(), pc = f.pcs[0]; pc.connectionState = 'disconnected'; pc.onconnectionstatechange(); await f.tick(5000);
  assert.equal(pc.offers.at(-1).iceRestart, true);
  pc.connectionState = 'failed'; pc.onconnectionstatechange(); const count = pc.offers.length;
  await f.send({type: 'peers', you: 'a', peers: ['a','c']}); await f.tick(30000); assert.equal(pc.offers.length, count);
  f.events.length = 0; pc.connectionState = 'connected'; pc.onconnectionstatechange(); assert.equal(f.events.length, 0);
});
test('ICE recovery has a bounded attempt budget', async () => {
  const f = await fixture(), pc = f.pcs[0];
  for (let i = 0; i < 5; i++) {pc.connectionState = 'failed'; pc.onconnectionstatechange(); await f.tick(1000);}
  assert.equal(pc.offers.filter(m => m?.iceRestart).length, 3);
});
test('a failed data-channel creation reports immediate unavailability', async () => {
  const f = await fixture(); f.pcs[0].throwChannel = f.pcs[1].throwChannel = true; await f.send({type: 'get', id: 'bad', hash: 'a'.repeat(64), bytes: 3});
  assert.equal(f.events.filter(m => m.type === 'failed' && m.id === 'bad').length, 1);
});
test('idle unopened file channels close after five seconds', async () => {
  const f = await fixture(), ch = f.incoming(); await f.tick(5000); assert.equal(ch.readyState, 'closed'); assert.equal(f.read('transfers.size'), 0);
});
test('a broken first data channel tries the next connected source', async () => {
  const f = await fixture(); f.pcs[0].throwChannel = true;
  await f.send({type: 'get', id: 'retry-channel', hash: 'a'.repeat(64), bytes: 3});
  assert.equal(f.pcs[1].channels.at(-1).label, 'flim-file-v1'); assert.equal(f.events.some(m => m.type === 'failed'), false);
});
test('a connection stuck in failed state retries without another state-change event', async () => {
  const f = await fixture(), pc = f.pcs[0]; pc.connectionState = 'failed'; pc.onconnectionstatechange();
  for (let i = 0; i < 5; i++) await f.tick(1000);
  assert.equal(pc.offers.filter(options => options?.iceRestart).length, 3); assert.equal(f.timers.size, 0);
});
