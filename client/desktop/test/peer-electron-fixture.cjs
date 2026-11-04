'use strict';
const {app, BrowserWindow, ipcMain, session} = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const {createHash} = require('node:crypto');
const assert = require('node:assert/strict');
const {createPeerFiles} = require('../electron/peer-electron.cjs');
app.on('window-all-closed', () => {});
app.whenReady().then(async () => {
  const config = JSON.parse(await fs.readFile(process.env.FLIM_PEER_TEST_CONFIG, 'utf8'));
  const log = [], core = createPeerFiles({BrowserWindow, ipcMain, session, relay: config.relay, record: (event, fields) => log.push({event, ...fields}), idle: () => {}});
  const clients = await Promise.all(config.tokens.map(() => core.prepare(config.room)));
  clients.forEach(c => c.launched(process.pid));
  const call = (i, route, data) => fetch(clients[i].env.FLIM_PEER_URL + route, {method: data ? 'POST' : 'GET', headers: {'x-flim-key': clients[i].env.FLIM_PEER_TOKEN}, ...(data ? {body: JSON.stringify(data)} : {})});
  try {
    const denied = await fetch(clients[0].env.FLIM_PEER_URL + '/offer', {method: 'POST', body: '{}'}); assert.equal(denied.status, 403);
    const origin = await fetch(clients[0].env.FLIM_PEER_URL + '/offer', {method: 'POST', headers: {'x-flim-key': clients[0].env.FLIM_PEER_TOKEN, origin: 'https://untrusted.invalid'}, body: '{}'}); assert.equal(origin.status, 403);
    for (let i = 0; i < clients.length; i++) assert.equal((await call(i, '/connect', {token: config.tokens[i], generation: 1})).status, 200);
    const until = Date.now() + 20000;
    while ([...core.sessions.values()].some(s => s.ready.size !== clients.length - 1)) {if (Date.now() > until) throw new Error('Direct connections did not open'); await new Promise(r => setTimeout(r, 50));}
    const bytes = await fs.readFile(config.source), hash = createHash('sha256').update(bytes).digest('hex');
    assert.equal((await call(0, '/offer', {generation: 1, h: hash, s: bytes.length, p: Buffer.from(config.source, 'utf16le').toString('base64')})).status, 200);
    const route = `/blob/${hash}?bytes=${bytes.length}&generation=1`;
    const first = await call(1, route); assert.equal(first.status, 200); assert.deepEqual(Buffer.from(await first.arrayBuffer()), bytes);
    const concurrent = await Promise.all([call(1, route), call(1, route)]);
    for (const response of concurrent) {assert.equal(response.status, 200); assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);}
    assert.equal((await call(1, route.replace('generation=1', 'generation=0'))).status, 400);
    assert.equal(log.filter(e => e.event === 'peer_download').length, 3);
    const received = path.join(path.dirname(config.source), 'verified-copy.wav'); await fs.writeFile(received, bytes);
    assert.equal((await call(1, '/offer', {generation: 1, h: hash, s: bytes.length, p: Buffer.from(received, 'utf16le').toString('base64')})).status, 200);
    const worker = BrowserWindow.getAllWindows()[0]; worker.webContents.forcefullyCrashRenderer();
    const recoveryUntil = Date.now() + 20000;
    while (!worker.isDestroyed() || [...core.sessions.values()].some(s => s.ready.size !== clients.length - 1)) {
      if (Date.now() > recoveryUntil) throw new Error('File transport did not recover');
      await new Promise(r => setTimeout(r, 50));
    }
    assert.equal(BrowserWindow.getAllWindows().length, 1);
    assert.equal(core.transfers.size, 0);
    await fs.appendFile(config.source, 'changed');
    assert.equal((await call(1, route)).status, 404);
    const alternate = await call(2, route); assert.equal(alternate.status, 200); assert.deepEqual(Buffer.from(await alternate.arrayBuffer()), bytes);
    clients[0].cancel(); await new Promise(r => setTimeout(r, 300));
    assert.equal((await call(1, route)).status, 404);
    const reseeded = await call(2, route); assert.equal(reseeded.status, 200); assert.deepEqual(Buffer.from(await reseeded.arrayBuffer()), bytes);
    clients[1].cancel(); await new Promise(r => setTimeout(r, 300));
    assert.equal((await call(2, route)).status, 404);
    const fallback = await fetch(`${config.relay}blob/${hash}`, {headers: {'x-flim-key': config.blob}});
    assert.equal(fallback.status, 200); assert.deepEqual(Buffer.from(await fallback.arrayBuffer()), bytes);
    assert.equal(log.filter(e => e.event === 'peer_download').length, 5);
    const result = {passed: true, bytes: bytes.length, participants: 3, directDownloads: 5, checks: [`Actual encrypted WebRTC file bytes through ${config.live ? 'deployed Cloudflare' : 'Cloudflare emulator'} signaling`, 'Two simultaneous direct downloads with bounded chunk flow', 'Loopback authentication and browser-origin rejection', 'Stale generation rejection', 'Transport renderer crash reconnects and restores readiness', 'Changed first source retries the next available source', 'Verified receiver serves onward after the original file companion stops', 'Lost direct peers leave verified R2 copy usable'], diagnostics: log};
    await fs.writeFile(config.result, JSON.stringify(result, null, 2)); console.log(JSON.stringify(result));
  } finally {await core.close(); assert.equal(core.sessions.size, 0); assert.equal(BrowserWindow.getAllWindows().length, 0);}
  app.exit(0);
}).catch(error => {console.error(error); app.exit(1);});
