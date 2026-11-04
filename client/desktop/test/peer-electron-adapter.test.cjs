const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {EventEmitter} = require('node:events');
const source = fs.readFileSync(path.join(__dirname, '../electron/peer-electron.cjs'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

function fixture() {
  const windows = [], timers = new Map(), ipc = new EventEmitter();
  ipc.handle = () => {}; ipc.removeHandler = () => {};
  class Window {
    constructor() {
      this.destroyed = false; this.sent = []; this.webContents = new EventEmitter();
      this.webContents.setWindowOpenHandler = () => {};
      this.webContents.send = (...args) => this.sent.push(args);
      this.loading = new Promise((resolve, reject) => {this.resolve = resolve; this.reject = reject;});
      windows.push(this);
    }
    isDestroyed() {return this.destroyed;}
    destroy() {this.destroyed = true;}
    loadURL(url) {this.webContents.mainFrame = {url}; return this.loading;}
  }
  class Core {
    constructor(options) {Object.assign(this, options); this.sessions = new Map();}
    async close() {}
  }
  const module = {exports: {}};
  vm.runInNewContext(source, {module, __dirname: path.join(__dirname, '../electron'),
    require: name => name === './peer-core.cjs' ? {PeerFiles: Core} : require(name),
    setTimeout: callback => {const id = {}; timers.set(id, callback); return id;}, clearTimeout: id => timers.delete(id)});
  const core = module.exports.createPeerFiles({BrowserWindow: Window, ipcMain: ipc,
    session: {fromPartition: () => ({setPermissionRequestHandler() {}, setPermissionCheckHandler() {}})}, relay: 'https://fixture.invalid'});
  const ack = (window, id, ok = true, frame = window.webContents.mainFrame) => ipc.emit('flim:peer-reply', {sender: window.webContents, senderFrame: frame}, id, ok);
  const chunk = signal => core.transport.chunk({session: 'fixture', id: 'transfer', data: Buffer.from('audio')}, signal);
  return {core, windows, timers, ack, chunk};
}

test('worker chunk cancellation settles IPC immediately and removes its timeout', async () => {
  const f = fixture(), controller = new AbortController();
  const pending = f.chunk(controller.signal), rejected = assert.rejects(pending, /worker_closed/);
  controller.abort(); await rejected; assert.equal(f.timers.size, 0);
  f.windows[0].resolve(); await flush(); await f.core.close();
});

test('a command awaiting a crashed worker cannot be sent into its replacement', async () => {
  const f = fixture(); f.core.transport.send({type: 'peers', session: 'old'});
  const first = f.windows[0]; first.webContents.emit('render-process-gone');
  f.core.transport.send({type: 'peers', session: 'new'});
  const second = f.windows[1]; first.resolve(); second.resolve(); await flush();
  assert.equal(first.sent.length, 0); assert.equal(second.sent.length, 1);
  assert.equal(second.sent[0][1].session, 'new'); await f.core.close();
});

test('a failed worker load destroys that window and the next request can create a new one', async () => {
  const f = fixture(), pending = f.chunk(), rejected = assert.rejects(pending, /worker_closed/);
  f.windows[0].reject(new Error('load_failed')); await rejected;
  assert.equal(f.windows[0].destroyed, true); assert.equal(f.timers.size, 0);
  f.core.transport.send({type: 'peers', session: 'retry'}); f.windows[1].resolve(); await flush();
  assert.equal(f.windows[1].sent.length, 1); await f.core.close();
});

test('chunk acknowledgments require the current worker frame and settle only once', async () => {
  const f = fixture(), pending = f.chunk(); f.windows[0].resolve(); await flush();
  const window = f.windows[0], reply = window.sent[0][1].reply;
  f.ack(window, reply, true, {url: window.webContents.mainFrame.url});
  assert.equal(f.timers.size, 1);
  f.ack(window, reply); await pending; assert.equal(f.timers.size, 0);
  f.ack(window, reply, false); await f.core.close();
});

test('chunk timeout and shutdown remove pending replies and abort listeners', async () => {
  const f = fixture(), controller = new AbortController();
  const pending = f.chunk(controller.signal), rejected = assert.rejects(pending, /worker_closed/);
  const expire = [...f.timers.values()][0]; expire(); await rejected; assert.equal(f.timers.size, 0);
  const next = f.chunk(controller.signal), closed = assert.rejects(next, /worker_closed/);
  await f.core.close(); await closed; controller.abort(); assert.equal(f.timers.size, 0);
  f.windows[0].resolve(); await flush(); assert.equal(f.windows[0].sent.length, 0);
});
