'use strict';
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {randomUUID} = require('node:crypto');
const {PeerFiles} = require('./peer-core.cjs');
function createPeerFiles({BrowserWindow, ipcMain, session, relay, record, idle}) {
  let window, ready, closing = false;
  const replies = new Map();
  const url = pathToFileURL(path.join(__dirname, 'peer-worker.html')).href;
  const valid = event => window && !window.isDestroyed() && event.sender === window.webContents && event.senderFrame === window.webContents.mainFrame && event.senderFrame.url === url;
  function ensure() {
    if (closing) throw new Error('worker_closed');
    if (window && !window.isDestroyed()) return ready;
    const partition = session.fromPartition('flim-peer-files');
    partition.setPermissionRequestHandler((_w, _p, done) => done(false)); partition.setPermissionCheckHandler(() => false);
    window = new BrowserWindow({show: false, webPreferences: {session: partition, preload: path.join(__dirname, 'peer-preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false}});
    window.webContents.setWindowOpenHandler(() => ({action: 'deny'}));
    window.webContents.on('will-navigate', event => event.preventDefault());
    const current = window;
    window.webContents.on('render-process-gone', () => {
      if (window !== current) return;
      window = null; if (!current.isDestroyed()) current.destroy();
      if (closing) return;
      for (const s of core.sessions.values()) {s.ready.clear(); s.ws?.close();}
      for (const reply of replies.values()) reply(false); replies.clear();
    });
    ready = window.loadURL(url).catch(error => {
      if (window === current) {window = null; if (!current.isDestroyed()) current.destroy();}
      throw error;
    }); return ready;
  }
  const send = async m => {const loading = ensure(), target = window; await loading;
    if (closing || !target || target.isDestroyed() || window !== target) throw new Error('worker_closed');
    target.webContents.send('flim:peer-command', m);
  };
  const transport = {send: m => {void send(m).catch(() => {});}, chunk: (m, signal) => new Promise((resolve, reject) => {
    const reply = randomUUID(); const timer = setTimeout(() => {const done = replies.get(reply); replies.delete(reply); done?.(false);}, 10000);
    const abort = () => {const done = replies.get(reply); replies.delete(reply); done?.(false);};
    replies.set(reply, ok => {clearTimeout(timer); signal?.removeEventListener('abort', abort); if (ok) resolve(); else reject(new Error('worker_closed'));});
    signal?.addEventListener('abort', abort, {once: true});
    if (signal?.aborted) {abort(); return;}
    const data = m.data.buffer.slice(m.data.byteOffset, m.data.byteOffset + m.data.byteLength);
    void send({...m, data, reply}).catch(() => {const done = replies.get(reply); replies.delete(reply); done?.(false);});
  })};
  const core = new PeerFiles({relay, transport, record, idle});
  ipcMain.handle('flim:peer-event', (event, m) => {if (!valid(event)) throw new Error('Invalid transport sender'); return core.event(m);});
  const replyHandler = (event, id, ok) => {if (!valid(event)) return; const done = replies.get(id); replies.delete(id); done?.(ok === true);};
  ipcMain.on('flim:peer-reply', replyHandler);
  const close = core.close.bind(core);
  core.close = async () => {
    closing = true; await close();
    for (const done of replies.values()) done(false); replies.clear();
    ipcMain.removeHandler('flim:peer-event'); ipcMain.off('flim:peer-reply', replyHandler);
    if (window && !window.isDestroyed()) window.destroy(); window = null;
  };
  return core;
}
module.exports = {createPeerFiles};
