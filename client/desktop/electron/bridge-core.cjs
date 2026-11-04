'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { execFile } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { readStableFile } = require('./local-file.cjs');
const {checkDirectory, validDirectory, folderError} = require('./sample-location.cjs');
const {writeSettings} = require('./atomic-settings.cjs');

const RELAY = 'https://flim-relay.cashflowbeatz.workers.dev';
const MAX_RESPONSE_BYTES = 16 * 1024;
const SAFE_ENV = /^(?:PATH|PATHEXT|SYSTEMROOT|SYSTEMDRIVE|WINDIR|COMSPEC|PROGRAMFILES(?:\(X86\))?|PROGRAMW6432|COMMONPROGRAMFILES(?:\(X86\))?|COMMONPROGRAMW6432|APPDATA|LOCALAPPDATA|USERPROFILE|HOMEDRIVE|HOMEPATH|TEMP|TMP|USERNAME|USERDOMAIN|COMPUTERNAME|LOGONSERVER|PROCESSOR_ARCHITECTURE|PROCESSOR_IDENTIFIER|NUMBER_OF_PROCESSORS|OS)$/i;

class BridgeError extends Error {
  constructor(message, code = '') { super(message); this.code = code; }
}

function displayName(value) {
  if (typeof value !== 'string' || value.length > 128) throw new BridgeError('Enter a name with up to 24 letters or numbers.');
  const name = value.normalize('NFC').replace(/[^\p{L}\p{N} ._\-\t]/gu, '').replace(/[\uD800-\uDFFF]/g, '').replace(/[ \t]+/g, ' ').trim().slice(0, 24).trim();
  if (!/[\p{L}\p{N}]/u.test(name)) throw new BridgeError('Enter a name with at least one letter or number.');
  return name;
}

function roomCode(value) {
  if (typeof value !== 'string' || value.length > 24) throw new BridgeError('Enter the eight-digit room number.');
  const code = value.normalize('NFKC').replace(/[\u0660-\u0669\u06f0-\u06f9]/g, digit => String(digit.charCodeAt(0) & 15))
    .replace(/[\u2010-\u2014\u2212]/g, '-').replace(/[\s-]/g, '');
  if (!/^\d{8}$/.test(code)) throw new BridgeError('Enter the eight-digit room number.');
  return code;
}

function childEnvironment(source, room, name) {
  const env = {};
  for (const [key, value] of Object.entries(source)) if (SAFE_ENV.test(key) && typeof value === 'string') env[key] = value;
  if (room) {
    env.FLIM_NAME = displayName(name);
    env.FLIM_AUTOCONNECT = `wss://${new URL(RELAY).host}/room/${roomCode(room.code)}`;
    env.FLIM_PASSWORD = room.password;
    env.FLIM_HOST = room.role === 'host' ? '1' : '0';
    if (room.role === 'host') env.FLIM_OWNER_KEY = room.hostToken;
  }
  return env;
}

function execute(file, args, options) {
  return new Promise((resolve, reject) => execFile(file, args, options, (error, stdout) => {
    if (error) {
      let message;
      try { const data = JSON.parse(stdout); if (typeof data.error === 'string') message = data.error.slice(0, 512); } catch {}
      const retryable = !!message || ['ENOENT', 'EACCES', 'EPERM'].includes(error.code);
      reject(new BridgeError(message || 'FL Studio could not start. Check the selected installation and try again.', retryable ? 'native_failed' : 'native_uncertain'));
    } else resolve(stdout);
  }));
}

async function jsonResponse(response) {
  if (Number(response.headers.get('content-length')) > MAX_RESPONSE_BYTES) {
    try { await response.body?.cancel(); } catch {}
    throw new BridgeError('The relay returned an invalid response.');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new BridgeError('The relay returned an empty response.');
  const chunks = []; let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) { try { await reader.cancel(); } catch {} throw new BridgeError('The relay returned an invalid response.'); }
      chunks.push(Buffer.from(part.value));
    }
    if (!bytes) throw new BridgeError('The relay returned an empty response.');
    try {
      const data = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks)));
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Expected an object.');
      return data;
    }
    catch { throw new BridgeError('The relay returned an invalid response.'); }
  } catch (error) {try {await reader.cancel();} catch {} throw error;}
  finally { try { reader.releaseLock(); } catch {} }
}

const SERVER_ERRORS = {
  room_not_ready: 'The host is still opening FL Studio. Try joining in a moment.',
  room_unavailable: 'That room is closed or could not be found. Ask your friend for a new room number.',
  room_full: 'This room already has eight people.',
  room_rate_limit: 'Please wait a little before trying again.',
  room_daily_limit: 'The relay has reached its daily room limit. Try again tomorrow.',
  relay_full: 'All rooms are in use. Try again later.',
  invalid_room: 'Enter the eight-digit room number.',
  rate_limited: 'Please wait a little before trying again.',
  too_many_attempts: 'Please wait a little before trying again.',
  capacity: 'All rooms are in use. Try again later.',
  room_capacity: 'All rooms are in use. Try again later.',
  r2_limit: 'File sharing has reached its safety limit. Try again after the limit resets.',
};

function validSecret(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{24,192}$/.test(value); }
function retryDelay(value, now) {
  if (typeof value !== 'string' || !value.trim()) return 0;
  const milliseconds = /^\d+(?:\.\d+)?$/.test(value.trim()) ? Number(value) * 1000 : /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), /.test(value) ? Date.parse(value) - now : 0;
  return Number.isFinite(milliseconds) ? Math.min(300_000, Math.max(0, milliseconds)) : 0;
}
function expiration(value) {
  const timestamp = typeof value === 'string' ? Date.parse(value) : value;
  return Number.isFinite(timestamp) && timestamp > 0 && timestamp <= 8.64e15 ? new Date(timestamp).toISOString() : null;
}
function parseRoom(data, role, expectedCode) {
  if (!data || typeof data.room !== 'string' || !/^\d{8}$/.test(data.room)) throw new BridgeError('The relay returned incomplete room information.');
  const code = data.room;
  if (expectedCode && code !== expectedCode) throw new BridgeError('The relay returned a different room. Please try again.');
  if (data.websocket !== `/room/${code}` || !validSecret(data.password) || (role === 'host' && (!validSecret(data.hostToken) || !expiration(data.expiresAt))) || data.maxParticipants !== 8) {
    throw new BridgeError('The relay returned incomplete room information.');
  }
  return { code, role, password: data.password, hostToken: role === 'host' ? data.hostToken : undefined,
    maxParticipants: 8, expiresAt: expiration(data.expiresAt),
    state: 'ready', status: role === 'host' ? 'waiting' : 'active', peers: [], statusUpdatedAt: null };
}

function samePath(a, b) { return path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase(); }
function validInstallPath(value) { return typeof value === 'string' && value.length > 0 && value.length <= 500 && path.isAbsolute(value) && !/[\x00-\x1f\x7f]/.test(value); }
function peerName(value) {
  return value.toWellFormed().normalize('NFC').replace(/[\x00-\x1f\x7f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, '').trim().slice(0, 24).replace(/[\uD800-\uDBFF]$/, '') || 'Participant';
}

function versionParts(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,4})(?:\.(?:0|[1-9]\d{0,4})){3}$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  return parts.every(part => part <= 65535) ? parts : null;
}

function roomStatus(data, code) {
  if (!data || data.room !== code || !['waiting', 'active'].includes(data.state) || !Array.isArray(data.peers) || data.peers.length > 8 || data.maxParticipants !== 8 ||
      data.peers.some(peer => !peer || typeof peer.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(peer.id) || typeof peer.name !== 'string' || !peer.name.trim() || peer.name.length > 64 || !['leader', 'member'].includes(peer.role) || !versionParts(peer.fl)) ||
      new Set(data.peers.map(peer => peer.id)).size !== data.peers.length || data.peers.filter(peer => peer.role === 'leader').length > 1 || (data.state === 'waiting' && data.peers.length)) throw new BridgeError('The relay returned invalid room status.');
  return data;
}

class DesktopBridge {
  constructor({ nativeDir, preferencesFile, platform = process.platform, environment = process.env,
    fetch = globalThis.fetch, run = execute, io = fs, chooseDirectory, copyText, readText = () => '', now = Date.now,
    record = () => {}, nativeLogDir = '', diagnosticsStatus = () => false, fileTransfers, peerFiles,
    defaultSampleDirectory = path.join(environment.USERPROFILE || path.dirname(preferencesFile), 'Documents', 'flim', 'samples'), chooseSampleDirectory }) {
    this.nativeDir = path.resolve(nativeDir);
    this.preferencesFile = preferencesFile;
    this.platform = platform;
    this.environment = environment;
    this.fetch = fetch;
    this.run = run;
    this.io = io;
    this.chooseDirectory = chooseDirectory;
    this.copyText = copyText;
    this.readText = readText;
    this.now = now;
    this.record = record; this.nativeLogDir = nativeLogDir; this.diagnosticsStatus = diagnosticsStatus;
    this.fileTransfers = fileTransfers;
    this.peerFiles = peerFiles;
    this.defaultSampleDirectory = defaultSampleDirectory;
    this.chooseSampleDirectory = chooseSampleDirectory;
    this.sampleDirectory = ''; this.sampleLocationError = '';
    this.extraPaths = new Set(); this.lastLoggedStatus = '';
    this.installs = new Map();
    this.name = ''; this.selectedInstallId = ''; this.room = null; this.busy = false; this.nativeReady = false;
    this.lastStatusAt = null; this.lastStatusError = null; this.statusFlight = null;
    this.statusFailures = 0; this.statusRetryAt = 0; this.serverRetryAt = 0;
    this.notice = '';
    this.preferencesNotice = '';
    this.scanGeneration = 0;
  }

  async initialize() {
    let saved = {};
    this.nativeReady = false;
    this.sampleDirectory = ''; this.sampleLocationError = '';
    try {
      saved = JSON.parse(await readStableFile(this.io, this.preferencesFile, 16_384));
      if (!saved || typeof saved !== 'object' || Array.isArray(saved)) throw new Error('Invalid preferences.');
      this.preferencesNotice = '';
    } catch (error) {
      saved = {};
      if (error?.code !== 'ENOENT') {
        this.preferencesNotice = 'Saved settings could not be loaded. Choose your name, FL Studio folder and received-files folder again.';
        this.sampleLocationError = 'The saved samples folder could not be recovered. Choose a folder or use the default in Files before opening FL Studio.';
        this.log('settings_failed', {operation: 'load', message: 'Preferences could not be read.'});
      }
    }
    if (typeof saved.name === 'string' && saved.name) {
      try { this.name = displayName(saved.name); }
      catch { this.preferencesNotice = 'Your saved name could not be used. Enter your name again.'; }
    }
    if (Object.hasOwn(saved, 'sampleDirectory')) {
      if (validDirectory(saved.sampleDirectory)) this.sampleDirectory = saved.sampleDirectory;
      else this.sampleLocationError = 'The saved samples folder cannot be used. Choose a folder or use the default in Files before opening FL Studio.';
    }
    if (this.platform !== 'win32') return this.state();
    try {
      for (const file of ['flim.exe', 'flim_engine.dll']) if (!(await this.io.stat(path.join(this.nativeDir, file))).isFile()) return this.state();
      this.nativeReady = true;
    } catch { return this.state(); }
    const directories = new Set();
    const preferred = validInstallPath(saved.flPath) ? saved.flPath : '';
    const remembered = Array.isArray(saved.flPaths) ? saved.flPaths.slice(0, 16) : [];
    if (preferred) remembered.push(preferred);
    for (const directory of remembered) if (validInstallPath(directory)) {
      for (const previous of this.extraPaths) if (samePath(previous, directory)) this.extraPaths.delete(previous);
      this.extraPaths.add(directory); directories.add(directory);
    }
    while (this.extraPaths.size > 16) this.extraPaths.delete(this.extraPaths.values().next().value);
    return this.scanInstalls(preferred, [...directories]);
  }

  async scanInstalls(preferredPath = '', additionalPaths = []) {
    const generation = ++this.scanGeneration;
    preferredPath ||= this.installs.get(this.selectedInstallId)?.path || '';
    const directories = new Set([...this.extraPaths, ...additionalPaths]);
    if (preferredPath) directories.add(preferredPath);
    const roots = [];
    for (const key of ['ProgramW6432', 'ProgramFiles', 'ProgramFiles(x86)']) {
      const root = this.environment[key]; if (!root) continue;
      if (roots.some(previous => samePath(previous, root))) continue;
      roots.push(root);
      const base = path.join(root, 'Image-Line');
      try { for (const entry of await this.io.readdir(base, { withFileTypes: true })) if (entry.isDirectory() && /^FL Studio/i.test(entry.name)) directories.add(path.join(base, entry.name)); } catch {}
    }
    const candidates = [];
    for (const directory of directories) if (!candidates.some(previous => samePath(previous, directory))) candidates.push(directory);
    const inspected = new Array(candidates.length);
    let cursor = 0;
    // Hash at most three engine files at once; retain discovery order for selection.
    await Promise.all(Array.from({ length: Math.min(3, candidates.length) }, async () => {
      for (;;) {
        const index = cursor++;
        if (index >= candidates.length) return;
        try { inspected[index] = await this.inspect(candidates[index]); } catch {}
      }
    }));
    const next = new Map();
    let selectedId = '';
    for (const install of inspected) {
      if (install) {
        next.set(install.id, install);
        if (preferredPath && samePath(install.path, preferredPath)) selectedId = install.id;
      }
    }
    if (generation !== this.scanGeneration) return this.state();
    this.installs = next;
    this.selectedInstallId = selectedId || [...next.values()].find(install => install.supported && !install.experimental)?.id || [...next.values()].find(install => install.supported)?.id || [...next.keys()][0] || '';
    return this.state();
  }

  state() {
    const { password, hostToken, sampleDirectory, ...room } = this.room ?? {};
    let diagnosticsAvailable = false;
    try {diagnosticsAvailable = this.diagnosticsStatus() === true;} catch {}
    return { platform: this.platform, name: this.name, installs: [...this.installs.values()], selectedInstallId: this.selectedInstallId,
      room: this.room ? room : null, busy: this.busy, nativeReady: this.nativeReady, diagnosticsAvailable, notice: [this.notice, this.preferencesNotice].filter(Boolean).join(' ') };
  }

  log(event, fields) {
    try { Promise.resolve(this.record(event, fields)).catch(() => {}); } catch {}
  }

  logStatus() {
    if (!this.room) return;
    const {status, role, state, peers} = this.room;
    const signature = JSON.stringify([status, role, state, peers.map(peer => [peer.id, peer.name, peer.role, peer.fl]).sort((a, b) => a[0].localeCompare(b[0]))]);
    if (signature === this.lastLoggedStatus) return;
    this.lastLoggedStatus = signature;
    this.log('room_status', {status, role, state, peerCount: peers.length});
  }

  async exclusive(task) {
    if (this.busy) throw new BridgeError('Please wait for the current step to finish.');
    this.busy = true;
    if (this.statusFlight) {
      const flight = this.statusFlight;
      this.statusFlight = null; this.lastStatusAt = null; this.lastStatusError = null;
      flight.controller.abort();
    }
    this.notice = '';
    try { await task(); } finally { this.busy = false; }
    return this.state();
  }

  async inspect(directory) {
    if (!this.nativeReady || this.platform !== 'win32') throw new BridgeError('The Windows FL Studio launcher is not included in this build.');
    if (!validInstallPath(directory)) throw new BridgeError('Select an FL Studio installation folder.');
    let result;
    try { result = JSON.parse(await this.run(path.join(this.nativeDir, 'flim.exe'), ['--inspect-json', directory],
      { cwd: this.nativeDir, env: childEnvironment(this.environment), windowsHide: true, shell: false, timeout: 30_000, maxBuffer: 16_384, encoding: 'utf8' })); }
    catch (error) { if (error instanceof BridgeError) throw error; throw new BridgeError('That folder could not be checked. Select the folder containing FL64.exe.'); }
    if (!result || typeof result.path !== 'string' || !samePath(result.path, directory) || typeof result.supported !== 'boolean' || typeof result.version !== 'string') throw new BridgeError('The launcher returned an invalid compatibility result.');
    if (!versionParts(result.version)) throw new BridgeError(typeof result.reason === 'string' && result.reason ? result.reason.slice(0, 512) : 'Select the FL Studio folder containing FL64.exe.');
    const existing = [...this.installs.values()].find(install => samePath(install.path, directory));
    this.log('install_inspected', {flVersion: result.version, supported: result.supported, experimental: result.experimental === true});
    return { id: existing?.id ?? randomUUID(), path: directory, version: result.version.slice(0, 64), supported: result.supported,
      experimental: result.experimental === true,
      reason: typeof result.reason === 'string' ? result.reason.slice(0, 512) : '' };
  }

  async persist() {
    if (this.sampleLocationError) {
      this.preferencesNotice = 'Choose a valid samples folder in Files before saving settings.';
      return false;
    }
    const install = this.installs.get(this.selectedInstallId);
    try {
      await this.io.mkdir(path.dirname(this.preferencesFile), { recursive: true });
      await writeSettings(this.io, this.preferencesFile, `${JSON.stringify({ name: this.name, flPath: install?.path ?? '', flPaths: [...this.extraPaths].slice(-16), ...(this.sampleDirectory ? {sampleDirectory: this.sampleDirectory} : {}) })}\n`);
      this.preferencesNotice = '';
      return true;
    } catch (error) {
      this.log('settings_failed', {operation: 'save', code: error?.code, message: 'Preferences could not be saved.'});
      this.preferencesNotice = 'Your settings could not be saved. You can still use this session, but you may need to choose your name and FL Studio folder next time.';
      return false;
    }
  }

  getSampleLocation() {
    return {path: this.room?.sampleDirectory || this.sampleDirectory || this.defaultSampleDirectory,
      defaultPath: this.defaultSampleDirectory, custom: !!this.sampleDirectory,
      canChange: !this.room && !this.busy, error: this.sampleLocationError};
  }

  async checkedSampleDirectory({writable = true} = {}) {
    if (this.sampleLocationError) throw new BridgeError(this.sampleLocationError);
    const directory = this.room?.sampleDirectory || this.sampleDirectory || this.defaultSampleDirectory;
    try { return await checkDirectory(directory, {io: this.io, create: !this.sampleDirectory && !this.room?.sampleDirectory, writable}); }
    catch (error) {
      this.log('settings_failed', {operation: 'sample-folder', code: error?.code, message: 'The received-files folder is unavailable.'});
      throw new BridgeError(folderError(error, 'The samples folder is unavailable or cannot be written. Check its drive, permissions and free space, or choose another folder in Files.'));
    }
  }

  async changeSampleLocation(reset = false) {
    await this.exclusive(async () => {
      if (this.room) throw new BridgeError('Return to start before changing where received files are saved. Existing FL sessions keep their current folder.');
      let chosen;
      if (reset) chosen = this.defaultSampleDirectory;
      else {
        if (!this.chooseSampleDirectory) throw new BridgeError('Reopen the complete flim app to choose a samples folder.');
        chosen = await this.chooseSampleDirectory(this.sampleDirectory || this.defaultSampleDirectory);
        if (!chosen) return;
      }
      let resolved;
      try { resolved = await checkDirectory(chosen, {io: this.io, create: reset}); }
      catch (error) { throw new BridgeError(folderError(error, 'That folder cannot be written. Check its drive, permissions and free space, then choose again.')); }
      const previous = this.sampleDirectory;
      const previousError = this.sampleLocationError;
      this.sampleDirectory = reset || samePath(resolved, this.defaultSampleDirectory) ? '' : resolved;
      this.sampleLocationError = '';
      if (!await this.persist()) { this.sampleDirectory = previous; this.sampleLocationError = previousError; throw new BridgeError('The folder choice could not be saved. Your previous samples folder is still selected. Try again after checking settings-folder access.'); }
      this.log('sample_folder_changed', {custom: !!this.sampleDirectory});
    });
    return this.getSampleLocation();
  }

  preferences(input) {
    if (!input || typeof input !== 'object' || typeof input.installId !== 'string' || !this.installs.has(input.installId)) throw new BridgeError('Choose your FL Studio installation.');
    return { name: displayName(input.name), installId: input.installId };
  }

  async savePreferences(input) {
    return this.exclusive(async () => {
      if (this.room) throw new BridgeError('Leave this room before changing your name or installation.');
      const selected = this.preferences(input); this.name = selected.name; this.selectedInstallId = selected.installId; await this.persist();
    });
  }

  async chooseInstall(currentInstallId) {
    return this.exclusive(async () => {
      if (this.room) throw new BridgeError('Leave this room before choosing another installation.');
      if (!this.chooseDirectory) throw new BridgeError('Reopen the complete flim app to choose an FL Studio folder.');
      if (typeof currentInstallId === 'string' && this.installs.has(currentInstallId)) this.selectedInstallId = currentInstallId;
      const directory = await this.chooseDirectory(this.installs.get(this.selectedInstallId)?.path); if (!directory) return;
      const install = await this.inspect(directory); this.installs.set(install.id, install); this.selectedInstallId = install.id;
      for (const previous of this.extraPaths) if (samePath(previous, directory)) this.extraPaths.delete(previous);
      this.extraPaths.add(directory);
      while (this.extraPaths.size > 16) this.extraPaths.delete(this.extraPaths.values().next().value);
      await this.persist();
    });
  }

  async rescanInstalls(currentInstallId) {
    return this.exclusive(async () => {
      if (this.room) throw new BridgeError('Return to start before checking installations.');
      if (!this.nativeReady || this.platform !== 'win32') throw new BridgeError('The Windows FL Studio launcher is not included in this build.');
      const preferred = this.installs.get(currentInstallId) ?? this.installs.get(this.selectedInstallId);
      await this.scanInstalls(preferred?.path);
      if (preferred && ![...this.installs.values()].some(install => samePath(install.path, preferred.path)))
        this.notice = 'The selected installation could no longer be checked. Choose an available copy or its folder.';
      await this.persist();
    });
  }

  async readyPreferences(input) {
    if (this.room) throw new BridgeError('Leave this room before opening another one.');
    const selected = this.preferences(input);
    const install = await this.inspect(this.installs.get(selected.installId).path);
    this.installs.set(install.id, install);
    if (!install.supported) throw new BridgeError(install.reason || 'This FL Studio build does not have a verified compatibility profile yet.');
    this.name = selected.name; this.selectedInstallId = selected.installId;
    await this.persist();
  }

  async request(route, body, signal, timeoutMs = 12_000) {
    let response, data;
    const started = this.now();
    const timeout = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    for (let attempt = 0; ; attempt++) {
      try {
        combined.throwIfAborted();
        response = await this.fetch(`${RELAY}${route}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), redirect: 'error', signal: combined });
        try { data = await jsonResponse(response); }
        catch (error) { if (response.ok) throw error; data = {}; }
        if (route === '/rooms/status' && attempt === 0 && [502, 503, 504].includes(response.status) && !retryDelay(response.headers.get('retry-after'), this.now())) {
          this.log('request_retry', {operation: route, status: response.status});
          await delay(250, undefined, {signal: combined}); continue;
        }
        break;
    } catch (error) {
      if (signal?.aborted) {
        this.log('request_canceled', {operation: route, durationMs: Math.max(0, this.now() - started)});
        throw new BridgeError('The room status check was canceled.', 'request_canceled');
      }
      if (route === '/rooms/status' && attempt === 0 && !combined.aborted && !(error instanceof BridgeError)) {
        this.log('request_retry', {operation: route, code: 'network'});
        await delay(250, undefined, {signal: combined}).catch(() => {}); continue;
      }
      if (timeout.aborted) {
        this.log('request_failed', {operation: route, code: 'timeout', durationMs: Math.max(0, this.now() - started)});
        throw new BridgeError('The relay took too long to respond. Check your connection and try again.', 'timeout');
      }
      this.log('request_failed', {operation: route, code: error?.code, message: error instanceof BridgeError ? error.message : 'Relay request did not complete.', durationMs: Math.max(0, this.now() - started)});
      if (error instanceof BridgeError) throw error;
      throw new BridgeError('The relay could not be reached. Check your connection and try again.');
      }
    }
    if (!response.ok) {
      const code = typeof data?.code === 'string' && Object.hasOwn(SERVER_ERRORS, data.code) ? data.code : '';
      this.log('request_failed', {operation: route, status: response.status, code: code || 'relay_error', durationMs: Math.max(0, this.now() - started)});
      const error = new BridgeError(code ? SERVER_ERRORS[code] : response.status === 429 ? 'Please wait a little before trying again.' : response.status === 503 ? 'The relay is unavailable or has reached its safety limit. Try again later.' : 'The room request could not be completed. Please try again.', code || 'relay_error');
      if ([429, 503].includes(response.status)) error.retryAfterMs = retryDelay(response.headers.get('retry-after'), this.now());
      throw error;
    }
    return data;
  }

  async createRoom(input) {
    return this.exclusive(async () => { await this.readyPreferences(input); this.room = parseRoom(await this.request('/rooms', {}), 'host'); this.resetStatus(); this.logStatus(); });
  }

  async joinRoom(input) {
    return this.exclusive(async () => {
      const code = roomCode(input?.code); await this.readyPreferences(input);
      this.room = parseRoom(await this.request('/rooms/join', { room: code }), 'member', code); this.resetStatus();
      this.logStatus();
    });
  }

  async launchFL() {
    return this.exclusive(async () => {
      const room = this.room;
      if (!room) throw new BridgeError('Create or join a room first.');
      if (room.state === 'launched') throw new BridgeError('FL Studio has already been opened for this room.');
      if (room.state === 'uncertain') throw new BridgeError('The previous launch could not be confirmed. Check FL Studio before leaving this room and trying again.');
      if (room.status === 'ended') throw new BridgeError('This room has ended. Create or join another room.');
      this.checkReservation(room);
      const selected = this.installs.get(this.selectedInstallId);
      if (!selected) throw new BridgeError('Choose your FL Studio installation.');
      const install = await this.inspect(selected.path); this.installs.set(install.id, install);
      if (!install.supported) throw new BridgeError(install.reason || 'This FL Studio build is not verified.');
      if (room.role === 'member') {
        let data;
        try { data = roomStatus(await this.request('/rooms/status', { room: room.code, password: room.password }), room.code); }
        catch (error) {
          if (error instanceof BridgeError && error.code === 'room_unavailable') { room.status = 'ended'; room.peers = []; this.logStatus(); }
          throw error;
        }
        const hosts = data.peers.filter(peer => peer.role === 'leader');
        this.applyStatus(room, data); this.lastStatusAt = this.now(); this.lastStatusError = null;
        if (data.state !== 'active' || hosts.length !== 1) throw new BridgeError('The host is still opening FL Studio or has disconnected. Try joining again when they are ready.');
        const local = versionParts(install.version), host = versionParts(hosts[0].fl);
        if (!local) throw new BridgeError('This FL Studio build is not verified.');
        const difference = local.map((part, i) => part - host[i]).find(part => part !== 0) || 0;
        if (difference < 0 && data.portable_sync !== 1) throw new BridgeError('Update flim on the host computer and update the relay to join a newer FL host automatically.', 'compatibility');
      }
      const started = this.now();
      const details = {flVersion: install.version, experimental: install.experimental, role: room.role};
      const env = childEnvironment(this.environment, room, this.name);
      const sampleDirectory = await this.checkedSampleDirectory();
      env.FLIM_SAMPLE_DIR = sampleDirectory;
      if (this.fileTransfers) {
        try { env.FLIM_FILES_DIR = await this.fileTransfers.start(room); }
        catch { this.log('settings_failed', {operation: 'file-status', message: 'The local file status folder is unavailable. Sample sharing can continue.'}); }
      }
      if (typeof this.nativeLogDir === 'string' && path.isAbsolute(this.nativeLogDir) && !/[\x00-\x1f]/.test(this.nativeLogDir)) env.FLIM_LOG_DIR = this.nativeLogDir;
      const args = ['--desktop', '--fl-dir', install.path];
      if (install.experimental) args.push('--allow-experimental');
      this.checkReservation(room);
      this.log('launch_started', details);
      room.sampleDirectory = sampleDirectory;
      let peerSession;
      try {peerSession = await this.peerFiles?.prepare(room.code); if (peerSession) Object.assign(env, peerSession.env);}
      catch {this.log('peer_unavailable', {message: 'Direct file setup unavailable; relay transfers remain enabled.'});}
      try {this.checkReservation(room);}
      catch (error) {try {peerSession?.cancel();} catch {} throw error;}
      try {
        // The native launcher owns its injection timeout and cleans up suspended FL on failure.
        const output = await this.run(path.join(this.nativeDir, 'flim.exe'), args,
          { cwd: this.nativeDir, env, windowsHide: true, shell: false, timeout: 0, maxBuffer: 16_384, encoding: 'utf8' });
        let result; try { result = JSON.parse(output); } catch { throw new BridgeError('The launcher did not confirm that FL Studio opened. Check FL Studio before trying again.', 'native_uncertain'); }
        if (!result || Array.isArray(result) || result.launched !== true || !Number.isSafeInteger(result.pid) || result.pid < 1 || result.pid > 0xffffffff) throw new BridgeError('The launcher did not confirm that FL Studio opened. Check FL Studio before trying again.', 'native_uncertain');
        room.state = 'launched';
        try {peerSession?.launched(result.pid);}
        catch {this.log('peer_unavailable', {message: 'FL opened, but direct file lifetime tracking failed. Relay transfers remain enabled.'});}
        this.log('launch_confirmed', {...details, pid: result.pid, durationMs: Math.max(0, this.now() - started)}); this.logStatus();
      } catch (error) {
        if (error instanceof BridgeError && error.code === 'native_failed') {
          try {peerSession?.cancel();} catch {}
          delete room.sampleDirectory;
        }
        this.log('launch_failed', {...details, code: error?.code, message: error?.message, durationMs: Math.max(0, this.now() - started)});
        if (!(error instanceof BridgeError) || error.code !== 'native_failed') room.state = 'uncertain';
        throw error;
      }
    });
  }

  checkReservation(room) {
    if (room.status === 'waiting' && room.expiresAt && Date.parse(room.expiresAt) <= this.now()) {
      room.status = 'ended'; room.peers = []; this.logStatus();
      throw new BridgeError('This room reservation expired. Create a new room.');
    }
  }

  applyStatus(room, data) {
    room.statusUpdatedAt = this.now();
    room.status = data.state;
    room.expiresAt = data.state === 'waiting' ? expiration(data.expiresAt) ?? room.expiresAt : null;
    room.peers = data.peers.map(peer => ({id: peer.id, name: peerName(peer.name), role: peer.role === 'leader' ? 'host' : 'member', fl: peer.fl}));
    this.logStatus();
  }

  resetStatus() {
    this.statusFlight?.controller.abort();
    this.statusFlight = null; this.lastStatusAt = null; this.lastStatusError = null;
    this.statusFailures = 0; this.statusRetryAt = 0; this.serverRetryAt = 0;
    this.lastLoggedStatus = '';
  }

  async refreshRoom(options) {
    if (!this.room || this.room.status === 'ended' || this.busy) return this.state();
    if (this.room.role === 'host' && this.room.state === 'ready' && this.room.status === 'waiting' && this.room.expiresAt && Date.parse(this.room.expiresAt) <= this.now()) {
      this.room.status = 'ended'; this.room.peers = []; this.room.statusUpdatedAt = this.now(); this.logStatus(); return this.state();
    }
    if (this.statusFlight?.room === this.room) return this.statusFlight.promise;
    if (this.lastStatusAt !== null && this.now() < this.lastStatusAt) {this.statusRetryAt = 0; this.serverRetryAt = 0;}
    if (this.lastStatusError && (this.now() < this.serverRetryAt || options?.force !== true && this.now() < this.statusRetryAt)) throw this.lastStatusError;
    const interval = options?.force === true ? 1000 : this.room.status === 'waiting' ? 5000 : 10_000;
    const elapsed = this.lastStatusAt === null ? null : this.now() - this.lastStatusAt;
    if (elapsed !== null && elapsed >= 0 && elapsed < interval) {
      if (this.lastStatusError) throw this.lastStatusError;
      return this.state();
    }
    const room = this.room;
    const flight = { room, controller: new AbortController(), promise: null };
    flight.promise = (async () => {
      let data;
      try {
        data = await this.request('/rooms/status', { room: room.code, password: room.password }, flight.controller.signal);
        if (this.room !== room || this.statusFlight !== flight) return this.state();
        roomStatus(data, room.code);
      }
      catch (error) {
        if (this.room !== room || this.statusFlight !== flight) return this.state();
        if (error instanceof BridgeError && error.code === 'room_unavailable') {
          room.status = 'ended'; room.peers = []; room.statusUpdatedAt = this.now(); this.lastStatusError = null; this.logStatus(); return this.state();
        }
        this.lastStatusError = error;
        this.statusFailures = Math.min(this.statusFailures + 1, 5);
        this.statusRetryAt = this.now() + Math.max(error?.retryAfterMs || 0, Math.min(60_000, 5000 * 2 ** (this.statusFailures - 1)));
        this.serverRetryAt = this.now() + (error?.retryAfterMs || 0);
        throw error;
      }
      this.lastStatusError = null;
      this.statusFailures = 0; this.statusRetryAt = 0; this.serverRetryAt = 0;
      this.applyStatus(room, data);
      return this.state();
    })();
    this.statusFlight = flight;
    try { return await flight.promise; } finally {
      if (this.statusFlight === flight) {this.statusFlight = null; this.lastStatusAt = this.now();}
    }
  }

  async leaveRoom() {
    return this.exclusive(async () => {
      const room = this.room;
      if (room) this.log('room_left', {role: room.role, state: room.state, status: room.status});
      this.room = null; this.resetStatus();
      if (room?.role === 'host' && room.state === 'ready' && room.status === 'waiting') {
        try { await this.request('/rooms/cancel', { room: room.code, hostToken: room.hostToken }, undefined, 3000); }
        catch (error) {
          if (!(error instanceof BridgeError) || error.code !== 'room_unavailable')
            this.notice = 'The unused room could not be released. It will expire automatically within ten minutes. You can still create or join another room.';
        }
      }
    });
  }

  async copyInvite() {
    if (!this.room) throw new BridgeError('Create or join a room first.');
    if (this.room.status === 'ended') throw new BridgeError('This room has ended. Create or join another room.');
    this.checkReservation(this.room);
    try { await this.copyText(this.room.code); }
    catch { throw new BridgeError('The clipboard could not be updated. Select and copy the room number instead.'); }
    return { copied: true };
  }

  async pasteRoomCode() {
    try { return {code: roomCode((await this.readText()).trim())}; }
    catch { throw new BridgeError('Copy an eight-digit room number, then paste again.'); }
  }
}

function trustedSender(event, webContents, rendererURL) {
  return !!event.senderFrame && event.sender === webContents && event.senderFrame === webContents.mainFrame && event.senderFrame.url === rendererURL;
}

module.exports = { DesktopBridge, BridgeError, RELAY, displayName, roomCode, childEnvironment, trustedSender, parseRoom };
