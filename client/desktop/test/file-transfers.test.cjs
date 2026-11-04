'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {FileTransfers, parseSnapshot} = require('../electron/file-transfers.cjs');
const {fitBounds} = require('../electron/window-fit.cjs');
const {DesktopBridge} = require('../electron/bridge-core.cjs');
const hash = 'a'.repeat(64);
const item = {id: 'download:' + hash, name: 'kick.wav', direction: 'download', state: 'downloading', reason: '', bytes: 100, done: 50, updatedAt: 1000};
const snapshot = items => JSON.stringify({version: 1, pid: 42, updatedAt: 1000, items});

test('malformed Unicode file names cannot corrupt the status renderer', () => {
  assert.throws(() => parseSnapshot(snapshot([{...item, name: 'bad\ud800.wav'}]), 42), /Invalid file status/);
});
test('oversized status directories retain confirmed activity and stop file reads', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([item])); await store.snapshot(room);
  let stats = 0; store.io = {...fs, readdir: async () => Array.from({length: 4097}, (_, i) => `files-${i + 1}.json`), open: async () => {stats++; throw new Error('must not read');}};
  const result = await store.snapshot(room); assert.equal(result.stale, true); assert.equal(result.items.length, 1); assert.equal(stats, 0);
});
test('a close failure cannot hide the original local file read error', async () => {
  const {readStableFile} = require('../electron/local-file.cjs');
  const metadata = {isFile: () => true, isSymbolicLink: () => false, size: 5, dev: 1, ino: 1, mtimeMs: 1, ctimeMs: 1};
  const io = {open: async () => ({stat: async () => metadata, read: async () => {throw Object.assign(new Error('read'), {code: 'EIO'});}, close: async () => {throw new Error('close');}})};
  await assert.rejects(readStableFile(io, 'fixture', 100, metadata), {code: 'EIO'});
});

test('file activity rejects reversed transfer states and gives invisible-only names a usable label', () => {
  assert.throws(() => parseSnapshot(snapshot([{...item, state: 'uploading'}]), 42));
  assert.throws(() => parseSnapshot(snapshot([{...item, direction: 'upload', id: 'upload:' + hash}]), 42));
  assert.equal(parseSnapshot(snapshot([{...item, name: ' \u200b\ufeff\u2060 '}]), 42)[0].name, 'Sample file');
  assert.equal(parseSnapshot(snapshot([{...item, name: '  kick.wav  '}]), 42)[0].name, 'kick.wav');
});

test('aggregate caps retain older unfinished files and expose the actual size of a limited list', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  const ready = Array.from({length: 96}, (_, i) => ({...item, id: 'download:' + i.toString(16).padStart(64, '0'), state: 'ready', done: 100, updatedAt: 10_000}));
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot(ready));
  await fs.writeFile(path.join(directory, 'files-43.json'), JSON.stringify({version: 1, pid: 43, updatedAt: 1000, items: [{...item, state: 'waiting'}]}));
  const result = await store.snapshot(room);
  assert.equal(result.items.length, 96); assert.equal(result.total, 97); assert.equal(result.truncated, true); assert.equal(result.available, true);
  assert.equal(result.items[0].state, 'waiting'); assert.equal(result.items[0].id.startsWith('43:'), true);
});

test('continuous file replacement gets only one bounded reread and keeps confirmed progress', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room), file = path.join(directory, 'files-42.json');
  await fs.writeFile(file, snapshot([item])); await store.snapshot(room);
  await fs.writeFile(file, snapshot([{...item, done: 75}])); let opens = 0;
  store.io = {...fs, open: async (...args) => {
    opens++; const handle = await fs.open(...args);
    return wrappedHandle(handle, {read: async (...args) => {const result = await handle.read(...args); if (result.bytesRead) await fs.appendFile(file, ' '); return result;}});
  }};
  const result = await store.snapshot(room); assert.equal(result.stale, true); assert.equal(result.items[0].done, 50); assert.equal(opens, 2);
});

test('file-status diagnostics record transitions once without filenames, paths or transfer content', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room), events = [];
  store.record = (event, fields) => events.push({event, ...fields});
  await store.snapshot(room); await store.snapshot(room);
  await fs.writeFile(path.join(directory, 'files-42.json'), 'bad status'); await store.snapshot(room); await store.snapshot(room);
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([item])); await store.snapshot(room);
  assert.deepEqual(events, [{event: 'file_status', state: 'available'}, {event: 'file_status', state: 'unavailable'}, {event: 'file_status', state: 'available'}]);
});

test('renderer snapshot reuse updates truncation metadata and retains it through empty failed reads', async () => {
  const {reconcileTransfers} = await import('../src/utils/fileTransfers.js');
  const previous = {items: [item], available: true, stale: false, total: 97, truncated: true};
  const reduced = reconcileTransfers(previous, {...previous, total: 1, truncated: false}); assert.notEqual(reduced, previous); assert.equal(reduced.items[0], item);
  const retained = reconcileTransfers(previous, {items: [], available: false, stale: true, total: 0, truncated: false});
  assert.equal(retained.total, 97); assert.equal(retained.truncated, true); assert.equal(retained.items[0], item);
});
async function fixture(t) {
  const base = path.resolve(__dirname, '.tmp'); await fs.mkdir(base, {recursive: true});
  const root = await fs.mkdtemp(path.join(base, 'files-store-'));
  t.after(async () => { assert.ok(root.startsWith(base + path.sep)); await fs.rm(root, {recursive: true, force: true}); });
  return {root, store: new FileTransfers(root)};
}
test('file status exposes bounded file names and progress without source paths', () => {
  assert.deepEqual(parseSnapshot(snapshot([item]), 42), [{...item, id: '42:' + item.id}]);
  for (const change of [{name: 'C:\\private\\kick.wav'}, {name: '../kick.wav'}, {state: 'unknown'}, {bytes: -1}, {done: 101}, {reason: 'raw server secret'}, {id: 'upload:' + hash}]) {
    assert.throws(() => parseSnapshot(snapshot([{...item, ...change}]), 42));
  }
  assert.throws(() => parseSnapshot(snapshot([item]), 43));
  assert.throws(() => parseSnapshot(snapshot(Array.from({length: 97}, () => item)), 42));
  assert.equal(parseSnapshot(snapshot([{...item, name: '\u202ekick.wav'}]), 42)[0].name, 'kick.wav');
  assert.equal(parseSnapshot(snapshot([{...item, name: '\u202e'}]), 42)[0].name, 'Sample file');
  assert.equal(parseSnapshot(snapshot([{...item, sourcePath: 'C:\\private\\kick.wav'}]), 42)[0].sourcePath, undefined);
});
test('file status belongs to the current launch and concurrent reads share one request', async t => {
  const {store} = await fixture(t), room = {}, other = {};
  const directory = await store.start(room);
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([item]));
  const [a, b] = await Promise.all([store.snapshot(room), store.snapshot(room)]);
  assert.deepEqual(a, b); assert.equal(a.items[0].done, 50);
  assert.deepEqual((await store.snapshot(other)).items, []);
  await store.start(other);
  assert.deepEqual((await store.snapshot(room)).items, []);
  assert.deepEqual((await store.snapshot(other)).items, []);
});
test('temporary, unrelated and oversized status files do not expose arbitrary data', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  await fs.writeFile(path.join(directory, 'files-42.json.part'), 'partial');
  await fs.writeFile(path.join(directory, 'preferences.json'), 'private');
  assert.deepEqual((await store.snapshot(room)).items, []);
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([item]));
  assert.equal((await store.snapshot(room)).items.length, 1);
  await fs.writeFile(path.join(directory, 'files-42.json'), 'x'.repeat(300000));
  const result = await store.snapshot(room);
  assert.equal(result.stale, true); assert.equal(result.available, false); assert.equal(result.items.length, 1);
});
test('failed status setup remains visible while sample delivery can run', async t => {
  const {root} = await fixture(t), room = {};
  const store = new FileTransfers(path.join(root, 'file'));
  await fs.writeFile(store.root, 'cannot create a directory here');
  await assert.rejects(store.start(room));
  assert.equal((await store.snapshot(room)).available, false);
});

function launchFixture(root, fileTransfers) {
  const calls = [], installPath = path.join(root, 'FL Studio');
  const bridge = new DesktopBridge({nativeDir: path.join(root, 'native'), preferencesFile: path.join(root, 'preferences.json'),
    platform: 'win32', environment: {SystemRoot: 'C:\\Windows', FLIM_FILES_DIR: 'C:\\unowned-status', FLIM_PASSWORD: 'unowned-password'}, fileTransfers,
    run: async (_file, args, options) => {
      calls.push({args, options});
      return JSON.stringify(args[0] === '--inspect-json' ? {path: installPath, version: '26.1.7.5654', supported: true} : {launched: true, pid: 123});
    }});
  bridge.nativeReady = true; bridge.name = 'Musician'; bridge.selectedInstallId = 'test';
  bridge.installs.set('test', {id: 'test', path: installPath, version: '26.1.7.5654', supported: true});
  bridge.room = {code: '12345678', password: 'a'.repeat(64), hostToken: 'b'.repeat(64), role: 'host', state: 'ready', status: 'waiting', peers: []};
  return {bridge, calls};
}

test('native launch receives only its owned file-status directory and no inherited override', async t => {
  const {root, store} = await fixture(t), {bridge, calls} = launchFixture(root, store);
  await bridge.launchFL();
  const launch = calls.find(call => call.args[0] === '--desktop');
  assert.equal(bridge.room.state, 'launched');
  assert.equal(launch.options.env.FLIM_FILES_DIR, store.directory);
  assert.ok(store.directory.startsWith(root + path.sep));
  assert.equal(calls[0].options.env.FLIM_FILES_DIR, undefined);
  assert.equal(launch.options.env.FLIM_PASSWORD, bridge.room.password);
});

test('file-status setup failure does not prevent native launch or inherit an unsafe directory', async t => {
  const {root} = await fixture(t);
  const {bridge, calls} = launchFixture(root, {start: async () => {throw new Error('disk unavailable');}});
  await bridge.launchFL();
  assert.equal(bridge.room.state, 'launched');
  assert.equal(calls.find(call => call.args[0] === '--desktop').options.env.FLIM_FILES_DIR, undefined);
});
test('compact room and sidebar widths remain bounded by the monitor', () => {
  const bounds = {x: 0, y: 0, width: 472, height: 500}, content = [456, 460], area = {x: 0, y: 0, width: 1920, height: 1080};
  assert.equal(fitBounds(500, bounds, content, area).width, 472);
  assert.equal(fitBounds(500, bounds, content, area, 1, 400).width, 416);
  assert.equal(fitBounds(500, bounds, content, area, 1, 680).width, 696);
  assert.equal(fitBounds(500, bounds, content, {...area, width: 600}, 1, 680).width, 576);
  assert.equal(fitBounds(500, bounds, content, area, 1, 756).width, 772);
  assert.equal(fitBounds(500, bounds, content, {...area, width: 600}, 1, 756).width, 576);
  assert.equal(fitBounds(500, bounds, content, area, 1, 999), null);
});
test('file sizes, status descriptions and progress reflect actual transfer direction', async () => {
  const {fileSize, fileProgress, fileStatus} = await import('../src/utils/fileTransfers.js');
  assert.equal(fileSize(1024), '1.0 KB'); assert.equal(fileSize(1048576), '1.0 MB');
  assert.equal(fileProgress(item), 50); assert.equal(fileProgress({...item, bytes: 0}), 0);
  assert.equal(fileStatus({...item, state: 'ready'}), 'Ready on this computer');
  assert.equal(fileStatus({...item, state: 'ready', direction: 'upload'}), 'Available to the room');
  assert.equal(fileStatus({...item, state: 'failed', reason: 'verification'}), 'Download could not be verified');
  assert.equal(fileStatus({...item, state: 'waiting', reason: 'retrying'}), 'Waiting to retry automatically');
  assert.equal(fileStatus({...item, state: 'waiting', reason: 'verification'}), 'Checking again automatically');
});

test('native pending-file snapshots retain retry state without claiming the file is ready', () => {
  const pending = parseSnapshot(snapshot([{...item, state: 'waiting', reason: 'retrying'}]), 42);
  assert.equal(pending[0].state, 'waiting'); assert.equal(pending[0].reason, 'retrying');
  assert.equal(pending[0].done, item.done);
});

test('duplicate transfer keys and negative snapshot times are rejected', () => {
  assert.throws(() => parseSnapshot(snapshot([item, item]), 42), /Invalid file status/);
  assert.throws(() => parseSnapshot(JSON.stringify({version: 1, pid: 42, updatedAt: -1, items: [item]}), 42), /Invalid file status/);
});

test('directional control characters cannot disguise displayed sample names', () => {
  assert.equal(parseSnapshot(snapshot([{...item, name: '\u061c\u200e\u200fkick\u2066.wav\u2069'}]), 42)[0].name, 'kick.wav');
});

test('one broken process snapshot preserves its files while healthy process progress updates', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  const second = done => JSON.stringify({version: 1, pid: 43, updatedAt: 2000, items: [{...item, done}]});
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([item]));
  await fs.writeFile(path.join(directory, 'files-43.json'), second(10));
  assert.equal((await store.snapshot(room)).items.length, 2);
  await fs.writeFile(path.join(directory, 'files-42.json'), '{partial');
  await fs.writeFile(path.join(directory, 'files-43.json'), second(75));
  const partial = await store.snapshot(room);
  assert.equal(partial.available, false); assert.equal(partial.stale, true);
  assert.equal(partial.items.find(file => file.id.startsWith('42:')).done, 50);
  assert.equal(partial.items.find(file => file.id.startsWith('43:')).done, 75);
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([{...item, done: 100, state: 'ready'}]));
  const recovered = await store.snapshot(room);
  assert.equal(recovered.available, true); assert.equal(recovered.stale, false);
  assert.equal(recovered.items.find(file => file.id.startsWith('42:')).state, 'ready');
});

test('sample search normalizes accents, width and case without altering displayed names', async () => {
  const {fileSearchKey} = await import('../src/utils/fileTransfers.js');
  assert.equal(fileSearchKey('  KÍCK Ｂass.wav '), 'kick bass.wav');
  assert.equal(fileSearchKey(''), '');
});

test('amount labels distinguish unknown sizes and report actual transferred bytes at large sizes', async () => {
  const {fileAmount, fileSize} = await import('../src/utils/fileTransfers.js');
  assert.equal(fileSize(1024 ** 3), '1.0 GB'); assert.equal(fileSize(1024 ** 4), '1.0 TB');
  assert.equal(fileSize(-1), 'Size unavailable'); assert.equal(fileSize(NaN), 'Size unavailable');
  assert.equal(fileAmount(item), '50 B of 100 B · 50%');
  assert.equal(fileAmount({...item, bytes: 0, done: 0, state: 'checking'}), 'Size not known yet');
  assert.equal(fileAmount({...item, bytes: 0, done: 0, state: 'failed', reason: 'empty'}), '0 B');
});

test('unchanged transfer snapshots reuse references and failed empty reads keep confirmed files', async () => {
  const {reconcileTransfers} = await import('../src/utils/fileTransfers.js');
  const previous = {items: [item], available: true, stale: false};
  assert.equal(reconcileTransfers(previous, structuredClone(previous)), previous);
  const next = reconcileTransfers(previous, {items: [{...item, done: 75}], available: true, stale: false});
  assert.notEqual(next, previous); assert.equal(next.items[0].done, 75);
  for (const failure of [{available: false, stale: true}, {available: true, stale: true}]) {
    const retained = reconcileTransfers(previous, {items: [], ...failure});
    assert.equal(retained.items[0], item); assert.equal(retained.stale, true);
  }
  assert.equal(reconcileTransfers(previous, {items: [], available: true, stale: false}).items.length, 0);
});

test('connection labels prioritize closed rooms, offline state and unconfirmed status before active', async () => {
  const {connectionStatus} = await import('../src/utils/roomUI.js');
  assert.deepEqual(connectionStatus('ended', false, true), {label: 'Room closed', tone: 'ended'});
  assert.deepEqual(connectionStatus('active', false, false), {label: 'Offline', tone: 'waiting'});
  assert.deepEqual(connectionStatus('active', true, true), {label: 'Status unavailable', tone: 'waiting'});
  assert.deepEqual(connectionStatus('active', true, false), {label: 'Room is open', tone: 'active'});
  assert.deepEqual(connectionStatus('waiting', true, false), {label: 'Getting ready', tone: 'waiting'});
});

function wrappedHandle(handle, overrides = {}) {
  return {read: (...args) => handle.read(...args), stat: () => handle.stat(), close: () => handle.close(), ...overrides};
}

test('unchanged status polls do not reopen files and atomic replacements invalidate cached data', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room), file = path.join(directory, 'files-42.json');
  let opens = 0;
  store.io = {...fs, open: async (...args) => {opens++; return fs.open(...args);}};
  await fs.writeFile(file, snapshot([item]));
  assert.equal((await store.snapshot(room)).items[0].done, 50);
  for (let i = 0; i < 8; i++) await store.snapshot(room);
  assert.equal(opens, 1);
  const before = await fs.stat(file), replacement = file + '.part';
  await fs.writeFile(replacement, snapshot([{...item, done: 75}]));
  await fs.utimes(replacement, before.atime, before.mtime);
  await fs.rename(replacement, file);
  assert.equal((await store.snapshot(room)).items[0].done, 75); assert.equal(opens, 2);
});

test('short filesystem reads are assembled into one verified status snapshot', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  await fs.writeFile(path.join(directory, 'files-42.json'), snapshot([item]));
  let reads = 0;
  store.io = {...fs, open: async (...args) => {
    const handle = await fs.open(...args);
    return wrappedHandle(handle, {read: async (buffer, offset, length, position) => {reads++; return handle.read(buffer, offset, Math.min(7, length), position);}});
  }};
  const result = await store.snapshot(room);
  assert.equal(result.available, true); assert.equal(result.items[0].done, 50); assert.ok(reads > 10);
});

test('an atomic replacement during inspection gets one fresh verified read without a stale pause', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room), file = path.join(directory, 'files-42.json');
  await fs.writeFile(file, snapshot([item])); await store.snapshot(room);
  await fs.writeFile(file, snapshot([{...item, done: 80}]));
  let replace = true;
  store.io = {...fs, open: async (...args) => {
    if (replace) {replace = false; await fs.writeFile(file + '.part', snapshot([{...item, done: 100, state: 'ready'}])); await fs.rename(file + '.part', file);}
    return fs.open(...args);
  }};
  const changed = await store.snapshot(room);
  assert.equal(changed.stale, false); assert.equal(changed.items[0].done, 100);
  const recovered = await store.snapshot(room);
  assert.equal(recovered.stale, false); assert.equal(recovered.items[0].done, 100);
});

test('a file modified during its read is reread and verified before publishing its new progress', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room), file = path.join(directory, 'files-42.json');
  await fs.writeFile(file, snapshot([item])); await store.snapshot(room);
  await fs.writeFile(file, snapshot([{...item, done: 75}]));
  let mutate = true;
  store.io = {...fs, open: async (...args) => {
    const handle = await fs.open(...args);
    return wrappedHandle(handle, {read: async (...readArgs) => {
      const result = await handle.read(...readArgs);
      if (mutate) {mutate = false; await fs.appendFile(file, ' ');}
      return result;
    }});
  }};
  assert.equal((await store.snapshot(room)).items[0].done, 75);
  assert.equal((await store.snapshot(room)).items[0].done, 75);
});

test('overlapping status setup for the same room keeps the newest directory', async t => {
  const {root} = await fixture(t), room = {};
  let release, entered;
  const waiting = new Promise(resolve => {entered = resolve;});
  let first = true;
  const store = new FileTransfers(root, {...fs, mkdir: async (...args) => {
    if (args[0] === root && first) {first = false; entered(); await new Promise(resolve => {release = resolve;});}
    return fs.mkdir(...args);
  }});
  const older = store.start(room); await waiting;
  const latest = await store.start(room); release();
  assert.notEqual(await older, latest); assert.equal(store.directory, latest);
});

test('an obsolete failed snapshot cannot mark a newly started room unavailable', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  let release, entered;
  const waiting = new Promise(resolve => {entered = resolve;});
  store.io = {...fs, readdir: async target => {
    if (target === directory) {entered(); await new Promise(resolve => {release = resolve;}); throw new Error('old read failed');}
    return fs.readdir(target);
  }};
  const older = store.snapshot(room); await waiting;
  await store.start(room); release();
  assert.deepEqual(await older, {items: [], available: true, stale: false});
  assert.equal((await store.snapshot(room)).available, true);
});

test('per-process confirmed files survive aggregate truncation and another process disappearing', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  for (const pid of [42, 43]) {
    const items = Array.from({length: 96}, (_, i) => ({...item, id: 'download:' + i.toString(16).padStart(64, '0'), updatedAt: pid * 1000}));
    await fs.writeFile(path.join(directory, `files-${pid}.json`), JSON.stringify({version: 1, pid, updatedAt: 1000, items}));
  }
  const initial = await store.snapshot(room); assert.equal(initial.items.length, 96); assert.ok(initial.items.every(file => file.id.startsWith('43:')));
  await fs.unlink(path.join(directory, 'files-43.json')); await fs.writeFile(path.join(directory, 'files-42.json'), '{partial');
  const retained = await store.snapshot(room);
  assert.equal(retained.stale, true); assert.equal(retained.items.length, 96); assert.ok(retained.items.every(file => file.id.startsWith('42:')));
});

test('process selection is deterministic and excess or invalid process files show partial status', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room);
  for (let pid = 1; pid <= 17; pid++) await fs.writeFile(path.join(directory, `files-${pid}.json`), JSON.stringify({version: 1, pid, updatedAt: 1000, items: [item]}));
  store.io = {...fs, readdir: async (...args) => (await fs.readdir(...args)).reverse()};
  const result = await store.snapshot(room);
  assert.equal(result.stale, true); assert.equal(result.items.length, 16); assert.ok(!result.items.some(file => file.id.startsWith('17:')));
  await fs.unlink(path.join(directory, 'files-17.json'));
  assert.equal((await store.snapshot(room)).available, true);
  await fs.writeFile(path.join(directory, 'files-9999999999.json'), '{}');
  assert.equal((await store.snapshot(room)).stale, true);
  assert.throws(() => parseSnapshot(JSON.stringify({version: 1, pid: 0x100000000, updatedAt: 1000, items: []}), 0x100000000), /Invalid file status/);
});

test('invalid UTF-8 status data retains the previous sample name instead of replacing bytes silently', async t => {
  const {store} = await fixture(t), room = {}, directory = await store.start(room), file = path.join(directory, 'files-42.json');
  await fs.writeFile(file, snapshot([item])); await store.snapshot(room);
  const text = snapshot([item]), index = text.indexOf('kick');
  await fs.writeFile(file, Buffer.concat([Buffer.from(text.slice(0, index)), Buffer.from([0xff]), Buffer.from(text.slice(index + 1))]));
  const result = await store.snapshot(room);
  assert.equal(result.stale, true); assert.equal(result.items[0].name, 'kick.wav');
});

test('oversized preferences are rejected before the file body is opened', async t => {
  const {root} = await fixture(t), file = path.join(root, 'preferences.json');
  await fs.writeFile(file, 'x'.repeat(20000));
  let opens = 0;
  const bridge = new DesktopBridge({nativeDir: root, preferencesFile: file, platform: 'test', io: {...fs, open: async (...args) => {opens++; return fs.open(...args);}}});
  assert.match((await bridge.initialize()).notice, /Saved settings could not be loaded/);
  assert.equal(opens, 0);
});
