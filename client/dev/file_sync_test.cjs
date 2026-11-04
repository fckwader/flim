const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const assert = require('node:assert/strict');
const {parseSnapshot} = require('../desktop/electron/file-transfers.cjs');
(async () => {
  const root = path.resolve(__dirname, '../desktop/test/.tmp'); await fs.mkdir(root, {recursive: true});
  const directory = await fs.mkdtemp(path.join(root, 'file-sync-'));
  const statusDir = path.join(directory, 'status'); await fs.mkdir(statusDir);
  const store = new Map(); let mode = '', downloads = 0, puts = 0, retried = 0, quotaRequests = 0, lookups = 0, outageDownloads = 0, uploadAttempts = 0, verifyAttempts = 0;
  const offered = [], pending = new Set();
  const pendingChecks = [];
  function expectPending(label) {
    pendingChecks.push(new Promise(resolve => setTimeout(() => {
      confirmPending(label).catch(error => errors.push(String(error))).finally(resolve);
    }, 100)));
  }
  async function confirmPending(label) {
    const names = (await fs.readdir(statusDir)).filter(name => /^files-\d+\.json$/.test(name));
    const states = (await Promise.all(names.map(name => fs.readFile(path.join(statusDir, name), 'utf8')))).flatMap(text => JSON.parse(text).items);
    assert.ok(states.some(item => item.state === 'waiting')); pending.add(label);
  }
  const errors = [];
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk); const body = Buffer.concat(chunks);
      if (req.url === '/test-mode') { mode = body.toString(); res.end(); return; }
      if (req.url === '/connect') { assert.equal(JSON.parse(body).token, '2'.repeat(64)); res.end(); return; }
      if (req.url === '/offer') {
        const offer = JSON.parse(body); assert.equal(offer.generation, 1); assert.equal(offer.s, 26);
        offer.file = Buffer.from(offer.p, 'base64').toString('utf16le');
        assert.ok(path.isAbsolute(offer.file) && !/\.tmp$/i.test(offer.file)); offered.push(offer); res.end(); return;
      }
      if (req.url === '/offer-count') { res.end(String(offered.length)); return; }
      if (req.headers['x-flim-key'] === '1'.repeat(64) && req.url.startsWith('/blob/')) { res.writeHead(404); res.end(); return; }
      if (req.url === '/blobs/missing') {
        if (mode === 'outage-lookup' && lookups++ < 2) {if (lookups === 2) expectPending('lookup'); res.writeHead(503); res.end(); return;}
        res.end(body.toString().trim().split('\n').filter(hash => !store.has(hash)).join('\n')); return;
      }
      const hash = req.url.slice(6);
      if (req.method === 'PUT') {
        if (uploadAttempts++ < 2) {if (uploadAttempts === 2) expectPending('upload'); res.writeHead(503); res.end(); return;}
        assert.equal(createHash('sha256').update(body).digest('hex'), hash); store.set(hash, body); puts++; res.writeHead(201); res.end(); return;
      }
      downloads++;
      if (mode === 'outage-download' && outageDownloads++ < 2) {if (outageDownloads === 2) expectPending('download'); res.writeHead(503); res.end(); return;}
      if (mode === 'recover-verification' && verifyAttempts++ === 0) {expectPending('verification'); res.end('invalid audio'); return;}
      if (mode === 'quota') { quotaRequests++; res.writeHead(507); res.end('{"code":"r2_storage_limit"}'); return; }
      if (mode === 'retry-download' && retried++ === 0) { res.writeHead(503); res.end(); return; }
      if (mode === 'corrupt') { res.end('invalid audio'); return; }
      assert.ok(store.has(hash)); res.end(store.get(hash));
    } catch (error) { errors.push(String(error)); res.writeHead(500); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let output = '';
  try {
    const child = spawn(path.join(__dirname, 'harness/t_file_sync.exe'), [`http://127.0.0.1:${server.address().port}`], {
      cwd: directory, windowsHide: true, env: {...process.env, FLIM_FILES_DIR: statusDir, FLIM_LOG_DIR: directory}, stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', data => { output += data; process.stdout.write(data); }); child.stderr.on('data', data => process.stderr.write(data));
    const timer = setTimeout(() => child.kill(), 45000);
    let code; try { code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); }); } finally { clearTimeout(timer); }
    await Promise.all(pendingChecks);
    assert.deepEqual(errors, []); assert.equal(code, 0); assert.equal(puts, 1); assert.equal(downloads, 13); assert.equal(quotaRequests, 1);
    assert.equal(lookups, 4); assert.equal(outageDownloads, 3);
    assert.equal(uploadAttempts, 3); assert.equal(verifyAttempts, 2); assert.equal(pending.size, 4);
    assert.ok(offered.some(offer => offer.file.startsWith(path.join(directory, 'peer') + path.sep)), 'Verified received files must be available to other peers');
    const files = await fs.readdir(statusDir); assert.equal(files.filter(file => file.endsWith('.part')).length, 0);
    const name = files.find(file => /^files-\d+\.json$/.test(file)); assert.ok(name);
    const items = parseSnapshot(await fs.readFile(path.join(statusDir, name), 'utf8'), Number(name.slice(6, -5)));
    assert.ok(items.some(item => item.state === 'ready' && item.direction === 'upload'));
    assert.ok(items.some(item => item.state === 'blocked' && item.direction === 'download'));
    assert.ok(items.every(item => !item.name.includes('\\') && !item.name.includes('/')));
    for (const hashDir of await fs.readdir(path.join(directory, 'peer'))) {
      assert.ok(!(await fs.readdir(path.join(directory, 'peer', hashDir))).some(name => /^flm.*\.tmp$/i.test(name)), 'Owned download temporary files must be removed');
    }
    const evidence = path.resolve(__dirname, '../desktop/test/evidence/file-sync'); await fs.mkdir(evidence, {recursive: true});
    await fs.writeFile(path.join(evidence, 'native.json'), JSON.stringify({passed: true, puts, downloads, quotaRequests, uploadAttempts, verifyAttempts, registeredVerifiedCopies: offered.length, pending: [...pending], output, statusItems: items.length,
      scope: 'Native transfer workers and loopback file store. No user FL process, project, or Cloudflare account changed.'}, null, 2));
    console.log('PASS local file sidebar status parses real native events without exposing source folders');
  } finally { await new Promise(resolve => server.close(resolve)); assert.ok(directory.startsWith(root + path.sep)); await fs.rm(directory, {recursive: true, force: true}); }
})().catch(error => { console.error(error); process.exitCode = 1; });
