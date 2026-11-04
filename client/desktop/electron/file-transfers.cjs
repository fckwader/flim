'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const {randomUUID} = require('node:crypto');
const {sameMetadata, readStableFile} = require('./local-file.cjs');
const STATES = new Set(['checking', 'uploading', 'downloading', 'waiting', 'ready', 'missing', 'failed', 'blocked']);
const REASONS = new Set(['', 'retrying', 'source_missing', 'source_changed', 'too_large', 'empty', 'network', 'allowance', 'verification', 'local_cache', 'relay_cache', 'uploaded', 'downloaded']);
const MAX_BYTES = 256 * 1024;

function parseSnapshot(source, pid) {
  const value = JSON.parse(source);
  if (!value || value.version !== 1 || value.pid !== pid || !Number.isInteger(pid) || pid < 1 || pid > 0xffffffff || !Array.isArray(value.items) || value.items.length > 96 || !Number.isSafeInteger(value.updatedAt) || value.updatedAt < 0 || new Set(value.items.map(item => item?.id)).size !== value.items.length) throw new Error('Invalid file status.');
  return value.items.map(item => {
    if (!item || typeof item.id !== 'string' || !/^(?:upload|download):(?:[a-f0-9]{64}|path-[a-f0-9]{16})$/.test(item.id) ||
        typeof item.name !== 'string' || !item.name || item.name.length > 768 || !item.name.isWellFormed() || /[\\/\x00-\x1f\x7f]/.test(item.name) ||
        !['upload', 'download'].includes(item.direction) || !item.id.startsWith(item.direction + ':') || !STATES.has(item.state) || !REASONS.has(item.reason) ||
        (item.state === 'uploading' && item.direction !== 'upload') || (item.state === 'downloading' && item.direction !== 'download') ||
        !Number.isSafeInteger(item.bytes) || item.bytes < 0 || !Number.isSafeInteger(item.done) || item.done < 0 || item.done > item.bytes ||
        !Number.isSafeInteger(item.updatedAt) || item.updatedAt < 0) throw new Error('Invalid file status.');
    return {id: `${pid}:${item.id}`, name: item.name.replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, '').trim() || 'Sample file',
      direction: item.direction, state: item.state, reason: item.reason, bytes: item.bytes, done: item.done, updatedAt: item.updatedAt};
  });
}

class FileTransfers {
  constructor(root, io = fs, record = () => {}) { this.root = path.resolve(root); this.io = io; this.record = record; this.health = ''; this.owner = null; this.directory = ''; this.last = []; this.flight = null; this.generation = 0; this.cache = new Map(); this.lastTotal = 0; this.lastTruncated = false; }
  report(state) {
    if (this.health === state) return;
    this.health = state;
    try { Promise.resolve(this.record('file_status', {state})).catch(() => {}); } catch {}
  }
  async start(owner) {
    const generation = ++this.generation;
    this.owner = owner; this.directory = ''; this.last = []; this.lastTotal = 0; this.lastTruncated = false; this.flight = null; this.cache = new Map(); this.health = '';
    await this.io.mkdir(this.root, {recursive: true, mode: 0o700});
    const root = await this.io.realpath(this.root);
    const directory = path.join(root, 'files-' + randomUUID());
    await this.io.mkdir(directory, {mode: 0o700});
    if (this.generation === generation && this.owner === owner) this.directory = directory;
    return directory;
  }
  async snapshot(owner) {
    if (!owner || owner !== this.owner) return {items: [], available: true, stale: false};
    if (!this.directory) return {items: [], available: false, stale: true};
    if (this.flight) return this.flight;
    const directory = this.directory, generation = this.generation, cache = this.cache;
    const current = () => directory === this.directory && owner === this.owner && generation === this.generation;
    const detached = () => ({items: [], available: true, stale: false});
    const task = (async () => {
      try {
        const stat = await this.io.lstat(directory);
        if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Invalid status directory.');
        const names = await this.io.readdir(directory);
        if (names.length > 4096) throw new Error('Status directory exceeds its file limit.');
        const candidates = names.filter(name => /^files-[1-9]\d{0,9}\.json$/.test(name));
        const valid = candidates.filter(name => Number(name.slice(6, -5)) <= 0xffffffff).sort((a, b) => Number(a.slice(6, -5)) - Number(b.slice(6, -5)));
        const files = valid.slice(0, 16);
        const results = await Promise.allSettled(files.map(async name => {
          const file = path.join(directory, name);
          for (let attempt = 0; ; attempt++) {
            const metadata = await this.io.lstat(file);
            if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_BYTES) throw new Error('Invalid status file.');
            const previous = cache.get(name);
            if (previous && sameMetadata(previous.metadata, metadata)) return previous;
            try {
              const source = await readStableFile(this.io, file, MAX_BYTES, metadata);
              return {metadata, items: parseSnapshot(source, Number(name.slice(6, -5)))};
            } catch (error) { if (attempt || error.code !== 'FILE_CHANGED') throw error; }
          }
        }));
        if (!current()) return detached();
        for (const name of cache.keys()) if (!files.includes(name)) cache.delete(name);
        results.forEach((result, index) => {if (result.status === 'fulfilled') cache.set(files[index], result.value);});
        const stale = candidates.length !== valid.length || valid.length > files.length || results.some(result => result.status === 'rejected');
        const all = files.flatMap(name => cache.get(name)?.items ?? []);
        const items = all.sort((a, b) => Number(a.state === 'ready') - Number(b.state === 'ready') || b.updatedAt - a.updatedAt || a.id.localeCompare(b.id)).slice(0, 96);
        this.last = items;
        this.lastTotal = all.length;
        this.lastTruncated = all.length > items.length || valid.length > files.length;
        this.report(stale ? 'unavailable' : 'available');
        return {items, available: !stale, stale, total: all.length, truncated: this.lastTruncated};
      } catch {
        if (!current()) return detached();
        this.report('unavailable');
        return {items: this.last, available: false, stale: true, total: this.lastTotal, truncated: this.lastTruncated};
      }
    })();
    this.flight = task;
    try { return await task; } finally { if (this.flight === task) this.flight = null; }
  }
}

module.exports = {FileTransfers, parseSnapshot};
