'use strict';

function sameMetadata(a, b) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].every(key => a[key] === b[key]);
}
const changed = message => Object.assign(new Error(message), {code: 'FILE_CHANGED'});

async function readStableFile(io, file, limit, metadata) {
  metadata ??= await io.lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > limit || metadata.size < 0) throw new Error('Invalid local file.');
  const handle = await io.open(file, 'r');
  let failure;
  try {
    if (!sameMetadata(metadata, await handle.stat())) throw changed('Local file changed before reading.');
    const bytes = Buffer.alloc(metadata.size + 1);
    let total = 0;
    for (;;) {
      const {bytesRead} = await handle.read(bytes, total, bytes.length - total, total);
      if (!bytesRead) break;
      total += bytesRead;
      if (total > metadata.size) throw changed('Local file grew while reading.');
    }
    const current = await io.lstat(file);
    if (total !== metadata.size || current.isSymbolicLink() || !sameMetadata(metadata, await handle.stat()) || !sameMetadata(metadata, current)) throw changed('Local file changed while reading.');
    return new TextDecoder('utf-8', {fatal: true}).decode(bytes.subarray(0, total));
  } catch (error) {failure = error; throw error;}
  finally {try {await handle.close();} catch (error) {if (!failure) throw error;}}
}

module.exports = {sameMetadata, readStableFile};
