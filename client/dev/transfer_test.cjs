const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs/promises');
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');

(async()=>{
  const root=path.resolve(__dirname,'../desktop/test/.tmp');
  await fs.mkdir(root,{recursive:true});
  const directory=await fs.mkdtemp(path.join(root,'transfer-'));
  const batches=[], failures=[];
  let mode = 'normal', modeCalls = 0, redirectsFollowed = 0, offers = 0;
  const server=http.createServer(async(req,res)=>{
    try{
      const chunks=[];for await(const chunk of req)chunks.push(chunk);
      const body=Buffer.concat(chunks);
      if(req.url==='/test-mode'){
        mode=body.toString();modeCalls=0;res.end();
      }else if(req.url==='/connect'){
        assert.equal(JSON.parse(body).token,'2'.repeat(64));res.end();
      }else if(req.url==='/offer'){
        assert.equal(JSON.parse(body).s,65569);offers++;res.end();
      }else if(req.url==='/offer-count'){
        res.end(String(offers));
      }else if(/^\/blob\/[a-f0-9]{64}(?:\?|$)/.test(req.url)){
        const direct=req.headers['x-flim-key']==='1'.repeat(64);
        if(direct && mode==='peer-missing'){res.writeHead(404);res.end();return;}
        if(direct && mode==='peer-throttle'){res.writeHead(429);res.end('{"code":"local_busy"}');return;}
        res.end(direct && mode==='peer-corrupt'?'wrong transfer content':'flim transfer download');
      }else if(req.url==='/blobs/missing'){
        const hashes=body.toString().trim().split('\n');
        assert.ok(hashes.length<=512);modeCalls++;
        if(mode==='normal')batches.push(hashes.length);
        if(mode==='failed' || (mode==='retry' && modeCalls===1) || (mode==='partial' && modeCalls>1)) {res.writeHead(503);res.end();return;}
        if(mode==='alien'){res.end('f'.repeat(64));return;}
        res.end(hashes.filter(hash=>parseInt(hash.slice(-8),16)%2===0).join('\n'));
      }else if(req.url==='/blob/upload'){
        assert.equal(body.length,65569);
        for(let i=0;i<body.length;i++)assert.equal(body[i],i%251);
        res.writeHead(mode==='upload-conflict'?409:201);res.end();
      }else if(req.url==='/blob/redirect'){
        res.writeHead(302, {location: '/blob/redirect-target'});res.end();
      }else if(req.url==='/blob/redirect-target'){
        redirectsFollowed++;res.end('should not be requested');
      }else if(req.url==='/blob/download'){
        res.writeHead(200,{'content-length':22});res.end('flim transfer download');
      }else{res.writeHead(404);res.end();}
    }catch(error){failures.push(String(error));res.writeHead(500);res.end();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let output='';
  try{
    const child=spawn(path.join(__dirname,'harness/t_transfer.exe'),[`http://127.0.0.1:${server.address().port}`],{cwd:directory,windowsHide:true,stdio:['ignore','pipe','pipe']});
    child.stdout.on('data',data=>{output+=data;process.stdout.write(data);});
    child.stderr.on('data',data=>process.stderr.write(data));
    const timer=setTimeout(()=>child.kill(),30000);
    let code;try{code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);});}finally{clearTimeout(timer);}
    assert.equal(code,0);assert.deepEqual(batches,[512,512,1]);assert.deepEqual(failures,[]);assert.equal(redirectsFollowed,0);
    const result={passed:(output.match(/^PASS /gm)||[]).length,scope:'Real native WinHTTP against an ephemeral loopback fixture; no FL processes or Cloudflare writes',batches,output};
    const evidence = path.join(__dirname, '../desktop/test/evidence'); await fs.mkdir(evidence, {recursive: true});
    await fs.writeFile(path.join(evidence,'native-transfer-results.json'),JSON.stringify(result,null,2));
  }finally{
    await new Promise(resolve=>server.close(resolve));
    assert.ok(directory.startsWith(root+path.sep));await fs.rm(directory,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
