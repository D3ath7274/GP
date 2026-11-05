'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const http=require('node:http');
const {options,resolveMint,healthy,portFree,start}=require('../scripts/start_docs.cjs');

function cleanup(root) {
  const target=fs.realpathSync(root);
  assert.equal(path.dirname(target),fs.realpathSync(os.tmpdir()));
  assert.ok(path.basename(target).startsWith('apf '));
  fs.rmSync(target,{recursive:true,force:true});
}

test('bounds and unknown CLI options fail explicitly',()=>{
  assert.deepEqual(options([]),{port:3333,timeout:120,foreground:false});
  assert.equal(options(['--port','3334','--timeout','5','--foreground']).foreground,true);
  for (const args of [['--port','0'],['--timeout','NaN'],['--port'],['--other']]) assert.throws(()=>options(args));
});
test('resolve real package bin rather than assume index.js; reject incomplete and wrong version',()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'apf mint '));
  try {
    fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'mint',version:'4.2.1195',bin:{mint:'cli.cjs'}}));
    assert.throws(()=>resolveMint([root]),/No complete/);
    fs.writeFileSync(path.join(root,'cli.cjs'),'// fixture');
    assert.equal(resolveMint([root]),path.join(root,'cli.cjs'));
    fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'mint',version:'0.0.0',bin:'cli.cjs'}));
    assert.throws(()=>resolveMint([root]),/No complete/);
    fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'mint',version:'4.2.1195',bin:'../outside.cjs'}));
    assert.throws(()=>resolveMint([root]),/No complete/);
  } finally { cleanup(root); }
});
test('probe requires matching healthy brand; refuses occupied port; reuses without CLI or spawn',async()=>{
  const server=http.createServer((req,res)=>{res.end('Adaptive IPS test site');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'apf docs '));
  try {
    assert.equal(await healthy('http://127.0.0.1:'+port,'Adaptive IPS test site'),true);
    assert.equal(await healthy('http://127.0.0.1:'+port,'Different site'),false);
    await assert.rejects(portFree(port));
    fs.mkdirSync(path.join(root,'docs-site'));
    fs.writeFileSync(path.join(root,'docs-site','docs.json'),JSON.stringify({name:'Adaptive IPS test site'}));
    assert.equal((await start(root,{port,timeout:5,foreground:false},[])).status,'already_ready');
    assert.equal(fs.existsSync(path.join(root,'.local')),false);
  } finally {
    await new Promise(resolve=>server.close(resolve));
    cleanup(root);
  }
});
test('free listener and missing installation do not create runtime state',async()=>{
  const server=http.createServer();
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  await new Promise(resolve=>server.close(resolve));
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'apf missing '));
  try {
    fs.mkdirSync(path.join(root,'docs-site'));
    fs.writeFileSync(path.join(root,'docs-site','docs.json'),JSON.stringify({name:'Adaptive IPS test site'}));
    await assert.rejects(start(root,{port,timeout:5,foreground:false},[]),/No complete/);
    assert.equal(fs.existsSync(path.join(root,'.local')),false);
  } finally { cleanup(root); }
});

test('detached fixture startup confirms readiness and releases its lock',async()=>{
  const probe=http.createServer();
  await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));
  const port=probe.address().port;
  await new Promise(resolve=>probe.close(resolve));
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'apf background '));
  let pid;
  try {
    fs.mkdirSync(path.join(root,'docs-site'));
    fs.writeFileSync(path.join(root,'docs-site','docs.json'),JSON.stringify({name:'Adaptive IPS fixture'}));
    const pkg=path.join(root,'fixture mint');fs.mkdirSync(pkg);
    fs.writeFileSync(path.join(pkg,'package.json'),JSON.stringify({name:'mint',version:'4.2.1195',bin:'serve.cjs'}));
    fs.writeFileSync(path.join(pkg,'serve.cjs'),
      "const http=require('node:http');const p=Number(process.argv[process.argv.indexOf('--port')+1]);"+
      "http.createServer((q,s)=>s.end('Adaptive IPS fixture')).listen(p,'127.0.0.1');");
    const result=await start(root,{port,timeout:5,foreground:false},[pkg]);pid=result.pid;
    assert.equal(result.status,'ready');
    assert.equal(await healthy(result.url,'Adaptive IPS fixture'),true);
    assert.equal(fs.existsSync(path.join(root,'.local','docs-preview','node-start-'+port+'.lock')),false);
    assert.equal(JSON.parse(fs.readFileSync(path.join(root,'.local','docs-preview','mint-'+port+'.json'))).pid,pid);
  } finally {
    if (pid) {
      try { process.kill(pid,'SIGTERM'); } catch (error) { if (error.code!=='ESRCH') throw error; }
      for (let i=0;i<30 && await healthy('http://127.0.0.1:'+port,'Adaptive IPS fixture');i++)
        await new Promise(resolve=>setTimeout(resolve,100));
    }
    cleanup(root);
  }
});
