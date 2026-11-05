/* Start a checked-out Mintlify preview without PowerShell script execution. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const {spawn} = require('node:child_process');

const TESTED_MINT = '4.2.1195';
function options(argv) {
  const result = {port:3333, timeout:120, foreground:false};
  for (let i=0;i<argv.length;i++) {
    if (argv[i]==='--foreground') result.foreground=true;
    else if (argv[i]==='--port' || argv[i]==='--timeout') {
      const key=argv[i].slice(2), value=Number(argv[++i]);
      if (!Number.isInteger(value) || value<(key==='port'?1024:5) || value>(key==='port'?65535:300)) throw Error('Invalid '+key);
      result[key]=value;
    } else throw Error('Unknown option: '+argv[i]);
  }
  return result;
}
function resolveMint(roots) {
  const checked=[];
  for (const root of [...new Set(roots.filter(Boolean))]) {
    const manifest=path.join(root,'package.json');
    if (!fs.existsSync(manifest)) continue;
    const info=JSON.parse(fs.readFileSync(manifest,'utf8'));
    if (info.name!=='mint') continue;
    const bin=typeof info.bin==='string'?info.bin:info.bin?.mint;
    const entry=bin && path.resolve(root,bin);
    checked.push(root);
    if (info.version===TESTED_MINT && entry && !path.isAbsolute(path.relative(root,entry)) && path.relative(root,entry)!=='..' &&
        !path.relative(root,entry).startsWith('..'+path.sep) && fs.existsSync(entry) && fs.statSync(entry).isFile()) return entry;
  }
  throw Error('No complete mint@'+TESTED_MINT+' installation. Checked: '+checked.join(', ')+
    '. Repair with npm.cmd install --global mint@'+TESTED_MINT+'; then retry. No process was started.');
}
function healthy(url, name) {
  return new Promise(resolve=>{
    const request=http.get(url,response=>{
      let text='', size=0;
      response.on('data',chunk=>{
        size+=chunk.length;
        if (size>8*1024*1024) { response.destroy(); resolve(false); }
        else text+=chunk.toString();
      });
      response.on('end',()=>resolve(response.statusCode===200 && text.includes(name)));
      response.on('error',()=>resolve(false));
    });
    request.setTimeout(2000,()=>request.destroy());
    request.on('error',()=>resolve(false));
  });
}
function portFree(port) {
  return new Promise((resolve,reject)=>{
    const server=net.createServer();
    server.once('error',reject);
    server.listen(port,'127.0.0.1',()=>server.close(()=>resolve()));
  });
}
async function start(repo, settings, roots) {
  const docs=path.join(repo,'docs-site');
  const name=JSON.parse(fs.readFileSync(path.join(docs,'docs.json'),'utf8')).name;
  if (typeof name!=='string' || !name.trim()) throw Error('docs.json needs a site name');
  const url='http://127.0.0.1:'+settings.port+'/';
  if (await healthy(url,name)) return {status:'already_ready',url};
  // Refuse an occupied port: Mintlify must not silently fall back to another.
  await portFree(settings.port);
  const entry=resolveMint(roots);
  const args=[entry,'dev','--port',String(settings.port),'--no-open'];
  if (settings.foreground) {
    const child=spawn(process.execPath,args,{cwd:docs,stdio:'inherit'});
    await new Promise((resolve,reject)=>{
      child.once('error',reject);
      child.once('exit',code=>code===0?resolve():reject(Error('Mintlify exited: '+code)));
    });
    return {status:'stopped',url};
  }
  const runtime=path.join(repo,'.local','docs-preview');
  fs.mkdirSync(runtime,{recursive:true});
  const lockPath=path.join(runtime,'node-start-'+settings.port+'.lock');
  // Fail closed on an existing lock, including a stale one; never kill a PID by guess.
  let lock;
  try { lock=fs.openSync(lockPath,'wx',0o600); }
  catch { throw Error('Startup lock already exists: '+lockPath+'. Check the launcher before removing a stale lock.'); }
  try {
    fs.writeFileSync(lock,JSON.stringify({pid:process.pid,started_at:new Date().toISOString()}));
    if (await healthy(url,name)) return {status:'already_ready',url};
    await portFree(settings.port);
    const stdout=path.join(runtime,'mint-'+settings.port+'.stdout.log');
    const stderr=path.join(runtime,'mint-'+settings.port+'.stderr.log');
    const out=fs.openSync(stdout,'a'), err=fs.openSync(stderr,'a');
    let child;
    try { child=spawn(process.execPath,args,{cwd:docs,detached:true,windowsHide:true,stdio:['ignore',out,err]}); }
    finally { fs.closeSync(out); fs.closeSync(err); }
    await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject);});
    child.unref();
    fs.writeFileSync(path.join(runtime,'mint-'+settings.port+'.json'),
      JSON.stringify({pid:child.pid,port:settings.port,url,entry,started_at:new Date().toISOString()},null,2));
    const deadline=Date.now()+settings.timeout*1000;
    while (Date.now()<deadline) {
      if (await healthy(url,name)) return {status:'ready',url,pid:child.pid};
      if (child.exitCode!==null || child.signalCode!==null) throw Error('Mintlify exited before readiness; inspect '+stderr);
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    throw Error('Readiness timed out; process may still be preparing. Inspect '+stdout+' and '+stderr);
  } finally { fs.closeSync(lock); fs.unlinkSync(lockPath); }
}
async function main() {
  const repo=path.resolve(__dirname,'..');
  const roots=[path.join(repo,'docs-site','node_modules','mint'),path.join(repo,'node_modules','mint'),
    process.env.APPDATA && path.join(process.env.APPDATA,'npm','node_modules','mint'),
    path.join(path.dirname(process.execPath),'node_modules','mint'),
    path.resolve(path.dirname(process.execPath),'..','lib','node_modules','mint')];
  console.log(JSON.stringify(await start(repo,options(process.argv.slice(2)),roots),null,2));
}
module.exports={options,resolveMint,healthy,portFree,start};
if (require.main===module) main().catch(error=>{console.error(error.message);process.exitCode=1;});
