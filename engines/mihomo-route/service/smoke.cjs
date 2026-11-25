'use strict';
const {spawn,execFileSync}=require('node:child_process');
const {randomBytes}=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const net=require('node:net');
const http=require('node:http');
const assert=require('node:assert/strict');
const normal=path.resolve(process.argv[2]),lab=path.resolve(process.argv[3]);
const endpoint='/__netverge_service_lab/bootstrap';
const sid=execFileSync('whoami.exe',['/user','/fo','csv','/nh'],{encoding:'utf8'}).match(/S-1-5-21-\d+-\d+-\d+-\d+/)?.[0];
assert.ok(sid,'Windows owner SID required');
const acl='D:P(A;;GA;;;'+sid+')(A;;GA;;;SY)(A;;GA;;;BA)';
const config=Buffer.from('mode: rule\nlog-level: warning\nmixed-port: 0\nallow-lan: false\ngeo-auto-update: false\nrules:\n  - MATCH,DIRECT\n').toString('base64');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function ports(){
 const a=net.createServer(),b=net.createServer();
 for(const s of [a,b])await new Promise((r,j)=>{s.once('error',j);s.listen(0,'127.0.0.1',r)});
 const p=[a.address().port,b.address().port];
 for(const s of [a,b])await new Promise(r=>s.close(r));
 return p;
}
function req(target,method,route,payload,extra={}){
 return new Promise((resolve,reject)=>{
  const body=payload===undefined?undefined:Buffer.from(JSON.stringify(payload));
  const r=http.request({...target,method,path:route,agent:false,headers:{Host:'netverge-local',Connection:'close',...(body?{'Content-Type':'application/json','Content-Length':body.length}:{}),...extra}},res=>{
   let data='';res.setEncoding('utf8');
   res.on('data',c=>{data+=c;if(data.length>65536)r.destroy(Error('response too large'))});
   res.on('end',()=>resolve({status:res.statusCode,body:data}));
   res.on('error',reject);
  });
  r.setTimeout(2500,()=>r.destroy(Error('timeout')));r.on('error',reject);r.end(body);
 });
}
async function run(exe,descriptor,fn,envLaunch=false){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'nv-pipe-lab-'));
 const pipe='\\\\.\\pipe\\netverge-service-lab-'+randomBytes(12).toString('hex');
 const [tcpPort,port]=await ports(),secret=randomBytes(24).toString('base64url');
 const env={...process.env};
 for(const k of ['NETVERGE_CORE_CONTROL_PORT','NETVERGE_CORE_CONTROL_SECRET','LISTEN_NAMEDPIPE_SDDL'])delete env[k];
 if(descriptor)env.LISTEN_NAMEDPIPE_SDDL=descriptor;
 if(envLaunch){env.NETVERGE_CORE_CONTROL_PORT=String(port);env.NETVERGE_CORE_CONTROL_SECRET=secret;}
 const child=spawn(exe,['-d',dir,'-config',config,'-ext-ctl-pipe',pipe,'-ext-ctl','127.0.0.1:'+tcpPort],{env,stdio:['ignore','ignore','inherit'],windowsHide:true});
 let err;child.once('error',e=>{err=e});
 const exited=new Promise(r=>child.once('close',r));
 const local={socketPath:pipe},tcp={hostname:'127.0.0.1',port:tcpPort};
 try{
  let ready=false;
  for(let i=0;i<80;i++){
   if(err||child.exitCode!==null)throw Error('core exited before pipe readiness');
   try{if((await req(local,'GET','/version')).status===200&&(await req(tcp,'GET','/version')).status===200){ready=true;break}}catch{}
   await pause(250);
  }
  assert.ok(ready,'pipe and TCP API must be ready');
  await fn(local,tcp,{port,secret});
 }finally{child.kill();await exited;fs.rmSync(dir,{recursive:true,force:true});}
}
async function main(){
 await run(normal,acl,async(p,t,i)=>{
  assert.equal((await req(p,'POST',endpoint,i)).status,404);
  assert.equal((await req(t,'POST',endpoint,i)).status,404);
 });
 await run(lab,null,async(p,t,i)=>assert.equal((await req(p,'POST',endpoint,i)).status,404));
 await run(lab,acl,async(p,t,i)=>{
  assert.equal((await req(t,'POST',endpoint,i)).status,404);
  assert.equal((await req(p,'POST',endpoint,i,{Origin:'http://example.test'})).status,403);
  assert.equal((await req(p,'POST',endpoint,{...i,extra:true})).status,400);
  assert.equal((await req(p,'POST',endpoint,i)).status,204);
  assert.equal((await req(p,'POST',endpoint,i)).status,204);
  assert.equal((await req(p,'POST',endpoint,{...i,secret:randomBytes(24).toString('base64url')})).status,409);
  const target={hostname:'127.0.0.1',port:i.port};
  assert.equal((await req(target,'GET','/v1/mitm',undefined,{Host:'127.0.0.1:'+i.port})).status,401);
  const r=await req(target,'GET','/v1/mitm',undefined,{Host:'127.0.0.1:'+i.port,Authorization:'Bearer '+i.secret});
  assert.equal(r.status,200);assert.deepEqual(JSON.parse(r.body),{protocol:1,enabled:false,hosts:[]});
 });
 await run(lab,acl,async(p,t,i)=>assert.equal((await req(p,'POST',endpoint,i)).status,404),true);
 console.log('PASS: owner-pipe-only service-shaped bootstrap; ordinary core and TCP reject; no env-controller takeover; fresh controller disabled');
}
main().catch(err=>{console.error(err.message);process.exitCode=1});
