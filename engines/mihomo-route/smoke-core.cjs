'use strict';
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');
const exe=path.resolve(process.argv[2]);
const secret=randomBytes(24).toString('base64url');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'netverge-core-'));
const config=Buffer.from('mode: rule\nlog-level: warning\nmixed-port: 0\nallow-lan: false\ngeo-auto-update: false\nrules:\n  - MATCH,DIRECT\n').toString('base64');
async function main(){
  const reserve=net.createServer();
  await new Promise((resolve,reject)=>{reserve.once('error',reject);reserve.listen(0,'127.0.0.1',resolve);});
  const port=reserve.address().port;
  await new Promise(resolve=>reserve.close(resolve));
  const env={...process.env,NETVERGE_CORE_CONTROL_PORT:String(port),NETVERGE_CORE_CONTROL_SECRET:secret};
  const child=spawn(exe,['-d',dir,'-config',config],{env,stdio:['ignore','ignore','inherit'],windowsHide:true});
  let exitError;
  child.once('error',e=>{exitError=e;});
  const exited=new Promise(resolve=>child.once('close',resolve));
  try{
    const url='http://127.0.0.1:'+port+'/v1/mitm';
    const auth={Authorization:'Bearer '+secret};
    let state;
    for(let i=0;i<80;i++){
      if(exitError||child.exitCode!==null)throw new Error('core exited before controller readiness');
      try {
        const response=await fetch(url,{headers:auth,signal:AbortSignal.timeout(500)});
        if(response.status===200){state=await response.json();break;}
      }catch{}
      await new Promise(resolve=>setTimeout(resolve,250));
    }
    assert.equal(state?.protocol,1);
    assert.equal(state?.enabled,false);
    assert.equal((await fetch(url,{signal:AbortSignal.timeout(2000)})).status,401);
    assert.equal((await fetch(url,{method:'DELETE',headers:auth,signal:AbortSignal.timeout(2000)})).status,204);
    console.log('PASS: built core exposes authenticated local controller, disabled by default');
  }finally{
    child.kill();
    await exited;
    fs.rmSync(dir,{recursive:true,force:true});
  }
}
main().catch(err=>{console.error(err.message);process.exitCode=1;});
