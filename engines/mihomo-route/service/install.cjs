'use strict';
const fs=require('node:fs');
const path=require('node:path');
const dir=path.join(process.argv[2],'hub','route');
const target=path.join(dir,'server.go');
let s=fs.readFileSync(target,'utf8').replace(/\r\n/g,'\n');
const start=s.indexOf('func startPipe(cfg *Config)');
const end=s.indexOf('\nfunc safeEqual(',start);
if(start<0||end<0)throw Error('Unexpected pinned pipe router');
const part=s.slice(start,end);
const anchor='Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),';
if(part.split(anchor).length!==2)throw Error('Unexpected pinned pipe handler');
s=s.slice(0,start)+part.replace(anchor,()=> 'Handler: netvergeServicePipeHandler(router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors)),')+s.slice(end);
fs.writeFileSync(target,s);
fs.copyFileSync(path.join(__dirname,'netverge_service_pipe_lab.go'),path.join(dir,'netverge_service_pipe_lab.go'));

const main=path.join(process.argv[2],'main.go');
let m=fs.readFileSync(main,'utf8').replace(/\r\n/g,'\n');
function once(a,b){if(m.split(a).length!==2)throw Error('Unexpected main startup layout');m=m.replace(a,()=>b);}
once('"github.com/metacubex/mihomo/hub/executor"','"github.com/metacubex/mihomo/hub/executor"\n\t"github.com/metacubex/mihomo/hub/route"');
once('\n\tif err := hub.Parse(configBytes, options...); err != nil {','\n\troute.NetVergeServiceLabArm(externalControllerPipe)\n\tif err := hub.Parse(configBytes, options...); err != nil {');
fs.writeFileSync(main,m);
