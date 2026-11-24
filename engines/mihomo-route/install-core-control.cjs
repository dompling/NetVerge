'use strict';
// Build-time only: install precisely scoped changes into the pinned upstream.
const fs = require('node:fs');
const path = require('node:path');
const target = path.join(process.argv[2], 'main.go');
let source = fs.readFileSync(target, 'utf8').replace(/\r\n/g,'\n');
function replace(before,after) {
  if (source.split(before).length !== 2) throw new Error('Unexpected pinned main layout');
  source=source.replace(before,()=>after);
}
replace('"github.com/metacubex/mihomo/log"', '"github.com/metacubex/mihomo/log"\n\t"github.com/metacubex/mihomo/netvergecontrol"');
replace('\tif updater.GeoAutoUpdate() {', '\tcloseNetVergeControl, err := netvergecontrol.StartFromEnv()\n\tif err != nil {\n\t\tlog.Fatalln("NetVerge local controller startup failed")\n\t\treturn\n\t}\n\tdefer closeNetVergeControl()\n\n\tif updater.GeoAutoUpdate() {');
fs.writeFileSync(target,source);
