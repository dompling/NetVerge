'use strict';

// Trusted CI fixture, never a guest API or a packaged script.
const { spawnSync } = require('node:child_process');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  process.stdout.write('started:' + process.pid + '\n');
  if (input === 'descendant') {
    const result = spawnSync(process.execPath, ['-e', 'process.exit(0)'], { timeout: 1000 });
    process.stdout.write(result.error && result.status === null ? 'denied\n' : 'not-denied\n');
  } else if (input === 'memory') {
    const blocks = [];
    try {
      for (let i = 0; i < 32; i++) blocks.push(Buffer.alloc(16 * 1024 * 1024, 1));
      process.stdout.write('exceeded\n');
    } catch {
      process.exitCode = 17;
    }
  } else if (input === 'hang') {
    setInterval(() => {}, 1000);
  }
});
