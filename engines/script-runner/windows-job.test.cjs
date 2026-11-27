'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { setTimeout: sleep } = require('node:timers/promises');
const path = require('node:path');

const windows = process.platform === 'win32';
const launcher = path.join(path.resolve(process.env.NETVERGE_TEST_RUNNER_DIR || __dirname), 'netverge-script-job.exe');
const fixture = path.join(__dirname, 'windows-job-fixture.cjs');

function start(t, mode, timeoutMs = 5000) {
  const child = spawn(launcher, [process.execPath, fixture, String(timeoutMs)], {
    windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const closed = once(child, 'close');
  let output = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', chunk => { output += chunk; });
  child.stdin.on('error', () => {});
  child.stdin.end(mode);
  return { child, closed, output: () => output };
}

async function until(predicate, limitMs = 2500) {
  const deadline = Date.now() + limitMs;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await sleep(25);
  }
  assert.fail('condition did not become true');
}

function startedPid(job) {
  const match = /^started:(\d+)\r?\n/.exec(job.output());
  return match ? Number(match[1]) : 0;
}

function gone(pid) {
  try { process.kill(pid, 0); return false; }
  catch (err) { if (err.code === 'ESRCH') return true; throw err; }
}

test('Windows job denies a third process', { skip: !windows, timeout: 10000 }, async t => {
  const job = start(t, 'descendant');
  const [code] = await job.closed;
  assert.equal(code, 0);
  assert.ok(startedPid(job));
  assert.match(job.output(), /denied\r?\n$/);
  assert.doesNotMatch(job.output(), /not-denied/);
});

test('Windows job caps native committed memory, not just the JS heap', { skip: !windows, timeout: 10000 }, async t => {
  const job = start(t, 'memory', 6500);
  const [code] = await job.closed;
  assert.ok(startedPid(job));
  assert.equal(code, 125);
  assert.doesNotMatch(job.output(), /exceeded/);
});

test('Windows launcher enforces its own deadline and cleans up its runner', { skip: !windows, timeout: 10000 }, async t => {
  const job = start(t, 'hang', 1800);
  const pid = await until(() => startedPid(job));
  const [code] = await job.closed;
  assert.equal(code, 124);
  await until(() => gone(pid));
});

test('killing Windows launcher also kills the running Node child', { skip: !windows, timeout: 10000 }, async t => {
  const job = start(t, 'hang', 6500);
  const pid = await until(() => startedPid(job));
  assert.equal(job.child.kill(), true);
  await job.closed;
  await until(() => gone(pid));
});
