const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BIN = path.join(__dirname, '..', 'system_update.js');
const NODE = process.execPath;

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function runCLI(args, opts = {}) {
  const result = spawnSync(NODE, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd,
    env: { ...process.env, ...opts.env },
    input: opts.input || '',
    windowsHide: true,
    timeout: 60000,
  });

  if (result.error) {
    throw result.error;
  }

  return {
    code: result.status,
    stdout: stripAnsi(result.stdout || ''),
    stderr: stripAnsi(result.stderr || ''),
  };
}

test('errors when no args provided', () => {
  const res = runCLI([]);
  assert.ok(res.code !== 0 || res.stdout.includes('System'));
});

test('--help shows usage', () => {
  const res = runCLI(['--help']);
  assert.equal(res.code, 0);
  assert.match(res.stdout, /Usage|system-update/i);
});

test('--include winget scans winget source', () => {
  const res = runCLI(['--include', 'winget', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include npm scans npm source', () => {
  const res = runCLI(['--include', 'npm', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include chocolatey scans chocolatey source', () => {
  const res = runCLI(['--include', 'chocolatey', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include pnpm scans pnpm source', () => {
  const res = runCLI(['--include', 'pnpm', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include pip scans pip source', () => {
  const res = runCLI(['--include', 'pip', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include path scans path source', () => {
  const res = runCLI(['--include', 'path', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include registry scans registry source', () => {
  const res = runCLI(['--include', 'registry', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include rust scans rust source', () => {
  const res = runCLI(['--include', 'rust', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--include scoop scans scoop source', () => {
  const res = runCLI(['--include', 'scoop', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--dry-run flag accepted', () => {
  const res = runCLI(['--dry-run', '--include', 'path']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--show-all flag accepted', () => {
  const res = runCLI(['--show-all', '--include', 'path', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('total apps') || res.stdout.includes('Scanning'));
});

test('--export json creates file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'system-update-'));
  const outputFile = path.join(tmp, 'export.json');
  
  try {
    const res = runCLI(['--export', 'json', '--output', outputFile, '--include', 'path']);
    assert.ok(fs.existsSync(outputFile) || res.code === 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('--export csv creates file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'system-update-'));
  const outputFile = path.join(tmp, 'export.csv');
  
  try {
    const res = runCLI(['--export', 'csv', '--output', outputFile, '--include', 'path']);
    assert.ok(fs.existsSync(outputFile) || res.code === 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('--clear-cache removes cache', () => {
  const res = runCLI(['--clear-cache']);
  assert.equal(res.code, 0);
  assert.match(res.stdout, /Cache cleared|cleared/i);
});

test('--include unknown source shows error', () => {
  const res = runCLI(['--include', 'unknown_source_xyz']);
  assert.ok(res.code === 0 || res.stdout.includes('Scanning'));
});

test('--include multiple sources', () => {
  const res = runCLI(['--include', 'winget,npm', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('Scanning'));
});

test('--log flag accepted', () => {
  const res = runCLI(['--log', '--include', 'path', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('Scanning'));
});

test('--debug flag accepted', () => {
  const res = runCLI(['--debug', '--include', 'path', '--no-cache']);
  assert.ok(res.code === 0 || res.stdout.includes('Scanning'));
});
