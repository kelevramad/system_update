#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const https = require('node:https');
const { spawn } = require('node:child_process');
const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');

const VERSION = '1.0.1';
const APP_NAME = 'system-update';
const IS_WINDOWS = process.platform === 'win32';
const PREFERRED_DATA_DIR = process.env.SYSTEM_UPDATE_HOME
  ? path.resolve(process.env.SYSTEM_UPDATE_HOME)
  : path.join(os.homedir(), '.system_update');
let ACTIVE_DATA_DIR = PREFERRED_DATA_DIR;
let CACHE_FILE = path.join(ACTIVE_DATA_DIR, 'cache.json');
let LOG_FILE = path.join(ACTIVE_DATA_DIR, 'system.log');
const IS_TTY = Boolean(process.stdout.isTTY);
const SUPPORTS_COLOR = IS_TTY && process.env.NO_COLOR !== '1';

const Status = Object.freeze({
  UP_TO_DATE: 'up_to_date',
  UPDATE_AVAILABLE: 'update_available',
  UNKNOWN: 'unknown',
  ERROR: 'error',
  VULNERABLE: 'vulnerable',
  SECURITY_UPDATE_AVAILABLE: 'security_update_available',
});

const DEFAULT_CONFIG = {
  cache: {
    enabled: true,
    durationHours: 2,
  },
  performance: {
    timeoutSeconds: 45,
    maxWorkers: 6,
  },
  sources: {
    winget: true,
    chocolatey: true,
    npm: true,
    pnpm: true,
    pip: true,
    bun: true,
    yarn: true,
    path: true,
    registry: true,
  },
  security: {
    enabled: true,
    autoCheck: true,
    severityThreshold: 'medium',
  },
  ui: {
    compact: false,
  },
};

function switchToLocalDataDir() {
  const fallback = path.join(process.cwd(), '.system_update');
  if (path.resolve(ACTIVE_DATA_DIR) === path.resolve(fallback)) return false;
  ACTIVE_DATA_DIR = fallback;
  CACHE_FILE = path.join(ACTIVE_DATA_DIR, 'cache.json');
  LOG_FILE = path.join(ACTIVE_DATA_DIR, 'system.log');
  return true;
}

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

function paint(text, ...styles) {
  if (!SUPPORTS_COLOR) return String(text);
  return `${styles.join('')}${text}${ANSI.reset}`;
}

function emoji(name) {
  const map = {
    rocket: '🚀',
    package: '📦',
    scan: '🔎',
    update: '⬆️',
    ok: '✅',
    warn: '⚠️',
    fail: '❌',
    gear: '⚙️',
    sparkle: '✨',
    chart: '📊',
    disk: '💾',
    hourglass: '⏱️',
    export: '📄',
    lock: '🔒',
    fire: '🔥',
    shield: '🛡️',
  };
  return map[name] || '';
}

function statusBadge(status) {
  if (status === Status.UPDATE_AVAILABLE) return paint(`${emoji('update')} update`, ANSI.yellow, ANSI.bold);
  if (status === Status.UP_TO_DATE) return paint(`${emoji('ok')} up-to-date`, ANSI.green);
  if (status === Status.ERROR) return paint(`${emoji('fail')} error`, ANSI.red);
  if (status === Status.VULNERABLE) return paint(`${emoji('fire')} vulnerable`, ANSI.red, ANSI.bold);
  if (status === Status.SECURITY_UPDATE_AVAILABLE) return paint(`${emoji('lock')} security update`, ANSI.magenta, ANSI.bold);
  return paint('❔ unknown', ANSI.gray);
}

function sourceBadge(source) {
  const value = String(source || 'unknown');
  const color = {
    winget: ANSI.blue,
    chocolatey: ANSI.yellow,
    npm: ANSI.red,
    pnpm: ANSI.magenta,
    bun: ANSI.magenta,
    yarn: ANSI.blue,
    pip: ANSI.cyan,
    path: ANSI.green,
    registry: ANSI.gray,
  }[value] || ANSI.gray;
  return paint(value, color, ANSI.bold);
}

function hr(ch = '─', width = 72) {
  return ch.repeat(width);
}

function headerCard(title, subtitle) {
  const top = paint(`┌${hr('─', 70)}┐`, ANSI.cyan);
  const bottom = paint(`└${hr('─', 70)}┘`, ANSI.cyan);
  const line1 = paint(`│ ${title.padEnd(68)} │`, ANSI.bold, ANSI.cyan);
  const line2 = paint(`│ ${subtitle.padEnd(68)} │`, ANSI.dim, ANSI.cyan);
  console.log(top);
  console.log(line1);
  console.log(line2);
  console.log(bottom);
}

function createProgress(total, label) {
  let current = 0;
  const width = 26;
  const startTime = Date.now();

  function render(extra = '') {
    const ratio = total === 0 ? 1 : Math.min(1, current / total);
    const filled = Math.round(width * ratio);
    const bar = `${'█'.repeat(filled)}${'░'.repeat(width - filled)}`;
    const pct = `${Math.round(ratio * 100)}`.padStart(3, ' ');
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const msg = `${label} ${bar} ${pct}% (${current}/${total}) ${emoji('hourglass')} ${elapsed}s ${extra}`.trimEnd();
    if (IS_TTY) {
      process.stdout.write(`\r\x1b[2K${msg}`);
    } else {
      console.log(msg);
    }
  }

  function tick(extra = '') {
    current += 1;
    render(extra);
  }

  function done(extra = '') {
    current = total;
    render(extra);
    if (IS_TTY) process.stdout.write('\n');
  }

  render();
  return { tick, done };
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'SystemUpdateCLI' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchJson(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (err) { reject(err); }
      });
    }).on('error', reject);
  });
}

async function ensureConfigDir() {
  try {
    await fs.mkdir(ACTIVE_DATA_DIR, { recursive: true });
  } catch (err) {
    if (switchToLocalDataDir()) {
      await fs.mkdir(ACTIVE_DATA_DIR, { recursive: true });
      return;
    }
    throw err;
  }
}

async function writeLog(message) {
  const line = `${new Date().toISOString()} ${message}\n`;
  try {
    await fs.appendFile(LOG_FILE, line, 'utf8');
  } catch {
    // keep CLI resilient; logging should never break flow
  }
}

function normalizeCommand(cmd) {
  if (!IS_WINDOWS) return cmd;
  const useCmdShim = new Set(['npm', 'pnpm', 'npx', 'yarn']);
  if (useCmdShim.has(cmd) && !cmd.endsWith('.cmd')) return `${cmd}.cmd`;
  return cmd;
}

function runCommand(cmd, args = [], options = {}) {
  const {
    timeoutMs = 45_000,
    allowFailure = false,
    cwd = process.cwd(),
  } = options;

  return new Promise((resolve) => {
    const command = normalizeCommand(cmd);
    const useShell = IS_WINDOWS && (command.endsWith('.cmd') || command.endsWith('.bat'));
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        windowsHide: true,
        shell: useShell,
      });
    } catch (err) {
      resolve({ ok: allowFailure, stdout: '', stderr: String(err), code: null });
      return;
    }

    let stdoutData = '';
    let stderrData = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      resolve({ ok: false, stdout: stdoutData.trim(), stderr: `timeout: ${command}`, code: null });
    }, timeoutMs);

    child.stdout.on('data', (d) => {
      stdoutData += d.toString('utf8');
    });

    child.stderr.on('data', (d) => {
      stderrData += d.toString('utf8');
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok: allowFailure, stdout: stdoutData.trim(), stderr: String(err), code: null });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const ok = allowFailure ? true : code === 0;
      resolve({ ok, stdout: stdoutData.trim(), stderr: stderrData.trim(), code });
    });
  });
}

function parseArgs(argv) {
  const args = {
    updateAll: false,
    dryRun: false,
    noCache: false,
    clearCache: false,
    export: null,
    output: null,
    packageName: null,
    version: null,
    source: null,
    updateSource: null,
    include: null,
    yes: false,
    help: false,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const token = argv[i];
    switch (token) {
      case '--update-all':
        args.updateAll = true;
        break;
      case '--dry-run':
        args.dryRun = true;
        break;
      case '--no-cache':
        args.noCache = true;
        break;
      case '--clear-cache':
        args.clearCache = true;
        break;
      case '--export':
        args.export = argv[++i] || null;
        break;
      case '--output':
        args.output = argv[++i] || null;
        break;
      case '--package':
        args.packageName = argv[++i] || null;
        break;
      case '--version':
        args.version = argv[++i] || null;
        break;
      case '--source':
        args.source = (argv[++i] || '').toLowerCase() || null;
        break;
      case '--update-source':
        args.updateSource = (argv[++i] || '').toLowerCase() || null;
        break;
      case '--include':
        args.include = (argv[++i] || null);
        break;
      case '--yes':
      case '-y':
        args.yes = true;
        break;
      case '--help':
      case '-h':
        args.help = true;
        break;
      default:
        throw new Error(`Unknown argument: ${token}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`
${emoji('sparkle')} ${paint(`System Update Node CLI v${VERSION}`, ANSI.bold, ANSI.cyan)}

Usage:
  node system_update.js [options]

Options:
  --update-all              Update every package with updates
  --update-source <source>  Update all packages from one source (winget|chocolatey|npm|pnpm|pip|path)
  --package <name>          Update one package by name
  --version <ver>           Target version (with --package)
  --source <source>         Source filter for --package
  --dry-run                 Print planned updates without executing
  --no-cache                Force fresh scan
  --clear-cache             Remove cache file and exit
  --export <json|csv>       Export scan results
  --output <file>           Output path for export
  --include <csv>           Limit scan sources (e.g. winget,npm,pip)
  --yes, -y                 Skip confirmation prompts
  --help, -h                Show help

Features:
  • Multi-source package discovery (Winget, Chocolatey, NPM, PNPM, PIP, PATH, Registry)
  • Security vulnerability scanning for NPM and PIP packages
  • Parallel scanning for optimal performance
  • Flexible export options (JSON, CSV)
  • Caching system for faster subsequent runs

Examples:
  node system_update.js
  node system_update.js --update-all --yes
  node system_update.js --package git --source chocolatey
  node system_update.js --update-source winget --dry-run
  node system_update.js --export json --output report.json
`);
}

function getSourceToggle(config, source) {
  return Boolean(config.sources[source]);
}

async function isCommandAvailable(command) {
  const lookup = IS_WINDOWS ? 'where' : 'which';
  const result = await runCommand(lookup, [command], { allowFailure: true, timeoutMs: 10_000 });
  return result.ok && Boolean(result.stdout);
}

function parseWingetTable(output, includeAvailable = false) {
  const apps = [];
  if (!output) return apps;
  const lines = output.split(/\r?\n/);
  const headerIndex = lines.findIndex((line) => line.includes('Name') && line.includes('Id') && line.includes('Version'));
  if (headerIndex < 0) return apps;

  let header = lines[headerIndex];
  const nameMatch = header.match(/Name\s+Id/);
  if (nameMatch) {
    header = header.slice(nameMatch.index);
  }

  const positions = {
    id: header.indexOf('Id'),
    version: header.indexOf('Version'),
    available: header.indexOf('Available'),
    source: header.indexOf('Source'),
  };

  for (const line of lines.slice(headerIndex + 2)) {
    if (!line.trim()) continue;
    const name = line.slice(0, Math.max(positions.id, 0)).trim();
    const appId = positions.version > 0 ? line.slice(positions.id, positions.version).trim() : '';
    const versionEnd = positions.available > -1 ? positions.available : positions.source > -1 ? positions.source : line.length;
    const version = positions.version > -1 ? line.slice(positions.version, versionEnd).trim() : '';
    let latest = '';
    if (includeAvailable && positions.available > -1) {
      const availEnd = positions.source > -1 ? positions.source : line.length;
      latest = line.slice(positions.available, availEnd).trim();
    }
    if (name && appId && version) {
      apps.push({
        name,
        source: 'winget',
        version,
        latestVersion: latest,
        appId,
        status: latest ? Status.UPDATE_AVAILABLE : Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  }

  return apps;
}

async function scanWinget(timeoutMs) {
  const result = await runCommand('winget', ['list', '--accept-source-agreements'], { allowFailure: true, timeoutMs });
  return parseWingetTable(result.stdout, false);
}

async function scanChocolatey(timeoutMs) {
  const result = await runCommand('choco', ['list', '--local-only', '--limit-output'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;
  for (const line of result.stdout.split(/\r?\n/)) {
    const [name, version] = line.split('|');
    if (!name || !version) continue;
    apps.push({
      name: name.trim(),
      source: 'chocolatey',
      version: version.trim(),
      latestVersion: '',
      appId: name.trim(),
      status: Status.UNKNOWN,
      scanTime: new Date().toISOString(),
    });
  }
  return apps;
}

async function scanBun(timeoutMs) {
  const result = await runCommand('bun', ['pm', 'ls', '-g'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;

  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^\s*([^\s@]+)@([^\s]+)/);
    if (match) {
      apps.push({
        name: match[1],
        source: 'bun',
        version: match[2],
        latestVersion: '',
        appId: match[1],
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  }
  return apps;
}

async function scanYarn(timeoutMs) {
  const result = await runCommand('yarn', ['global', 'list'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;

  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^info "([^@]+)@([^"]+)"/);
    if (match) {
      apps.push({
        name: match[1],
        source: 'yarn',
        version: match[2],
        latestVersion: '',
        appId: match[1],
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  }
  return apps;
}

async function scanNpm(timeoutMs) {
  const result = await runCommand('npm', ['list', '-g', '--depth=0', '--json', '--silent'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;
  try {
    const parsed = JSON.parse(result.stdout);
    const deps = parsed.dependencies || {};
    for (const [name, details] of Object.entries(deps)) {
      apps.push({
        name,
        source: 'npm',
        version: details.version || 'N/A',
        latestVersion: '',
        appId: name,
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  } catch (err) {
    await writeLog(`parse npm list failed: ${err}`);
  }
  return apps;
}

async function scanPnpm(timeoutMs) {
  const result = await runCommand('pnpm', ['list', '-g', '--depth=0', '--json'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;
  try {
    const parsed = JSON.parse(result.stdout);
    const root = Array.isArray(parsed) ? parsed[0] : parsed;
    const deps = (root && root.dependencies) || {};
    for (const [name, details] of Object.entries(deps)) {
      apps.push({
        name,
        source: 'pnpm',
        version: details.version || 'N/A',
        latestVersion: '',
        appId: name,
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  } catch (err) {
    await writeLog(`parse pnpm list failed: ${err}`);
  }
  return apps;
}

async function runPip(args, timeoutMs) {
  const candidates = [
    { cmd: 'py', args: ['-m', 'pip', ...args] },
    { cmd: 'python', args: ['-m', 'pip', ...args] },
    { cmd: 'python3', args: ['-m', 'pip', ...args] },
    { cmd: 'pip', args },
  ];

  for (const c of candidates) {
    const result = await runCommand(c.cmd, c.args, { allowFailure: true, timeoutMs });
    if (result.stdout) return { ...result, runner: c };
  }
  return { ok: false, stdout: '', stderr: 'pip unavailable', code: null, runner: null };
}

async function scanPip(timeoutMs) {
  const result = await runPip(['list', '--format=json'], timeoutMs);
  const apps = [];
  if (!result.stdout) return apps;
  try {
    const parsed = JSON.parse(result.stdout);
    for (const item of parsed) {
      apps.push({
        name: item.name,
        source: 'pip',
        version: item.version,
        latestVersion: '',
        appId: item.name,
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  } catch (err) {
    await writeLog(`parse pip list failed: ${err}`);
  }
  return apps;
}

async function scanPath(timeoutMs) {
  const apps = [];
  const candidates = ['node', 'npm', 'pnpm', 'yarn', 'python', 'git', 'go', 'bun', 'deno', 'rustc', 'cargo', 'dotnet', 'java', 'pwsh'];
  for (const tool of candidates) {
    const exists = await isCommandAvailable(tool);
    if (!exists) continue;

    let version = 'installed';
    const versionArgs = tool === 'java' ? ['-version'] : ['--version'];
    const res = await runCommand(tool, versionArgs, { allowFailure: true, timeoutMs: Math.min(timeoutMs, 10_000) });
    const combined = `${res.stdout}\n${res.stderr}`.trim();
    const first = combined.split(/\r?\n/)[0] || version;
    version = first.slice(0, 80);

    apps.push({
      name: tool,
      source: 'path',
      version,
      latestVersion: '',
      appId: tool,
      status: Status.UNKNOWN,
      scanTime: new Date().toISOString(),
    });
  }
  return apps;
}

async function scanRegistry(timeoutMs) {
  if (!IS_WINDOWS) return [];
  const script = [
    '$paths = @(',
    " 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',",
    " 'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',",
    " 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'",
    ')',
    '$apps = foreach ($p in $paths) {',
    ' Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |',
    ' Where-Object { $_.DisplayName -and $_.DisplayVersion -and !$_.SystemComponent } |',
    ' Select-Object DisplayName, DisplayVersion, PSChildName',
    '}',
    '$apps | ConvertTo-Json -Depth 2',
  ].join('\n');

  const result = await runCommand('powershell', ['-NoProfile', '-Command', script], { allowFailure: true, timeoutMs });
  if (!result.stdout) return [];

  try {
    const parsed = JSON.parse(result.stdout);
    const rows = Array.isArray(parsed) ? parsed : [parsed];
    return rows
      .filter((x) => x.DisplayName && x.DisplayVersion)
      .map((x) => ({
        name: String(x.DisplayName).trim(),
        source: 'registry',
        version: String(x.DisplayVersion).trim(),
        latestVersion: '',
        appId: x.PSChildName ? String(x.PSChildName).trim() : null,
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      }));
  } catch (err) {
    await writeLog(`parse registry failed: ${err}`);
    return [];
  }
}

function uniqueApps(apps) {
  const map = new Map();
  for (const app of apps) {
    const key = `${app.source}|${app.name}|${app.version}`.toLowerCase();
    map.set(key, app);
  }
  return [...map.values()].sort((a, b) => (a.source + a.name).localeCompare(b.source + b.name));
}

async function loadCache(config) {
  if (!config.cache.enabled) return null;

  try {
    const raw = await fs.readFile(CACHE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    const timestamp = new Date(parsed.timestamp);
    if (Number.isNaN(timestamp.getTime())) return null;

    const ageMs = Date.now() - timestamp.getTime();
    const validMs = Number(config.cache.durationHours || 2) * 3600_000;
    if (ageMs > validMs) return null;

    return Array.isArray(parsed.apps) ? parsed.apps : null;
  } catch {
    return null;
  }
}

async function saveCache(apps) {
  await ensureConfigDir();
  const payload = {
    timestamp: new Date().toISOString(),
    version: VERSION,
    totalApps: apps.length,
    apps,
  };
  try {
    await fs.writeFile(CACHE_FILE, JSON.stringify(payload, null, 2), 'utf8');
  } catch (err) {
    if ((err && (err.code === 'EPERM' || err.code === 'EACCES')) && switchToLocalDataDir()) {
      await ensureConfigDir();
      await fs.writeFile(CACHE_FILE, JSON.stringify(payload, null, 2), 'utf8');
      return;
    }
    throw err;
  }
}

async function clearCache() {
  try {
    await fs.unlink(CACHE_FILE);
  } catch {
    // no-op if file doesn't exist
  }
}

async function checkWingetUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'winget');
  if (!target.length) return 0;

  const result = await runCommand('winget', ['upgrade', '--accept-source-agreements'], { allowFailure: true, timeoutMs });
  const updates = parseWingetTable(result.stdout, true);
  let count = 0;

  for (const upd of updates) {
    const app = target.find((a) => a.appId && upd.appId && a.appId.toLowerCase() === upd.appId.toLowerCase());
    if (!app) continue;
    app.latestVersion = upd.latestVersion;
    app.status = Status.UPDATE_AVAILABLE;
    count += 1;
  }
  return count;
}

async function checkRegistryUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'registry');
  if (!target.length) return 0;

  // winget internally queries the Registry to build its upgrade list.
  // Cross-reference Registry apps against `winget upgrade` by name.
  const result = await runCommand('winget', ['upgrade', '--accept-source-agreements'], { allowFailure: true, timeoutMs });
  const upgrades = parseWingetTable(result.stdout, true);

  const upgradeMap = new Map();
  for (const u of upgrades) {
    upgradeMap.set(u.name.toLowerCase(), u);
  }

  let count = 0;
  for (const app of target) {
    const match = upgradeMap.get(app.name.toLowerCase());
    if (match && match.latestVersion) {
      app.latestVersion = match.latestVersion;
      app.appId = app.appId || match.appId;
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    } else {
      app.status = Status.UP_TO_DATE;
    }
  }
  return count;
}

async function checkChocolateyUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'chocolatey');
  if (!target.length) return 0;

  const result = await runCommand('choco', ['outdated', '--limit-output'], { allowFailure: true, timeoutMs });
  let count = 0;
  for (const line of result.stdout.split(/\r?\n/)) {
    const [name, current, latest] = line.split('|');
    if (!name || !latest) continue;
    const app = target.find((a) => a.name.toLowerCase() === name.toLowerCase());
    if (!app) continue;
    app.latestVersion = latest.trim();
    app.status = Status.UPDATE_AVAILABLE;
    count += 1;
  }
  return count;
}

async function checkNpmUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'npm');
  if (!target.length) return 0;

  const result = await runCommand('npm', ['outdated', '-g', '--json', '--silent'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return 0;

  try {
    const parsed = JSON.parse(result.stdout);
    let count = 0;
    for (const [name, details] of Object.entries(parsed)) {
      const app = target.find((a) => a.name === name);
      if (!app) continue;
      app.latestVersion = details.latest || '';
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
    return count;
  } catch (err) {
    await writeLog(`parse npm outdated failed: ${err}`);
    return 0;
  }
}

async function checkPnpmUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'pnpm');
  if (!target.length) return 0;

  const result = await runCommand('pnpm', ['outdated', '-g', '--json'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return 0;

  try {
    const parsed = JSON.parse(result.stdout);
    let entries = [];
    if (Array.isArray(parsed)) {
      entries = parsed.map((x) => [x.name, x]);
    } else {
      entries = Object.entries(parsed);
    }

    let count = 0;
    for (const [name, details] of entries) {
      const app = target.find((a) => a.name === name);
      if (!app) continue;
      app.latestVersion = details.latest || details.wanted || '';
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
    return count;
  } catch (err) {
    await writeLog(`parse pnpm outdated failed: ${err}`);
    return 0;
  }
}

async function checkBunUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'bun');
  if (!target.length) return 0;

  let count = 0;
  for (const app of target) {
    const res = await runCommand('npm', ['info', app.name, 'version'], { allowFailure: true, timeoutMs });
    const latest = res.stdout.trim();
    if (latest && latest !== app.version && !latest.includes('ERR')) {
      app.latestVersion = latest;
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  }
  return count;
}

async function checkYarnUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'yarn');
  if (!target.length) return 0;

  let count = 0;
  for (const app of target) {
    const res = await runCommand('npm', ['info', app.name, 'version'], { allowFailure: true, timeoutMs });
    const latest = res.stdout.trim();
    if (latest && latest !== app.version && !latest.includes('ERR')) {
      app.latestVersion = latest;
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  }
  return count;
}

async function checkPipUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'pip');
  if (!target.length) return 0;

  const result = await runPip(['list', '--outdated', '--format=json'], timeoutMs);
  if (!result.stdout) return 0;

  try {
    const parsed = JSON.parse(result.stdout);
    let count = 0;
    for (const item of parsed) {
      const app = target.find((a) => a.name.toLowerCase() === String(item.name).toLowerCase());
      if (!app) continue;
      app.latestVersion = item.latest_version || '';
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
    return count;
  } catch (err) {
    await writeLog(`parse pip outdated failed: ${err}`);
    return 0;
  }
}

async function checkPathUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'path');
  if (!target.length) return 0;

  let count = 0;
  for (const app of target) {
    let latest = '';

    try {
      if (app.name === 'bun') {
        const res = await runCommand('bun', ['upgrade', '--dry-run'], { allowFailure: true, timeoutMs });
        const text = `${res.stdout}\n${res.stderr}`;
        const m = text.match(/Bun v([0-9.]+) is out!/);
        if (m && m[1]) latest = m[1];
        else latest = app.version; // it's already on latest
      } else if (app.name === 'deno') {
        const res = await runCommand('deno', ['upgrade', '--dry-run'], { allowFailure: true, timeoutMs });
        const text = `${res.stdout}\n${res.stderr}`;
        const m = text.match(/Found latest stable version\s+v?([0-9.]+)/i);
        if (m && m[1]) latest = m[1];
        else latest = app.version; // already on latest
      } else if (app.name === 'yarn' || app.name === 'npm' || app.name === 'pnpm' || app.name === 'node') {
        const res = await runCommand('npm', ['view', app.name, 'version'], { allowFailure: true, timeoutMs });
        const ver = res.stdout.trim();
        if (ver && !ver.includes('ERR')) latest = ver;
      } else if (app.name === 'python') {
        const data = await fetchJson('https://api.github.com/repos/python/cpython/releases/latest').catch(() => null);
        if (data && data.tag_name) {
          const m = data.tag_name.match(/v?([0-9.]+)/);
          if (m && m[1]) latest = m[1];
        }
        if (!latest) latest = app.version;
      } else if (app.name === 'git') {
        const data = await fetchJson('https://api.github.com/repos/git-for-windows/git/releases/latest').catch(() => null);
        if (data && data.tag_name) {
          const m = data.tag_name.match(/v?([0-9.]+?)(?:\.windows)/);
          latest = m ? m[1] : data.tag_name.replace('v', '');
        }
      } else if (app.name === 'pwsh') {
        const data = await fetchJson('https://api.github.com/repos/PowerShell/PowerShell/releases/latest').catch(() => null);
        if (data && data.tag_name) latest = data.tag_name.replace('v', '');
      } else if (app.name === 'dotnet') {
        const res = await runCommand('winget', ['show', 'Microsoft.DotNet.SDK.9', '--accept-source-agreements'], { allowFailure: true, timeoutMs });
        const m = res.stdout.match(/Version:\s+([0-9.]+)/);
        if (m && m[1]) latest = m[1];
      }
    } catch {
      // silently ignore individual fetch failures
    }

    if (latest) {
      const cleanVersion = app.version.replace(/^[^\d]+/, '').trim();
      const cleanLatest = latest.replace(/^[^\d]+/, '').trim();
      app.latestVersion = cleanLatest;
      if (cleanLatest !== cleanVersion && !app.version.includes(cleanLatest)) {
        app.status = Status.UPDATE_AVAILABLE;
        count += 1;
      } else {
        app.status = Status.UP_TO_DATE;
      }
    }
  }
  return count;
}

function finalizeStatuses(apps) {
  for (const app of apps) {
    if (app.status === Status.UPDATE_AVAILABLE) continue;
    if (app.status === Status.UP_TO_DATE) continue;
    if (app.latestVersion || ['winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn', 'pip'].includes(app.source)) {
      app.status = Status.UP_TO_DATE;
    } else {
      app.status = Status.UNKNOWN;
    }
  }
}

async function scanSystem(config, args) {
  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  const sourceFilter = new Set(
    args.include
      ? String(args.include)
        .split(',')
        .map((x) => x.trim().toLowerCase())
        .filter(Boolean)
      : []
  );
  if (args.source) {
    sourceFilter.add(args.source.toLowerCase());
  }

  const jobs = [
    ['winget', scanWinget],
    ['chocolatey', scanChocolatey],
    ['npm', scanNpm],
    ['pnpm', scanPnpm],
    ['bun', scanBun],
    ['yarn', scanYarn],
    ['pip', scanPip],
    ['path', scanPath],
    ['registry', scanRegistry],
  ];

  const selected = jobs.filter(([source]) => {
    if (!getSourceToggle(config, source)) return false;
    if (sourceFilter.size && !sourceFilter.has(source)) return false;
    return true;
  });

  const progress = createProgress(selected.length, `${emoji('scan')} Scanning`);
  const chunks = await Promise.all(selected.map(async ([source, fn]) => {
    const apps = await fn(timeoutMs);
    progress.tick(`${sourceBadge(source)} ${paint(String(apps.length).padStart(4), ANSI.bold)} apps`);
    return apps;
  }));
  progress.done(paint(`${emoji('ok')} scan complete`, ANSI.green));

  return uniqueApps(chunks.flat());
}

async function checkUpdates(apps, config) {
  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  const checks = [
    ['winget', () => checkWingetUpdates(apps, timeoutMs)],
    ['chocolatey', () => checkChocolateyUpdates(apps, timeoutMs)],
    ['npm', () => checkNpmUpdates(apps, timeoutMs)],
    ['pnpm', () => checkPnpmUpdates(apps, timeoutMs)],
    ['bun', () => checkBunUpdates(apps, timeoutMs)],
    ['yarn', () => checkYarnUpdates(apps, timeoutMs)],
    ['pip', () => checkPipUpdates(apps, timeoutMs)],
    ['path', () => checkPathUpdates(apps, timeoutMs)],
    ['registry', () => checkRegistryUpdates(apps, timeoutMs)],
  ];

  const progress = createProgress(checks.length, `${emoji('update')} Checking updates`);
  const counts = await Promise.all(checks.map(async ([source, fn]) => {
    const count = await fn();
    const msg = `${sourceBadge(source)} ${count > 0 ? paint(`${count} update(s)`, ANSI.yellow, ANSI.bold) : paint('none', ANSI.gray)}`;
    progress.tick(msg);
    return count;
  }));
  progress.done(paint(`${emoji('ok')} update checks complete`, ANSI.green));

  finalizeStatuses(apps);
  return counts.reduce((sum, n) => sum + n, 0);
}

async function checkSecurityVulnerabilities(apps, config) {
  if (!config.security?.enabled) return [];

  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  const vulnerabilities = [];
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const threshold = severityOrder[config.security.severityThreshold || 'medium'] || 2;

  const npmVulns = await checkNpmVulnerabilities(apps, timeoutMs);
  const pipVulns = await checkPipVulnerabilities(apps, timeoutMs);

  for (const vuln of [...npmVulns, ...pipVulns]) {
    const severityLevel = severityOrder[vuln.severity.toLowerCase()] || 1;
    if (severityLevel >= threshold) {
      vulnerabilities.push(vuln);
      const app = apps.find((a) => a.name.toLowerCase() === vuln.packageName.toLowerCase());
      if (app) {
        app.status = Status.VULNERABLE;
      }
    }
  }

  return vulnerabilities;
}

async function checkNpmVulnerabilities(apps, timeoutMs) {
  const npmApps = apps.filter((a) => a.source === 'npm');
  if (!npmApps.length) return [];

  const result = await runCommand('npm', ['audit', '--json', '--silent'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return [];

  try {
    const parsed = JSON.parse(result.stdout);
    const vulnerabilities = [];
    const vulnData = parsed.vulnerabilities || {};

    for (const [pkgName, vuln] of Object.entries(vulnData)) {
      const severity = vuln.severity || 'low';
      const app = npmApps.find((a) => a.name.toLowerCase() === pkgName.toLowerCase());
      if (!app) continue;

      vulnerabilities.push({
        packageName: pkgName,
        severity,
        cve: vuln.cves?.[0] || 'N/A',
        description: vuln.title || 'Vulnerability found',
        appInfo: app,
      });
    }
    return vulnerabilities;
  } catch {
    return [];
  }
}

async function checkPipVulnerabilities(apps, timeoutMs) {
  const pipApps = apps.filter((a) => a.source === 'pip');
  if (!pipApps.length) return [];

  const result = await runPip(['check', '--format=json'], timeoutMs);
  if (!result.stdout) return [];

  try {
    const parsed = JSON.parse(result.stdout);
    const vulnerabilities = [];

    for (const item of parsed) {
      if (!item.vulnerabilities || !item.vulnerabilities.length) continue;

      const app = pipApps.find((a) => a.name.toLowerCase() === String(item.package_name || item.name).toLowerCase());
      if (!app) continue;

      for (const vuln of item.vulnerabilities) {
        vulnerabilities.push({
          packageName: item.package_name || item.name,
          severity: vuln.severity || 'medium',
          cve: vuln.cve_id || 'N/A',
          description: vuln.description || 'Security vulnerability',
          appInfo: app,
        });
      }
    }
    return vulnerabilities;
  } catch {
    return [];
  }
}

function truncate(value, size) {
  const text = String(value ?? '');
  return text.length <= size ? text : `${text.slice(0, size - 1)}…`;
}

function printAppsTable(apps) {
  const cols = [
    { key: 'name', title: 'Package', width: 30 },
    { key: 'source', title: 'Source', width: 12 },
    { key: 'version', title: 'Current', width: 20 },
    { key: 'latestVersion', title: 'Latest', width: 20 },
    { key: 'status', title: 'Status', width: 17 },
  ];

  const header = cols.map((c) => paint(c.title.padEnd(c.width), ANSI.bold, ANSI.cyan)).join('  ');
  console.log(header);
  console.log(paint('─'.repeat(header.length), ANSI.gray));

  for (const app of apps) {
    const row = cols
      .map((c) => {
        const raw = truncate(app[c.key] || '-', c.width).padEnd(c.width);
        if (c.key === 'source') return sourceBadge(raw.trim()).padEnd(c.width + 11);
        if (c.key === 'status') return statusBadge(app.status).padEnd(c.width + 10);
        if (c.key === 'name') return paint(raw, ANSI.bold);
        if (c.key === 'latestVersion' && app.status === Status.UPDATE_AVAILABLE) return paint(raw, ANSI.yellow);
        return raw;
      })
      .join('  ');
    console.log(row);
  }
}

function printSecurityTable(vulnerabilities) {
  if (!vulnerabilities.length) return;

  console.log(`\n${paint('┌'.padEnd(74, '─') + '┐', ANSI.cyan)}`);
  console.log(paint(`│ ${emoji('fire')} Security Vulnerabilities Detected`.padEnd(72) + '│', ANSI.bold, ANSI.red));
  console.log(paint('├'.padEnd(74, '─') + '┤', ANSI.cyan));

  const header = ['Package', 'Severity', 'CVE', 'Description'].map((h, i) => {
    const widths = [20, 10, 18, 20];
    return paint(h.padEnd(widths[i]), ANSI.bold, ANSI.red);
  }).join('  ');
  console.log(paint(`│ ${header} │`, ANSI.cyan));
  console.log(paint('├'.padEnd(74, '─') + '┤', ANSI.cyan));

  for (const v of vulnerabilities) {
    const sevColor = { critical: ANSI.red, high: ANSI.red, medium: ANSI.yellow, low: ANSI.green }[v.severity.toLowerCase()] || ANSI.white;
    const row = [
      paint(truncate(v.packageName, 20).padEnd(20), ANSI.bold),
      paint(v.severity.toUpperCase().padEnd(10), sevColor, ANSI.bold),
      paint(truncate(v.cve, 18).padEnd(18), ANSI.cyan),
      paint(truncate(v.description, 20).padEnd(20), ANSI.dim),
    ].join('  ');
    console.log(paint(`│ ${row} │`, ANSI.cyan));
  }

  console.log(paint('└'.padEnd(74, '─') + '┘', ANSI.cyan));
}

function toCsvCell(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

async function exportResults(apps, format, output) {
  const lower = String(format || '').toLowerCase();
  const ts = new Date().toISOString().replace(/[T:.]/g, '-').slice(0, 19);
  const outputPath = output || path.join(process.cwd(), `system_update_${ts}.${lower}`);

  if (lower === 'json') {
    await fs.writeFile(outputPath, JSON.stringify({ scanTime: new Date().toISOString(), totalApps: apps.length, apps }, null, 2), 'utf8');
    return outputPath;
  }

  if (lower === 'csv') {
    const lines = [
      ['name', 'source', 'version', 'latestVersion', 'status', 'appId'].join(','),
      ...apps.map((a) => [a.name, a.source, a.version, a.latestVersion, a.status, a.appId].map(toCsvCell).join(',')),
    ];
    await fs.writeFile(outputPath, `${lines.join('\n')}\n`, 'utf8');
    return outputPath;
  }

  throw new Error(`Unsupported export format: ${format}`);
}

async function askToProceed(message, yes) {
  if (yes) return true;
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const answer = (await rl.question(`${message} [y/N]: `)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

function sourceName(source) {
  return String(source || '').toLowerCase();
}

async function executeSingleUpdate(app, dryRun, timeoutMs) {
  let command = null;
  let args = [];

  const targetVersion = app.latestVersion || '';
  const src = sourceName(app.source);

  if (src === 'winget') {
    command = 'winget';
    args = ['upgrade', '--id', app.appId, '--accept-source-agreements', '--accept-package-agreements'];
    if (targetVersion) args.push('--version', targetVersion);
  } else if (src === 'chocolatey') {
    command = 'choco';
    args = ['upgrade', app.name, '-y'];
    if (targetVersion) args.push('--version', targetVersion);
  } else if (src === 'npm') {
    command = 'npm';
    args = ['install', '-g', `${app.name}${targetVersion ? `@${targetVersion}` : ''}`];
  } else if (src === 'pnpm') {
    command = 'pnpm';
    args = ['add', '-g', `${app.name}${targetVersion ? `@${targetVersion}` : ''}`];
  } else if (src === 'bun') {
    command = 'bun';
    args = ['add', '-g', `${app.name}${targetVersion ? `@${targetVersion}` : ''}`];
  } else if (src === 'yarn') {
    command = 'yarn';
    args = ['global', 'add', `${app.name}${targetVersion ? `@${targetVersion}` : ''}`];
  } else if (src === 'pip') {
    const pipArgs = ['install', `${app.name}${targetVersion ? `==${targetVersion}` : ''}`];
    if (!targetVersion) pipArgs.push('--upgrade');
    const result = dryRun
      ? { ok: true, stdout: `[dry-run] py -m pip ${pipArgs.join(' ')}`, stderr: '', code: 0 }
      : await runPip(pipArgs, timeoutMs);
    return result.ok;
  } else if (src === 'path') {
    if (app.name === 'bun') {
      command = 'bun';
      args = ['upgrade'];
    } else if (app.name === 'deno') {
      command = 'deno';
      args = ['upgrade'];
      if (targetVersion) args.push('--version', targetVersion);
    } else if (app.name === 'git') {
      command = 'git';
      args = ['update-git-for-windows', '-y'];
    } else if (app.name === 'pwsh') {
      command = 'powershell';
      args = ['-NoProfile', '-Command', 'iex "& { $(irm https://aka.ms/install-powershell.ps1) }"'];
    } else if (app.name === 'yarn') {
      command = 'npm';
      args = ['install', '-g', targetVersion ? `yarn@${targetVersion}` : 'yarn'];
    }
  }

  if (!command) return false;

  if (dryRun) {
    console.log(`[dry-run] ${command} ${args.join(' ')}`);
    return true;
  }

  const result = await runCommand(command, args, { allowFailure: true, timeoutMs });
  if (!result.ok) {
    await writeLog(`update failed: ${app.name} (${app.source}) stderr=${result.stderr}`);
  }
  return result.ok;
}

async function executeUpdates(apps, args, config) {
  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  let success = 0;
  const progress = createProgress(apps.length, `${emoji('gear')} Applying updates`);

  for (const app of apps) {
    const label = `${app.name} (${app.source})`;
    const ok = await executeSingleUpdate(app, args.dryRun, timeoutMs);
    if (ok) {
      success += 1;
      progress.tick(`${paint(emoji('ok'), ANSI.green)} ${paint(label, ANSI.bold)}`);
    } else {
      progress.tick(`${paint(emoji('fail'), ANSI.red)} ${paint(label, ANSI.bold)}`);
    }
  }

  progress.done(paint(`${emoji('sparkle')} finished`, ANSI.cyan));
  console.log(`\n${emoji('chart')} Completed: ${paint(`${success}/${apps.length}`, ANSI.bold)} successful.`);
}

function selectPackage(apps, packageName, source) {
  const wanted = String(packageName).toLowerCase();
  const filtered = apps.filter((a) => {
    if (String(a.name).toLowerCase() !== wanted) return false;
    if (source && String(a.source).toLowerCase() !== source) return false;
    return true;
  });
  return filtered;
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv);
  } catch (err) {
    console.error(String(err.message || err));
    printHelp();
    process.exitCode = 1;
    return;
  }

  if (args.help) {
    printHelp();
    return;
  }

  const config = DEFAULT_CONFIG;
  await ensureConfigDir();

  if (args.clearCache) {
    await clearCache();
    console.log(`${emoji('disk')} ${paint('Cache cleared.', ANSI.green)}`);
    return;
  }

  headerCard(`${emoji('rocket')} System Update Node CLI v${VERSION}`, `${emoji('gear')} Data dir: ${ACTIVE_DATA_DIR}`);
  if (require('node:fs').existsSync(CACHE_FILE)) {
    console.log(`${paint('Cache ', ANSI.bold)} ${paint('→', ANSI.gray)} ${CACHE_FILE}`);
  }
  console.log();

  const start = Date.now();

  let apps = null;
  if (!args.noCache) {
    apps = await loadCache(config);
    if (apps) {
      console.log(`${emoji('disk')} ${paint(`Loaded ${apps.length} apps from cache.`, ANSI.green)}\n`);
    }
  }

  if (!apps) {
    console.log(`${emoji('scan')} ${paint('Scanning sources...', ANSI.bold, ANSI.cyan)}`);
    apps = await scanSystem(config, args);
    console.log(`\n${emoji('package')} ${paint(`Discovered ${apps.length} unique apps.`, ANSI.bold)}`);

    console.log(`${emoji('update')} ${paint('Checking for updates...', ANSI.bold, ANSI.cyan)}`);
    const updates = await checkUpdates(apps, config);
    console.log(`${emoji('chart')} ${paint(`Detected ${updates} update candidates.`, ANSI.bold, updates > 0 ? ANSI.yellow : ANSI.green)}\n`);

    if (config.security?.enabled && config.security.autoCheck) {
      console.log(`${emoji('lock')} ${paint('Checking security vulnerabilities...', ANSI.bold, ANSI.magenta)}`);
      const vulnerabilities = await checkSecurityVulnerabilities(apps, config);
      if (vulnerabilities.length) {
        console.log(`${emoji('fire')} ${paint(`Found ${vulnerabilities.length} security vulnerabilities.`, ANSI.bold, ANSI.red)}\n`);
      } else {
        console.log(`${emoji('shield')} ${paint('No security vulnerabilities found.', ANSI.green)}\n`);
      }
    }

    await saveCache(apps);
  }

  if (args.source) {
    apps = apps.filter((a) => String(a.source).toLowerCase() === args.source);
  }
  if (args.include) {
    const includedSources = args.include.toLowerCase().split(',').map((s) => s.trim());
    apps = apps.filter((a) => includedSources.includes(String(a.source).toLowerCase()));
  }

  const appsWithUpdates = apps.filter((a) => a.status === Status.UPDATE_AVAILABLE);
  const bySource = apps.reduce((acc, a) => {
    acc[a.source] = (acc[a.source] || 0) + 1;
    return acc;
  }, {});

  console.log(paint(`\n${emoji('chart')} Summary`, ANSI.bold, ANSI.magenta));
  console.log(`${emoji('package')} total apps      ${paint(String(apps.length), ANSI.bold)}`);
  console.log(`${emoji('update')} updates         ${paint(String(appsWithUpdates.length), appsWithUpdates.length ? ANSI.yellow : ANSI.green, ANSI.bold)}`);
  console.log(`${emoji('hourglass')} scan duration   ${paint(`${((Date.now() - start) / 1000).toFixed(2)}s`, ANSI.bold)}`);
  console.log(`${emoji('gear')} sources         ${Object.entries(bySource).map(([s, n]) => `${s}:${n}`).join(', ')}`);
  console.log('');

  printAppsTable(apps);

  const vulnerableApps = apps.filter((a) => a.status === Status.VULNERABLE);
  if (vulnerableApps.length && config.security?.enabled) {
    const vulnerabilities = vulnerableApps.map((a) => ({
      packageName: a.name,
      severity: 'high',
      cve: 'N/A',
      description: 'Security update recommended',
    }));
    printSecurityTable(vulnerabilities);
  }

  if (args.packageName) {
    const matches = selectPackage(apps, args.packageName, args.source);
    if (!matches.length) {
      console.error(`\n${emoji('fail')} ${paint(`Package not found: ${args.packageName}${args.source ? ` (source=${args.source})` : ''}`, ANSI.red, ANSI.bold)}`);
      process.exitCode = 2;
      return;
    }

    if (matches.length > 1 && !args.source) {
      console.error(`\n${emoji('warn')} ${paint('Multiple matching packages found. Re-run with --source.', ANSI.yellow, ANSI.bold)}`);
      for (const m of matches) {
        console.error(`- ${m.name} (${m.source}) ${m.version}`);
      }
      process.exitCode = 2;
      return;
    }

    const target = matches[0];
    if (args.version) target.latestVersion = args.version;
    if (!target.latestVersion && target.status !== Status.UPDATE_AVAILABLE && !args.version) {
      const force = await askToProceed(`${target.name} appears up-to-date. Force reinstall?`, args.yes);
      if (!force) return;
    }

    await executeUpdates([target], args, config);
  } else if (args.updateSource) {
    const candidates = appsWithUpdates.filter((a) => sourceName(a.source) === sourceName(args.updateSource));
    if (!candidates.length) {
      console.log(`\n${emoji('ok')} ${paint(`No updates found for source: ${args.updateSource}`, ANSI.green)}`);
    } else {
      const proceed = await askToProceed(`Proceed with ${candidates.length} update(s) from ${args.updateSource}?`, args.yes);
      if (proceed) await executeUpdates(candidates, args, config);
    }
  } else if (args.updateAll) {
    if (!appsWithUpdates.length) {
      console.log(`\n${emoji('ok')} ${paint('No updates available.', ANSI.green)}`);
    } else {
      const proceed = await askToProceed(`Proceed with all ${appsWithUpdates.length} updates?`, args.yes);
      if (proceed) await executeUpdates(appsWithUpdates, args, config);
    }
  }

  if (args.export) {
    const file = await exportResults(apps, args.export, args.output);
    console.log(`\n${emoji('export')} ${paint(`Exported results to: ${file}`, ANSI.green, ANSI.bold)}`);
  }
}

main().catch(async (err) => {
  await writeLog(`fatal: ${err?.stack || err}`);
  console.error(`Fatal error: ${err?.message || err}`);
  process.exitCode = 1;
});