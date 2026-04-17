#!/usr/bin/env node
/**
 * =============================================================================
 *                         SYSTEM UPDATE - NODE.JS CLI
 * =============================================================================
 * Version: 1.0.1
 * 
 * A comprehensive system update tool for managing package updates across multiple
 * package managers and sources on Windows and Unix-like systems.
 * 
 * Features:
 * - Multi-source package discovery (Winget, Chocolatey, NPM, PNPM, Bun, Yarn, Pip, Rust, Registry)
 * - Toolchain detection (Node.js, Python, Rust, Go, Deno, .NET, Java, Git, PowerShell)
 * - Security vulnerability scanning for NPM and PIP packages
 * - Parallel scanning for optimal performance
 * - Caching system for faster subsequent runs
 * - Flexible export options (JSON, CSV)
 * - Dry-run support for safe preview of updates
 */
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// MODULE IMPORTS
// ─────────────────────────────────────────────────────────────────────────────
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const https = require('node:https');
const { spawn } = require('node:child_process');
const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS AND CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────
const VERSION = '2.3.0';
const APP_NAME = 'system-update';
const IS_WINDOWS = process.platform === 'win32';

// Data directory: use SYSTEM_UPDATE_HOME env var if set, otherwise default to ~/.system_update
const PREFERRED_DATA_DIR = process.env.SYSTEM_UPDATE_HOME
  ? path.resolve(process.env.SYSTEM_UPDATE_HOME)
  : path.join(os.homedir(), '.system_update');
let ACTIVE_DATA_DIR = PREFERRED_DATA_DIR;
let CACHE_FILE = path.join(ACTIVE_DATA_DIR, 'cache.json');
let CONFIG_FILE = path.join(ACTIVE_DATA_DIR, 'config.json');
let LOG_FILE = path.join(ACTIVE_DATA_DIR, 'system.log');

// Terminal capabilities detection
const IS_TTY = Boolean(process.stdout.isTTY);
const SUPPORTS_COLOR = IS_TTY && process.env.NO_COLOR !== '1';
let LOGGING_ENABLED = false;
let DEBUG_ENABLED = false;

// ─────────────────────────────────────────────────────────────────────────────
// STATUS ENUMERATION
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Package update status constants
 * @enum {string}
 */
const Status = Object.freeze({
  UP_TO_DATE: 'up_to_date',
  UPDATE_AVAILABLE: 'update_available',
  UNKNOWN: 'unknown',
  ERROR: 'error',
  VULNERABLE: 'vulnerable',
  SECURITY_UPDATE_AVAILABLE: 'security_update_available',
});

// ─────────────────────────────────────────────────────────────────────────────
// DEFAULT CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Default application configuration
 * @type {Object}
 */
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
    rust: true,
    scoop: true,
    dotnet: true,
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

// ─────────────────────────────────────────────────────────────────────────────
// DATA DIRECTORY MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Switch to local data directory as fallback when primary directory fails
 * @returns {boolean} True if switch was successful
 */
function switchToLocalDataDir() {
  const fallback = path.join(process.cwd(), '.system_update');
  ACTIVE_DATA_DIR = fallback;
  CACHE_FILE = path.join(ACTIVE_DATA_DIR, 'cache.json');
  CONFIG_FILE = path.join(ACTIVE_DATA_DIR, 'config.json');
  LOG_FILE = path.join(ACTIVE_DATA_DIR, 'system.log');
  writeLog(`switched to local data dir: ${fallback}`);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ANSI COLOR CODES AND UI UTILITIES
// ─────────────────────────────────────────────────────────────────────────────
/**
 * ANSI escape codes for terminal colors and styles
 */
const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  underline: '\x1b[4m',

  // Standard colors
  black: '\x1b[30m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',

  // Bright colors (High intensity)
  gray: '\x1b[90m',
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightBlue: '\x1b[94m',
  brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
  brightWhite: '\x1b[97m',

  // Extended 256-colors
  orange: '\x1b[38;5;208m',
  purple: '\x1b[38;5;129m',
  pink: '\x1b[38;5;206m',
  teal: '\x1b[38;5;45m',
  gold: '\x1b[38;5;214m',
};

/**
 * Apply ANSI color styles to text
 * @param {string} text - Text to colorize
 * @param {...string} styles - ANSI style codes to apply
 * @returns {string} Styled text or plain text if color not supported
 */
function paint(text, ...styles) {
  if (!SUPPORTS_COLOR) return String(text);
  return `${styles.join('')}${text}${ANSI.reset}`;
}

/**
 * Get emoji character by name
 * @param {string} name - Emoji name key
 * @returns {string} Emoji character or empty string if not found
 */
function emoji(name) {
  const map = {
    rocket: '🚀',
    package: '📦',
    scan: '🔎',
    update: '🔄',
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
    target: '🎯',
  };
  return map[name] || '';
}

/**
 * Get status badge with emoji and color
 * @param {string} status - Status constant from Status enum
 * @returns {string} Formatted status badge
 */
function statusBadge(status) {
  if (status === Status.UPDATE_AVAILABLE) return paint(`${emoji('update')} update`, ANSI.yellow, ANSI.bold);
  if (status === Status.UP_TO_DATE) return paint(`${emoji('ok')} up-to-date`, ANSI.green);
  if (status === Status.ERROR) return paint(`${emoji('fail')} error`, ANSI.red);
  if (status === Status.VULNERABLE) return paint(`${emoji('fire')} vulnerable`, ANSI.red, ANSI.bold);
  if (status === Status.SECURITY_UPDATE_AVAILABLE) return paint(`${emoji('lock')} security update`, ANSI.magenta, ANSI.bold);
  return paint('❔ unknown', ANSI.gray);
}

/**
 * Get source badge with source-specific color
 * @param {string} source - Package source name
 * @returns {string} Colored source name
 */
function sourceBadge(source) {
  const value = String(source || 'unknown');
  const cfg = {
    winget: [ANSI.blue],
    chocolatey: [ANSI.yellow],
    npm: [ANSI.red],
    pnpm: [ANSI.pink],
    pip: [ANSI.cyan],
    bun: [ANSI.brightBlue],
    yarn: [ANSI.brightWhite],
    rust: [ANSI.purple],
    path: [ANSI.green],
    registry: [ANSI.gray],
    scoop: [ANSI.brightYellow],
    dotnet: [ANSI.gold],
  }[value] || [ANSI.brightWhite];
  return paint(value, ...cfg);
}

/**
 * Create horizontal line separator
 * @param {string} ch - Character to repeat
 * @param {number} width - Line width
 * @returns {string} Horizontal line
 */
function hr(ch = '─', width = 72) {
  return ch.repeat(width);
}

/**
 * Display header card with title and subtitle
 * @param {string} title - Main title
 * @param {string} subtitle - Subtitle text
 */
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

// ─────────────────────────────────────────────────────────────────────────────
// PROGRESS INDICATOR
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Create a progress bar for tracking operation progress
 * @param {number} total - Total number of items to process
 * @param {string} label - Label text for the progress bar
 * @returns {Object} Progress control object with tick, done, and render methods
 */
function createProgress(total, label) {
  let current = 0;
  const width = 26;
  const startTime = Date.now();

  /**
   * Render the progress bar to terminal
   * @param {string} extra - Additional text to append
   */
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

  /**
   * Increment progress by one step
   * @param {string} extra - Additional text to append
   */
  function tick(extra = '') {
    current += 1;
    render(extra);
  }

  /**
   * Mark progress as complete
   * @param {string} extra - Additional text to append
   */
  function done(extra = '') {
    current = total;
    render(extra);
    if (IS_TTY) process.stdout.write('\n');
  }

  render();
  return { tick, done };
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK UTILITIES
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Fetch and parse JSON from URL with redirect support
 * @param {string} url - URL to fetch
 * @returns {Promise<Object>} Parsed JSON response
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const parsed = await new Promise((resolve, reject) => {
        https.get(url, { headers: { 'User-Agent': 'SystemUpdateCLI' } }, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            return fetchJson(res.headers.location, retries - attempt).then(resolve).catch(reject);
          }
          if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (err) {
              reject(err);
            }
          });
        }).on('error', reject);
      });
      return parsed;
    } catch (err) {
      await writeLog(`fetchJson retry=${attempt + 1} url=${url} error=${err.message}`);
      if (attempt >= retries) throw err;
      await sleep((attempt + 1) * 400);
    }
  }
  throw new Error('fetchJson retry loop exhausted');
}

function deepMerge(target, source) {
  if (!source || typeof source !== 'object') return target;
  for (const [key, value] of Object.entries(source)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && target[key] && typeof target[key] === 'object') {
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

async function loadConfig() {
  const base = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  try {
    const raw = await fs.readFile(CONFIG_FILE, 'utf8');
    return deepMerge(base, JSON.parse(raw));
  } catch {
    return base;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION DIRECTORY MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Ensure configuration directory exists, with fallback to local directory
 * @returns {Promise<void>}
 */
async function ensureConfigDir() {
  try {
    await fs.mkdir(ACTIVE_DATA_DIR, { recursive: true });
  } catch (err) {
    await writeLog(`ensureConfigDir primary failed: ${err.message}`);
    if (switchToLocalDataDir()) {
      await fs.mkdir(ACTIVE_DATA_DIR, { recursive: true });
      await writeLog(`ensureConfigDir fallback success: ${ACTIVE_DATA_DIR}`);
      return;
    }
    throw err;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGGING SYSTEM
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Write message to log file if logging is enabled
 * @param {string} message - Message to log
 * @returns {Promise<void>}
 */
async function writeLog(message) {
  if (!LOGGING_ENABLED) return;
  const line = `${new Date().toISOString()} ${message}\n`;
  try {
    await fs.appendFile(LOG_FILE, line, 'utf8');
  } catch {
    // keep CLI resilient; logging should never break flow
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND EXECUTION
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Normalize command for Windows (add .cmd extension for npm/pnpm/npx/yarn)
 * @param {string} cmd - Command name
 * @returns {string} Normalized command
 */
function normalizeCommand(cmd) {
  if (!IS_WINDOWS) return cmd;
  const useCmdShim = new Set(['npm', 'pnpm', 'npx', 'yarn']);
  if (useCmdShim.has(cmd) && !cmd.endsWith('.cmd')) return `${cmd}.cmd`;
  return cmd;
}

/**
 * Execute shell command with timeout and error handling
 * @param {string} cmd - Command to execute
 * @param {string[]} args - Command arguments
 * @param {Object} options - Execution options
 * @param {number} options.timeoutMs - Timeout in milliseconds
 * @param {boolean} options.allowFailure - Don't treat non-zero exit as error
 * @param {string} options.cwd - Working directory
 * @returns {Promise<Object>} Result object with ok, stdout, stderr, code
 */
function runCommand(cmd, args = [], options = {}) {
  const {
    timeoutMs = 45_000,
    allowFailure = false,
    cwd = process.cwd(),
  } = options;

  return new Promise((resolve) => {
    const command = normalizeCommand(cmd);
    const useShell = IS_WINDOWS && (command.endsWith('.cmd') || command.endsWith('.bat'));

    if (DEBUG_ENABLED) {
      const fullCmd = `${command} ${args.join(' ')}`.trim();
      console.log(`${paint('[DEBUG]', ANSI.gray)} ${paint('Executing:', ANSI.bold)} ${fullCmd}`);
      writeLog(`[DEBUG] Executing: ${fullCmd}`);
    }

    let child;
    try {
      child = spawn(command, args, {
        cwd,
        windowsHide: true,
        shell: useShell,
      });
    } catch (err) {
      writeLog(`runCommand spawn error: cmd=${command}, error=${err.message}`);
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
      if (!ok) {
        writeLog(`runCommand non-zero exit: cmd=${command}, code=${code}, stderr=${stderrData.trim().slice(0, 200)}`);
      }
      resolve({ ok, stdout: stdoutData.trim(), stderr: stderrData.trim(), code });
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND LINE ARGUMENT PARSING
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Parse command line arguments into options object
 * @param {string[]} argv - Process arguments array
 * @returns {Object} Parsed arguments object
 */
function parseArgs(argv) {
  writeLog(`parsing arguments: ${argv.slice(2).join(' ')}`);
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
    log: false,
    debug: false,
    showAll: false,
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
        args.source = normalizeSource(argv[++i] || '');
        break;
      case '--update-source':
        args.updateSource = normalizeSource(argv[++i] || '');
        break;
      case '--include':
        args.include = parseIncludeSources(argv[++i] || '').join(',');
        break;
      case '--yes':
      case '-y':
        args.yes = true;
        break;
      case '--help':
      case '-h':
        args.help = true;
        break;
      case '--log':
        args.log = true;
        break;
      case '--debug':
        args.debug = true;
        break;
      case '--show-all':
        args.showAll = true;
        break;
      default:
        throw new Error(`Unknown argument: ${token}`);
    }
  }

  return args;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELP MESSAGE
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Display help message with usage examples
 */
function printHelp() {
  console.log(`
${emoji('sparkle')} ${paint(`System Update Node CLI v${VERSION}`, ANSI.bold, ANSI.cyan)}

Usage:
  node system_update.js [options]

Options:
  --update-all              Update every package with updates
  --update-source <source>  Update all from a source (winget,choco,npm,pnpm,pip,bun,yarn,path,rust,registry)
  --package <name>          Update one package by name
  --version <ver>           Target version (with --package)
  --source <source>         Source filter for --package (winget,choco,npm,pnpm,pip,bun,yarn,path,rust,registry)
  --dry-run                 Print planned updates without executing
  --no-cache                Force fresh scan
  --clear-cache             Remove cache file and exit
  --export <json|csv>       Export scan results
  --output <file>           Output path for export
  --log                     Enable logging to file
  --debug                   Show all executed commands on screen and in log
  --include <source>        Limit scan sources (e.g. winget,npm,path,registry)
  --yes, -y                 Skip confirmation prompts
  --help, -h                Show help
  --show-all                Show all packages (including up-to-date)

Features:
  • Package Discovery: Winget, Chocolatey, NPM, PNPM, Bun, Yarn, Pip, Rust, Registry
  • Toolchain Detection: Node.js, Python, Rust, Go, Deno, .NET, Java, Git, PWSH
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
  node system_update.js --show-all
`);
}

// ─────────────────────────────────────────────────────────────────────────────
// SOURCE CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Check if a package source is enabled in configuration
 * @param {Object} config - Configuration object
 * @param {string} source - Source name to check
 * @returns {boolean} True if source is enabled
 */
function getSourceToggle(config, source) {
  return Boolean(config.sources[source]);
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND AVAILABILITY CHECK
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Check if a command is available on the system
 * @param {string} command - Command name to check
 * @returns {Promise<boolean>} True if command is available
 */
async function isCommandAvailable(command) {
  if (!IS_WINDOWS) {
    const result = await runCommand('which', [command], { allowFailure: true, timeoutMs: 10_000 });
    const available = result.ok && Boolean(result.stdout);
    await writeLog(`command check: cmd=${command}, available=${available} (via which)`);
    return available;
  }

  // Windows strategy: try multiple fallbacks
  // 1. where
  let res = await runCommand('where', [command], { allowFailure: true, timeoutMs: 5_000 });
  if (res.ok && res.stdout) {
    await writeLog(`command check: cmd=${command}, available=true (via where)`);
    return true;
  }

  // 2. where.exe (sometimes the alias 'where' is problematic)
  res = await runCommand('where.exe', [command], { allowFailure: true, timeoutMs: 5_000 });
  if (res.ok && res.stdout) {
    await writeLog(`command check: cmd=${command}, available=true (via where.exe)`);
    return true;
  }

  // 3. PowerShell Get-Command
  const psCmd = `(Get-Command ${command} -ErrorAction SilentlyContinue).Path`;
  res = await runCommand('powershell', ['-NoProfile', '-Command', psCmd], { allowFailure: true, timeoutMs: 10_000 });
  if (res.ok && res.stdout) {
    await writeLog(`command check: cmd=${command}, available=true (via Get-Command)`);
    return true;
  }

  await writeLog(`command check: cmd=${command}, available=false`);
  return false;
}

/**
 * Parse winget command output table into structured app objects
 * @description Extracts package information from winget list/upgrade command output by parsing
 * the table format. Handles column position detection and extracts name, ID, version, and
 * available update version if present.
 * @param {string} output - Raw output from winget command
 * @param {boolean} [includeAvailable=false] - Whether to extract available update versions
 * @returns {Array<Object>} Array of parsed app objects with name, source, version, latestVersion, appId, and status
 */
function parseWingetTable(output, includeAvailable = false) {
  const apps = [];
  if (!output) return apps;
  const lines = output.split(/\r?\n/);
  // Find header line containing column names
  const headerIndex = lines.findIndex((line) => line.includes('Name') && line.includes('Id') && line.includes('Version'));
  if (headerIndex < 0) return apps;

  let header = lines[headerIndex];
  const nameMatch = header.match(/Name\s+Id/);
  if (nameMatch) {
    header = header.slice(nameMatch.index);
  }

  // Calculate column positions for parsing
  const positions = {
    id: header.indexOf('Id'),
    version: header.indexOf('Version'),
    available: header.indexOf('Available'),
    source: header.indexOf('Source'),
  };

  // Parse each data row after header
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

/**
 * Scan system for Winget-installed packages
 * @description Executes winget list command and parses output to discover all packages
 * installed via Windows Package Manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed Winget packages
 */
async function scanWinget(timeoutMs) {
  await writeLog('scanner: winget started');
  const result = await runCommand('winget', ['list', '--accept-source-agreements'], { allowFailure: true, timeoutMs });
  const apps = parseWingetTable(result.stdout, false);
  await writeLog(`scanner: winget finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan system for Chocolatey-installed packages
 * @description Executes choco list command and parses pipe-delimited output to discover
 * all packages installed via Chocolatey package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed Chocolatey packages
 */
async function scanChocolatey(timeoutMs) {
  await writeLog('scanner: chocolatey started');
  try {
    const result = await runCommand('choco', ['list', '--limit-output'], { allowFailure: true, timeoutMs });
    const apps = [];
    if (!result.stdout) {
      await writeLog('scanner: chocolatey no output');
      return apps;
    }
    // Parse pipe-delimited output: name|version
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
    await writeLog(`scanner: chocolatey finished, count=${apps.length}`);
    return apps;
  } catch (err) {
    await writeLog(`scanner: chocolatey error, ${err.message}`);
    return [];
  }
}

/**
 * Scan system for globally installed Bun packages
 * @description Executes bun pm ls -g command and parses output to discover all packages
 * installed globally via Bun package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed Bun packages
 */
async function scanBun(timeoutMs) {
  await writeLog('scanner: bun started');
  const result = await runCommand('bun', ['pm', 'ls', '-g'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;

  // Parse format: package@version
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
  await writeLog(`scanner: bun finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan system for globally installed Yarn packages
 * @description Executes yarn global list command and parses output to discover all packages
 * installed globally via Yarn package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed Yarn packages
 */
async function scanYarn(timeoutMs) {
  await writeLog('scanner: yarn started');
  const result = await runCommand('yarn', ['global', 'list'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;

  // Parse format: info "package@version"
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
  await writeLog(`scanner: yarn finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan system for globally installed NPM packages
 * @description Executes npm list -g --json command and parses JSON output to discover
 * all packages installed globally via NPM package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed NPM packages
 */
async function scanNpm(timeoutMs) {
  await writeLog('scanner: npm started');
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
  await writeLog(`scanner: npm finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan system for globally installed PNPM packages
 * @description Executes pnpm list -g --json command and parses JSON output to discover
 * all packages installed globally via PNPM package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed PNPM packages
 */
async function scanPnpm(timeoutMs) {
  await writeLog('scanner: pnpm started');
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
  await writeLog(`scanner: pnpm finished, count=${apps.length}`);
  return apps;
}

/**
 * Execute pip command with fallback to multiple Python executables
 * @description Attempts to run pip command using various Python executable candidates
 * (py, python, python3, pip) in order of preference. Returns the first successful result.
 * @param {string[]} args - Arguments to pass to pip command
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Object>} Result object with ok, stdout, stderr, code, and runner info
 */
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

/**
 * Scan system for installed Python pip packages
 * @description Executes pip list --format=json command and parses JSON output to discover
 * all packages installed in the Python environment.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed pip packages
 */
async function scanPip(timeoutMs) {
  await writeLog('scanner: pip started');
  const result = await runPip(['list', '--format=json'], timeoutMs);
  const apps = [];
  if (!result.stdout) {
    await writeLog('scanner: pip no output');
    return apps;
  }
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
  await writeLog(`scanner: pip finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan system for tools available in PATH
 * @description Checks for common development tools (node, npm, python, git, etc.) by verifying
 * their availability in system PATH and retrieving their version information.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed PATH tools
 */
async function scanPath(timeoutMs) {
  await writeLog('scanner: path started');
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
  await writeLog(`scanner: path finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan Windows Registry for installed applications
 * @description Executes PowerShell script to query Windows Registry uninstall keys from
 * HKLM and HKCU hives. Extracts display name, version, and product ID for all user-installed
 * applications (excludes system components). Windows-only function.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing registry-installed applications
 */
async function scanRegistry(timeoutMs) {
  if (!IS_WINDOWS) return [];
  await writeLog('scanner: registry started');
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
    const results = rows
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
    await writeLog(`scanner: registry finished, count=${results.length}`);
    return results;
  } catch (err) {
    await writeLog(`parse registry failed: ${err}`);
    return [];
  }
}

/**
 * Scan system for Rust crates installed via Cargo
 * @description Executes cargo install --list command and parses output to discover all
 * Rust binaries installed globally via Cargo package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed Rust crates
 */
async function scanRust(timeoutMs) {
  await writeLog('scanner: rust started');
  const result = await runCommand('cargo', ['install', '--list'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) return apps;

  // Format: package-name v1.2.3:
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^([^\s]+)\s+v([^\s:]+):/);
    if (match) {
      apps.push({
        name: match[1],
        source: 'rust',
        version: match[2],
        latestVersion: '',
        appId: match[1],
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  }
  await writeLog(`scanner: rust finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan system for Scoop-installed packages
 * @description Executes scoop list command and parses output to discover all packages
 * installed via Scoop package manager.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed Scoop packages
 */
async function scanScoop(timeoutMs) {
  await writeLog('scanner: scoop started');
  const result = await runCommand('scoop', ['list'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) {
    await writeLog('scanner: scoop no output');
    return apps;
  }

  const lines = result.stdout.split(/\r?\n/);
  let startIndex = 0;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (line.startsWith('Name') && line.includes('Version') && line.includes('')) {
      startIndex = i + 2;
      break;
    }
  }

  for (let i = startIndex; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line || line.startsWith('---') || line.startsWith('+')) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const name = parts[0];
      const version = parts[1];
      if (name && version && !name.startsWith(' ')) {
        apps.push({
          name,
          source: 'scoop',
          version,
          latestVersion: '',
          appId: name,
          status: Status.UNKNOWN,
          scanTime: new Date().toISOString(),
        });
      }
    }
  }

  await writeLog(`scanner: scoop finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan .NET Global Tools installed via dotnet.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed .NET Global Tools
 */
async function scanDotnet(timeoutMs) {
  await writeLog('scanner: dotnet started');
  const result = await runCommand('dotnet', ['tool', 'list', '-g'], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) {
    await writeLog('scanner: dotnet no output');
    return apps;
  }

  const lines = result.stdout.split(/\r?\n/);
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line || line.startsWith('---') || line.startsWith('Package')) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const name = parts[0];
      const version = parts[1];
      if (name && version) {
        apps.push({
          name,
          source: 'dotnet',
          version,
          latestVersion: '',
          appId: name,
          status: Status.UNKNOWN,
          scanTime: new Date().toISOString(),
        });
      }
    }
  }

  await writeLog(`scanner: dotnet finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan Windows AppX/Packaged apps (Microsoft Store apps).
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed AppX packages
 */
async function scanAppx(timeoutMs) {
  await writeLog('scanner: appx started');
  const psScript = `
    Get-AppxPackage -AllUsers |
      Where-Object { $_.IsFramework -eq $false -and $_.SignatureKind -ne 'System' } |
      Select-Object Name, Version, PackageFullName, InstallLocation |
      ConvertTo-Json
  `;
  const result = await runCommand('powershell', ['-NoProfile', '-Command', psScript], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) {
    await writeLog('scanner: appx no output');
    return apps;
  }

  try {
    let data = JSON.parse(result.stdout);
    if (!Array.isArray(data)) data = [data];
    for (const item of data) {
      apps.push({
        name: item.Name,
        source: 'appx',
        version: item.Version || '',
        latestVersion: '',
        appId: item.PackageFullName || item.Name,
        installPath: item.InstallLocation || '',
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  } catch (e) {
    await writeLog(`scanner: appx parse error, ${e.message}`);
  }

  await writeLog(`scanner: appx finished, count=${apps.length}`);
  return apps;
}

/**
 * Scan Windows MSIX packaged applications.
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of app objects representing installed MSIX packages
 */
async function scanMsix(timeoutMs) {
  await writeLog('scanner: msix started');
  const psScript = `
    Get-AppxPackage -AllUsers |
      Where-Object { $_.SignatureKind -eq 'AppxPackage' } |
      Select-Object Name, Version, PackageFullName, InstallLocation |
      ConvertTo-Json
  `;
  const result = await runCommand('powershell', ['-NoProfile', '-Command', psScript], { allowFailure: true, timeoutMs });
  const apps = [];
  if (!result.stdout) {
    await writeLog('scanner: msix no output');
    return apps;
  }

  try {
    let data = JSON.parse(result.stdout);
    if (!Array.isArray(data)) data = [data];
    for (const item of data) {
      apps.push({
        name: item.Name,
        source: 'msix',
        version: item.Version || '',
        latestVersion: '',
        appId: item.PackageFullName || item.Name,
        installPath: item.InstallLocation || '',
        status: Status.UNKNOWN,
        scanTime: new Date().toISOString(),
      });
    }
  } catch (e) {
    await writeLog(`scanner: msix parse error, ${e.message}`);
  }

  await writeLog(`scanner: msix finished, count=${apps.length}`);
  return apps;
}

/**
 * Check for .NET Global Tool updates.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of .NET tools with available updates
 */
async function checkDotnetUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'dotnet');
  if (!target.length) return 0;
  await writeLog('checking dotnet updates');

  const result = await runCommand('dotnet', ['tool', 'list', '-g', '--outdated'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return 0;

  let count = 0;
  const lines = result.stdout.split(/\r?\n/);
  const updateMap = new Map();

  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line || line.startsWith('---') || line.startsWith('Package')) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      updateMap.set(parts[0], parts[1]);
    }
  }

  for (const app of target) {
    const latest = updateMap.get(app.name);
    if (latest) {
      app.latestVersion = latest;
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  }

  await writeLog(`update check: dotnet finished, updates=${count}`);
  return count;
}

/**
 * Check for Scoop package updates
 * @description Executes scoop status command to check for available updates.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Scoop packages with available updates
 */
async function checkScoopUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'scoop');
  if (!target.length) return 0;
  await writeLog('checking scoop updates');

  const result = await runCommand('scoop', ['status'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return 0;

  let count = 0;
  const lines = result.stdout.split(/\r?\n/);
  const updateMap = new Map();

  for (const line of lines) {
    const match = line.match(/^([^\s]+)\s+([^\s]+)\s+(.*?)(\s+\(Scoop\))?$/);
    if (match) {
      const [, name, currentVersion, latestInfo] = match;
      const latestMatch = latestInfo.match(/(\d+\.\d+\.\d+)/);
      if (latestMatch && currentVersion !== latestMatch[1]) {
        updateMap.set(name, latestMatch[1]);
      }
    }
  }

  for (const app of target) {
    const latest = updateMap.get(app.name);
    if (latest) {
      app.latestVersion = latest;
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  }

  await writeLog(`update check: scoop finished, updates=${count}`);
  return count;
}

/**
 * Check for Rust crate updates using cargo install-update
 * @description Uses cargo install-update -l command to check for available updates for
 * installed Rust crates. Requires cargo-edit or cargo-update to be installed.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Rust packages with available updates
 */
async function checkRustUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'rust');
  if (!target.length) return 0;
  await writeLog('checking rust updates (via crates.io API)');

  let count = 0;
  let errors = 0;

  for (const app of target) {
    try {
      const url = `https://crates.io/api/v1/crates/${app.name}`;
      const res = await fetch(url, { headers: { 'User-Agent': 'SystemUpdateCLI' } });
      if (!res.ok) {
        errors += 1;
        continue;
      }
      const data = await res.json();
      const versions = data.versions || [];
      if (versions.length > 0 && versions[0].num) {
        app.latestVersion = versions[0].num;
        app.status = Status.UPDATE_AVAILABLE;
        count += 1;
      }
    } catch (err) {
      errors += 1;
      await writeLog(`rust update check error: ${app.name}, ${err.message}`);
    }
  }

  if (errors > 0) {
    console.log(`[dim]⚠️ ${errors} Rust crate(s) could not be checked via API[/dim]`);
  }

  await writeLog(`update check: rust finished, updates=${count}`);
  return count;
}

/**
 * Deduplicate app list by source, name, and version
 * @description Removes duplicate entries from the app list using a composite key of
 * source, name, and version. Returns sorted array by source and name.
 * @param {Array<Object>} apps - Array of app objects that may contain duplicates
 * @returns {Array<Object>} Array of unique app objects sorted by source and name
 */
function uniqueApps(apps) {
  writeLog(`filtering unique apps: input_count=${apps.length}`);
  const map = new Map();
  for (const app of apps) {
    const key = `${app.source}|${app.name}|${app.version}`.toLowerCase();
    map.set(key, app);
  }
  return [...map.values()].sort((a, b) => (a.source + a.name).localeCompare(b.source + b.name));
}

// ─────────────────────────────────────────────────────────────────────────────
// CACHE MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Load cached app data from disk if not expired
 * @description Reads the cache file and validates its age against the configured cache
 * duration. Returns null if cache is expired, disabled, or invalid.
 * @param {Object} config - Configuration object with cache settings
 * @returns {Promise<Array<Object>|null>} Cached app array or null if cache is invalid/expired
 */
async function loadCache(config) {
  if (!config.cache.enabled) return null;

  try {
    const raw = await fs.readFile(CACHE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    const timestamp = new Date(parsed.timestamp);
    if (Number.isNaN(timestamp.getTime())) return null;

    const ageMs = Date.now() - timestamp.getTime();
    const validMs = Number(config.cache.durationHours || 2) * 3600_000;
    if (ageMs > validMs) {
      await writeLog(`cache expired: age=${(ageMs / 3600000).toFixed(1)}h, limit=${config.cache.durationHours}h`);
      return null;
    }

    await writeLog(`cache loaded: ${parsed.apps.length} apps from ${parsed.timestamp}`);
    return Array.isArray(parsed.apps) ? parsed.apps : null;
  } catch (err) {
    if (err.code !== 'ENOENT') {
      await writeLog(`cache load error: ${err.message}`);
    }
    return null;
  }
}

/**
 * Save app data to cache file
 * @description Writes the current app scan results to the cache file with timestamp.
 * Includes fallback logic to switch to local directory if primary location fails.
 * @param {Array<Object>} apps - Array of app objects to cache
 * @returns {Promise<void>}
 */
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
    await writeLog(`cache saved: ${apps.length} apps`);
  } catch (err) {
    if ((err && (err.code === 'EPERM' || err.code === 'EACCES')) && switchToLocalDataDir()) {
      await ensureConfigDir();
      await fs.writeFile(CACHE_FILE, JSON.stringify(payload, null, 2), 'utf8');
      await writeLog(`cache saved (fallback): ${apps.length} apps`);
      return;
    }
    await writeLog(`cache save failed: ${err.message}`);
    throw err;
  }
}

/**
 * Clear the cache file manually
 * @description Deletes the cache file from disk. Silently ignores ENOENT errors
 * (file doesn't exist).
 * @returns {Promise<void>}
 */
async function clearCache() {
  try {
    await fs.unlink(CACHE_FILE);
    await writeLog('cache manual clear');
  } catch (err) {
    if (err.code !== 'ENOENT') {
      await writeLog(`cache clear error: ${err.message}`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UPDATE CHECKERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check for Winget package updates
 * @description Executes winget upgrade command to get list of packages with available
 * updates. Matches results against scanned apps and updates their status.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Winget packages with available updates
 */
async function checkWingetUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'winget');
  if (!target.length) return 0;
  await writeLog('checking winget updates');

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
  await writeLog(`update check: winget finished, updates=${count}`);
  return count;
}

/**
 * Check for Registry application updates via Winget
 * @description Uses winget upgrade command internally which queries the Windows Registry
 * to build its upgrade list. Matches registry apps by name against winget results.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Registry applications with available updates
 */
async function checkRegistryUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'registry');
  if (!target.length) return 0;
  await writeLog('checking registry updates (via winget)');

  // winget internally queries the Registry to build its upgrade list.
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
  await writeLog(`update check: registry finished, updates=${count}`);
  return count;
}

/**
 * Check for Chocolatey package updates
 * @description Executes choco outdated command to get list of packages with available
 * updates. Parses pipe-delimited output and updates matching app objects.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Chocolatey packages with available updates
 */
async function checkChocolateyUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'chocolatey');
  if (!target.length) return 0;
  await writeLog('checking chocolatey updates');

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
  await writeLog(`update check: chocolatey finished, updates=${count}`);
  return count;
}

/**
 * Check for NPM package updates
 * @description Executes npm outdated --json command to get list of packages with available
 * updates. Parses JSON output and updates matching app objects with latest versions.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of NPM packages with available updates
 */
async function checkNpmUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'npm');
  if (!target.length) return 0;
  await writeLog('checking npm updates');

  const result = await runCommand('npm', ['outdated', '-g', '--json', '--silent'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return 0;

  let count = 0;
  try {
    const parsed = JSON.parse(result.stdout);
    for (const [name, details] of Object.entries(parsed)) {
      const app = target.find((a) => a.name === name);
      if (!app) continue;
      app.latestVersion = details.latest || '';
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  } catch (err) {
    await writeLog(`parse npm outdated failed: ${err}`);
  }
  await writeLog(`update check: npm finished, updates=${count}`);
  return count;
}

/**
 * Check for PNPM package updates
 * @description Executes pnpm outdated --json command to get list of packages with available
 * updates. Parses JSON output and updates matching app objects with latest versions.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of PNPM packages with available updates
 */
async function checkPnpmUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'pnpm');
  if (!target.length) return 0;
  await writeLog('checking pnpm updates');

  const result = await runCommand('pnpm', ['outdated', '-g', '--json'], { allowFailure: true, timeoutMs });
  if (!result.stdout) return 0;

  let count = 0;
  try {
    const parsed = JSON.parse(result.stdout);
    for (const [name, details] of Object.entries(parsed)) {
      const app = target.find((a) => a.name === name);
      if (!app) continue;
      app.latestVersion = details.latest || details.wanted || '';
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  } catch (err) {
    await writeLog(`parse pnpm outdated failed: ${err}`);
  }
  await writeLog(`update check: pnpm finished, updates=${count}`);
  return count;
}

/**
 * Check for Bun package updates via npm info
 * @description Queries npm registry for latest version of each globally installed Bun package.
 * Uses npm info command as Bun doesn't have a native outdated command.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Bun packages with available updates
 */
async function checkBunUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'bun');
  if (!target.length) return 0;
  await writeLog('checking bun updates (via npm info)');

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
  await writeLog(`update check: bun finished, updates=${count}`);
  return count;
}

/**
 * Check for Yarn package updates via npm info
 * @description Queries npm registry for latest version of each globally installed Yarn package.
 * Uses npm info command as Yarn doesn't have a simple outdated command for global packages.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of Yarn packages with available updates
 */
async function checkYarnUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'yarn');
  if (!target.length) return 0;
  await writeLog('checking yarn updates (via npm info)');

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
  await writeLog(`update check: yarn finished, updates=${count}`);
  return count;
}

/**
 * Check for Python pip package updates
 * @description Executes pip list --outdated --format=json to get list of packages with
 * available updates. Parses JSON output and updates matching app objects.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of pip packages with available updates
 */
async function checkPipUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'pip');
  if (!target.length) return 0;
  await writeLog('checking pip updates');

  const result = await runPip(['list', '--outdated', '--format=json'], timeoutMs);
  if (!result.stdout) return 0;

  let count = 0;
  try {
    const parsed = JSON.parse(result.stdout);
    for (const item of parsed) {
      const app = target.find((a) => a.name.toLowerCase() === String(item.name).toLowerCase());
      if (!app) continue;
      app.latestVersion = item.latest_version || '';
      app.status = Status.UPDATE_AVAILABLE;
      count += 1;
    }
  } catch (err) {
    await writeLog(`parse pip outdated failed: ${err}`);
  }
  await writeLog(`update check: pip finished, updates=${count}`);
  return count;
}

/**
 * Check for PATH tool updates via various sources
 * @description Checks for updates to development tools found in system PATH by querying
 * GitHub APIs, npm registry, winget, or using tool-specific update commands. Handles
 * preview/release version logic to avoid suggesting downgrades.
 * @param {Array<Object>} apps - Array of all scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<number>} Number of PATH tools with available updates
 */
async function checkPathUpdates(apps, timeoutMs) {
  const target = apps.filter((a) => a.source === 'path');
  if (!target.length) return 0;
  await writeLog('checking path updates');

  // Parse version string into comparable array [major, minor, patch, isStable]
  function parseVersion(verStr) {
    const clean = String(verStr).replace(/^[^\d]+/, '').trim();
    const match = clean.match(/^(\d+)\.(\d+)\.(\d+)/);
    if (!match) {
      const match2 = clean.match(/^(\d+)\.(\d+)/);
      if (match2) {
        return [parseInt(match2[1]), parseInt(match2[2]), 0, !/preview|rc|beta|alpha|-pre/i.test(verStr)];
      }
      return [0, 0, 0, false];
    }
    const isStable = !/preview|rc|beta|alpha|-pre/i.test(verStr);
    return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), isStable];
  }

  // Check if latest is actually newer than current (handles previews)
  function isNewerVersion(current, latest) {
    const curr = parseVersion(current);
    const lat = parseVersion(latest);

    // If current is a newer major version preview, don't suggest downgrade
    if (curr[0] > lat[0]) return false;
    // If current is a newer minor in same major, don't suggest downgrade
    if (curr[0] === lat[0] && curr[1] > lat[1]) return false;

    // Both stable: standard comparison
    if (curr[3] && lat[3]) {
      return lat[0] > curr[0] || (lat[0] === curr[0] && lat[1] > curr[1]) || (lat[0] === curr[0] && lat[1] === curr[1] && lat[2] > curr[2]);
    }

    // Current is preview but same base version as latest stable
    if (!curr[3] && curr[0] === lat[0] && curr[1] === lat[1] && curr[2] === lat[2]) {
      return false;
    }

    // Latest stable is newer than current stable
    return lat[0] > curr[0] || (lat[0] === curr[0] && lat[1] > curr[1]) || (lat[0] === curr[0] && lat[1] === curr[1] && lat[2] > curr[2]);
  }

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
        // Python uses tags, not releases - get latest tag
        const data = await fetchJson('https://api.github.com/repos/python/cpython/tags?per_page=1').catch(() => null);
        if (data && Array.isArray(data) && data[0] && data[0].name) {
          const m = data[0].name.match(/v?([0-9.]+)/);
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
      } else if (app.name === 'rustc' || app.name === 'cargo') {
        const data = await fetchJson('https://api.github.com/repos/rust-lang/rust/releases/latest').catch(() => null);
        if (data && data.tag_name) {
          const m = data.tag_name.match(/([0-9.]+)/);
          if (m && m[1]) latest = m[1];
        }
        if (!latest) latest = app.version;
      }
    } catch {
      // silently ignore individual fetch failures
    }

    if (latest) {
      const cleanVersion = app.version.replace(/^[^\d]+/, '').trim();
      const cleanLatest = latest.replace(/^[^\d]+/, '').trim();
      app.latestVersion = cleanLatest;

      // Use proper version comparison that handles previews
      if (isNewerVersion(app.version, latest)) {
        app.status = Status.UPDATE_AVAILABLE;
        count += 1;
      } else {
        app.status = Status.UP_TO_DATE;
      }
    } else {
      // No latest version found, mark as up-to-date (don't show unknown)
      app.latestVersion = '-';
      app.status = Status.UP_TO_DATE;
    }
  }
  await writeLog(`update check: path finished, updates=${count}`);
  return count;
}

/**
 * Finalize status for apps without explicit update check results
 * @description Sets final status for apps that weren't marked during update checks.
 * Apps from known sources default to UP_TO_DATE, others remain UNKNOWN.
 * @param {Array<Object>} apps - Array of all scanned app objects to finalize
 * @returns {void}
 */
function finalizeStatuses(apps) {
  for (const app of apps) {
    if (app.status === Status.UPDATE_AVAILABLE) continue;
    if (app.status === Status.UP_TO_DATE) {
        if (!app.latestVersion) app.latestVersion = '-';
        continue;
    }
    if (app.latestVersion || ['winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn', 'pip', 'rust', 'path', 'dotnet'].includes(app.source)) {
      app.status = Status.UP_TO_DATE;
      if (!app.latestVersion) app.latestVersion = '-';
    } else {
      app.status = Status.UNKNOWN;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM SCANNING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scan system for all installed packages across enabled sources
 * @description Orchestrates parallel scanning of all enabled package sources (Winget,
 * Chocolatey, NPM, PNPM, Bun, Yarn, Pip, PATH, Registry, Rust). Applies source filters
 * if specified and displays progress during scanning.
 * @param {Object} config - Configuration object with source and performance settings
 * @param {Object} args - Parsed command line arguments with source/include filters
 * @returns {Promise<Array<Object>>} Array of unique app objects from all sources
 */
async function scanSystem(config, args) {
  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  const sourceFilter = new Set(parseIncludeSources(args.include));
  if (args.source) {
    sourceFilter.add(normalizeSource(args.source));
  }

  // Define all available scanner sources
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
    ['rust', scanRust],
    ['scoop', scanScoop],
    ['dotnet', scanDotnet],
    ['appx', scanAppx],
    ['msix', scanMsix],
  ];

  // Filter sources based on configuration and user filters
  const selected = jobs.filter(([source]) => {
    if (!getSourceToggle(config, source)) return false;
    if (sourceFilter.size && !sourceFilter.has(source)) return false;
    return true;
  });

  const progress = createProgress(selected.length, `${emoji('scan')} Scanning`);
  await writeLog(`scan started: sources=${selected.map(([s]) => s).join(',')}`);

  // Execute all scanners in parallel
  const chunks = await Promise.all(selected.map(async ([source, fn]) => {
    try {
      const apps = await fn(timeoutMs);
      progress.tick(`${sourceBadge(source)} ${paint(String(apps.length).padStart(4), ANSI.bold)} apps`);
      await writeLog(`scan source: ${source}, found=${apps.length}`);
      return apps;
    } catch (err) {
      await writeLog(`scan source error: ${source}, error=${err.message}`);
      return [];
    }
  }));
  progress.done(paint(`${emoji('ok')} scan complete`, ANSI.green));

  const unique = uniqueApps(chunks.flat());
  await writeLog(`scan complete: total_unique=${unique.length}`);
  return unique;
}

/**
 * Check for updates across all package sources
 * @description Orchestrates parallel update checks for all package sources. Displays
 * progress and aggregates update counts from all sources.
 * @param {Array<Object>} apps - Array of scanned app objects to check for updates
 * @param {Object} config - Configuration object with performance settings
 * @returns {Promise<number>} Total number of packages with available updates
 */
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
    ['rust', () => checkRustUpdates(apps, timeoutMs)],
    ['scoop', () => checkScoopUpdates(apps, timeoutMs)],
    ['dotnet', () => checkDotnetUpdates(apps, timeoutMs)],
  ];

  const progress = createProgress(checks.length, `${emoji('update')} Checking updates`);
  await writeLog('update check started');

  const counts = await Promise.all(checks.map(async ([source, fn]) => {
    try {
      const count = await fn();
      const msg = `${sourceBadge(source)} ${count > 0 ? paint(`${count} update(s)`, ANSI.yellow, ANSI.bold) : paint('none', ANSI.gray)}`;
      progress.tick(msg);
      if (count > 0) await writeLog(`update check: source=${source}, updates=${count}`);
      return count;
    } catch (err) {
      await writeLog(`update check error: source=${source}, error=${err.message}`);
      return 0;
    }
  }));
  progress.done(paint(`${emoji('ok')} update checks complete`, ANSI.green));

  finalizeStatuses(apps);
  const total = counts.reduce((sum, n) => sum + n, 0);
  await writeLog(`update check complete: total_updates=${total}`);
  return total;
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check for security vulnerabilities across all supported package sources
 * @description Orchestrates vulnerability scanning for NPM and PIP packages. Filters
 * results by configured severity threshold and updates app statuses for vulnerable packages.
 * @param {Array<Object>} apps - Array of scanned app objects to check for vulnerabilities
 * @param {Object} config - Configuration object with security settings
 * @returns {Promise<Array<Object>>} Array of vulnerability objects above severity threshold
 */
async function checkSecurityVulnerabilities(apps, config) {
  if (!config.security?.enabled) return [];
  await writeLog(`security analysis started: threshold=${config.security.severityThreshold}`);

  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  const vulnerabilities = [];
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const threshold = severityOrder[config.security.severityThreshold || 'medium'] || 2;

  const npmVulns = await checkNpmVulnerabilities(apps, timeoutMs);
  const pipVulns = await checkPipVulnerabilities(apps, timeoutMs);
  const osvVulns = await checkOsvVulnerabilities(apps, timeoutMs);

  await writeLog(`security check: npm_found=${npmVulns.length}, pip_found=${pipVulns.length}, osv_found=${osvVulns.length}`);

  for (const vuln of [...npmVulns, ...pipVulns, ...osvVulns]) {
    const severityLevel = severityOrder[vuln.severity.toLowerCase()] || 1;
    if (severityLevel >= threshold) {
      vulnerabilities.push(vuln);
      const app = apps.find((a) => a.name.toLowerCase() === vuln.packageName.toLowerCase());
      if (app) {
        app.status = Status.VULNERABLE;
      }
    }
  }

  if (vulnerabilities.length > 0) {
    await writeLog(`security warning: detected ${vulnerabilities.length} vulnerabilities above threshold`);
  } else {
    await writeLog('security check: clean');
  }

  return vulnerabilities;
}

/**
 * Check for NPM package security vulnerabilities
 * @description Executes npm audit --json command and parses vulnerability data. Extracts
 * CVE, severity, and description for each vulnerable package.
 * @param {Array<Object>} apps - Array of scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of vulnerability objects for NPM packages
 */
async function checkNpmVulnerabilities(apps, timeoutMs) {
  const npmApps = apps.filter((a) => a.source === 'npm');
  if (!npmApps.length) return [];
  await writeLog('checking npm vulnerabilities');

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

/**
 * Check for Python PIP package security vulnerabilities
 * @description Executes pip check --format=json command and parses vulnerability data.
 * Extracts CVE, severity, and description for each vulnerable package.
 * @param {Array<Object>} apps - Array of scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<Array<Object>>} Array of vulnerability objects for PIP packages
 */
async function checkPipVulnerabilities(apps, timeoutMs) {
  const pipApps = apps.filter((a) => a.source === 'pip');
  if (!pipApps.length) return [];
  await writeLog('checking pip vulnerabilities');

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

const OSV_ECOSYSTEM_MAP = {
  npm: 'npm',
  pip: 'PyPI',
  pypi: 'PyPI',
  cargo: 'crates.io',
  rust: 'crates.io',
  gem: 'RubyGems',
  ruby: 'RubyGems',
  go: 'Go',
  cocoapods: 'CocoaPods',
  hex: 'Hex',
};

/**
 * Check for vulnerabilities using Google's OSV API
 * @description Queries the OSV.dev vulnerability database for packages in supported ecosystems.
 * @param {Array<Object>} apps - Array of scanned app objects
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise<Array<Object>>} Array of vulnerability objects from OSV
 */
async function checkOsvVulnerabilities(apps, timeoutMs) {
  const vulnerabilities = [];
  const uniqueApps = new Map();
  for (const app of apps) {
    if (!uniqueApps.has(app.name.toLowerCase())) {
      uniqueApps.set(app.name.toLowerCase(), app);
    }
  }

  for (const [, app] of uniqueApps) {
    const ecosystem = OSV_ECOSYSTEM_MAP[app.source.toLowerCase()];
    if (!ecosystem || !app.version) continue;

    try {
      const response = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: { name: app.name, ecosystem },
          version: app.version,
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) continue;
      const data = await response.json();

      for (const vuln of (data.vulns || [])) {
        let severity = 'MEDIUM';
        if (vuln.severity) {
          for (const s of vuln.severity) {
            if (s.type === 'cvss_v3') {
              severity = String(s.score || 'MEDIUM');
              break;
            }
          }
        } else if (vuln.database_specific?.severity) {
          severity = vuln.database_specific.severity;
        }

        vulnerabilities.push({
          packageName: app.name,
          severity: severity.toUpperCase(),
          cve: vuln.id || 'N/A',
          description: (vuln.summary || '').slice(0, 200),
          appInfo: app,
        });
      }
    } catch {
      // Continue to next package on error
    }
  }

  return vulnerabilities;
}

// ─────────────────────────────────────────────────────────────────────────────
// UI UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Truncate text to specified length with ellipsis
 * @description Shortens a string to fit within a maximum character limit, adding an
 * ellipsis character if truncation occurs. Handles null/undefined values.
 * @param {string} value - Value to truncate
 * @param {number} size - Maximum character length
 * @returns {string} Truncated string or original if within limit
 */
function truncate(value, size) {
  const text = String(value ?? '');
  return text.length <= size ? text : `${text.slice(0, size - 1)}…`;
}

/**
 * Remove ANSI escape codes from text
 * @description Strips all ANSI color/formatting codes from a string, returning plain text.
 * Useful for calculating visible string length or logging.
 * @param {string} text - Text potentially containing ANSI codes
 * @returns {string} Text with ANSI codes removed
 */
function stripAnsi(text) {
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

/**
 * Pad text to specified width accounting for ANSI codes
 * @description Pads text to a target width while correctly handling ANSI escape codes
 * by measuring only visible characters.
 * @param {string} text - Text to pad (may contain ANSI codes)
 * @param {number} width - Target visible width
 * @returns {string} Padded text with correct visible width
 */
function padAnsi(text, width) {
  const visibleLength = stripAnsi(text).length;
  const padding = Math.max(0, width - visibleLength);
  return text + ' '.repeat(padding);
}

/**
 * Display formatted table of installed packages
 * @description Renders a formatted table showing package name, source, current version,
 * latest version, and status. Filters to show only updates/vulnerabilities unless showAll is true.
 * @param {Array<Object>} apps - Array of app objects to display
 * @param {boolean} [showAll=false] - Whether to show all packages or only those with updates
 */
function printAppsTable(apps, showAll = false) {
  writeLog(`printing apps table: count=${apps.length}, showAll=${showAll}`);

  // Filter apps: by default show only updates, unless showAll is true
  const displayApps = showAll ? apps : apps.filter((a) => a.status === Status.UPDATE_AVAILABLE || a.status === Status.VULNERABLE);

  const cols = [
    { key: 'name', title: 'Package', width: 30 },
    { key: 'source', title: 'Source', width: 12 },
    { key: 'version', title: 'Current', width: 20 },
    { key: 'latestVersion', title: 'Latest', width: 20 },
    { key: 'status', title: 'Status', width: 17 },
  ];

  const header = cols.map((c) => paint(c.title.padEnd(c.width), ANSI.bold, ANSI.cyan)).join('  ');
  console.log(header);
  const visibleWidth = stripAnsi(header).length;
  const terminalWidth = process.stdout.columns || 100;
  const lineWidth = Math.min(visibleWidth, terminalWidth);
  console.log(paint('─'.repeat(lineWidth), ANSI.gray));

  for (const app of displayApps) {
    const row = cols
      .map((c) => {
        // Latest column: show "-" when up-to-date, yellow bold when update available
        if (c.key === 'latestVersion') {
          if (app.status === Status.UP_TO_DATE) {
            return '-'.padEnd(c.width);
          }
          if (app.status === Status.UPDATE_AVAILABLE) {
            return padAnsi(paint(truncate(app.latestVersion || '-', c.width), ANSI.yellow, ANSI.bold), c.width);
          }
          return truncate(app.latestVersion || '-', c.width).padEnd(c.width);
        }
        const raw = truncate(app[c.key] || '-', c.width);
        if (c.key === 'source') return padAnsi(sourceBadge(raw), c.width);
        if (c.key === 'status') return padAnsi(statusBadge(app.status), c.width);
        if (c.key === 'name') return padAnsi(paint(raw, ANSI.bold), c.width);
        return raw.padEnd(c.width);
      })
      .join('  ');
    console.log(row);
  }
}

/**
 * Display formatted table of security vulnerabilities
 * @description Renders a formatted table showing vulnerable packages with their severity,
 * CVE identifier, and description. Uses color coding based on severity level.
 * @param {Array<Object>} vulnerabilities - Array of vulnerability objects to display
 */
function printSecurityTable(vulnerabilities) {
  if (!vulnerabilities.length) return;
  writeLog(`printing security table: count=${vulnerabilities.length}`);

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

// ─────────────────────────────────────────────────────────────────────────────
// DATA EXPORT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convert value to CSV-safe cell string
 * @description Escapes a value for CSV format, wrapping in quotes and escaping internal
 * quotes if the value contains commas, quotes, or newlines.
 * @param {string} val - Value to convert
 * @returns {string} CSV-safe cell string
 */
function toCsvCell(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

/**
 * Export scan results to file in specified format
 * @description Writes scan results to disk in JSON or CSV format. Generates timestamped
 * filename if output path not specified.
 * @param {Array<Object>} apps - Array of app objects to export
 * @param {string} format - Export format ('json' or 'csv')
 * @param {string} [output] - Optional output file path
 * @returns {Promise<string>} Path to the exported file
 * @throws {Error} If unsupported export format is specified
 */
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

  await writeLog(`export failed: unsupported format ${format}`);
  throw new Error(`Unsupported export format: ${format}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// USER INTERACTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Prompt user for confirmation with yes/no answer
 * @description Displays a confirmation message and waits for user input. Automatically
 * returns true if yes flag is set (non-interactive mode).
 * @param {string} message - Confirmation message to display
 * @param {boolean} yes - If true, skip prompt and return true
 * @returns {Promise<boolean>} True if user confirms, false otherwise
 */
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

/**
 * Normalize source name to lowercase string
 * @description Safely converts source value to lowercase string, handling null/undefined.
 * @param {string} source - Source name to normalize
 * @returns {string} Normalized lowercase source name
 */
function sourceName(source) {
  return String(source || '').toLowerCase();
}

const SOURCE_ALIASES = Object.freeze({
  choco: 'chocolatey',
});

function normalizeSource(source) {
  const key = sourceName(source).trim();
  return SOURCE_ALIASES[key] || key;
}

function parseIncludeSources(includeValue) {
  return String(includeValue || '')
    .split(',')
    .map((s) => normalizeSource(s))
    .filter(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────────
// UPDATE EXECUTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute update for a single package
 * @description Determines the correct update command based on package source and executes
 * the update. Supports dry-run mode for previewing commands without execution.
 * @param {Object} app - App object with name, source, appId, and latestVersion
 * @param {boolean} dryRun - If true, only log the command without executing
 * @param {number} timeoutMs - Timeout in milliseconds for the command execution
 * @returns {Promise<boolean>} True if update succeeded (or dry-run), false on failure
 */
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
  } else if (src === 'rust') {
    command = 'cargo';
    args = ['install-update', app.name];
  } else if (src === 'dotnet') {
    command = 'dotnet';
    args = ['tool', 'update', '-g', app.name];
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
    await writeLog(`update failed: ${app.name} (${app.source}) code=${result.code} stderr=${result.stderr}`);
  } else {
    await writeLog(`update ok: ${app.name} (${app.source})`);
  }
  return result.ok;
}

/**
 * Execute updates for multiple packages with progress tracking
 * @description Iterates through apps with updates and executes update for each one.
 * Displays progress bar and summary of successful/failed updates.
 * @param {Array<Object>} apps - Array of app objects to update
 * @param {Object} args - Parsed command line arguments with dryRun and yes flags
 * @param {Object} config - Configuration object with performance settings
 * @returns {Promise<void>}
 */
async function executeUpdates(apps, args, config) {
  const timeoutMs = Number(config.performance.timeoutSeconds || 45) * 1000;
  let success = 0;
  const progress = createProgress(apps.length, `${emoji('gear')} Applying updates`);
  await writeLog(`update execution started: count=${apps.length}, dry_run=${args.dryRun}`);

  for (const app of apps) {
    const label = `${app.name} (${app.source})`;
    const ok = await executeSingleUpdate(app, args.dryRun, timeoutMs);
    if (ok) {
      success += 1;
      progress.tick(`${paint(emoji('ok'), ANSI.green)} ${paint(label, ANSI.bold)}`);
      await writeLog(`update success: package=${app.name}, source=${app.source}`);
    } else {
      progress.tick(`${paint(emoji('fail'), ANSI.red)} ${paint(label, ANSI.bold)}`);
      await writeLog(`update failed: package=${app.name}, source=${app.source}`);
    }
  }

  progress.done(paint(`${emoji('sparkle')} finished`, ANSI.cyan));
  console.log(`\n${emoji('chart')} Completed: ${paint(`${success}/${apps.length}`, ANSI.bold)} successful.`);
  await writeLog(`update execution finished: successful=${success}/${apps.length}`);
}

/**
 * Find packages matching name and optional source filter
 * @description Searches through apps to find matches by package name with optional
 * source filtering. Case-insensitive matching.
 * @param {Array<Object>} apps - Array of app objects to search
 * @param {string} packageName - Package name to find (case-insensitive)
 * @param {string} [source] - Optional source filter (case-insensitive)
 * @returns {Array<Object>} Array of matching app objects
 */
function selectPackage(apps, packageName, source) {
  const wanted = String(packageName).toLowerCase();
  const filtered = apps.filter((a) => {
    if (String(a.name).toLowerCase() !== wanted) return false;
    if (source && String(a.source).toLowerCase() !== source) return false;
    return true;
  });
  return filtered;
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Main entry point for the System Update CLI
 * @description Orchestrates the complete system update workflow: parses arguments,
 * initializes configuration, scans for packages, checks for updates, performs security
 * analysis, displays results, and executes updates based on user options.
 * @returns {Promise<void>}
 */
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

  const config = await loadConfig();
  await ensureConfigDir();
  LOGGING_ENABLED = args.log;
  DEBUG_ENABLED = args.debug;
  await writeLog(`session start: v${VERSION}, platform=${process.platform}, node=${process.version}`);
  await writeLog(`args: ${process.argv.slice(2).join(' ')}`);

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
  let securityFindings = [];

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
      securityFindings = await checkSecurityVulnerabilities(apps, config);
      if (securityFindings.length) {
        console.log(`${emoji('fire')} ${paint(`Found ${securityFindings.length} security vulnerabilities.`, ANSI.bold, ANSI.red)}\n`);
      } else {
        console.log(`${emoji('shield')} ${paint('No security vulnerabilities found.', ANSI.green)}\n`);
      }
    }

    await saveCache(apps);
  }

  if (args.source) {
    const requestedSource = normalizeSource(args.source);
    apps = apps.filter((a) => String(a.source).toLowerCase() === requestedSource);
  }
  if (args.include) {
    const includedSources = parseIncludeSources(args.include);
    apps = apps.filter((a) => includedSources.includes(String(a.source).toLowerCase()));
  }

  const appsWithUpdates = apps.filter((a) => a.status === Status.UPDATE_AVAILABLE);
  const appsWithVulnerabilities = apps.filter((a) => a.status === Status.VULNERABLE);
  const displayApps = args.showAll ? apps : appsWithUpdates.concat(appsWithVulnerabilities);
  const bySource = apps.reduce((acc, a) => {
    acc[a.source] = (acc[a.source] || 0) + 1;
    return acc;
  }, {});

  console.log(paint(`\n${emoji('chart')} Summary`, ANSI.bold, ANSI.magenta));
  console.log(`${emoji('package')} total apps      ${paint(String(apps.length), ANSI.bold)}`);
  console.log(`${emoji('update')} updates         ${paint(String(appsWithUpdates.length), appsWithUpdates.length ? ANSI.yellow : ANSI.green, ANSI.bold)}`);
  console.log(`${emoji('hourglass')} scan duration   ${paint(`${((Date.now() - start) / 1000).toFixed(2)}s`, ANSI.bold)}`);
  console.log(`${emoji('gear')} sources         ${Object.entries(bySource).map(([s, n]) => `${sourceBadge(s)}:${paint(String(n), ANSI.bold)}`).join(', ')}`);
  console.log('');

  printAppsTable(apps, args.showAll);

  // Display showing status after table (matching desired format)
  if (args.showAll) {
    console.log(`\n${emoji('disk')} Showing: all packages`);
  } else {
    console.log(`\n${emoji('disk')} Showing: updates only`);
  }

  if (securityFindings.length && config.security?.enabled) {
    printSecurityTable(securityFindings);
  }

  // Display found updates message after table
  if (!args.packageName && !args.updateSource && !args.updateAll) {
    if (!appsWithUpdates.length) {
      console.log(`\n${emoji('sparkle')} ${paint('System is up to date!', ANSI.green)}`);
    } else {
      console.log(`\n${emoji('target')} ${paint(`Found ${appsWithUpdates.length} available updates`, ANSI.yellow, ANSI.bold)}`);
    }
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
    await writeLog(`export: format=${args.export}, file=${file}`);
  }

  if (securityFindings.length > 0) {
    process.exitCode = 20;
  } else if (appsWithUpdates.length > 0) {
    process.exitCode = 10;
  } else {
    process.exitCode = 0;
  }

  await writeLog(`session end: duration=${((Date.now() - start) / 1000).toFixed(2)}s`);
}

main().catch(async (err) => {
  await writeLog(`fatal: ${err?.stack || err}`);
  console.error(`Fatal error: ${err?.message || err}`);
  process.exitCode = 1;
});