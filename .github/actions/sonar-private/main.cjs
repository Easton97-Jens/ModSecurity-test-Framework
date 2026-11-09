'use strict';
// This executable must be loaded by GitHub from a previously reviewed immutable
// remote action commit. A token-bearing PR-head local action is forbidden.
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
// Ubuntu hosted runners provide system Git here; never resolve workspace PATH.
const GIT = '/usr/bin/git';
const MAX_LOG = 128 * 1024 * 1024;
const MAX_LINE = 65536;
const MAX_FACTS = 10000;
const FILE_FAILURE_INDEX = new WeakMap();
const LINE_MARKERS = Object.freeze({
  parsing: '[ParsingError]', cannotParse: 'Cannot parse',
  documentLimit: 'The incoming YAML document exceeds the limit:',
  cfamilyVersion: 'CFamily plugin version:',
  snakeEngine: 'org.snakeyaml.engine.v2.exceptions.YamlEngineException:',
  snakeClassic: 'org.yaml.snakeyaml.error.YAMLException:',
});
const SNAKE_ENGINE = 'org.snakeyaml.engine.v2.exceptions.YamlEngineException: ';
const SNAKE_CLASSIC = 'org.yaml.snakeyaml.error.YAMLException: ';
const MAX_COUNTER = 2147483647;
const SHA = /^[a-f0-9]{40}$/;
const FIXTURE = 'cfd5e49cada3fc793ef50993147e3796a0907443';
const ENV_KEYS = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'RUNNER_TEMP',
  'RUNNER_TOOL_CACHE', 'RUNNER_OS', 'RUNNER_ARCH', 'CI', 'GITHUB_ACTIONS',
  'GITHUB_ACTION', 'GITHUB_WORKSPACE', 'GITHUB_EVENT_NAME', 'GITHUB_EVENT_PATH',
  'GITHUB_REF', 'GITHUB_REF_NAME', 'GITHUB_HEAD_REF', 'GITHUB_BASE_REF',
  'GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_OWNER', 'GITHUB_RUN_ID',
  'GITHUB_RUN_NUMBER', 'GITHUB_SERVER_URL', 'GITHUB_API_URL'];
function demand(value) { if (!value) throw new Error('invalid diagnostic boundary'); }
function realDirectory(value) {
  demand(typeof value === 'string' && path.isAbsolute(value));
  demand(fs.realpathSync(value) === path.resolve(value) && fs.lstatSync(value).isDirectory());
  return value;
}
function privateFile(directory, name) {
  return fs.openSync(path.join(directory, name), fs.constants.O_WRONLY |
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
}
function privateEnv(original, directory, authentication = false) {
  const result = {};
  for (const key of ENV_KEYS) if (original[key] !== undefined) result[key] = original[key];
  result.GIT_CONFIG_NOSYSTEM = '1';
  result.GIT_CONFIG_GLOBAL = '/dev/null';
  result.GIT_TERMINAL_PROMPT = '0';
  for (const key of ['GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_OUTPUT', 'GITHUB_STATE', 'GITHUB_STEP_SUMMARY']) {
    const name = `${authentication ? 'scanner' : 'bootstrap'}-${key}`;
    fs.closeSync(privateFile(directory, name));
    result[key] = path.join(directory, name);
  }
  if (authentication) {
    demand(typeof original.SONAR_TOKEN === 'string' && original.SONAR_TOKEN.length > 0);
    result.SONAR_TOKEN = original.SONAR_TOKEN;
    result.SONAR_USER_HOME = original.SONAR_USER_HOME;
  }
  return result;
}
function runCaptured(command, args, descriptor, env, options = {}) {
  return new Promise((resolve, reject) => {
    let child, killTimer;
    let failed = false;
    // The same descriptor captures bootstrap and scanner children. The limit
    // applies to the complete raw file, never separately to each child.
    let size = fs.fstatSync(descriptor).size;
    const kill = signal => {
      try { if (Number.isInteger(child?.pid)) process.kill(-child.pid, signal); } catch {}
    };
    const stop = () => {
      failed = true;
      kill('SIGTERM');
      killTimer ??= setTimeout(() => kill('SIGKILL'), 1000);
    };
    try {
      child = spawn(command, args, {env, cwd: options.cwd, detached: true,
        stdio: ['ignore', 'pipe', 'pipe']});
    } catch { reject(new Error('captured child failed')); return; }
    const timer = setTimeout(stop, options.timeout ?? 40 * 60 * 1000);
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    const copy = chunk => {
      size += chunk.length;
      if (size > (options.limit ?? MAX_LOG)) { stop(); return; }
      try { fs.writeSync(descriptor, chunk); } catch { stop(); }
    };
    child.stdout.on('data', copy);
    child.stderr.on('data', copy);
    child.on('error', () => { failed = true; });
    child.on('close', (code, signal) => {
      // Descendants may close stdio and outlive an otherwise successful leader.
      kill('SIGKILL');
      clearTimeout(timer);
      clearTimeout(killTimer);
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
      if (failed || signal || !Number.isInteger(code)) reject(new Error('captured child failed'));
      else resolve(code);
    });
  });
}
async function withPrivateRun(temporaryRoot, callback) {
  realDirectory(temporaryRoot);
  const directory = fs.mkdtempSync(path.join(temporaryRoot, 'sonar-private-'));
  fs.chmodSync(directory, 0o700);
  try { return await callback(directory); }
  finally { fs.rmSync(directory, {recursive: true, force: true}); }
}
function privateCacheArguments(args, directory) {
  realDirectory(directory);
  // The pinned upstream action tokenizes args. Do not invent quoting rules.
  demand(/^[\w./+-]+$/.test(directory));
  demand(!args.includes('sonar.cfamily.analysisCache.'));
  const cache = path.join(directory, 'cfamily-analysis-cache');
  fs.mkdirSync(cache, {mode: 0o700});
  demand(realDirectory(cache) === cache && fs.readdirSync(cache).length === 0);
  demand((fs.statSync(cache).mode & 0o777) === 0o700);
  return args + ' -Dsonar.cfamily.analysisCache.mode=fs' +
    ` -Dsonar.cfamily.analysisCache.path=${cache}`;
}
function gitOutput(root, args, env) {
  return execFileSync(GIT, ['-c', 'credential.helper=', '-C', root, ...args], {
    env, encoding: 'utf8', timeout: 15000, maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']});
}
function inventory(root, revision, role, env) {
  realDirectory(root);
  demand(SHA.test(revision) && gitOutput(root, ['rev-parse', 'HEAD'], env).trim() === revision);
  demand(gitOutput(root, ['status', '--porcelain=v1', '--untracked-files=all'], env) === '');
  const result = new Map();
  result.roots = [root];
  for (const relative of gitOutput(root, ['ls-files', '-z'], env).split('\0')) {
    if (!relative || relative.length > 512 || !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(relative) ||
        relative.split('/').some(part => part === '.' || part === '..')) continue;
    const absolute = path.join(root, relative);
    if (!fs.existsSync(absolute) || !fs.lstatSync(absolute).isFile() || fs.realpathSync(absolute) !== absolute) continue;
    const fact = {repository: role, path: relative};
    result.set(absolute, fact);
    if (role !== 'product_fixture') result.set(relative, fact);
  }
  return result;
}
function staysWithinRoot(relative) {
  let depth = 0;
  for (const part of relative.split('/')) {
    if (part === '..') {
      depth--;
      if (depth < 0) return false;
    } else if (part !== '' && part !== '.') depth++;
  }
  return true;
}
function sourceLocation(raw, sources) {
  if (/[\x00-\x1f\x7f]/.test(raw)) return undefined;
  if (sources.has(raw)) return sources.get(raw);
  if (!path.posix.isAbsolute(raw)) return undefined;
  for (const root of sources.roots ?? []) {
    if (!raw.startsWith(root + '/')) continue;
    if (!staysWithinRoot(raw.slice(root.length + 1))) return undefined;
    return sources.get(path.posix.normalize(raw));
  }
  return undefined;
}
function emptyDiagnostics() {
  return {schema: 'private-sonar-diagnostics-v2', diagnosis_complete: false,
    warnings: {total: 0, parse: 0, invalid_location: 0, signature_trust: 0, unmapped: 0},
    errors: {total: 0, unmapped: 0}, parser_lines: 0, unmapped_parser_lines: 0,
    overlong_lines: 0, facts_truncated: 0, unmapped_counters: 0, locations: [], file_failures: [], counters: {},
    signals: {document_limits: [], llvm_errors: 0, top_level_drops: null, ir_methods: null, unmapped: 0},
    cfamily_version: null, cfamily_version_status: 'NOT_OBSERVED',
    visibility: {version_unmapped: 0, decoder_loss_lines: 0,
      overlong_markers: Object.fromEntries(Object.keys(LINE_MARKERS).map(key => [key, 0])),
      exception_classes: {SNAKEYAML_ENGINE: 0, SNAKEYAML_CLASSIC: 0},
      context_resets: {}, document_binding_reasons: {}}};
}
function boundedCounter(raw, grouping = false) {
  if (typeof raw !== 'string' || !(grouping ? /^(?:\d+|\d{1,3}(?:,\d{3})+)$/.test(raw) : /^\d+$/.test(raw))) return null;
  const value = Number(raw.replaceAll(',', ''));
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_COUNTER ? value : null;
}
function recordDocumentLimit(result, line, binding, reason) {
  const budget = line.match(/The incoming YAML document exceeds the limit: (\d{1,10}) code points\./);
  if (budget) {
    const limit = boundedCounter(budget[1]);
    if (limit !== null && limit > 0) {
      const reasons = result.visibility.document_binding_reasons;
      reasons[reason] = (reasons[reason] ?? 0) + 1;
      const identity = binding ? {...binding, source_binding: 'INVENTORY'} : {source_binding: 'UNBOUND'};
      const found = result.signals.document_limits.find(item => item.limit === limit &&
        item.source_binding === identity.source_binding && item.repository === identity.repository && item.path === identity.path);
      if (found) found.occurrences++;
      else if (result.signals.document_limits.length < 8) result.signals.document_limits.push({
        category: 'DOCUMENT_CODEPOINT_LIMIT', limit, occurrences: 1, ...identity});
      else result.signals.unmapped++;
    } else result.signals.unmapped++;
  }
}
function recordDroppedDeclarations(result, line) {
  const dropped = line.match(/Top-level declarations dropped decoding, encoding: (\d+), (\d+)\s*$/);
  if (dropped) {
    const values = dropped.slice(1).map(value => boundedCounter(value));
    if (values.every(value => value !== null)) result.signals.top_level_drops = {decoding: values[0], encoding: values[1]};
    else result.unmapped_counters++;
  } else if (line.includes('Top-level declarations dropped decoding, encoding:')) result.unmapped_counters++;
}
function recordIrMethods(result, line) {
  const methods = line.match(/IR generation: ([0-9,]+) skipped out of ([0-9,]+) total methods\s*$/);
  if (methods) {
    const values = methods.slice(1).map(value => boundedCounter(value, true));
    if (values.every(value => value !== null) && values[0] <= values[1]) {
      result.signals.ir_methods = {skipped: values[0], total: values[1]};
    } else result.unmapped_counters++;
  } else if (line.includes('IR generation:') && line.includes('total methods')) result.unmapped_counters++;
}
function scannerPayload(line) {
  const transport = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,9}Z /.exec(line);
  let text = transport ? line.slice(transport[0].length) : line;
  const timestamp = /^\d{2}:\d{2}:\d{2}\.\d{3} /.exec(text);
  if (timestamp) text = text.slice(timestamp[0].length);
  const level = /^(?:INFO|DEBUG|WARN|ERROR):? +/.exec(text);
  if (level) text = text.slice(level[0].length);
  return text.replace(/\r?\n$/, '');
}
function recordCFamilyVersion(result, line) {
  const text = scannerPayload(line);
  const prefix = 'CFamily plugin version: ';
  if (!text.startsWith(prefix)) return;
  const value = text.slice(prefix.length);
  if (!/^\d{1,6}(?:\.\d{1,6}){3}$/.test(value)) {
    result.visibility.version_unmapped++;
    return;
  }
  if (result.cfamily_version_status === 'CONFLICT') return;
  if (result.cfamily_version !== null && result.cfamily_version !== value) {
    result.cfamily_version = null;
    result.cfamily_version_status = 'CONFLICT';
    return;
  }
  result.cfamily_version = value;
  result.cfamily_version_status = 'OBSERVED';
}
function recordSignals(result, line, binding, reason) {
  if (line.includes('LLVM ERROR')) result.signals.llvm_errors++;
  recordDocumentLimit(result, line, binding, reason);
  recordCFamilyVersion(result, line);
  const exception = snakeExceptionClass(line);
  if (exception) result.visibility.exception_classes[exception]++;
  recordDroppedDeclarations(result, line);
  recordIrMethods(result, line);
  const mode = line.match(/CFamily analysis configuration mode: (AutoConfig|Compile-Commands)/i);
  if (mode) result.observed_cfamily_mode = mode[1].toLowerCase() === 'autoconfig' ? 'AUTO_CONFIG' : 'COMPILE_COMMANDS';
}
function diagnosticCategory(message) {
  if (/file not found|No such file or directory|cannot open.*include/i.test(message)) return 'MISSING_INCLUDE';
  if (/unknown type name/i.test(message)) return 'UNKNOWN_TYPE';
  if (/undeclared identifier|not declared in this scope/i.test(message)) return 'UNDECLARED_IDENTIFIER';
  if (/expected /i.test(message)) return 'EXPECTED_TOKEN';
  return 'OTHER_PARSE';
}
// Search fixed delimiters and inspect only their preceding digit runs. This
// avoids retrying an unanchored digit quantifier on every nonmatching digit.
function precedingDigits(line, marker) {
  let offset = 0;
  let end;
  while ((end = line.indexOf(marker, offset)) !== -1) {
    let start = end;
    while (start > 0 && /\d/.test(line[start - 1])) start--;
    if (start < end) return line.slice(start, end);
    offset = end + marker.length;
  }
  return null;
}
function recordSeverity(result, line, flags) {
  const warning = flags.warning ?? /\bWARN(?:ING)?\b/i.test(line);
  const error = flags.error ?? /\bERROR\b/i.test(line);
  if (warning) {
    result.warnings.total++;
    if (flags.truncated) result.warnings.unmapped++;
    else if (/Cannot parse/.test(line)) result.warnings.parse++;
    else if (/Dropping internal\.debug finding: primary location/.test(line)) result.warnings.invalid_location++;
    else if (/gpg: WARNING:/.test(line)) result.warnings.signature_trust++;
    else result.warnings.unmapped++;
  }
  if (error) { result.errors.total++; result.errors.unmapped++; }
}
function recordCounters(result, line) {
  for (const [label, marker] of [
    ['full_translation_units', ' compilation units were fully analyzed'],
    ['partial_translation_units', ' compilation units were partially analyzed'],
  ]) {
    const raw = precedingDigits(line, marker);
    if (raw === null) continue;
    const value = boundedCounter(raw);
    if (value === null) result.unmapped_counters++;
    else result.counters[label] = value;
  }
  const ratio = line.match(/of (functions|statements) were parsed successfully \((\d+) out of (\d+) have parsing errors\)/);
  if (ratio) {
    const errors = boundedCounter(ratio[2]);
    const total = boundedCounter(ratio[3]);
    if (errors === null || total === null || errors > total) result.unmapped_counters++;
    else result.counters[ratio[1]] = {errors, total};
  }
}
function recordParserLocation(result, line, sources, parsing, cannotParse, fileFailure) {
  if (!parsing && !cannotParse) return;
  if (parsing) result.parser_lines++;
  if (!parsing && fileFailure) return;
  const payload = parsing ? line.split('[ParsingError]').slice(1).join('[ParsingError]').trim() :
    line.slice(line.indexOf('Cannot parse') + 'Cannot parse'.length).trim();
  const match = payload.match(/^'?(.+?):(\d+)(?::(\d+))?(?:[':\s]|$)(.*)$/);
  const fact = match && sourceLocation(match[1], sources);
  const lineNumber = match && Number(match[2]);
  const column = match?.[3] ? Number(match[3]) : 0;
  if (!fact || !Number.isSafeInteger(lineNumber) || lineNumber < 1 || lineNumber > 10000000 ||
      !Number.isSafeInteger(column) || column < 0 || column > 1000000) { result.unmapped_parser_lines++; return; }
  if (result.locations.length >= MAX_FACTS) { result.facts_truncated++; return; }
  result.locations.push({...fact, line: lineNumber, column,
    category: parsing ? diagnosticCategory(match[4]) : 'CANNOT_PARSE', translation_unit: 'UNKNOWN'});
}
function fileOnlyFailure(line, sources) {
  // Only a complete, unambiguous warning envelope establishes a file identity.
  // The optional ISO timestamp is the outer hosted-log transport timestamp.
  const transport = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,9}Z /.exec(line);
  const message = transport ? line.slice(transport[0].length) : line;
  const logger = /^\d{2}:\d{2}:\d{2}\.\d{3} WARN +Cannot parse /.exec(message);
  if (!logger) return undefined;
  const match = /^'([^'\r\n]+)'\.?[ \t]*\r?\n?$/.exec(message.slice(logger[0].length));
  return match && sourceLocation(match[1], sources);
}
function recordFileFailure(result, fact) {
  let index = FILE_FAILURE_INDEX.get(result);
  if (!index) { index = new Map(); FILE_FAILURE_INDEX.set(result, index); }
  const key = fact.repository + '\0' + fact.path;
  const found = index.get(key);
  if (found) found.occurrences++;
  else if (result.file_failures.length < MAX_FACTS) {
    const entry = {...fact, category: 'CANNOT_PARSE', occurrences: 1};
    result.file_failures.push(entry);
    // Index only retained facts: overflow identities never consume index space.
    index.set(key, entry);
  }
  else result.facts_truncated++;
}
function snakeExceptionClass(line) {
  let text = line.trimStart();
  if (text.startsWith('Caused by: ')) text = text.slice('Caused by: '.length);
  // Prospective Java exception headers, not a claim about a hosted run's format.
  if (text.startsWith(SNAKE_ENGINE)) return 'SNAKEYAML_ENGINE';
  if (text.startsWith(SNAKE_CLASSIC)) return 'SNAKEYAML_CLASSIC';
  return null;
}
function snakeExceptionHeader(line) {
  if (!snakeExceptionClass(line)) return null;
  return line.trimStart().startsWith('Caused by: ') ? 'CAUSED_BY' : 'ROOT';
}
function javaStackContinuation(line) {
  const text = line.replace(/\r?\n$/, '');
  return /^[ \t]+at [\w.$/<>]+\((?:[\w$.-]+\.java:\d+|Unknown Source|Native Method)\)$/.test(text) ||
    /^[ \t]+\.\.\. \d{1,6} more$/.test(text);
}
function documentBudgetReason(candidate) {
  if (candidate.lines > 32) return 'CONTEXT_LINE_LIMIT';
  if (candidate.bytes > 16384) return 'CONTEXT_BYTE_LIMIT';
  return null;
}
function resetDocumentContext(result, state, reason) {
  if (state.candidate) {
    const resets = result.visibility.context_resets;
    resets[reason] = (resets[reason] ?? 0) + 1;
  }
  state.candidate = null;
  state.reason = reason;
}
function interruptedDocumentReason(line, header) {
  if (header) return 'EXCEPTION_ORDER';
  if (scannerPayload(line) !== line.replace(/\r?\n$/, '')) return 'NEW_LOG_EVENT';
  return 'UNSUPPORTED_OR_INTERLEAVED_EVENT';
}
function advanceDocumentContext(result, line, fact, state) {
  state.reason = 'NO_ACTIVE_FILE_EVENT';
  if (fact) {
    state.candidate = {fact, lines: 1, bytes: Buffer.byteLength(line, 'utf8'), exception: false};
    return undefined;
  }
  const candidate = state.candidate;
  if (!candidate) return undefined;
  candidate.lines++;
  candidate.bytes += Buffer.byteLength(line, 'utf8');
  const budgetReason = documentBudgetReason(candidate);
  if (budgetReason) {
    resetDocumentContext(result, state, budgetReason);
    return undefined;
  }
  const header = snakeExceptionHeader(line);
  if (header === (candidate.exception ? 'CAUSED_BY' : 'ROOT')) {
    candidate.exception = true;
    state.reason = 'VERIFIED_CONTIGUOUS_EVENT';
    return candidate.fact;
  }
  if (header || !candidate.exception || !javaStackContinuation(line)) {
    resetDocumentContext(result, state, interruptedDocumentReason(line, header));
  }
  return undefined;
}
function recordTruncatedLine(result, line, flags, parsing, cannotParse) {
  for (const [key, marker] of Object.entries(LINE_MARKERS)) {
    if (flags[key] ?? line.includes(marker)) result.visibility.overlong_markers[key]++;
  }
  if (parsing) result.parser_lines++;
  if (parsing || cannotParse) result.unmapped_parser_lines++;
}
function acceptLine(result, line, sources, flags = {}, state = {}) {
  recordSeverity(result, line, flags);
  const loss = flags.decoderLoss ?? line.includes('\uFFFD');
  if (loss) result.visibility.decoder_loss_lines++;
  const parsing = flags.parsing ?? line.includes('[ParsingError]');
  const cannotParse = flags.cannotParse ?? line.includes('Cannot parse');
  if (flags.truncated) {
    resetDocumentContext(result, state, 'TRUNCATED_LINE');
    recordTruncatedLine(result, line, flags, parsing, cannotParse);
    return;
  }
  // Decoder replacement (including loss at a byte boundary) cannot bind events.
  if (loss) resetDocumentContext(result, state, 'DECODER_LOSS');
  const fileFailure = loss ? undefined : fileOnlyFailure(line, sources);
  if (fileFailure) recordFileFailure(result, fileFailure);
  const binding = advanceDocumentContext(result, line, fileFailure, state);
  recordSignals(result, line, binding, loss ? 'DECODER_LOSS' : state.reason);
  recordCounters(result, line);
  recordParserLocation(result, line, sources, parsing, cannotParse, fileFailure);
}
function diagnostics(filename, sources) {
  const result = emptyDiagnostics();
  const state = {};
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  const buffer = Buffer.alloc(65536);
  let pending = '', word = '', tail = '';
  let discarded = false;
  let flags = {warning: false, error: false, parsing: false, cannotParse: false};
  const flushWord = () => {
    if (/^WARN(?:ING)?$/i.test(word)) flags.warning = true;
    if (/^ERROR$/i.test(word)) flags.error = true;
    word = '';
  };
  const track = fragment => {
    for (const character of fragment) {
      if (/\w/.test(character)) { if (word.length < 8) word += character; }
      else flushWord();
    }
    const markers = tail + fragment;
    for (const [key, marker] of Object.entries(LINE_MARKERS)) flags[key] ||= markers.includes(marker);
    flags.decoderLoss ||= fragment.includes('\uFFFD');
    tail = markers.slice(-96);
  };
  const finish = () => {
    flushWord();
    if (discarded) result.overlong_lines++;
    acceptLine(result, pending, sources, {...flags, truncated: discarded}, state);
    pending = ''; word = ''; tail = ''; discarded = false;
    flags = {warning: false, error: false, parsing: false, cannotParse: false};
  };
  let bytes;
  try {
    while ((bytes = fs.readSync(descriptor, buffer, 0, buffer.length, null)) > 0) {
      for (const fragment of buffer.subarray(0, bytes).toString('utf8').split(/(?<=\n)/)) {
        track(fragment);
        if (pending.length + fragment.length <= MAX_LINE) pending += fragment;
        else { discarded = true; pending = (pending + fragment).slice(0, MAX_LINE); }
        if (fragment.endsWith('\n')) finish();
      }
    }
    if (pending || discarded) finish();
  } finally { resetDocumentContext(result, state, 'END_OF_INPUT'); fs.closeSync(descriptor); }
  return result;
}
function validateArguments(args, temporaryRoot, revision) {
  demand(SHA.test(revision));
  const expected = `-Dsonar.scm.revision=${revision} ` +
    `-Dsonar.working.directory=${path.join(temporaryRoot, 'framework-sonar-work')} ` +
    `-Dsonar.cfamily.compile-commands=${path.join(temporaryRoot, 'framework-sonar-native/compile_commands.json')}`;
  demand(args.trim().replace(/\s+/g, ' ') === expected);
  return expected + ' -Dsonar.log.level=DEBUG -Dsonar.verbose=true';
}
function parentIncludes(temporaryRoot, revision) {
  const context = realDirectory(path.join(temporaryRoot, 'sonar-native-context'));
  const filename = path.join(context, 'manifest.json');
  demand(fs.lstatSync(filename).isFile() && !fs.lstatSync(filename).isSymbolicLink() && fs.statSync(filename).size <= 1048576);
  const manifest = JSON.parse(fs.readFileSync(filename, 'utf8'));
  demand(manifest.revision === revision && manifest.uncommitted_changes === false);
  demand(Array.isArray(manifest.includes) && manifest.includes.length > 0 && manifest.includes.length <= 128);
  for (const include of manifest.includes) {
    demand(typeof include === 'string' && include.length <= 4096 && /^[A-Za-z0-9_./+-]+$/.test(include));
    demand(include === path.resolve(include) && include.startsWith(context + path.sep));
    realDirectory(include);
    demand(fs.realpathSync(include).startsWith(context + path.sep));
  }
  demand(manifest.include_value === manifest.includes.join(','));
  return manifest.include_value + ',/usr/include,/usr/include/apache2,/usr/include/apr-1.0';
}
function profileArguments(original, temporaryRoot, revision) {
  const mode = original['INPUT_OWNER-MODE'];
  if (mode === 'framework') {
    demand(original.GITHUB_REPOSITORY === 'Easton97-Jens/ModSecurity-test-Framework');
    demand(original.CONNECTOR_REVISION === FIXTURE && original.SONAR_USER_HOME === path.join(temporaryRoot, 'framework-sonar-cache'));
    return {mode, args: validateArguments(original.INPUT_ARGS ?? '', temporaryRoot, revision),
      project: 'Easton97-Jens_ModSecurity-test-Framework', work_directory: path.join(temporaryRoot, 'framework-sonar-work'),
      source_role: 'framework', configured_mode: 'COMPILE_COMMANDS', fixture_revision: FIXTURE};
  }
  const parent = /^parent-cpp(17|20|23)$/.exec(mode ?? '');
  demand(parent && original.GITHUB_REPOSITORY === 'Easton97-Jens/ModSecurity-conector');
  demand(original.SONAR_USER_HOME === path.join(temporaryRoot, 'sonar-cache'));
  const standard = parent[1];
  const project = 'Easton97-Jens_ModSecurity-conector' + (standard === '17' ? '' : `_cpp${standard}_advisory`);
  const includes = parentIncludes(temporaryRoot, revision);
  const expected = `-Dsonar.projectKey=${project} -Dsonar.cfamily.reportingCppStandardOverride=c++${standard} ` +
    `-Dsonar.scm.revision=${revision} -Dsonar.working.directory=${path.join(temporaryRoot, 'sonar-work')} ` +
    `-Dsonar.cfamily.customCIncludes=${includes} -Dsonar.cfamily.customCppIncludes=${includes} ` +
    '-Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=600';
  demand((original.INPUT_ARGS ?? '').trim().replace(/\s+/g, ' ') === expected);
  return {mode, args: expected + ' -Dsonar.log.level=DEBUG -Dsonar.verbose=true',
    project, work_directory: path.join(temporaryRoot, 'sonar-work'),
    source_role: 'parent', configured_mode: 'AUTO_CONFIG', fixture_revision: null};
}
function readBoundedRegular(filename, limit) {
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(descriptor);
    demand(stat.isFile() && stat.size <= limit);
    const buffer = Buffer.alloc(limit + 1);
    let filled = 0;
    let count;
    while (filled < buffer.length && (count = fs.readSync(descriptor, buffer, filled, buffer.length - filled, null)) > 0) filled += count;
    demand(filled <= limit);
    return buffer.subarray(0, filled).toString('utf8');
  } finally { fs.closeSync(descriptor); }
}
function validateProjectBinding(root, profile) {
  const content = readBoundedRegular(path.join(root, 'sonar-project.properties'), 65536);
  // The current checked-in contracts use literal keys. Refuse escape syntax
  // instead of implementing an incomplete Java-properties escape interpreter.
  demand(!content.includes('\\'));
  const values = [];
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    const key = /^sonar\.projectKey\s*[=:]/.exec(trimmed);
    if (key) values.push(trimmed.slice(key[0].length).trim());
  }
  const expected = profile.source_role === 'parent' ? 'Easton97-Jens_ModSecurity-conector' : profile.project;
  demand(values.length === 1 && values[0] === expected);
}
function reportTaskIdentity(workDirectory, project) {
  try {
    realDirectory(workDirectory);
    const lines = readBoundedRegular(path.join(workDirectory, 'report-task.txt'), 8192).split(/\r?\n/);
    const projects = lines.filter(line => line.startsWith('projectKey='));
    const tasks = lines.filter(line => line.startsWith('ceTaskId='));
    if (projects.length !== 1 || projects[0] !== `projectKey=${project}` || tasks.length !== 1 ||
        !/^ceTaskId=[A-Za-z0-9_-]{8,128}$/.test(tasks[0])) return {status: 'INVALID', ce_task_id: null};
    return {status: 'VALID', ce_task_id: tasks[0].slice('ceTaskId='.length)};
  } catch { return {status: 'NOT_PUBLISHED_OR_UNREADABLE', ce_task_id: null}; }
}
function validatedRunId(raw) {
  if (!/^[1-9]\d{0,19}$/.test(raw ?? '')) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}
async function main() {
  process.umask(0o077);
  demand(process.versions.node.split('.')[0] === '24' && process.platform === 'linux');
  const original = process.env;
  const root = realDirectory(original.GITHUB_WORKSPACE);
  const temporaryRoot = realDirectory(original.RUNNER_TEMP);
  demand(!temporaryRoot.startsWith(root + path.sep) && !root.startsWith(temporaryRoot + path.sep));
  const upstream = /^SonarSource\/sonarqube-scan-action@([a-f0-9]{40})$/.exec(original['INPUT_UPSTREAM-ACTION'] ?? '');
  demand(upstream && original.INPUT_SCANNERVERSION === '8.2.0.6438');
  await withPrivateRun(temporaryRoot, async directory => {
    const descriptor = privateFile(directory, 'raw.log');
    try {
      const clean = privateEnv(original, directory);
      const revision = gitOutput(root, ['rev-parse', 'HEAD'], clean).trim();
      const profile = profileArguments(original, temporaryRoot, revision);
      validateProjectBinding(root, profile);
      const sources = inventory(root, revision, profile.source_role, clean);
      if (profile.fixture_revision) {
        const fixture = inventory(original.CONNECTOR_ROOT, profile.fixture_revision, 'product_fixture', clean);
        for (const [name, fact] of fixture) sources.set(name, fact);
        sources.roots.push(...fixture.roots);
      }
      const action = path.join(directory, 'upstream');
      // Initialization, fetch and checkout each depend on the previous success.
      demand(await runCaptured(GIT, ['init', action], descriptor, clean, {timeout: 120000}) === 0);
      demand(await runCaptured(GIT, ['-C', action, '-c', 'credential.helper=', 'fetch', '--depth=1', '--no-tags',
        'https://github.com/SonarSource/sonarqube-scan-action.git', upstream[1]], descriptor, clean, {timeout: 120000}) === 0);
      demand(await runCaptured(GIT, ['-C', action, 'checkout', '--detach', upstream[1]],
        descriptor, clean, {timeout: 120000}) === 0);
      demand(gitOutput(action, ['rev-parse', 'HEAD'], clean).trim() === upstream[1]);
      const metadata = fs.readFileSync(path.join(action, 'action.yml'), 'utf8');
      demand(/using: node24/.test(metadata) && /main: dist\/index\.js/.test(metadata));
      const env = privateEnv(original, directory, true);
      Object.assign(env, {INPUT_ARGS: privateCacheArguments(profile.args, directory), INPUT_SCANNERVERSION: '8.2.0.6438', INPUT_PROJECTBASEDIR: root,
        INPUT_SCANNERBINARIESURL: 'https://binaries.sonarsource.com/Distribution/sonar-scanner-cli',
        INPUT_SKIPSIGNATUREVERIFICATION: 'false', INPUT_SCANNERBINARIESAUTHHEADER: '', PYTHONDONTWRITEBYTECODE: '1'});
      if (profile.source_role === 'parent') Object.assign(env, {GOTOOLCHAIN: 'local', GOWORK: 'off'});
      const scannerExit = await runCaptured(process.execPath, [path.join(action, 'dist/index.js')], descriptor, env, {cwd: root});
      fs.fsyncSync(descriptor);
      const result = diagnostics(path.join(directory, 'raw.log'), sources);
      const identity = reportTaskIdentity(profile.work_directory, profile.project);
      Object.assign(result, {revision, fixture_revision: profile.fixture_revision, owner_mode: profile.mode,
        project: profile.project, scanner_version: '8.2.0.6438', run_id: validatedRunId(original.GITHUB_RUN_ID),
        report_identity_status: identity.status, ce_task_id: identity.ce_task_id,
        configured_cfamily_mode: profile.configured_mode, configured_cfamily_cache_mode: 'FS',
        cache_initial_state: 'EMPTY_PRIVATE', configured_verbose: true,
        scanner_exit: scannerExit, action_commit: upstream[1]});
      process.stdout.write(JSON.stringify(result) + '\n');
      process.exitCode = scannerExit === 0 && identity.status === 'VALID' ? 0 : 1;
    } finally { fs.closeSync(descriptor); }
  });
}
module.exports = {gitOutput, privateEnv, privateFile, runCaptured, withPrivateRun, diagnostics, acceptLine,
  emptyDiagnostics, validateArguments, inventory, sourceLocation, parentIncludes, profileArguments,
  boundedCounter, readBoundedRegular, validateProjectBinding, reportTaskIdentity, validatedRunId, privateCacheArguments};
if (require.main === module) main().catch(() => {
  process.stderr.write('Private Sonar diagnostics failed; raw output was not published.\n');
  process.exitCode = 1;
});
