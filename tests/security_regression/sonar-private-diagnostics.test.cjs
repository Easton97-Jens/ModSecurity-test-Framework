'use strict';
// Offline controls only: no scanner, network, real token or production Git write.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const api = require('../../.github/actions/sonar-private/main.cjs');
const temporaryRoot = process.env.SONAR_DIAGNOSTIC_TEST_ROOT;
assert.ok(temporaryRoot && path.isAbsolute(temporaryRoot));
const canary = ['CANARY', 'PRIVATE', 'DIAGNOSTIC'].join('_');
const cacheName = 'cfamily-analysis-cache';
const cfamilyVersion = '6.86.0.113840';
const cfamilyVersionLine = 'CFamily plugin version: ' + cfamilyVersion;
function temporary(callback) {
  const directory = fs.mkdtempSync(path.join(temporaryRoot, 'diagnostic-test-'));
  return Promise.resolve().then(() => callback(directory)).finally(() => fs.rmSync(directory, {recursive: true, force: true}));
}
test('raw stdout/stderr/workflow commands remain private; status and cleanup hold', () => temporary(async root => {
  let owned;
  await api.withPrivateRun(root, async directory => {
    owned = directory;
    const fd = api.privateFile(directory, 'raw.log');
    try {
      const code = await api.runCaptured(process.execPath, ['-e',
        `process.stdout.write(${JSON.stringify('::error::' + canary + '\n')});process.stderr.write(${JSON.stringify(canary + '\n')});process.exit(7)`], fd, {}, {timeout: 2000});
      assert.equal(code, 7);
      assert.equal(fs.statSync(path.join(directory, 'raw.log')).mode & 0o777, 0o600);
      const result = api.diagnostics(path.join(directory, 'raw.log'), new Map());
      assert.equal(result.errors.total, 1);
      assert.equal(result.errors.unmapped, 1);
      assert.equal(result.diagnosis_complete, false);
      assert.ok(!JSON.stringify(result).includes(canary));
      api.acceptLine(result, `gpg: WARNING: ${canary}`, new Map());
      assert.equal(result.warnings.signature_trust, 1);
      assert.ok(!JSON.stringify(result).includes(canary));
    } finally { fs.closeSync(fd); }
  });
  assert.equal(fs.existsSync(owned), false);
}));
test('unrelated credentials and execution injection controls are absent', () => temporary(root => {
  const original = {PATH: '/usr/bin', HOME: root, SONAR_TOKEN: canary, SONAR_USER_HOME: root,
    GITHUB_TOKEN: canary, ACTIONS_RUNTIME_TOKEN: canary, OTHER_PASSWORD: canary,
    NODE_OPTIONS: canary, RUNNER_DEBUG: '1', BASH_ENV: canary, GITHUB_ENV: '/outside/env'};
  const env = api.privateEnv(original, root, true);
  assert.equal(env.SONAR_TOKEN, canary);
  for (const key of ['GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'OTHER_PASSWORD', 'NODE_OPTIONS', 'RUNNER_DEBUG', 'BASH_ENV']) assert.equal(env[key], undefined);
  assert.equal(path.dirname(env.GITHUB_ENV), root);
  assert.equal(api.privateEnv(original, root).SONAR_TOKEN, undefined);
  const target = path.join(root, 'sentinel');
  fs.writeFileSync(target, canary);
  fs.symlinkSync(target, path.join(root, 'raw.log'));
  assert.throws(() => api.privateFile(root, 'raw.log'));
  assert.equal(fs.readFileSync(target, 'utf8'), canary);
}));
test('real metric prose, safe locations and independent budget/IR facts are retained', () => {
  const sources = new Map([['/fixture/src/a.c', {repository: 'product_fixture', path: 'src/a.c'}]]);
  sources.roots = ['/fixture'];
  const result = api.emptyDiagnostics();
  for (const line of [
    `DEBUG [ParsingError] /fixture/sub/../src/a.c:12:4 unknown type name '${canary}'`,
    `WARN Cannot parse '/fixture/src/a.c:338:15'`,
    'WARN Dropping internal.debug finding: primary location :0 is not a valid source location.',
    `WARN ${canary}`, `ERROR ${canary}`,
    'DEBUG [ParsingError] /outside/../fixture/src/a.c:3 expected identifier',
    'DEBUG [ParsingError] ../src/a.c:3 expected identifier',
    'INFO 85 compilation units were fully analyzed', 'INFO 0 compilation units were partially analyzed',
    '94.64% of functions were parsed successfully (60 out of 1120 have parsing errors)',
    '97.74% of statements were parsed successfully (443 out of 19635 have parsing errors)',
    `YamlEngineException: The incoming YAML document exceeds the limit: 3145728 code points. ${canary}`,
    'Top-level declarations dropped decoding, encoding: 84, 1',
    'IR generation: 48 skipped out of 72,079 total methods', `LLVM ERROR: ${canary}`,
  ]) api.acceptLine(result, line, sources);
  assert.equal(result.warnings.total, 3);
  assert.equal(result.warnings.unmapped, 1);
  assert.equal(result.locations.length, 2);
  assert.equal(result.locations[0].category, 'UNKNOWN_TYPE');
  assert.equal(result.locations[1].column, 15);
  assert.equal(result.unmapped_parser_lines, 2);
  assert.deepEqual(result.counters.functions, {errors: 60, total: 1120});
  assert.deepEqual(result.counters.statements, {errors: 443, total: 19635});
  assert.deepEqual(result.signals.document_limits, [{category: 'DOCUMENT_CODEPOINT_LIMIT', limit: 3145728, occurrences: 1, source_binding: 'UNBOUND'}]);
  assert.deepEqual(result.signals.top_level_drops, {decoding: 84, encoding: 1});
  assert.deepEqual(result.signals.ir_methods, {skipped: 48, total: 72079});
  assert.equal(result.signals.llvm_errors, 1);
  assert.ok(!JSON.stringify(result).includes(canary));
  for (const raw of ['/fixture/../fixture/src/a.c', '../src/a.c', '/fixture/src/\x00a.c']) assert.equal(api.sourceLocation(raw, sources), undefined);
});
test('severity beyond the line budget is counted without exposing raw tail', () => temporary(root => {
  const filename = path.join(root, 'long.log');
  fs.writeFileSync(filename, 'x'.repeat(100000) + ` WARN ${canary} ERROR\n`, {mode: 0o600});
  const result = api.diagnostics(filename, new Map());
  assert.equal(result.warnings.total, 1);
  assert.equal(result.warnings.unmapped, 1);
  assert.equal(result.errors.total, 1);
  assert.equal(result.overlong_lines, 1);
  assert.ok(!JSON.stringify(result).includes(canary));
}));
test('Framework original arguments accept; scope injection rejects', () => {
  const revision = 'a'.repeat(40);
  const args = `-Dsonar.scm.revision=${revision} -Dsonar.working.directory=/private/framework-sonar-work -Dsonar.cfamily.compile-commands=/private/framework-sonar-native/compile_commands.json`;
  const expected = args + ' -Dsonar.log.level=DEBUG -Dsonar.verbose=true';
  assert.equal(api.validateArguments(args, '/private', revision), expected);
  const env = {'INPUT_OWNER-MODE': 'framework', GITHUB_REPOSITORY: 'Easton97-Jens/ModSecurity-test-Framework',
    CONNECTOR_REVISION: 'cfd5e49cada3fc793ef50993147e3796a0907443', SONAR_USER_HOME: '/private/framework-sonar-cache', INPUT_ARGS: args};
  assert.equal(api.profileArguments(env, '/private', revision).args, expected);
  for (const bad of [args + ' -Dsonar.exclusions=**', args.replace(revision, 'master'), args.replace('compile_commands.json', 'partial.json'),
    ...['-Dsonar.verbose=false', '-Dsonar.verbose=true', '-Dsonar.log.level=TRACE', '-Dsonar.log.level=DEBUG', '-X',
      '-Dsonar.cfamily.analysisCache.mode=server', '-Dsonar.cfamily.analysisCache.path=/outside'].map(value => args + ' ' + value)]) {
    assert.throws(() => api.validateArguments(bad, '/private', revision));
    assert.throws(() => api.profileArguments({...env, INPUT_ARGS: bad}, '/private', revision));
  }
});
test('Parent profiles retain exact AutoConfig/includes/std/project/wait without fixture substitution', () => temporary(root => {
  const revision = 'b'.repeat(40);
  const context = path.join(root, 'sonar-native-context');
  const includes = path.join(context, 'headers');
  fs.mkdirSync(includes, {recursive: true});
  const manifest = {revision, uncommitted_changes: false, includes: [includes], include_value: includes};
  fs.writeFileSync(path.join(context, 'manifest.json'), JSON.stringify(manifest));
  for (const standard of ['17', '20', '23']) {
    const project = 'Easton97-Jens_ModSecurity-conector' + (standard === '17' ? '' : `_cpp${standard}_advisory`);
    const inc = includes + ',/usr/include,/usr/include/apache2,/usr/include/apr-1.0';
    const args = `-Dsonar.projectKey=${project} -Dsonar.cfamily.reportingCppStandardOverride=c++${standard} ` +
      `-Dsonar.scm.revision=${revision} -Dsonar.working.directory=${root}/sonar-work ` +
      `-Dsonar.cfamily.customCIncludes=${inc} -Dsonar.cfamily.customCppIncludes=${inc} ` +
      '-Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=600';
    const env = {'INPUT_OWNER-MODE': `parent-cpp${standard}`, GITHUB_REPOSITORY: 'Easton97-Jens/ModSecurity-conector', SONAR_USER_HOME: `${root}/sonar-cache`, INPUT_ARGS: args};
    const valid = api.profileArguments(env, root, revision);
    assert.equal(valid.configured_mode, 'AUTO_CONFIG');
    assert.equal(valid.fixture_revision, null);
    assert.equal(valid.args, args + ' -Dsonar.log.level=DEBUG -Dsonar.verbose=true');
    for (const modified of [args + ' -Dsonar.sources=common', args.replace('wait=true', 'wait=false'), args.replace('c++' + standard, 'c++99'),
      ...['-Dsonar.verbose=false', '-Dsonar.verbose=true', '-Dsonar.log.level=TRACE', '-Dsonar.log.level=DEBUG', '-X',
        '-Dsonar.cfamily.analysisCache.mode=server', '-Dsonar.cfamily.analysisCache.path=/outside'].map(value => args + ' ' + value)]) assert.throws(() => api.profileArguments({...env, INPUT_ARGS: modified}, root, revision));
  }
  manifest.uncommitted_changes = true;
  fs.writeFileSync(path.join(context, 'manifest.json'), JSON.stringify(manifest));
  assert.throws(() => api.parentIncludes(root, revision));
}));
for (const options of [{timeout: 30}, {timeout: 2000, limit: 128}]) {
  test(`timeout/log overflow cleanup (${options.limit ? 'overflow' : 'timeout'})`, () => temporary(async root => {
    let owned;
    await assert.rejects(api.withPrivateRun(root, async directory => {
      owned = directory;
      api.privateCacheArguments('', directory);
      assert.deepEqual(fs.readdirSync(path.join(directory, cacheName)), []);
      const fd = api.privateFile(directory, 'raw.log');
      try {
        const program = options.limit ? 'process.stdout.write("x".repeat(100000))' : 'setInterval(()=>{},1000)';
        await api.runCaptured(process.execPath, ['-e', program], fd, {}, options);
      } finally { fs.closeSync(fd); }
    }), /captured child failed/);
    assert.equal(fs.existsSync(owned), false);
    assert.equal(fs.existsSync(path.join(owned, cacheName)), false);
  }));
}
function active(pid) {
  try { const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8'); return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[0] !== 'Z'; }
  catch { return false; }
}
function waitForExit(pid) {
  return new Promise(resolve => {
    let attempts = 0;
    const poll = () => {
      if (!active(pid) || attempts++ >= 20) resolve();
      else setTimeout(poll, 10);
    };
    poll();
  });
}
test('a leader exit terminates inherited-group descendants with closed stdio', () => temporary(async root => {
  const pidFile = path.join(root, 'descendant.pid');
  let pid;
  try {
    await api.withPrivateRun(root, async directory => {
      const fd = api.privateFile(directory, 'raw.log');
      try {
        const program = `const {spawn}=require('node:child_process');const fs=require('node:fs');` +
          `const child=spawn(process.execPath,['-e','process.on("SIGTERM",()=>{});setInterval(()=>{},1000)'],{stdio:'ignore'});` +
          `fs.writeFileSync(${JSON.stringify(pidFile)},String(child.pid));child.unref();process.exit(0);`;
        assert.equal(await api.runCaptured(process.execPath, ['-e', program], fd, {}, {timeout: 2000}), 0);
        pid = Number(fs.readFileSync(pidFile, 'utf8'));
        await waitForExit(pid);
        assert.equal(active(pid), false);
      } finally { fs.closeSync(fd); }
    });
  } finally { if (pid && active(pid)) { try { process.kill(pid, 'SIGKILL'); } catch {} } }
}));
test('top-level exceptions do not replay private content', () => temporary(root => {
  const result = spawnSync(process.execPath, [path.resolve(__dirname, '../../.github/actions/sonar-private/main.cjs')], {
    env: {GITHUB_WORKSPACE: path.join(root, canary), RUNNER_TEMP: root}, encoding: 'utf8', timeout: 2000});
  assert.equal(result.status, 1);
  assert.ok(!result.stdout.includes(canary) && !result.stderr.includes(canary));
  assert.match(result.stderr, /Private Sonar diagnostics failed/);
}));
test('unsafe or inconsistent counters become explicit unknowns', () => {
  const result = api.emptyDiagnostics();
  for (const line of [
    '99% of functions were parsed successfully (99999999999999999999 out of 999999999999999999999 have parsing errors)',
    '99% of statements were parsed successfully (3 out of 2 have parsing errors)',
    '99999999999999999999 compilation units were fully analyzed',
    'Top-level declarations dropped decoding, encoding: 99999999999999999999, 1',
    'IR generation: 4 skipped out of 3 total methods',
  ]) api.acceptLine(result, line, new Map());
  assert.equal(result.unmapped_counters, 5);
  assert.deepEqual(result.counters, {});
  assert.equal(result.signals.top_level_drops, null);
  assert.equal(result.signals.ir_methods, null);
  assert.equal(api.boundedCounter('7,203', true), 7203);
  assert.equal(api.boundedCounter('7,,203', true), null);
});
test('a capture limit applies cumulatively across child invocations', () => temporary(async root => {
  await api.withPrivateRun(root, async directory => {
    const fd = api.privateFile(directory, 'raw.log');
    try {
      const args = ['-e', 'process.stdout.write("x".repeat(80))'];
      assert.equal(await api.runCaptured(process.execPath, args, fd, {}, {limit: 128, timeout: 2000}), 0);
      await assert.rejects(api.runCaptured(process.execPath, args, fd, {}, {limit: 128, timeout: 2000}), /captured child failed/);
      assert.ok(fs.fstatSync(fd).size <= 128);
    } finally { fs.closeSync(fd); }
  });
}));
test('canonical include containment rejects lexical escapes and symlinks', () => temporary(root => {
  const context = path.join(root, 'sonar-native-context');
  const outside = path.join(root, 'outside');
  fs.mkdirSync(context); fs.mkdirSync(outside);
  const revision = 'c'.repeat(40);
  const filename = path.join(context, 'manifest.json');
  for (const include of [context + '/../outside', context + '//../outside']) {
    fs.writeFileSync(filename, JSON.stringify({revision, uncommitted_changes: false, includes: [include], include_value: include}));
    assert.throws(() => api.parentIncludes(root, revision));
  }
  const alias = path.join(context, 'alias'); fs.symlinkSync(outside, alias);
  fs.writeFileSync(filename, JSON.stringify({revision, uncommitted_changes: false, includes: [alias], include_value: alias}));
  assert.throws(() => api.parentIncludes(root, revision));
}));
test('report identity exposes only an exact project and bounded CE task identifier', () => temporary(root => {
  const project = 'Easton97-Jens_ModSecurity-test-Framework';
  const filename = path.join(root, 'report-task.txt');
  const task = 'AaG7YsANhQXxjEzKTonG';
  fs.writeFileSync(filename, `projectKey=${project}\nceTaskId=${task}\ndashboardUrl=https://example.invalid/${canary}\n`);
  assert.deepEqual(api.reportTaskIdentity(root, project), {status: 'VALID', ce_task_id: task});
  for (const text of [`projectKey=other\nceTaskId=${task}\n`, `projectKey=${project}\nceTaskId=${task}\nceTaskId=${task}\n`, `projectKey=${project}\nceTaskId=bad/${canary}\n`]) {
    fs.writeFileSync(filename, text);
    const result = api.reportTaskIdentity(root, project);
    assert.equal(result.status, 'INVALID'); assert.equal(result.ce_task_id, null);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  fs.unlinkSync(filename);
  const target = path.join(root, 'target'); fs.writeFileSync(target, canary); fs.symlinkSync(target, filename);
  assert.equal(api.reportTaskIdentity(root, project).ce_task_id, null);
  assert.equal(api.validatedRunId('42540006336'), 42540006336);
  assert.equal(api.validatedRunId('99999999999999999999'), null);
  assert.equal(api.validatedRunId(canary), null);
}));
test('checked-in literal project binding cannot silently disagree with owner', () => temporary(root => {
  const filename = path.join(root, 'sonar-project.properties');
  const profile = {source_role: 'framework', project: 'Easton97-Jens_ModSecurity-test-Framework'};
  fs.writeFileSync(filename, `sonar.projectKey=${profile.project}\n`);
  api.validateProjectBinding(root, profile);
  fs.writeFileSync(filename, `sonar.projectKey=${profile.project}\nsonar.projectKey=other\n`);
  assert.throws(() => api.validateProjectBinding(root, profile));
}));
test('fixed system Git ignores a hostile PATH and reads the actual repository', () => temporary(root => {
  const sentinel = path.join(root, 'shadow-executed');
  fs.writeFileSync(path.join(root, 'git'), `#!/bin/sh\n/usr/bin/touch '${sentinel}'\nexit 99\n`, {mode: 0o700});
  const repository = process.env.SONAR_DIAGNOSTIC_SOURCE_ROOT ?? path.resolve(__dirname, '../..');
  const expected = spawnSync('/usr/bin/git', ['-C', repository, 'rev-parse', 'HEAD'], {encoding: 'utf8'});
  assert.equal(expected.status, 0);
  assert.equal(api.gitOutput(repository, ['rev-parse', 'HEAD'], {PATH: root}).trim(), expected.stdout.trim());
  assert.equal(fs.existsSync(sentinel), false);
}));
test('adversarial digit runs and property whitespace finish within a hard deadline without disclosure', () => temporary(root => {
  const modulePath = path.resolve(__dirname, '../../.github/actions/sonar-private/main.cjs');
  const program = String.raw`
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    const api = require(${JSON.stringify(modulePath)});
    const root = ${JSON.stringify(root)};
    const canary = ${JSON.stringify(canary)};
    const result = api.emptyDiagnostics();
    const digits = '9'.repeat(60000);
    api.acceptLine(result, digits + ' not a compilation counter WARN ' + canary, new Map());
    api.acceptLine(result, digits + ' compilation units were fully analyzed', new Map());
    api.acceptLine(result, 'x compilation units were fully analyzed 85 compilation units were fully analyzed', new Map());
    api.acceptLine(result, 'INFO 0 compilation units were partially analyzed', new Map());
    assert.equal(result.warnings.total, 1);
    assert.equal(result.warnings.unmapped, 1);
    assert.equal(result.unmapped_counters, 1);
    assert.equal(result.counters.full_translation_units, 85);
    assert.equal(result.counters.partial_translation_units, 0);
    const project = 'Easton97-Jens_ModSecurity-test-Framework';
    const filename = root + '/sonar-project.properties';
    fs.writeFileSync(filename, 'sonar.projectKey=' + ' '.repeat(60000) + project + '\n');
    api.validateProjectBinding(root, {source_role: 'framework', project});
    fs.writeFileSync(filename, 'sonar.projectKey' + ' '.repeat(60000) + canary + '\n');
    assert.throws(() => api.validateProjectBinding(root, {source_role: 'framework', project}));
    fs.writeFileSync(filename, '  sonar.projectKey :  ' + project + '  \r\n');
    api.validateProjectBinding(root, {source_role: 'framework', project});
    fs.writeFileSync(filename, 'sonar.projectKey=' + project + '\n sonar.projectKey : ' + project + '\n');
    assert.throws(() => api.validateProjectBinding(root, {source_role: 'framework', project}));
    const log = root + '/adversarial.log';
    fs.writeFileSync(log, digits.repeat(4) + ' WARN ERROR [ParsingError] Cannot parse ' + canary + '\n');
    const tail = api.diagnostics(log, new Map());
    assert.equal(tail.overlong_lines, 1);
    assert.equal(tail.warnings.total, 1);
    assert.equal(tail.errors.total, 1);
    assert.equal(tail.parser_lines, 1);
    assert.equal(tail.unmapped_parser_lines, 1);
    assert.equal(tail.diagnosis_complete, false);
    assert.ok(!JSON.stringify({result, tail}).includes(canary));
    fs.writeFileSync(log, "12:34:56.789 WARN Cannot parse '" + "'".repeat(60000) + canary + "\n" +
      "12:34:56.789 WARN Cannot parse '" + 'a'.repeat(60000) + canary + "\n" +
      'org.snakeyaml.engine.v2.exceptions.YamlEngineException: The incoming YAML document exceeds the limit: 3145728 code points.\n');
    const quoted = api.diagnostics(log, new Map());
    assert.deepEqual(quoted.file_failures, []);
    assert.equal(quoted.signals.document_limits[0].source_binding, 'UNBOUND');
    assert.ok(!JSON.stringify(quoted).includes(canary));
    const inventory = new Map();
    for (let count = 0; count <= 10000; count++) {
      inventory.set('data/f' + count + '.json', {repository: 'framework', path: 'data/f' + count + '.json'});
    }
    const many = api.emptyDiagnostics();
    for (let count = 0; count < 10000; count++) {
      api.acceptLine(many, "12:34:56.789 WARN Cannot parse 'data/f" + count + ".json'", inventory);
    }
    const last = "12:34:56.789 WARN Cannot parse 'data/f9999.json'";
    for (let count = 0; count < 50000; count++) api.acceptLine(many, last, inventory);
    for (let count = 0; count < 3; count++) {
      api.acceptLine(many, "12:34:56.789 WARN Cannot parse 'data/f10000.json'", inventory);
    }
    assert.equal(many.file_failures.length, 10000);
    assert.equal(many.file_failures[0].path, 'data/f0.json');
    assert.equal(many.file_failures[0].occurrences, 1);
    assert.equal(many.file_failures[9999].path, 'data/f9999.json');
    assert.equal(many.file_failures[9999].occurrences, 50001);
    assert.equal(many.facts_truncated, 3);
    assert.equal(many.warnings.total, 60003);
    assert.equal(many.unmapped_parser_lines, 0);
    const isolated = api.emptyDiagnostics();
    api.acceptLine(isolated, last, inventory);
    assert.equal(isolated.file_failures[0].occurrences, 1);
    assert.ok(!JSON.stringify(many).includes(canary));
    process.stdout.write('bounded parsing passed\n');
  `;
  const result = spawnSync(process.execPath, ['-e', program], {encoding: 'utf8', timeout: 2500, env: {}});
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'bounded parsing passed\n');
  assert.equal(result.stderr, '');
  assert.ok(!result.stdout.includes(canary) && !result.stderr.includes(canary));
}));
const documentLimit = 'The incoming YAML document exceeds the limit: 3145728 code points.';
const nativeLogger = 'org.sonar.iac.common.extension.analyzer.AbstractAnalyzer';
const nativeConvertFrame = '\tat org.sonar.iac.common.extension.ParseException.toParseException(ParseException.java:67)';
const nativeAnalyzerFrame = '\tat org.sonar.iac.common.extension.analyzer.AbstractAnalyzer.parse(AbstractAnalyzer.java:81)';
function nativeLines(context = '', source = 'data/a.json') {
  return [`12:34:56.789 WARN ${context}Cannot parse '${source}'`,
    `12:34:56.790 DEBUG ${context}${documentLimit}`,
    `12:34:56.791 DEBUG ${context}org.sonar.iac.common.extension.ParseException: Cannot parse '${source}'`,
    nativeConvertFrame, nativeAnalyzerFrame];
}
test('native three-event sequence correlates only a complete bounded stack and successful EOF', () => temporary(root => {
  for (const [context, status] of [['', 'SEQUENCE_CORRELATED'],
    [`[worker-1] ${nativeLogger} - `, 'LOGGER_THREAD_MATCHED']]) {
    const result = logDiagnostics(root, nativeLines(context));
    assert.deepEqual(result.signals.document_limit_associations, [{repository: 'framework', path: 'data/a.json',
      category: 'DOCUMENT_CODEPOINT_LIMIT', limit: 3145728, association_status: status, occurrences: 1}]);
    assert.equal(result.signals.document_limits[0].source_binding, 'UNBOUND');
    assert.equal(result.signals.document_limits[0].occurrences, 1);
    assert.equal(result.diagnosis_complete, false);
  }
  const nextEvent = logDiagnostics(root, [...nativeLines(), '12:34:56.792 INFO Sensor finished']);
  assert.equal(nextEvent.signals.document_limit_associations.length, 1);
  const filename = path.join(root, 'no-final-newline.log');
  fs.writeFileSync(filename, nativeLines().join('\n'), {mode: 0o600});
  assert.equal(api.diagnostics(filename, jsonSources()).signals.document_limit_associations.length, 1);
  assert.throws(() => api.diagnostics(root, jsonSources()), {code: 'EISDIR'});
}));
test('native correlation rejects missing reordered interleaved and conflicting contexts', () => temporary(root => {
  const original = nativeLines();
  const wrongHeader = original[2].replace('data/a.json', 'data/b.json');
  const known = `[worker-1] ${nativeLogger} - `;
  const explicit = nativeLines(known);
  const cases = [original.slice(1), original.filter((_, i) => i !== 1), original.filter((_, i) => i !== 2),
    original.filter((_, i) => i !== 3), original.filter((_, i) => i !== 4),
    [original[0], original[2], original[1], ...original.slice(3)],
    [original[0], original[1], wrongHeader, ...original.slice(3)],
    [original[0], original[1] + ' ' + canary, ...original.slice(2)],
    [original[0], original[1].replace('3145728', '2147483648'), ...original.slice(2)],
    [original[0], explicit[1], ...original.slice(2)],
    [explicit[0], explicit[1].replace('worker-1', 'worker-2'), ...explicit.slice(2)],
    [explicit[0], explicit[1], explicit[2].replace(nativeLogger, 'untrusted.Logger'), ...explicit.slice(3)]];
  for (const interruption of ['12:34:56.790 INFO Sensor other', '12:34:56.790 DEBUG ' + canary,
    '', canary, '\u001b[31m', '\uFFFD']) {
    cases.push([original[0], interruption, ...original.slice(1)],
      [...original.slice(0, 3), interruption, ...original.slice(3)]);
  }
  for (const lines of cases) {
    const result = logDiagnostics(root, lines);
    assert.deepEqual(result.signals.document_limit_associations, []);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
}));
test('native correlation honors line byte overlong and decoder-loss boundaries', () => temporary(root => {
  const original = nativeLines();
  for (const middle of [new Array(28).fill(stackFrame),
    new Array(20).fill('\tat ' + 'a'.repeat(900) + '.method(Scanner.java:42)'),
    ['x'.repeat(70000)], ['\t' + '\uFFFD' + canary]]) {
    const result = logDiagnostics(root, [...original.slice(0, 3), ...middle, ...original.slice(3)]);
    assert.deepEqual(result.signals.document_limit_associations, []);
    assert.equal(result.signals.document_limits[0].source_binding, 'UNBOUND');
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  const truncated = logDiagnostics(root, [original[0], original[1] + 'x'.repeat(70000), ...original.slice(2)]);
  assert.deepEqual(truncated.signals.document_limit_associations, []);
  assert.equal(truncated.overlong_lines, 1);
}));
test('native correlation preserves warning visibility transport boundaries and redaction', () => temporary(root => {
  const identity = `[${canary}] ${nativeLogger} - `;
  const lines = nativeLines(identity, '/fixture/data/a.json');
  const transport = lines.map(line => '2026-11-09T12:34:56.7890000Z ' + line);
  const result = logDiagnostics(root, [...transport,
    '12:34:56.792 WARN Dropping internal.debug finding: primary location ' + canary,
    '12:34:56.793 WARN Dropping internal.debug finding: primary location ' + canary], '\r\n', 'x'.repeat(65520) + '\r\n');
  assert.equal(result.signals.document_limit_associations[0].association_status, 'LOGGER_THREAD_MATCHED');
  assert.equal(result.signals.document_limit_associations[0].path, 'data/a.json');
  assert.equal(result.warnings.invalid_location, 2);
  assert.equal(result.warnings.total, 3);
  assert.ok(!JSON.stringify(result).includes(canary));
  assert.ok(!JSON.stringify(result).includes(nativeLogger));
}));
test('CFamily version accepts only optional exact lowercase build metadata and emits numeric version', () => temporary(root => {
  const build = '829eaa25b0b1054f587bbeeb168e51409c72f905';
  for (const suffix of ['', ` (${build})`]) {
    const result = logDiagnostics(root, [cfamilyVersionLine + suffix]);
    assert.equal(result.cfamily_version, cfamilyVersion);
    assert.equal(result.cfamily_version_status, 'OBSERVED');
    assert.ok(!JSON.stringify(result).includes(build));
  }
  for (const suffix of [` (${build.slice(1)})`, ` (${build}a)`, ` (${build.toUpperCase()})`,
    ` (${build.slice(1)}g)`, `  (${build})`, ` (${build}) ${canary}`, '\u001b[0m', '\t',
    ' (' + 'a'.repeat(50000) + ')', ' (Linux)']) {
    const result = logDiagnostics(root, [cfamilyVersionLine + suffix]);
    assert.equal(result.cfamily_version, null);
    assert.equal(result.cfamily_version_status, 'NOT_OBSERVED');
    assert.equal(result.visibility.version_unmapped, 1);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  const conflict = logDiagnostics(root, [cfamilyVersionLine + ` (${build})`, 'CFamily plugin version: 6.87.0.1']);
  assert.equal(conflict.cfamily_version_status, 'CONFLICT');
  assert.equal(conflict.cfamily_version, null);
}));
const engineLimit = 'org.snakeyaml.engine.v2.exceptions.YamlEngineException: ' + documentLimit;
const classicLimit = 'Caused by: org.yaml.snakeyaml.error.YAMLException: ' + documentLimit;
const stackFrame = '\tat org.snakeyaml.engine.v2.scanner.ScannerImpl.fetchMoreTokens(ScannerImpl.java:42)';
function jsonSources() {
  const sources = new Map([
    ['/fixture/data/a.json', {repository: 'framework', path: 'data/a.json'}],
    ['/fixture/data/b.json', {repository: 'framework', path: 'data/b.json'}],
    ['data/a.json', {repository: 'framework', path: 'data/a.json'}],
    ['data/b.json', {repository: 'framework', path: 'data/b.json'}],
  ]);
  sources.roots = ['/fixture'];
  return sources;
}
function jsonWarning(source = 'data/a.json') {
  return `12:34:56.789 WARN Cannot parse '${source}'`;
}
function logDiagnostics(root, lines, separator = '\n', prefix = '') {
  const filename = path.join(root, 'document.log');
  fs.writeFileSync(filename, prefix + lines.join(separator) + separator, {mode: 0o600});
  return api.diagnostics(filename, jsonSources());
}
test('prospective Java exception envelope binds only complete inventory file failures', () => temporary(root => {
  const result = logDiagnostics(root, [jsonWarning(), engineLimit, stackFrame, classicLimit]);
  assert.deepEqual(result.file_failures, [{repository: 'framework', path: 'data/a.json', category: 'CANNOT_PARSE', occurrences: 1}]);
  assert.deepEqual(result.locations, []);
  assert.equal(result.unmapped_parser_lines, 0);
  assert.equal(result.warnings.total, 1);
  assert.deepEqual(result.signals.document_limits, [{category: 'DOCUMENT_CODEPOINT_LIMIT', limit: 3145728,
    occurrences: 2, repository: 'framework', path: 'data/a.json', source_binding: 'INVENTORY'}]);
  assert.equal(result.diagnosis_complete, false);
}));
test('file bindings remain distinct and never retroactively bind earlier exceptions', () => temporary(root => {
  const result = logDiagnostics(root, [engineLimit, jsonWarning(), engineLimit, jsonWarning('data/b.json'),
    engineLimit, jsonWarning(), engineLimit]);
  assert.equal(result.signals.document_limits.length, 3);
  assert.deepEqual(result.signals.document_limits.map(item => [item.source_binding, item.path, item.occurrences]),
    [['UNBOUND', undefined, 1], ['INVENTORY', 'data/a.json', 2], ['INVENTORY', 'data/b.json', 1]]);
  assert.deepEqual(result.file_failures.map(item => [item.path, item.occurrences]), [['data/a.json', 2], ['data/b.json', 1]]);
  const eof = logDiagnostics(root, [engineLimit, jsonWarning()]);
  assert.equal(eof.signals.document_limits[0].source_binding, 'UNBOUND');
  assert.equal(logDiagnostics(root, [engineLimit]).signals.document_limits[0].source_binding, 'UNBOUND');
}));
test('unknown, escaping, partial and ambiguous warning identities never bind or disclose', () => temporary(root => {
  for (const warning of [jsonWarning('../data/a.json'), jsonWarning('/fixture/../fixture/data/a.json'),
    jsonWarning('data/' + canary + '.json'), jsonWarning().slice(0, -1), jsonWarning() + " 'data/b.json'",
    jsonWarning() + ' ' + canary, '12:34:56.789 WARN Cannot parse "data/a.json"',
    '2026-11-09T12:34:56.78Z ' + jsonWarning(), '2026-11-09T12:34:56.7890000000Z ' + jsonWarning(),
    '2026-11-09T12:34:56.789Z  ' + jsonWarning(), '12:34:56.78 WARN Cannot parse \'data/a.json\'']) {
    const result = logDiagnostics(root, [warning, engineLimit]);
    assert.deepEqual(result.file_failures, []);
    assert.equal(result.signals.document_limits[0].source_binding, 'UNBOUND');
    assert.equal(result.warnings.total, 1);
    assert.equal(result.unmapped_parser_lines, 1);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
}));
test('new logger events, sensors, interleaving, unknown source and decoder loss reset association', () => temporary(root => {
  for (const separator of ['12:34:56.790 DEBUG ' + canary, '12:34:56.790 INFO Sensor JSON [json]',
    '2026-11-09T12:34:56.7900000Z ' + engineLimit, canary, '', jsonWarning('data/' + canary + '.json'),
    'unrecognized.Exception: ' + canary, stackFrame, '\uFFFD' + canary]) {
    const result = logDiagnostics(root, [jsonWarning(), separator, engineLimit]);
    assert.ok(result.signals.document_limits.every(item => item.source_binding === 'UNBOUND'));
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  const preliminary = 'org.snakeyaml.engine.v2.exceptions.YamlEngineException: preliminary exception';
  for (const lines of [[jsonWarning(), classicLimit, engineLimit],
    [jsonWarning(), preliminary, engineLimit], [jsonWarning(), preliminary, stackFrame, engineLimit]]) {
    const result = logDiagnostics(root, lines);
    assert.ok(result.signals.document_limits.every(item => item.source_binding === 'UNBOUND'));
    assert.ok(!JSON.stringify(result).includes(canary));
  }
}));
test('context expires at line and byte budgets and on overlong log lines', () => temporary(root => {
  for (const middle of [[...new Array(31).fill(stackFrame)],
    [...new Array(20).fill('\tat ' + 'a'.repeat(900) + '.method(Scanner.java:42)')], ['x'.repeat(70000) + canary]]) {
    const result = logDiagnostics(root, [jsonWarning(),
      'org.snakeyaml.engine.v2.exceptions.YamlEngineException: preliminary exception', ...middle, classicLimit]);
    assert.equal(result.signals.document_limits[0].source_binding, 'UNBOUND');
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  const boundary = logDiagnostics(root, [jsonWarning(),
    'org.snakeyaml.engine.v2.exceptions.YamlEngineException: preliminary exception', ...new Array(29).fill(stackFrame), classicLimit]);
  assert.equal(boundary.signals.document_limits[0].source_binding, 'INVENTORY');
}));
test('CRLF and read-chunk boundaries preserve bounded association and privacy', () => temporary(root => {
  const warning = '2026-11-09T12:34:56.7890000Z ' + jsonWarning('/fixture/data/a.json');
  const prefix = 'x'.repeat(65520) + '\r\n';
  const result = logDiagnostics(root, [warning, engineLimit, stackFrame, classicLimit, canary], '\r\n', prefix);
  assert.equal(result.file_failures[0].path, 'data/a.json');
  assert.equal(result.signals.document_limits[0].source_binding, 'INVENTORY');
  assert.equal(result.signals.document_limits[0].occurrences, 2);
  assert.ok(!JSON.stringify(result).includes(canary));
  const head = jsonWarning() + '\norg.snakeyaml.engine.v2.exceptions.YamlEngineException: ';
  const padding = 'x'.repeat(65535 - Buffer.byteLength(head, 'utf8') - 1) + '\n';
  const filename = path.join(root, 'split-utf8.log');
  fs.writeFileSync(filename, padding + head + '\u00E9 ' + documentLimit + ' ' + canary + '\n', {mode: 0o600});
  const loss = api.diagnostics(filename, jsonSources());
  assert.equal(loss.overlong_lines, 0);
  assert.equal(loss.file_failures.length, 1);
  assert.equal(loss.signals.document_limits[0].source_binding, 'UNBOUND');
  assert.ok(!JSON.stringify(loss).includes(canary));
}));
test('private analysis caches start empty, survive the child and are removed on every exit', () => temporary(async root => {
  const seen = new Set();
  const cases = [0, 7, 'exception'];
  await Promise.all(cases.map(async status => {
    let owned;
    const run = api.withPrivateRun(root, async directory => {
      owned = directory;
      const args = api.privateCacheArguments('-Dsonar.verbose=true', directory);
      const cache = path.join(directory, cacheName);
      assert.ok(args.endsWith(' -Dsonar.cfamily.analysisCache.mode=fs -Dsonar.cfamily.analysisCache.path=' + cache));
      assert.equal(fs.statSync(cache).mode & 0o777, 0o700);
      assert.deepEqual(fs.readdirSync(cache), []);
      assert.equal(seen.has(cache), false); seen.add(cache);
      if (status === 'exception') throw new Error('controlled failure');
      const fd = api.privateFile(directory, 'raw.log');
      try {
        const program = `require('node:fs').writeFileSync(${JSON.stringify(path.join(cache, 'entry'))}, 'cache');process.exit(${status})`;
        assert.equal(await api.runCaptured(process.execPath, ['-e', program], fd, {}, {timeout: 2000}), status);
        assert.equal(fs.existsSync(path.join(cache, 'entry')), true);
      } finally { fs.closeSync(fd); }
    });
    if (status === 'exception') await assert.rejects(run, /controlled failure/);
    else await run;
    assert.equal(fs.existsSync(owned), false);
  }));
  assert.equal(seen.size, 3);
}));
test('private cache creation rejects aliases, preexisting entries and argument tokenization', () => temporary(root => {
  const cache = path.join(root, cacheName);
  for (const args of ['-Dsonar.cfamily.analysisCache.mode=server', '-Dsonar.cfamily.analysisCache.path=/outside']) {
    assert.throws(() => api.privateCacheArguments(args, root));
    assert.equal(fs.existsSync(cache), false);
  }
  fs.writeFileSync(cache, canary);
  assert.throws(() => api.privateCacheArguments('', root)); fs.unlinkSync(cache);
  fs.symlinkSync(root, cache);
  assert.throws(() => api.privateCacheArguments('', root)); fs.unlinkSync(cache);
  fs.mkdirSync(cache);
  assert.throws(() => api.privateCacheArguments('', root)); fs.rmdirSync(cache);
  for (const suffix of [' space', "'quote", '"quote', String.raw`\escape`, '\tcontrol']) {
    const unsafe = root + suffix; fs.mkdirSync(unsafe);
    assert.throws(() => api.privateCacheArguments('', unsafe));
    assert.equal(fs.existsSync(path.join(unsafe, cacheName)), false);
  }
}));
test('CFamily version is a bounded observed literal, never a guessed default', () => {
  const result = api.emptyDiagnostics();
  assert.equal(result.cfamily_version, null);
  assert.equal(result.cfamily_version_status, 'NOT_OBSERVED');
  for (const line of [cfamilyVersionLine,
    '12:34:56.789 INFO  ' + cfamilyVersionLine + '\r\n',
    '2026-11-09T12:34:56.7890000Z 12:34:56.789 DEBUG ' + cfamilyVersionLine]) {
    api.acceptLine(result, line, new Map());
  }
  assert.equal(result.cfamily_version, cfamilyVersion);
  for (const value of [cfamilyVersion + ' ' + canary, '6.86', '9'.repeat(60000), cfamilyVersion + 'suffix']) {
    api.acceptLine(result, 'CFamily plugin version: ' + value, new Map());
  }
  api.acceptLine(result, canary + ' CFamily plugin version: 1.2.3.4', new Map());
  assert.equal(result.visibility.version_unmapped, 4);
  assert.equal(result.cfamily_version, cfamilyVersion);
  api.acceptLine(result, 'CFamily plugin version: 1.2.3.4', new Map());
  api.acceptLine(result, cfamilyVersionLine, new Map());
  assert.equal(result.cfamily_version, null);
  assert.equal(result.cfamily_version_status, 'CONFLICT');
  assert.ok(!JSON.stringify(result).includes(canary));
});
test('late overlong markers retain only finite visibility facts and never source bindings', () => temporary(root => {
  const filename = path.join(root, 'late.log');
  const marker = 'org.snakeyaml.engine.v2.exceptions.YamlEngineException:';
  // Split the class literal across the second raw-read boundary, after retention ended.
  const prefix = 'x'.repeat(131072 - 17);
  fs.writeFileSync(filename, prefix + marker + ' ' + documentLimit +
    ' [ParsingError] Cannot parse \'data/a.json:1:2\' ' + cfamilyVersionLine + ' ' +
    'org.yaml.snakeyaml.error.YAMLException: ' + canary + '\uFFFD WARN ERROR\n');
  const result = api.diagnostics(filename, jsonSources());
  assert.equal(result.overlong_lines, 1);
  assert.deepEqual(result.visibility.overlong_markers,
    {parsing: 1, cannotParse: 1, documentLimit: 1, cfamilyVersion: 1, snakeEngine: 1, snakeClassic: 1});
  assert.equal(result.visibility.decoder_loss_lines, 1);
  assert.equal(result.warnings.total, 1); assert.equal(result.errors.total, 1);
  assert.equal(result.parser_lines, 1); assert.equal(result.unmapped_parser_lines, 1);
  assert.deepEqual(result.locations, []); assert.deepEqual(result.file_failures, []);
  assert.deepEqual(result.signals.document_limits, []);
  assert.equal(result.cfamily_version, null);
  assert.deepEqual(result.visibility.exception_classes, {SNAKEYAML_ENGINE: 0, SNAKEYAML_CLASSIC: 0});
  assert.ok(!JSON.stringify(result).includes(canary));
}));
test('exception enums and per-limit binding reasons do not infer sensor ownership or reuse stale context', () => temporary(root => {
  const result = logDiagnostics(root, [jsonWarning(), engineLimit, stackFrame, classicLimit,
    '12:34:56.790 INFO Sensor hypothetical ' + canary, engineLimit,
    jsonWarning(), 'unexpected.Exception: ' + documentLimit,
    engineLimit, 'body ' + engineLimit, '\uFFFD' + engineLimit]);
  assert.deepEqual(result.visibility.exception_classes, {SNAKEYAML_ENGINE: 3, SNAKEYAML_CLASSIC: 1});
  assert.deepEqual(result.visibility.context_resets, {NEW_LOG_EVENT: 1, UNSUPPORTED_OR_INTERLEAVED_EVENT: 1});
  assert.deepEqual(result.visibility.document_binding_reasons,
    {VERIFIED_CONTIGUOUS_EVENT: 2, NO_ACTIVE_FILE_EVENT: 3, UNSUPPORTED_OR_INTERLEAVED_EVENT: 1, DECODER_LOSS: 1});
  assert.equal(result.signals.document_limits[0].source_binding, 'INVENTORY');
  assert.equal(result.signals.document_limits[1].source_binding, 'UNBOUND');
  assert.equal(result.diagnosis_complete, false);
  assert.ok(!JSON.stringify(result).includes(canary));
}));

// Prospective primary-log layouts, not claims about the deployed CFamily output.
const irFailureHeader = count => 'INFO: Encountered LLVM IR file generation failures for taint analysis for C and C++ for the following ' + count + ' translation unit(s):';
const irDropHeader = 'INFO: The following translation unit(s) had the most function definitions dropped during LLVM IR generation for taint analysis (up to 10 shown out of 1):';
function cfamilySources() {
  const sources = new Map([
    ['/fixture/src/a.c', {repository: 'framework', path: 'src/a.c'}],
    ['/fixture/src/b.c', {repository: 'product_fixture', path: 'src/b.c'}],
    ['/fixture/include/a.h', {repository: 'framework', path: 'include/a.h'}],
  ]);
  sources.roots = ['/fixture'];
  return sources;
}
function cfamilyLog(root, lines) {
  const filename = path.join(root, 'cfamily.log');
  fs.writeFileSync(filename, lines.join('\n') + '\n', {mode: 0o600});
  return api.diagnostics(filename, cfamilySources());
}
test('linear native event parsing preserves spaces and rejects embedded line terminators', () => temporary(root => {
  const spaced = nativeLines().map(line => line.replace(/ (WARN|DEBUG) /, ' $1     '));
  assert.equal(logDiagnostics(root, spaced).signals.document_limit_associations.length, 1);
  for (const ending of ['\ntrailing', '\rtrailing', '\u2028trailing', '\u2029trailing']) {
    const lines = nativeLines();
    lines[1] += ending;
    assert.deepEqual(logDiagnostics(root, lines).signals.document_limit_associations, []);
  }
}));
test('published failed IR list binds only exact trusted inventory paths and expected count', () => temporary(root => {
  const result = cfamilyLog(root, [irFailureHeader(2), '/fixture/src/a.c', '/fixture/src/b.c', '/fixture/include/a.h']);
  assert.deepEqual(result.cfamily_attribution.failed_ir_units.map(fact => [fact.repository, fact.path]),
    [['framework', 'src/a.c'], ['product_fixture', 'src/b.c']]);
  assert.ok(result.cfamily_attribution.failed_ir_units.every(fact => fact.category === 'IR_GENERATION_FAILURE' &&
    fact.association_status === 'PUBLISHED_LAYOUT_CORRELATED'));
  assert.equal(result.diagnosis_complete, false);
  assert.deepEqual(cfamilyLog(root, ['/fixture/src/a.c']).cfamily_attribution.failed_ir_units, []);
}));
test('IR dropped-function counts remain unbound and cannot consume an invented path layout', () => temporary(root => {
  const result = cfamilyLog(root, [irDropHeader, '1094 dropped in', '/fixture/src/a.c', '99 dropped in']);
  assert.deepEqual(result.cfamily_attribution.dropped_function_counts,
    [{category: 'IR_DROPPED_FUNCTIONS', count: 1094, source_binding: 'UNBOUND'}]);
  assert.deepEqual(result.cfamily_attribution.failed_ir_units, []);
  for (const number of ['2147483648', '99999999999', '-1', '1 ' + canary]) {
    assert.deepEqual(cfamilyLog(root, [irDropHeader, number + ' dropped in']).cfamily_attribution.dropped_function_counts, []);
  }
}));
test('published TU and header diagnostic grammar emits only fixed categories and inventory facts', () => temporary(root => {
  const result = cfamilyLog(root, ['/fixture/src/a.c:',
    "  /fixture/include/a.h:85 - unknown type name 'size_t'",
    "  /fixture/include/a.h:86 - use of undeclared identifier '" + canary + "'",
    "  /fixture/include/a.h:87 - module 'stdlib' requires feature 'compatible_headers'"]);
  assert.deepEqual(result.cfamily_attribution.parser_diagnostics.map(fact => [fact.path, fact.line, fact.category]),
    [['include/a.h', 85, 'UNKNOWN_TYPE'], ['include/a.h', 86, 'UNDECLARED_IDENTIFIER'], ['include/a.h', 87, 'MODULE_FEATURE']]);
  assert.ok(result.cfamily_attribution.parser_diagnostics.every(fact => fact.translation_unit.path === 'src/a.c'));
  assert.equal(result.diagnosis_complete, false);
  assert.ok(!JSON.stringify(result).includes(canary));
}));
test('CFamily contexts reject unknown identity severity paths messages capture loss and interleaving', () => temporary(root => {
  const diagnostic = "  /fixture/include/a.h:85 - unknown type name 'size_t'";
  for (const interruption of [canary, '', 'INFO: Sensor other', 'DEBUG: ' + canary,
    'INFO: [thread-2] ' + canary, '\u001b[31m', '\uFFFD', 'x'.repeat(70000)]) {
    const result = cfamilyLog(root, ['/fixture/src/a.c:', interruption, diagnostic]);
    assert.deepEqual(result.cfamily_attribution.parser_diagnostics, []);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  for (const invalid of ["  /outside/secret.h:85 - unknown type name 'size_t'",
    "  /fixture/../fixture/include/a.h:85 - unknown type name 'size_t'",
    "  /fixture/include/a.h:0 - unknown type name 'size_t'",
    "  /fixture/include/a.h:10000001 - unknown type name 'size_t'",
    diagnostic + ' ' + canary, '  /fixture/include/a.h:85 - ' + canary]) {
    const result = cfamilyLog(root, ['/fixture/src/a.c:', invalid, diagnostic]);
    assert.deepEqual(result.cfamily_attribution.parser_diagnostics, []);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  for (const invalid of ['/outside/secret.c', '/fixture/src/' + canary + '.c', '/fixture/src/a.c ' + canary]) {
    assert.deepEqual(cfamilyLog(root, [irFailureHeader(2), invalid, '/fixture/src/a.c']).cfamily_attribution.failed_ir_units, []);
  }
  const result = api.emptyDiagnostics(); const state = {};
  api.acceptLine(result, irFailureHeader(1), cfamilySources(), {}, state);
  api.acceptLine(result, '/fixture/src/a.c', cfamilySources(), {truncated: true}, state);
  assert.deepEqual(result.cfamily_attribution.failed_ir_units, []);
}));
test('CFamily attribution honors finite records and existing line and byte context budgets', () => temporary(root => {
  const lines = [];
  for (let n = 0; n < 140; n++) lines.push(irFailureHeader(1), '/fixture/src/a.c');
  const capped = cfamilyLog(root, lines);
  assert.equal(capped.cfamily_attribution.failed_ir_units.length, 128);
  assert.equal(capped.cfamily_attribution.truncated, 12);
  const repeated = new Array(32).fill("  /fixture/include/a.h:85 - unknown type name 'size_t'");
  const bounded = cfamilyLog(root, ['/fixture/src/a.c:', ...repeated]);
  assert.equal(bounded.cfamily_attribution.parser_diagnostics.length, 31);
  assert.equal(bounded.cfamily_attribution.resets.CONTEXT_BUDGET, 1);
  const bytes = cfamilyLog(root, [irFailureHeader(1), ' '.repeat(16400), '/fixture/src/a.c']);
  assert.deepEqual(bytes.cfamily_attribution.failed_ir_units, []);
  assert.equal(bytes.cfamily_attribution.resets.CONTEXT_BUDGET, 1);
}));
test('document reset shapes retain only finite neutral enums without changing unbound evidence', () => temporary(root => {
  const result = logDiagnostics(root, [jsonWarning(), '12:34:56.790 DEBUG ' + canary, engineLimit]);
  assert.deepEqual(result.visibility.document_reset_shapes,
    {severity: {DEBUG: 1}, payload: {OTHER: 1}, logger_presence: {ABSENT: 1}});
  assert.equal(result.visibility.context_resets.NEW_LOG_EVENT, 1);
  assert.equal(result.signals.document_limits[0].source_binding, 'UNBOUND');
  assert.equal(result.warnings.total, 1);
  assert.equal(result.diagnosis_complete, false);
  assert.ok(!JSON.stringify(result).includes(canary));
  const logger = logDiagnostics(root, [jsonWarning(), '12:34:56.790 INFO [' + canary + '] unknown.Logger - ' + canary]);
  assert.deepEqual(logger.visibility.document_reset_shapes.logger_presence, {UNRECOGNIZED: 1});
  assert.ok(!JSON.stringify(logger).includes(canary));
}));
test('linear long-space and newline rejection stays within a hard private deadline', () => temporary(root => {
  const program = String.raw`
    const assert = require('node:assert/strict');
    const api = require(${JSON.stringify(path.resolve(__dirname, '../../.github/actions/sonar-private/main.cjs'))});
    const spaces = ' '.repeat(60000);
    const result = api.emptyDiagnostics();
    for (let n = 0; n < 500; n++) {
      api.acceptLine(result, '12:34:56.789 DEBUG ' + spaces + '\ntrailing', new Map());
      api.acceptLine(result, '12:34:56.789 DEBUG ' + spaces, new Map());
    }
    assert.equal(result.diagnosis_complete, false);
    assert.deepEqual(result.signals.document_limit_associations, []);
  `;
  const result = spawnSync(process.execPath, ['-e', program], {encoding: 'utf8', timeout: 2500, env: {}});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0);
  assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
}));

test('consecutive trusted translation-unit contexts retain independent diagnostic ownership', () => temporary(root => {
  const diagnostic = number => "  /fixture/include/a.h:" + number + " - unknown type name 'size_t'";
  const result = cfamilyLog(root, ['/fixture/src/a.c:', diagnostic(85), '/fixture/src/b.c:', diagnostic(86)]);
  assert.deepEqual(result.cfamily_attribution.parser_diagnostics.map(fact => [fact.translation_unit.path, fact.line]),
    [['src/a.c', 85], ['src/b.c', 86]]);
  assert.equal(result.cfamily_attribution.resets.NEW_KNOWN_CONTEXT, 1);
  assert.equal(result.diagnosis_complete, false);
}));
test('published PARSE and IR sections replace old contexts without bridging ownership', () => temporary(root => {
  const diagnostic = "  /fixture/include/a.h:85 - unknown type name 'size_t'";
  const result = cfamilyLog(root, ['/fixture/src/a.c:', diagnostic,
    irFailureHeader(2), '/fixture/src/a.c', '/fixture/src/b.c:', diagnostic,
    irDropHeader, '1094 dropped in', irFailureHeader(1), '/fixture/src/b.c']);
  assert.deepEqual(result.cfamily_attribution.parser_diagnostics.map(fact => fact.translation_unit.path), ['src/a.c', 'src/b.c']);
  assert.deepEqual(result.cfamily_attribution.failed_ir_units.map(fact => fact.path), ['src/a.c', 'src/b.c']);
  assert.deepEqual(result.cfamily_attribution.dropped_function_counts,
    [{category: 'IR_DROPPED_FUNCTIONS', count: 1094, source_binding: 'UNBOUND'}]);
  assert.equal(result.cfamily_attribution.resets.NEW_KNOWN_CONTEXT, 4);
  assert.equal(result.diagnosis_complete, false);
}));
test('unknown malformed conflicting and lost replacement headers never revive the old context', () => temporary(root => {
  const diagnostic = "  /fixture/include/a.h:85 - unknown type name 'size_t'";
  for (const replacement of ['/outside/' + canary + '.c:',
    '/fixture/../fixture/src/b.c:', irFailureHeader(0), irFailureHeader('2147483648'),
    irFailureHeader(1) + ' ' + canary, 'DEBUG: ' + irFailureHeader(1).slice(6),
    'INFO: [' + canary + '] ' + irFailureHeader(1).slice(6)]) {
    const result = cfamilyLog(root, ['/fixture/src/a.c:', diagnostic, replacement, diagnostic, '/fixture/src/b.c']);
    assert.equal(result.cfamily_attribution.parser_diagnostics.length, 1);
    assert.equal(result.cfamily_attribution.parser_diagnostics[0].translation_unit.path, 'src/a.c');
    assert.deepEqual(result.cfamily_attribution.failed_ir_units, []);
    assert.ok(!JSON.stringify(result).includes(canary));
  }
  for (const flags of [{truncated: true}, {decoderLoss: true}]) {
    const result = api.emptyDiagnostics(); const state = {}; const sources = cfamilySources();
    api.acceptLine(result, '/fixture/src/a.c:', sources, {}, state);
    api.acceptLine(result, '/fixture/src/b.c:', sources, flags, state);
    api.acceptLine(result, diagnostic, sources, {}, state);
    assert.deepEqual(result.cfamily_attribution.parser_diagnostics, []);
    assert.equal(result.cfamily_attribution.resets.CAPTURE_LOSS, 1);
  }
}));
