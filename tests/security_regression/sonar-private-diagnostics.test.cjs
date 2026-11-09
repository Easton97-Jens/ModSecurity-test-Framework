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
  assert.equal(api.validateArguments(args, '/private', revision), args + ' -Dsonar.log.level=DEBUG -Dsonar.verbose=false');
  for (const bad of [args + ' -Dsonar.exclusions=**', args.replace(revision, 'master'), args.replace('compile_commands.json', 'partial.json')]) assert.throws(() => api.validateArguments(bad, '/private', revision));
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
    assert.equal(valid.args, args + ' -Dsonar.log.level=DEBUG -Dsonar.verbose=false');
    for (const modified of [args + ' -Dsonar.sources=common', args.replace('wait=true', 'wait=false'), args.replace('c++' + standard, 'c++99')]) assert.throws(() => api.profileArguments({...env, INPUT_ARGS: modified}, root, revision));
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
      const fd = api.privateFile(directory, 'raw.log');
      try {
        const program = options.limit ? 'process.stdout.write("x".repeat(100000))' : 'setInterval(()=>{},1000)';
        await api.runCaptured(process.execPath, ['-e', program], fd, {}, options);
      } finally { fs.closeSync(fd); }
    }), /captured child failed/);
    assert.equal(fs.existsSync(owned), false);
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
  const repository = path.resolve(__dirname, '../..');
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
