import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, writeFileSync, appendFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createAnomalyDetector } from '../src/soc/anomaly.mjs';
import { createEventStore } from '../src/soc/events.mjs';
import { createNativeAlerter } from '../src/soc/alerts.mjs';
import { classifyRecord, createAgentAudit, isSensitivePath } from '../src/soc/agent-audit.mjs';
import { createChecks, firewallFindings, defenderFindings, newExposedPorts, eventLogFindings } from '../src/soc/checks.mjs';
import { createFileWatcher, defaultWatchTargets } from '../src/soc/file-watch.mjs';
import { createMonitor } from '../src/soc/monitor.mjs';
import { attachPcStatus } from '../src/pc-status/routes.mjs';
import { createSampler } from '../src/pc-status/sampler.mjs';
import { createHistory } from '../src/pc-status/history.mjs';

const HOOK = fileURLToPath(new URL('../tools/agent-audit-hook.mjs', import.meta.url));
const feed = (detector, values) => values.map((v) => detector.update(typeof v === 'object' ? v : { cpu: v }));

// ---------- 이상 탐지 ----------
test('이상 탐지: 기준 수집 전에는 급증 규칙을 평가하지 않는다', () => {
  const last = feed(createAnomalyDetector(), [5, 5, 5, 90]).at(-1);
  assert.equal(last.cpu.learning, true);
  assert.ok(!last.cpu.reasons.some((r) => r.ruleId === 'CPU-SPIKE'));
});

test('이상 탐지: CPU 급증은 주의(warn), 규칙 id·기준선·증가폭을 근거로 남긴다', () => {
  const last = feed(createAnomalyDetector(), [5, 5, 5, 5, 5, 5, 60]).at(-1);
  assert.equal(last.cpu.level, 'warn');
  const reason = last.cpu.reasons.find((r) => r.ruleId === 'CPU-SPIKE');
  assert.equal(reason.evidence.baseline, 5);
  assert.equal(reason.evidence.delta, 55);
  assert.ok(reason.text.length > 0);
});

test('이상 탐지: CPU 지속 고부하는 85%·2회 주의, 95%·3회 이상(critical)', () => {
  assert.equal(feed(createAnomalyDetector(), [90, 88]).at(-1).cpu.reasons[0].ruleId, 'CPU-HIGH');
  assert.equal(feed(createAnomalyDetector(), [90]).at(-1).cpu.level, 'normal');
  const crit = feed(createAnomalyDetector(), [97, 98, 99]).at(-1);
  assert.equal(crit.cpu.level, 'critical');
  assert.equal(crit.cpu.reasons[0].ruleId, 'CPU-CRIT');
});

test('이상 탐지: 메모리 높음·급증, 디스크 부족·급감', () => {
  const mem = (values) => feed(createAnomalyDetector(), values.map((v) => ({ memoryPercent: v }))).at(-1).memory;
  assert.equal(mem([86]).level, 'warn');
  assert.equal(mem([93]).level, 'critical');
  assert.ok(mem([40, 40, 40, 40, 40, 40, 50]).reasons.some((r) => r.ruleId === 'MEM-SURGE'));
  const disk = (values) => feed(createAnomalyDetector(), values).at(-1).disk;
  assert.equal(disk([{ diskFreePercent: 12 }]).level, 'warn');
  assert.equal(disk([{ diskFreePercent: 5 }]).level, 'critical');
  assert.ok(disk([...Array(6).fill({ diskFreePercent: 50, diskFreeGb: 200 }), { diskFreePercent: 48, diskFreeGb: 190 }]).reasons.some((r) => r.ruleId === 'DISK-DROP'));
});

test('이상 탐지: 읽지 못한 값은 unknown 이며 정상으로 바꾸지 않는다, 평온한 값은 normal', () => {
  const unknown = createAnomalyDetector().update({});
  assert.equal(unknown.cpu.level, 'unknown');
  assert.equal(unknown.memory.level, 'unknown');
  const calm = feed(createAnomalyDetector(), [{ cpu: 5, memoryPercent: 50, diskFreePercent: 60, diskFreeGb: 200 }, { cpu: 6, memoryPercent: 50, diskFreePercent: 60, diskFreeGb: 200 }]).at(-1);
  assert.equal(calm.overall, 'normal');
});

// ---------- 사건 저장소 ----------
test('사건 저장소: 같은 key 는 확인 전·쿨다운 안에서 횟수만 올리고 새 경보를 만들지 않는다', () => {
  let t = 0;
  const store = createEventStore({ now: () => new Date(t), cooldownMs: 1000 });
  const first = store.add({ severity: 'critical', source: 's', title: 'x', key: 'k' });
  assert.equal(first.created, true);
  t = 500;
  const second = store.add({ severity: 'critical', source: 's', title: 'x', key: 'k' });
  assert.equal(second.created, false);
  assert.equal(second.event.count, 2);
  t = 2000;
  assert.equal(store.add({ severity: 'critical', source: 's', title: 'x', key: 'k' }).created, true);
  assert.equal(store.counts().unackedCritical, 2);
});

test('사건 저장소: 확인(ack)하면 긴급 미확인 수가 줄고 구독자에게 알린다', () => {
  const store = createEventStore();
  const seen = [];
  store.subscribe((type, payload) => seen.push(type));
  const { event } = store.add({ severity: 'critical', source: 's', title: 'x' });
  store.add({ severity: 'medium', source: 's', title: 'y' });
  assert.equal(store.ack(event.id), true);
  assert.equal(store.ack(event.id), false);
  assert.equal(store.counts().unackedCritical, 0);
  assert.deepEqual(seen, ['created', 'created', 'ack']);
  assert.throws(() => store.add({ severity: 'bogus', source: 's', title: 'x' }));
});

test('사건 저장소: 최대 건수를 넘으면 오래된 것부터 버린다', () => {
  const store = createEventStore({ max: 3 });
  for (let i = 0; i < 7; i++) store.add({ severity: 'info', source: 's', title: `e${i}` });
  assert.deepEqual(store.list().map((e) => e.title), ['e6', 'e5', 'e4']);
});

// ---------- 경보(Windows 팝업) ----------
test('경보: 긴급만 팝업을 띄우고, 메시지는 환경 변수로 넘기며, 쿨다운 안에서는 막는다', () => {
  let t = 0; const launched = [];
  const alerter = createNativeAlerter({ enabled: true, platform: 'win32', cooldownMs: 30000, now: () => t, launch: (env) => launched.push(env) });
  assert.equal(alerter.alert({ severity: 'high', title: 'a' }), 'not-critical');
  assert.equal(alerter.alert({ severity: 'critical', title: '방화벽\u0000 꺼짐', detail: 'd', test: false }), 'launched');
  assert.equal(alerter.alert({ severity: 'critical', title: 'b' }), 'cooldown');
  t = 31000;
  assert.equal(alerter.alert({ severity: 'critical', title: 'c', test: true }), 'launched');
  assert.equal(launched.length, 2);
  assert.ok(!launched[0].SOC_ALERT_TEXT.includes('\u0000'));
  assert.match(launched[1].SOC_ALERT_TITLE, /시험/);
  assert.match(launched[1].SOC_ALERT_TEXT, /실제 사건 아님/);
});

test('경보: 꺼져 있거나 Windows 가 아니면 띄우지 않는다', () => {
  assert.equal(createNativeAlerter({ enabled: false, launch: () => { throw Error('x'); } }).alert({ severity: 'critical' }), 'disabled');
  assert.equal(createNativeAlerter({ enabled: true, platform: 'linux', launch: () => { throw Error('x'); } }).alert({ severity: 'critical' }), 'disabled');
});

// ---------- 에이전트 감사 ----------
test('에이전트 감사: 민감 경로는 긴급, 작업 폴더 밖은 주의, 작업 폴더 안은 판정 없음', () => {
  const base = { agent: 'claude-code', cwd: 'C:\\work\\proj' };
  assert.equal(classifyRecord({ ...base, tool: 'Read', targets: ['C:\\Users\\u\\.ssh\\id_rsa'] }).findings[0].ruleId, 'AGENT-SENSITIVE');
  assert.equal(classifyRecord({ ...base, tool: 'Read', targets: ['C:\\work\\proj\\src\\a.js'] }).findings.length, 0);
  assert.equal(classifyRecord({ ...base, tool: 'Read', targets: ['D:\\other\\x.txt'] }).findings[0].ruleId, 'AGENT-OUTSIDE');
  assert.equal(classifyRecord({ ...base, tool: 'Read', targets: ['D:\\other\\x.txt'] }, { allowedRoots: ['D:\\other'] }).findings.length, 0);
  assert.equal(classifyRecord({ ...base, tool: 'Bash', command: 'cat ~/.ssh/id_ed25519' }).findings[0].ruleId, 'AGENT-SENSITIVE');
  assert.equal(classifyRecord({ ...base, tool: 'PowerShell', command: 'Get-Content "C:\\Users\\u\\.env"' }).findings[0].ruleId, 'AGENT-SENSITIVE');
  assert.equal(classifyRecord({ ...base, tool: 'Bash', command: 'npm test' }).findings.length, 0);
  for (const path of ['C:/Users/u/.aws/credentials', 'C:/p/.env.production', 'C:/x/server.pem', 'C:/Users/u/AppData/Local/Google/Chrome/User Data/Default/Login Data']) assert.equal(isSensitivePath(path), true, path);
  assert.equal(isSensitivePath('C:/p/src/environment.ts'), false);
});

function auditSetup(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'soc-audit-'));
  const file = join(dir, 'agent-audit.jsonl');
  let t = Date.parse('2026-10-27T01:00:00Z');
  const store = createEventStore({ now: () => new Date(t) });
  const audit = createAgentAudit({ file, store, now: () => t, ...extra });
  const line = (o) => `${JSON.stringify({ at: new Date(t).toISOString(), agent: 'claude-code', session: 's1', cwd: 'C:\\work\\proj', targets: [], ...o })}\n`;
  return { dir, file, store, audit, line, advance: (ms) => { t += ms; } };
}

test('에이전트 감사: 파일이 없으면 수집 안 함 상태이고, 기록을 읽으면 사건과 집계가 생긴다', () => {
  const { dir, file, store, audit, line } = auditSetup();
  try {
    assert.equal(audit.status().state, 'not_configured');
    writeFileSync(file, line({ tool: 'Read', targets: ['C:\\work\\proj\\a.js'] }) + line({ tool: 'Read', targets: ['C:\\Users\\u\\.ssh\\id_rsa'] }) + 'not json\n' + line({ tool: 'Read', targets: ['D:\\x\\y.txt'] }));
    audit.poll();
    const status = audit.status();
    assert.equal(status.state, 'active');
    assert.equal(status.counts.calls, 3);
    assert.equal(status.counts.sensitive, 1);
    assert.equal(status.counts.outside, 1);
    const severities = store.list().map((e) => e.severity).sort();
    assert.deepEqual(severities, ['critical', 'medium']);
    assert.equal(store.list().find((e) => e.severity === 'critical').rule.id, 'AGENT-SENSITIVE');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('에이전트 감사: 줄이 끝나지 않은 기록은 완성될 때까지 읽지 않고, 파일이 줄면 처음부터 다시 읽는다', () => {
  const { dir, file, store, audit, line } = auditSetup();
  try {
    const full = line({ tool: 'Read', targets: ['C:\\Users\\u\\.ssh\\id_rsa'] });
    writeFileSync(file, full.slice(0, 30));
    audit.poll();
    assert.equal(store.list().length, 0);
    appendFileSync(file, full.slice(30));
    audit.poll();
    assert.equal(store.list().length, 1);
    // 파일이 더 길어진 뒤(읽은 위치가 커진 뒤) 짧은 새 파일로 바뀌는 순환(rotate) 상황
    appendFileSync(file, line({ tool: 'Read', targets: [`C:\\work\\proj\\${'x'.repeat(300)}`] }));
    audit.poll();
    writeFileSync(file, line({ tool: 'Read', targets: ['C:\\Users\\u\\.aws\\credentials'], cwd: 'C:\\w' }));
    audit.poll();
    assert.equal(store.list().length, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('에이전트 감사: 1분 안에 파일 도구 100회 이상이면 높음 사건을 한 번만 만든다', () => {
  const { dir, file, store, audit, line } = auditSetup();
  try {
    writeFileSync(file, Array.from({ length: 120 }, (_, i) => line({ tool: 'Read', targets: [`C:\\work\\proj\\f${i}.js`] })).join(''));
    audit.poll();
    const bursts = store.list().filter((e) => e.rule && e.rule.id === 'AGENT-BURST');
    assert.equal(bursts.length, 1);
    assert.equal(bursts[0].severity, 'high');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('에이전트 훅: 기록을 한 줄 남기고, 비밀 값을 지우고, 아무것도 출력하지 않고 0으로 끝난다', () => {
  const dir = mkdtempSync(join(tmpdir(), 'soc-hook-'));
  const file = join(dir, 'nested', 'a.jsonl');
  try {
    const input = JSON.stringify({ session_id: 'abc', cwd: 'C:\\work\\proj', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'curl -H "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz" https://x --password hunter2' } });
    const run = spawnSync(process.execPath, [HOOK], { input, env: { ...process.env, ON_SOC_AUDIT_FILE: file }, encoding: 'utf8' });
    assert.equal(run.status, 0);
    assert.equal(run.stdout, '');
    const record = JSON.parse(readFileSync(file, 'utf8').trim());
    assert.equal(record.tool, 'Bash');
    assert.equal(record.cwd, 'C:\\work\\proj');
    assert.ok(!record.command.includes('sk-abcdefghijklmnop'));
    assert.ok(!record.command.includes('hunter2'));
    assert.match(record.command, /삭제됨/);
    const read = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ cwd: 'C:\\w', tool_name: 'Read', tool_input: { file_path: 'C:\\w\\a.txt' } }), env: { ...process.env, ON_SOC_AUDIT_FILE: file }, encoding: 'utf8' });
    assert.equal(read.status, 0);
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8').trim().split('\n')[1]).targets, ['C:\\w\\a.txt']);
    const garbage = spawnSync(process.execPath, [HOOK], { input: '이건 JSON 이 아님', env: { ...process.env, ON_SOC_AUDIT_FILE: join(dir, 'none.jsonl') }, encoding: 'utf8' });
    assert.equal(garbage.status, 0);
    assert.equal(existsSync(join(dir, 'none.jsonl')), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------- 보안 점검 규칙 ----------
const profiles = (...states) => ({ status: 'measured', measuredAt: 't', profiles: states.map((enabled, i) => ({ name: ['Domain', 'Private', 'Public'][i], enabled })) });
test('보안 점검 규칙: 방화벽 모두 꺼짐은 긴급, 일부는 높음, 켜져 있거나 읽지 못하면 사건 없음', () => {
  assert.equal(firewallFindings(profiles('off', 'off', 'off'))[0].severity, 'critical');
  assert.equal(firewallFindings(profiles('on', 'off', 'on'))[0].severity, 'high');
  assert.equal(firewallFindings(profiles('on', 'on', 'on')).length, 0);
  assert.equal(firewallFindings({ status: 'unavailable' }).length, 0);
});

test('보안 점검 규칙: Defender 실시간 보호 꺼짐은 긴급, 서명 7일 초과는 주의, 확인 불가는 사건 없음', () => {
  assert.equal(defenderFindings({ status: 'measured', realTime: false, antivirus: true, signatureAgeDays: 0 })[0].ruleId, 'DEF-RT-OFF');
  assert.equal(defenderFindings({ status: 'measured', realTime: true, antivirus: true, signatureAgeDays: 9 })[0].severity, 'medium');
  assert.equal(defenderFindings({ status: 'measured', realTime: true, antivirus: true, signatureAgeDays: 1 }).length, 0);
  assert.equal(defenderFindings({ status: 'unavailable' }).length, 0);
  assert.equal(defenderFindings({ status: 'measured', realTime: null, antivirus: null, signatureAgeDays: null }).length, 0);
});

test('보안 점검 규칙: 기준선에 없던 외부 접근 포트만 높음, 기록 오류는 10건 이상 늘 때만 주의', () => {
  const baseline = [{ port: 80, process: 'a', exposed: true }];
  const current = { status: 'measured', ports: [{ port: 80, process: 'a', exposed: true }, { port: 9999, process: 'evil', exposed: true, address: '0.0.0.0' }, { port: 7000, process: 'local', exposed: false, address: '127.0.0.1' }] };
  const found = newExposedPorts(baseline, current);
  assert.equal(found.length, 1);
  assert.equal(found[0].evidence.port, 9999);
  assert.equal(newExposedPorts(null, current).length, 0);
  const events = (n) => ({ status: 'measured', logs: { System: { errors: { status: 'measured', value: n } }, Application: { errors: { status: 'measured', value: 0 } } } });
  assert.equal(eventLogFindings(30, events(35)).length, 0);
  assert.equal(eventLogFindings(30, events(41))[0].ruleId, 'LOG-SURGE');
  assert.equal(eventLogFindings(null, events(99)).length, 0);
});

test('보안 점검 읽기: Defender 와 수신 포트 응답을 해석하고, 실패는 확인 불가로 둔다', async () => {
  const now = () => new Date('2026-10-27T00:00:00Z');
  const ok = createChecks({ now, run: async (script) => (script.includes('Get-MpComputerStatus') ? JSON.stringify({ realTime: 'True', antivirus: 'False', signatureUpdated: '2026-10-25T00:00:00.0000000Z' }) : JSON.stringify([{ port: 80, address: '0.0.0.0', process: 'nginx' }, { port: 80, address: '::', process: 'nginx' }, { port: 5000, address: '127.0.0.1', process: null }])) });
  const defender = await ok.readDefender();
  assert.equal(defender.realTime, true);
  assert.equal(defender.antivirus, false);
  assert.equal(defender.signatureAgeDays, 2);
  const ports = await ok.readPorts();
  assert.equal(ports.exposedCount, 1);
  assert.equal(ports.total, 3);
  const denied = createChecks({ now, run: async () => JSON.stringify({ error: 'UnauthorizedAccessException' }) });
  assert.equal((await denied.readDefender()).code, 'PERMISSION');
  const slow = createChecks({ now, run: async () => { throw Object.assign(new Error('t'), { code: 'TIMEOUT' }); } });
  assert.equal((await slow.readPorts()).code, 'TIMEOUT');
  assert.equal((await createChecks({ now, run: async () => 'garbage' }).readDefender()).status, 'unavailable');
});

// ---------- 폴더 변경 감시 ----------
test('폴더 감시: 민감 폴더의 변경은 긴급, 1초 안의 중복은 무시, 대량 변경은 높음', () => {
  let t = 0;
  const store = createEventStore({ now: () => new Date(t) });
  const watcher = createFileWatcher({ targets: [], store, now: () => t, burstLimit: 5, burstWindowMs: 10000 });
  const sensitive = { dir: 'C:\\Users\\u\\.ssh', sensitive: true };
  watcher.onChange(sensitive, 'change', 'id_rsa');
  watcher.onChange(sensitive, 'change', 'id_rsa');
  assert.equal(store.list().filter((e) => e.severity === 'critical').length, 1);
  const plain = { dir: 'C:\\work', sensitive: false };
  for (let i = 0; i < 5; i++) { t += 1500; watcher.onChange(plain, 'change', `f${i}`); }
  assert.equal(store.list().filter((e) => e.rule && e.rule.id === 'FILE-BURST').length, 1);
  assert.equal(store.list().filter((e) => e.rule && e.rule.id === 'FILE-SENSITIVE-CHANGE').length, 1);
  const targets = defaultWatchTargets({ home: 'C:\\Users\\u', exists: (dir) => dir.endsWith('.ssh') || dir === 'C:\\extra', extra: ['C:\\extra', 'C:\\missing'] });
  assert.deepEqual(targets.map((x) => [x.dir.split('\\').pop(), x.sensitive]), [['.ssh', true], ['extra', false]]);
});

// ---------- 감시 루프 ----------
function fakeSampler(values) {
  let i = 0;
  return { sample() { const v = values[Math.min(i++, values.length - 1)]; return { measuredAt: 't', cpu: { status: 'measured', value: v.cpu }, memory: { status: 'measured', value: 8, percent: v.mem ?? 50, totalGb: 16 }, disk: { status: 'measured', value: 200, totalGb: 400 } }; } };
}
const fakeReader = (firewall) => ({ readFirewall: async () => firewall, readEvents: async () => ({ status: 'measured', logs: { System: { errors: { status: 'measured', value: 1 }, warnings: { status: 'measured', value: 1 } }, Application: { errors: { status: 'measured', value: 0 }, warnings: { status: 'measured', value: 0 } } } }), readNetwork: () => ({ status: 'measured', adapters: [] }) });

test('감시 루프: CPU 급증은 주의 사건, 정상 복귀는 정보 사건을 만든다', () => {
  const store = createEventStore();
  const samples = [...Array(7).fill({ cpu: 5 }), { cpu: 70 }, ...Array(12).fill({ cpu: 5 })];
  const monitor = createMonitor({ sampler: fakeSampler(samples), store, anomaly: createAnomalyDetector(), securityReader: fakeReader(null), checks: { readDefender: async () => ({ status: 'unavailable' }), readPorts: async () => ({ status: 'unavailable' }) } });
  for (let i = 0; i < samples.length; i++) monitor.tick();
  const events = store.list().reverse();
  const spike = events.find((e) => e.rule && e.rule.id === 'CPU-SPIKE');
  assert.equal(spike.severity, 'medium');
  assert.equal(spike.source, 'metrics');
  assert.ok(events.some((e) => e.severity === 'info' && /정상 범위/.test(e.title)));
  assert.equal(monitor.snapshot().points.length, samples.length);
});

test('감시 루프: 방화벽이 모두 꺼지면 긴급 사건과 경보가 한 번만 나오고, 새 포트는 기준선 이후에만 알린다', async () => {
  const store = createEventStore();
  const alerts = [];
  let ports = [{ port: 80, address: '0.0.0.0', process: 'a' }];
  const checks = { readDefender: async () => ({ status: 'measured', realTime: true, antivirus: true, signatureAgeDays: 0 }), readPorts: async () => ({ status: 'measured', ports: ports.map((p) => ({ ...p, exposed: p.address === '0.0.0.0' })) }) };
  const monitor = createMonitor({ sampler: fakeSampler([{ cpu: 5 }]), store, anomaly: createAnomalyDetector(), checks, alerter: { alert: (e) => alerts.push(e), status: () => ({}) }, securityReader: fakeReader({ status: 'measured', measuredAt: 't', profiles: [{ name: 'Domain', enabled: 'off' }, { name: 'Private', enabled: 'off' }, { name: 'Public', enabled: 'off' }] }) });
  await monitor.slowTick();
  assert.equal(store.list().filter((e) => e.rule && e.rule.id === 'FW-OFF-ALL').length, 1);
  assert.equal(store.list().filter((e) => e.rule && e.rule.id === 'PORT-NEW-EXPOSED').length, 0);
  ports = [...ports, { port: 4444, address: '0.0.0.0', process: 'x' }];
  await monitor.slowTick();
  assert.equal(store.list().filter((e) => e.rule && e.rule.id === 'PORT-NEW-EXPOSED').length, 1);
  assert.equal(store.list().filter((e) => e.rule && e.rule.id === 'FW-OFF-ALL').length, 1);
  assert.equal(alerts.filter((e) => e.severity === 'critical').length, 1);
});

test('감시 루프: 시험 경보는 test 표시가 붙고 5초에 한 번만 만든다', () => {
  let t = 0;
  const store = createEventStore({ now: () => new Date(t) });
  const alerts = [];
  const monitor = createMonitor({ sampler: fakeSampler([{ cpu: 5 }]), store, anomaly: createAnomalyDetector(), securityReader: fakeReader(null), checks: {}, alerter: { alert: (e) => alerts.push(e), status: () => ({}) }, now: () => new Date(t) });
  const first = monitor.testAlert();
  assert.equal(first.test, true);
  assert.equal(first.severity, 'critical');
  assert.equal(monitor.testAlert(), null);
  t = 6000;
  assert.ok(monitor.testAlert());
  assert.equal(alerts.length, 2);
});

// ---------- 서버: 실시간 전송과 확인 ----------
async function startSoc() {
  const server = http.createServer((req, res) => { res.writeHead(200); res.end('original'); });
  const store = createEventStore();
  const monitor = createMonitor({ sampler: fakeSampler([{ cpu: 5 }]), store, anomaly: createAnomalyDetector(), securityReader: fakeReader(null), checks: {} });
  const sampler = createSampler({ osModule: { cpus: () => [{ times: { user: 1, nice: 0, sys: 1, idle: 1, irq: 0 } }], totalmem: () => 2 ** 33, freemem: () => 2 ** 32 }, fsModule: { statfsSync: () => ({ blocks: 10, bsize: 2 ** 30, bavail: 5 }) } });
  attachPcStatus(server, { sampler, history: createHistory(), soc: { store, monitor } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, store, monitor, port: server.address().port };
}
const request = (port, path, { method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
  const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => { let text = ''; res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, text, headers: res.headers })); });
  req.on('error', reject);
  if (body !== undefined) req.write(body);
  req.end();
});

test('서버: 스냅샷을 주고, 확인(ack)은 같은 출처의 JSON 요청만 받는다', async () => {
  const { server, store, port } = await startSoc();
  try {
    const { event } = store.add({ severity: 'critical', source: 's', title: 'x' });
    const snap = JSON.parse((await request(port, '/api/soc/snapshot')).text);
    assert.equal(snap.data.counts.unackedCritical, 1);
    const origin = `http://127.0.0.1:${port}`;
    const json = { 'content-type': 'application/json', origin };
    assert.equal((await request(port, '/api/soc/ack', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: event.id }) })).status, 403);
    assert.equal((await request(port, '/api/soc/ack', { method: 'POST', headers: { origin, 'content-type': 'text/plain' }, body: '{}' })).status, 415);
    assert.equal((await request(port, '/api/soc/ack', { method: 'POST', headers: json, body: '{bad' })).status, 400);
    assert.equal((await request(port, '/api/soc/ack', { method: 'POST', headers: { ...json, 'sec-fetch-site': 'cross-site' }, body: '{}' })).status, 403);
    assert.equal((await request(port, '/api/soc/snapshot?x=1')).status, 400);
    assert.equal((await request(port, '/api/soc/snapshot', { headers: { host: 'evil.example' } })).status, 403);
    const ack = await request(port, '/api/soc/ack', { method: 'POST', headers: json, body: JSON.stringify({ id: event.id }) });
    assert.equal(ack.status, 200);
    assert.equal(JSON.parse(ack.text).data.counts.unackedCritical, 0);
    assert.equal((await request(port, '/api/soc/ack', { method: 'POST', headers: json, body: JSON.stringify({ id: event.id }) })).status, 404);
  } finally { server.close(); server.closeAllConnections?.(); }
});

test('서버: 시험 경보 요청은 test 사건을 만들고 5초 안의 반복은 429', async () => {
  const { server, port } = await startSoc();
  try {
    const headers = { 'content-type': 'application/json', origin: `http://127.0.0.1:${port}` };
    const first = await request(port, '/api/soc/test-alert', { method: 'POST', headers, body: '{}' });
    assert.equal(first.status, 200);
    assert.equal(JSON.parse(first.text).data.event.test, true);
    assert.equal((await request(port, '/api/soc/test-alert', { method: 'POST', headers, body: '{}' })).status, 429);
  } finally { server.close(); server.closeAllConnections?.(); }
});

test('서버: 실시간 스트림은 처음에 snapshot 을 주고, 새 사건과 확인을 바로 밀어 준다', async () => {
  const { server, store, port } = await startSoc();
  try {
    const received = [];
    const done = new Promise((resolve, reject) => {
      const req = http.get({ host: '127.0.0.1', port, path: '/api/soc/stream' }, (res) => {
        assert.equal(res.headers['content-type'].split(';')[0], 'text/event-stream');
        let buffer = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          buffer += chunk;
          for (const block of buffer.split('\n\n').slice(0, -1)) { const m = block.match(/^event: (\w+)\ndata: (.*)$/m); if (m) received.push([m[1], JSON.parse(m[2])]); }
          buffer = buffer.slice(buffer.lastIndexOf('\n\n') + 2);
          if (received.length === 1) { const { event } = store.add({ severity: 'critical', source: 's', title: '실시간' }); setTimeout(() => store.ack(event.id), 20); }
          if (received.length >= 3) { req.destroy(); resolve(); }
        });
      });
      req.on('error', (error) => (error.code === 'ECONNRESET' ? resolve() : reject(error)));
      setTimeout(() => { req.destroy(); resolve(); }, 3000);
    });
    await done;
    assert.deepEqual(received.map(([name]) => name), ['snapshot', 'event', 'ack']);
    assert.equal(received[1][1].event.title, '실시간');
    assert.equal(received[2][1].counts.unackedCritical, 0);
  } finally { server.close(); server.closeAllConnections?.(); }
});
