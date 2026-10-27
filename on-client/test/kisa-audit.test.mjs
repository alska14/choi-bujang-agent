import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, createKisaAudit, ITEMS } from '../src/soc/kisa-audit.mjs';

const NOW = new Date('2026-10-27T00:00:00Z');
const base = () => ({
  maxPwAge: '42', minPwLen: '0', recoveryLevel: '0', shares: [{ name: 'ADMIN$', type: 2147483648 }, { name: 'C$', type: 2147483648 }, { name: 'IPC$', type: 2147483651 }],
  services: [{ name: 'SSDPSRV', display: 'SSDP Discovery', status: 'Running', start: 'Manual' }, { name: 'Spooler', display: 'Print Spooler', status: 'Running', start: 'Automatic' }],
  messengers: ['카카오톡'], messengerProcs: [], volumes: [{ id: 'C:', fs: 'NTFS' }], iePersistent: '1', edgePolicy: [], chromePolicy: [],
  wuHistory: [{ title: '2026-10 보안 업데이트 (KB5127648)', at: '2026-10-13T00:00:00Z' }, { title: 'Store app 9NRZ', at: '2026-10-26T00:00:00Z' }],
  os: { build: '26100', ubr: '9711', edition: 'Professional', display: '24H2' }, autoAdminLogon: '1',
  defender: { av: true, rt: true, ageDays: 0, at: '2026-10-26T00:00:00Z' }, avProducts: [{ name: 'Windows Defender', state: 397568 }], fwProducts: [],
  fwProfiles: [{ name: 'Domain', enabled: 'True' }, { name: 'Private', enabled: 'True' }, { name: 'Public', enabled: 'False' }],
  screen: { active: '1', timeout: null, secure: null, exe: null }, autoplay: { disable: '0' }, remoteAssist: '1', elevated: false,
});
const byCode = (items) => Object.fromEntries(items.map((i) => [i.code, i]));

test('KISA 점검: 워크시트의 18개 항목을 모두 판정하고, 이 PC와 같은 상태에서 기대한 결과가 나온다', () => {
  const r = byCode(evaluate(base(), NOW));
  assert.equal(Object.keys(r).length, 18);
  assert.deepEqual(ITEMS.map((i) => i.code), Array.from({ length: 18 }, (_, i) => `PC-${String(i + 1).padStart(2, '0')}`));
  assert.equal(r['PC-01'].verdict, 'good');
  assert.equal(r['PC-02'].verdict, 'vuln'); // 최소 길이 0
  assert.equal(r['PC-04'].verdict, 'vuln'); // 기본 관리 공유
  assert.equal(r['PC-05'].verdict, 'vuln'); // SSDP 실행 중
  assert.equal(r['PC-06'].verdict, 'vuln');
  assert.equal(r['PC-08'].verdict, 'manual'); // 관리자 권한 없이는 읽지 못함
  assert.equal(r['PC-10'].verdict, 'good');
  assert.match(r['PC-10'].evidence, /KB5127648/); // 스토어 앱 업데이트는 보안 패치로 치지 않음
  assert.equal(r['PC-11'].verdict, 'vuln'); // 24H2 Home/Pro 는 2026-10-13 종료
  assert.equal(r['PC-12'].verdict, 'vuln');
  assert.equal(r['PC-15'].verdict, 'vuln');
  assert.equal(r['PC-16'].verdict, 'vuln');
  assert.equal(r['PC-17'].verdict, 'vuln');
  assert.equal(r['PC-18'].verdict, 'vuln');
  assert.ok(r['PC-12'].fixes.some((f) => f.id === 'autologon-off' && f.admin));
  assert.deepEqual(r['PC-03'].fixes, []); // 양호하면 자동 조치를 내놓지 않는다
});

test('KISA 점검: 경계값 — 25H2 는 지원 중, 화면보호기 대체 통제는 판단 필요, 비밀번호 무제한은 취약', () => {
  const f = base();
  f.os.build = '26200'; f.maxPwAge = 'Unlimited'; f.screen = { active: '0', inactivity: '600' };
  const r = byCode(evaluate(f, NOW));
  assert.equal(r['PC-11'].verdict, 'good');
  assert.equal(r['PC-16'].verdict, 'review');
  assert.equal(r['PC-01'].verdict, 'vuln');
});

function fakeExec(log, codes = {}) {
  return async (script) => {
    log.push(script);
    if (script.includes('ConvertTo-Json -Compress -Depth 5')) return { code: 0, stdout: JSON.stringify(base()) };
    for (const [needle, code] of Object.entries(codes)) if (script.includes(needle)) return { code, stdout: '' };
    return { code: 0, stdout: '' };
  };
}
const memFs = () => { const files = new Map(); return { readFileSync: (p) => { if (!files.has(p)) throw Error('ENOENT'); return files.get(p); }, writeFileSync: (p, v) => files.set(p, v), renameSync: (a, b) => { files.set(b, files.get(a)); files.delete(a); }, mkdirSync: () => {} }; };

test('KISA 조치: 승인 표 없이는 실행하지 않고, 표는 한 번만 쓰이며, 관리자 조치는 UAC(RunAs)로만 실행한다', async () => {
  const log = [];
  const audit = createKisaAudit({ exec: fakeExec(log), logFile: 'log.json', fs: memFs(), now: () => NOW });
  assert.match(audit.preview({ code: 'PC-12', fixId: 'autologon-off' }).error, /점검/);
  await audit.run();
  const p = audit.preview({ code: 'PC-12', fixId: 'autologon-off' });
  assert.equal(p.admin, true);
  assert.match(p.script, /AutoAdminLogon/);
  assert.equal((await audit.apply('가짜')).error !== undefined, true);
  const done = await audit.apply(p.token);
  assert.equal(done.outcome, 'done');
  assert.ok(log.some((s) => s.includes('-Verb RunAs') && s.includes('-EncodedCommand')));
  assert.ok((await audit.apply(p.token)).error, '같은 표는 다시 쓸 수 없다');
  const [entry] = audit.state().history;
  assert.equal(entry.code, 'PC-12');
  const undo = audit.preview({ undoId: entry.id });
  assert.match(undo.script, /AutoAdminLogon' -Value '1'/); // 조치 전 값 '1' 로 되돌림
  assert.equal((await audit.apply(undo.token)).outcome, 'done');
  assert.ok(audit.state().history[0].undoneAt);
});

test('KISA 조치: UAC 를 거절하면 취소로 기록하고, 사용자 범위 조치는 RunAs 없이 실행한다', async () => {
  const log = [];
  const audit = createKisaAudit({ exec: fakeExec(log, { '-Verb RunAs': 1223 }), fs: memFs(), now: () => NOW });
  await audit.run();
  const cancelled = await audit.apply(audit.preview({ code: 'PC-18', fixId: 'remote-assist-off' }).token);
  assert.equal(cancelled.outcome, 'cancelled');
  const p = audit.preview({ code: 'PC-17', fixId: 'autoplay-off' });
  assert.equal(p.admin, false);
  log.length = 0;
  await audit.apply(p.token);
  assert.ok(log[0].includes('DisableAutoplay') && !log[0].includes('RunAs'));
});

test('KISA 설정 열기: 고정 목록 밖의 화면은 열지 않는다', async () => {
  const audit = createKisaAudit({ exec: fakeExec([]), fs: memFs() });
  assert.ok((await audit.open('cmd.exe /c calc')).error);
  assert.equal((await audit.open('update')).opened, true);
});
