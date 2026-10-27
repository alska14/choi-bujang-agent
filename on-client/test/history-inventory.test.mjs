import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEventStore } from '../src/soc/events.mjs';
import { createEventLog } from '../src/soc/event-log.mjs';
import { createInventory, taskFinding, parseUsb } from '../src/soc/inventory.mjs';
import { createAgentAudit } from '../src/soc/agent-audit.mjs';
import { patchTargets } from '../tools/agent-audit-hook.mjs';

const tempDir = () => mkdtempSync(join(tmpdir(), 'soc-hist-'));

test('사건 기록: 저장한 사건을 새 저장소가 되살리고, 번호를 이어 쓰며, 팝업용 created 를 내보내지 않는다', () => {
  const dir = tempDir();
  try {
    const file = join(dir, 'events.json');
    const store = createEventStore();
    const log = createEventLog({ file, store, delayMs: 10 });
    store.add({ severity: 'critical', source: 'files', title: '첫 사건', rule: { id: 'X', text: 'x' } });
    store.add({ severity: 'medium', source: 'usb', title: '둘째 사건' });
    store.ack(1);
    assert.equal(log.flush(), true);

    const again = createEventStore();
    const seen = [];
    again.subscribe((type) => seen.push(type));
    const log2 = createEventLog({ file, store: again });
    assert.equal(log2.load(), 2);
    assert.deepEqual(seen, []);
    const [second, first] = again.list();
    assert.equal(first.title, '첫 사건');
    assert.equal(first.ack, true);
    assert.equal(second.restored, true);
    assert.equal(again.add({ severity: 'info', source: 'x', title: '새 사건' }).event.id, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('사건 기록: 되살린 미확인 사건과 같은 문제가 다시 걸리면 새 사건 대신 횟수만 늘린다', () => {
  const store = createEventStore({ cooldownMs: 1000 });
  store.restore([{ id: 7, at: '2026-10-01T00:00:00Z', severity: 'medium', title: '자동 로그인 켜짐', key: 'IAM-AUTOLOGON:true' }]);
  const { created, event } = store.add({ severity: 'medium', source: 'iam', title: '자동 로그인 켜짐', key: 'IAM-AUTOLOGON:true' });
  assert.equal(created, false);
  assert.equal(event.id, 7);
  assert.equal(event.count, 2);
});

test('사건 기록: 보관 기간보다 오래된 사건과 깨진 항목은 되살리지 않는다', () => {
  const dir = tempDir();
  try {
    const file = join(dir, 'events.json');
    const nowMs = Date.parse('2026-10-27T00:00:00Z');
    writeFileSync(file, JSON.stringify({ version: 1, events: [
      { id: 1, at: '2026-08-01T00:00:00Z', severity: 'high', title: '오래됨' },
      { id: 2, at: '2026-10-26T00:00:00Z', severity: 'high', title: '최근' },
      { id: 3, at: '2026-10-26T00:00:00Z', severity: 'nope', title: '깨짐' },
    ] }));
    const store = createEventStore();
    const log = createEventLog({ file, store, now: () => nowMs, maxAgeDays: 30 });
    assert.equal(log.load(), 1);
    assert.equal(store.list()[0].title, '최근');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function fakeRun(state) {
  return async (script) => {
    if (script.includes('Uninstall')) return JSON.stringify(state.programs);
    if (script.includes('Get-ScheduledTask')) return JSON.stringify(state.tasks);
    if (script.includes('Win32_DiskDrive')) return JSON.stringify(state.usb);
    throw Object.assign(Error('FAILED'), { code: 'FAILED' });
  };
}
const memFs = () => {
  const files = new Map();
  return { files, readFileSync: (p) => { if (!files.has(p)) throw Object.assign(Error('ENOENT'), { code: 'ENOENT' }); return files.get(p); }, writeFileSync: (p, v) => files.set(p, v), renameSync: (a, b) => { files.set(b, files.get(a)); files.delete(a); }, mkdirSync: () => {} };
};

test('프로그램·예약 작업: 첫 실행은 기준만 만들고, 기준 파일이 있으면 서버가 꺼져 있던 동안 생긴 것도 알린다', async () => {
  const fs = memFs();
  const data = {
    programs: [{ name: 'Old App', version: '1.0', publisher: 'A', scope: 'machine' }],
    tasks: [{ path: '\\', name: 'Updater', state: 'Ready', author: 'A', exec: 'C:\\Program Files\\A\\up.exe', args: '' }],
    usb: { disks: [], removable: [] },
  };
  const store = createEventStore();
  const first = createInventory({ store, file: 'base.json', run: fakeRun(data), fs });
  await first.scanSoftware();
  assert.equal(store.list().length, 0);
  assert.equal(first.status().baseline.firstRun, true);

  data.programs.push({ name: 'New Tool', version: '2.0', publisher: 'B', scope: 'user' });
  data.programs[0].version = '1.1'; // 업데이트는 새 설치로 보지 않는다
  data.tasks.push({ path: '\\', name: 'Evil', state: 'Ready', author: 'x', exec: 'powershell.exe', args: '-enc AAAA' });
  const second = createInventory({ store, file: 'base.json', run: fakeRun(data), fs });
  await second.scanSoftware();
  const titles = store.list().map((e) => e.title);
  assert.equal(titles.length, 2);
  assert.ok(titles.some((t) => t.includes('New Tool')));
  const task = store.list().find((e) => e.rule.id === 'INV-NEW-TASK-SCRIPT');
  assert.equal(task.severity, 'high');
  assert.equal(task.attack[0].id, 'T1053.005');

  await second.scanSoftware();
  assert.equal(store.list().length, 2, '같은 항목은 다시 알리지 않는다');
});

test('예약 작업 위험도: 일반 프로그램은 주의, 스크립트 실행기는 높음', () => {
  assert.equal(taskFinding({ path: '\\', name: 'a', exec: 'C:\\Program Files\\x.exe', args: '', author: '', state: '' }).severity, 'medium');
  assert.equal(taskFinding({ path: '\\', name: 'b', exec: '"C:\\Windows\\System32\\mshta.exe"', args: '', author: '', state: '' }).severity, 'high');
});

test('USB: 처음 있던 장치는 알리지 않고, 새로 꽂으면 주의, 빼면 정보로 남기며 일련번호를 내보내지 않는다', async () => {
  const data = { programs: [], tasks: [], usb: { disks: [], removable: [] } };
  const store = createEventStore();
  const inv = createInventory({ store, run: fakeRun(data) });
  await inv.scanUsb();
  data.usb.disks = [{ id: 'USBSTOR\\DISK&VEN_X\\SERIAL123', model: 'X Flash', size: 32 * 1073741824, letters: ['E:'] }];
  await inv.scanUsb();
  const [plugged] = store.list();
  assert.equal(plugged.severity, 'medium');
  assert.match(plugged.title, /X Flash \(E:\)/);
  assert.ok(!JSON.stringify(plugged).includes('SERIAL123'));
  assert.ok(!JSON.stringify(inv.status()).includes('SERIAL123'));
  data.usb.disks = [];
  await inv.scanUsb();
  assert.equal(store.list()[0].severity, 'info');
  assert.equal(parseUsb({ disks: [], removable: [{ letter: 'F:', label: 'SD', size: 1e9 }] })[0].kind, 'removable');
});

test('에이전트 감사: 다시 켤 때 이미 있던 기록으로는 사건을 만들지 않고 목록에만 보인다', () => {
  const dir = tempDir();
  try {
    const file = join(dir, 'audit.jsonl');
    const rec = (path) => JSON.stringify({ at: new Date().toISOString(), agent: 'codex-cli', tool: 'Read', cwd: 'C:/work', targets: [path] });
    writeFileSync(file, `${rec('C:/Users/u/.ssh/id_rsa')}\n`);
    const store = createEventStore();
    const audit = createAgentAudit({ file, store, replayQuiet: true });
    audit.poll();
    assert.equal(store.list().length, 0);
    assert.equal(audit.status().latest.length, 1);
    writeFileSync(file, `${readFileSync(file, 'utf8')}${rec('C:/Users/u/.ssh/id_ed25519')}\n`);
    audit.poll();
    assert.equal(store.list().length, 1);
    assert.equal(store.list()[0].severity, 'critical');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('시작 프로그램 폴더: Windows가 알려 준 이름(desktop.ini)이 아니라 실제로 생긴 파일을 알린다', async () => {
  const { createFileWatcher } = await import('../src/soc/file-watch.mjs');
  const store = createEventStore();
  const target = { dir: 'C:/Startup', sensitive: false, kind: 'startup' };
  let print = 'desktop.ini:174:1';
  const watcher = createFileWatcher({ targets: [target], store, watch: () => ({ on() {}, close() {} }), fingerprint: () => print, now: (() => { let t = 0; return () => (t += 5000); })() });
  watcher.start();
  print = 'desktop.ini:174:1|evil.lnk:900:2';
  watcher.onChange(target, 'rename', 'desktop.ini');
  watcher.onChange(target, 'change', 'desktop.ini');
  assert.equal(store.list().length, 1);
  assert.equal(store.list()[0].title, '시작 프로그램 폴더 변경: evil.lnk(새로 생김)');
});

test('Codex 훅: apply_patch 에서는 패치 내용 대신 바뀌는 파일 경로만 뽑는다', () => {
  const patch = '*** Begin Patch\n*** Update File: src/a.js\n@@\n-secret=1\n+secret=2\n*** Add File: C:/abs/b.txt\n+hello\n*** End Patch';
  assert.deepEqual(patchTargets(patch, 'C:\\work'), [join('C:\\work', 'src/a.js'), 'C:/abs/b.txt']);
});
