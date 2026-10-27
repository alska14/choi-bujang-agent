import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createSecurityReader } from '../src/pc-status/security-reader.mjs';
import { createSampler } from '../src/pc-status/sampler.mjs';
import { createHistory } from '../src/pc-status/history.mjs';
import { attachPcStatus } from '../src/pc-status/routes.mjs';

const fixedNow = () => new Date('2026-10-27T01:00:00.000Z');
const reader = (run, interfaces = {}) => createSecurityReader({ osModule: { networkInterfaces: () => interfaces }, run, now: fixedNow });
const reject = (code) => async () => { throw Object.assign(new Error(code), { code }); };

test('네트워크: 루프백은 빼고 IPv4 보유 여부만 알려 주며 주소와 MAC 은 담지 않는다', () => {
  const r = reader(async () => '', {
    '이더넷': [{ family: 'IPv4', address: '192.168.10.20', mac: 'aa:bb:cc:dd:ee:ff', internal: false }, { family: 'IPv6', address: 'fe80::1', mac: 'aa:bb:cc:dd:ee:ff', internal: false }],
    'Wi-Fi': [{ family: 'IPv6', address: 'fe80::2', mac: '11:22:33:44:55:66', internal: false }],
    Loopback: [{ family: 'IPv4', address: '127.0.0.1', internal: true }],
  });
  const network = r.readNetwork();
  assert.equal(network.status, 'measured');
  assert.deepEqual(network.adapters.map((a) => a.name), ['이더넷', 'Wi-Fi']);
  assert.equal(network.connectedCount, 1);
  const text = JSON.stringify(network);
  for (const secret of ['192.168', 'aa:bb', '11:22', 'fe80', '127.0.0.1']) assert.ok(!text.includes(secret), secret);
});

test('네트워크: 읽기에 실패하면 확인 불가', () => {
  const r = createSecurityReader({ osModule: { networkInterfaces: () => { throw new Error('x'); } }, run: async () => '', now: fixedNow });
  assert.equal(r.readNetwork().status, 'unavailable');
});

test('방화벽: 프로필별 켜짐·꺼짐을 읽고, 한 개뿐인 응답도 처리한다', async () => {
  const rows = JSON.stringify([{ name: 'Domain', enabled: 'True', inbound: 'Block', outbound: 'Allow' }, { name: 'Private', enabled: 'False', inbound: 'Block', outbound: 'Allow' }, { name: 'Public', enabled: 'NotConfigured', inbound: 'Block', outbound: 'Allow' }]);
  const firewall = await reader(async () => rows).readFirewall();
  assert.equal(firewall.status, 'measured');
  assert.deepEqual(firewall.profiles.map((p) => p.enabled), ['on', 'off', 'unknown']);
  const single = await reader(async () => JSON.stringify({ name: 'Domain', enabled: 'True', inbound: 'Block', outbound: 'Allow' })).readFirewall();
  assert.equal(single.profiles.length, 1);
});

test('방화벽: 권한 없음은 우회하지 않고 확인 불가와 PERMISSION 으로 둔다', async () => {
  const firewall = await reader(async () => JSON.stringify({ error: 'UnauthorizedAccessException' })).readFirewall();
  assert.equal(firewall.status, 'unavailable');
  assert.equal(firewall.code, 'PERMISSION');
  assert.equal(firewall.profiles, undefined);
});

test('방화벽: 시간 초과·실행 실패·형식 오류는 모두 확인 불가', async () => {
  assert.equal((await reader(reject('TIMEOUT')).readFirewall()).code, 'TIMEOUT');
  assert.equal((await reader(reject('FAILED')).readFirewall()).code, 'READ_FAILED');
  assert.equal((await reader(async () => 'not json').readFirewall()).status, 'unavailable');
  assert.equal((await reader(async () => JSON.stringify([{ name: 'Weird', enabled: 'True' }])).readFirewall()).status, 'unavailable');
  assert.equal((await reader(async () => JSON.stringify([])).readFirewall()).status, 'unavailable');
});

test('기록 건수: System·Application 의 오류·경고 건수를 읽는다', async () => {
  const output = JSON.stringify({ System: { errors: 28, warnings: 18 }, Application: { errors: 2, warnings: 0 } });
  const events = await reader(async () => output).readEvents();
  assert.equal(events.status, 'measured');
  assert.equal(events.hours, 24);
  assert.equal(events.logs.System.errors.value, 28);
  assert.equal(events.logs.Application.warnings.value, 0);
  assert.equal(events.logs.Application.warnings.status, 'measured');
});

test('기록 건수: 읽지 못한 항목만 확인 불가이고 나머지는 유지한다', async () => {
  const output = JSON.stringify({ System: { errors: 5, warnings: 'UnauthorizedAccessException' }, Application: { errors: 'SomeOtherException', warnings: 1 } });
  const events = await reader(async () => output).readEvents();
  assert.equal(events.status, 'measured');
  assert.equal(events.logs.System.errors.value, 5);
  assert.equal(events.logs.System.warnings.status, 'unavailable');
  assert.equal(events.logs.System.warnings.code, 'PERMISSION');
  assert.equal(events.logs.Application.errors.code, 'READ_FAILED');
  assert.match(events.logs.Application.errors.reason, /SomeOtherException/);
});

test('기록 건수: 5000건에 닿으면 상한 표시, 전부 실패하면 전체가 확인 불가', async () => {
  const capped = await reader(async () => JSON.stringify({ System: { errors: 5000, warnings: 0 }, Application: { errors: 0, warnings: 0 } })).readEvents();
  assert.equal(capped.logs.System.errors.capped, true);
  const failed = await reader(reject('TIMEOUT')).readEvents();
  assert.equal(failed.status, 'unavailable');
  assert.equal(failed.logs.System.code, 'TIMEOUT');
  const garbage = await reader(async () => 'nope').readEvents();
  assert.equal(garbage.status, 'unavailable');
});

test('읽기 명령은 고정된 읽기 전용 스크립트이며 설정을 바꾸는 명령을 포함하지 않는다', async () => {
  const scripts = [];
  await reader(async (script) => { scripts.push(script); return '[]'; }).read();
  assert.equal(scripts.length, 2);
  const all = scripts.join('\n');
  assert.match(all, /Get-NetFirewallProfile/);
  assert.match(all, /Get-WinEvent/);
  assert.ok(!/Set-|New-|Remove-|Enable-|Disable-|netsh|Stop-|Start-|Invoke-/i.test(all));
});

function startServer(engineMode, securityReader) {
  const server = http.createServer((req, res) => { res.writeHead(200); res.end('original'); });
  const sampler = createSampler({ osModule: { cpus: () => [{ times: { user: 1, nice: 0, sys: 1, idle: 1, irq: 0 } }], totalmem: () => 2 ** 33, freemem: () => 2 ** 32 }, fsModule: { statfsSync: () => ({ blocks: 10, bsize: 2 ** 30, bavail: 5 }) } });
  attachPcStatus(server, { sampler, history: createHistory(), securityReader, engineMode: () => engineMode });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}
const get = (port, path) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path }, (res) => { let body = ''; res.on('data', (c) => { body += c; }); res.on('end', () => resolve({ status: res.statusCode, body })); }).on('error', reject);
});
const okReader = reader(async (script) => (script.includes('Get-NetFirewallProfile') ? JSON.stringify([{ name: 'Domain', enabled: 'True', inbound: 'Block', outbound: 'Allow' }]) : JSON.stringify({ System: { errors: 1, warnings: 2 }, Application: { errors: 0, warnings: 0 } })), { 이더넷: [{ family: 'IPv4', address: '10.0.0.5', internal: false }] });

test('서버: /api/pc-security 는 SDP 상태를 PC 조회 결과와 따로 알려 준다', async () => {
  for (const [mode, status] of [['disconnected', 'not_connected'], ['demo', 'demo'], ['connected', 'connected']]) {
    const { server, port } = await startServer(mode, okReader);
    try {
      const body = JSON.parse((await get(port, '/api/pc-security')).body);
      assert.equal(body.ok, true);
      assert.equal(body.data.sdp.status, status);
      assert.equal(body.data.firewall.status, 'measured');
      assert.equal(body.data.events.logs.System.errors.value, 1);
      assert.equal(body.data.network.status, 'measured');
      assert.ok(!JSON.stringify(body).includes('10.0.0.5'));
    } finally { server.close(); }
  }
});

test('서버: SDP 미연결이어도 PC 조회가 실패하면 PC 조회는 확인 불가로 남는다', async () => {
  const { server, port } = await startServer('disconnected', reader(reject('TIMEOUT')));
  try {
    const body = JSON.parse((await get(port, '/api/pc-security')).body);
    assert.equal(body.data.sdp.status, 'not_connected');
    assert.equal(body.data.firewall.status, 'unavailable');
    assert.equal(body.data.events.status, 'unavailable');
  } finally { server.close(); }
});

test('서버: 읽기 객체가 없으면 /api/pc-security 를 제공 서버에 넘긴다', async () => {
  const { server, port } = await startServer('disconnected', undefined);
  try { assert.equal((await get(port, '/api/pc-security')).body, 'original'); } finally { server.close(); }
});
