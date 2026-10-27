import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createSampler } from '../src/pc-status/sampler.mjs';
import { createHistory } from '../src/pc-status/history.mjs';
import { attachPcStatus } from '../src/pc-status/routes.mjs';

const GB = 2 ** 30;
const cpu = (user, idle) => ({ times: { user, nice: 0, sys: 0, idle, irq: 0 } });
const fakeOs = (state) => ({ cpus: () => state.cpus, totalmem: () => state.total, freemem: () => state.free });
const fakeFs = (stat) => ({ statfsSync: () => { if (stat instanceof Error) throw stat; return stat; } });
const clockFrom = (times) => { let i = 0; return () => new Date(times[Math.min(i++, times.length - 1)]); };

function makeSampler(state, stat, times = [0, 5000, 10000]) {
  return createSampler({ osModule: fakeOs(state), fsModule: fakeFs(stat), now: clockFrom(times), diskPath: 'C:\\' });
}

test('CPU: 첫 측정은 확인 불가이고 예시 값으로 채우지 않는다', () => {
  const sampler = makeSampler({ cpus: [cpu(100, 900)], total: 8 * GB, free: 2 * GB }, { blocks: 100, bsize: GB, bavail: 40 });
  const first = sampler.sample();
  assert.equal(first.cpu.status, 'unavailable');
  assert.match(first.cpu.reason, /첫 측정/);
  assert.equal(first.cpu.value, undefined);
});

test('CPU: 두 번째 측정부터 직전 측정 이후 구간의 사용률을 계산한다', () => {
  const state = { cpus: [cpu(100, 900)], total: 8 * GB, free: 2 * GB };
  const sampler = makeSampler(state, { blocks: 100, bsize: GB, bavail: 40 });
  sampler.sample();
  state.cpus = [cpu(400, 1600)];
  const second = sampler.sample();
  assert.equal(second.cpu.status, 'measured');
  assert.equal(second.cpu.value, 30);
  assert.equal(second.cpu.unit, '%');
  assert.equal(second.cpu.windowSeconds, 5);
  assert.equal(second.cpu.measuredAt, '1970-01-01T00:00:05.000Z');
});

test('CPU: 누적 시간이 늘지 않으면 계산하지 않고 확인 불가로 둔다', () => {
  const state = { cpus: [cpu(100, 900)], total: 8 * GB, free: 2 * GB };
  const sampler = makeSampler(state, { blocks: 100, bsize: GB, bavail: 40 });
  sampler.sample();
  assert.equal(sampler.sample().cpu.status, 'unavailable');
});

test('CPU: cpus()가 올바르지 않으면 확인 불가', () => {
  const sampler = makeSampler({ cpus: [{ times: { user: NaN, nice: 0, sys: 0, idle: 1, irq: 0 } }], total: GB, free: 0 }, { blocks: 1, bsize: 1, bavail: 1 });
  assert.equal(sampler.sample().cpu.status, 'unavailable');
});

test('메모리: 사용량은 전체 − 여유이며 단위와 잰 시각이 붙는다', () => {
  const sampler = makeSampler({ cpus: [cpu(1, 1)], total: 16 * GB, free: 4 * GB }, { blocks: 100, bsize: GB, bavail: 40 });
  const { memory } = sampler.sample();
  assert.equal(memory.status, 'measured');
  assert.equal(memory.value, 12);
  assert.equal(memory.unit, 'GB');
  assert.equal(memory.percent, 75);
  assert.ok(memory.measuredAt);
});

test('메모리: 값이 올바르지 않으면 확인 불가', () => {
  for (const [total, free] of [[0, 0], [GB, 2 * GB], [NaN, 1], [GB, -1]]) {
    const sampler = makeSampler({ cpus: [cpu(1, 1)], total, free }, { blocks: 1, bsize: 1, bavail: 1 });
    assert.equal(sampler.sample().memory.status, 'unavailable', `${total}/${free}`);
  }
});

test('디스크: 남은 공간은 bavail × bsize 이다', () => {
  const sampler = makeSampler({ cpus: [cpu(1, 1)], total: GB, free: 0 }, { blocks: 200, bsize: GB, bavail: 80 });
  const { disk } = sampler.sample();
  assert.equal(disk.status, 'measured');
  assert.equal(disk.value, 80);
  assert.equal(disk.totalGb, 200);
  assert.equal(disk.drive, 'C:\\');
});

test('디스크: 읽기에 실패하면 오류 코드만 이유로 쓰고 확인 불가', () => {
  const error = Object.assign(new Error('C:\\secret\\path denied'), { code: 'EACCES' });
  const sampler = makeSampler({ cpus: [cpu(1, 1)], total: GB, free: 0 }, error);
  const { disk } = sampler.sample();
  assert.equal(disk.status, 'unavailable');
  assert.match(disk.reason, /EACCES/);
  assert.ok(!disk.reason.includes('secret'));
  assert.equal(disk.value, undefined);
});

test('추이: 직전 대비 증감, 최소·최대, 확인 불가는 null 로 남는다', () => {
  const history = createHistory({ max: 5 });
  const m = (value) => ({ status: 'measured', value, unit: 'GB', measuredAt: 't' });
  const u = { status: 'unavailable', reason: 'x', measuredAt: 't' };
  history.add({ measuredAt: 'a', cpu: u, memory: m(10), disk: m(100) });
  history.add({ measuredAt: 'b', cpu: m(20), memory: m(12.5), disk: m(100) });
  history.add({ measuredAt: 'c', cpu: m(15), memory: m(11), disk: u });
  const { trend } = history.snapshot();
  assert.deepEqual(trend.cpu.series, [null, 20, 15]);
  assert.equal(trend.cpu.delta, -5);
  assert.equal(trend.cpu.direction, 'down');
  assert.equal(trend.cpu.min, 15);
  assert.equal(trend.cpu.max, 20);
  assert.equal(trend.memory.delta, -1.5);
  assert.equal(trend.memory.min, 10);
  assert.equal(trend.memory.max, 12.5);
  assert.equal(trend.disk.delta, null);
  assert.equal(trend.disk.direction, 'unknown');
});

test('추이: 직전 값이 확인 불가면 더 오래된 값과 비교하지 않는다', () => {
  const history = createHistory();
  const m = (value) => ({ status: 'measured', value, unit: '%', measuredAt: 't' });
  const u = { status: 'unavailable', reason: 'x', measuredAt: 't' };
  history.add({ measuredAt: 'a', cpu: m(10), memory: u, disk: u });
  history.add({ measuredAt: 'b', cpu: u, memory: u, disk: u });
  history.add({ measuredAt: 'c', cpu: m(30), memory: u, disk: u });
  assert.equal(history.snapshot().trend.cpu.delta, null);
});

test('추이: 최근 max 개만 보관한다', () => {
  const history = createHistory({ max: 3 });
  for (let i = 0; i < 7; i++) history.add({ measuredAt: String(i), cpu: { status: 'measured', value: i, unit: '%', measuredAt: 't' }, memory: { status: 'unavailable' }, disk: { status: 'unavailable' } });
  const snap = history.snapshot();
  assert.equal(snap.count, 3);
  assert.deepEqual(snap.rows.map((row) => row.measuredAt), ['4', '5', '6']);
});

// 제공 서버를 흉내 낸 처리기에 attachPcStatus 를 붙여 경로 분기와 보안 검사를 확인한다.
function startServer() {
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('original'); });
  const state = { cpus: [cpu(100, 900)], total: 8 * GB, free: 2 * GB };
  attachPcStatus(server, { sampler: makeSampler(state, { blocks: 100, bsize: GB, bavail: 40 }), history: createHistory(), clock: () => new Date(0) });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, state })));
}
function request(port, path, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('서버: /api/pc-status 는 실측 값과 추이를 돌려주고 매 요청마다 기록이 쌓인다', async () => {
  const { server, port, state } = await startServer();
  try {
    const first = JSON.parse((await request(port, '/api/pc-status')).body);
    assert.equal(first.ok, true);
    assert.equal(first.data.sample.cpu.status, 'unavailable');
    assert.equal(first.data.sample.memory.status, 'measured');
    assert.equal(first.data.history.count, 1);
    state.cpus = [cpu(400, 1600)];
    const second = JSON.parse((await request(port, '/api/pc-status')).body);
    assert.equal(second.data.sample.cpu.value, 30);
    assert.equal(second.data.history.count, 2);
    assert.equal(second.data.history.trend.cpu.delta, null);
  } finally { server.close(); }
});

test('서버: 화면 파일을 보안 정책 헤더와 함께 제공한다', async () => {
  const { server, port } = await startServer();
  try {
    for (const path of ['/pc-status', '/pc-status/', '/pc-status/pc-status.js', '/pc-status/pc-status.css']) {
      const res = await request(port, path);
      assert.equal(res.status, 200, path);
      assert.match(res.headers['content-security-policy'], /default-src 'self'/);
      assert.equal(res.headers['cache-control'], 'no-store');
    }
  } finally { server.close(); }
});

test('서버: 잘못된 Host, 쿼리, POST, cross-site 요청은 거부한다', async () => {
  const { server, port } = await startServer();
  try {
    assert.equal((await request(port, '/api/pc-status', { headers: { host: 'example.com' } })).status, 403);
    assert.equal((await request(port, '/api/pc-status?x=1')).status, 400);
    assert.equal((await request(port, '/api/pc-status', { method: 'POST' })).status, 405);
    assert.equal((await request(port, '/api/pc-status', { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  } finally { server.close(); }
});

test('서버: 다른 경로는 제공 서버의 처리기에 그대로 넘긴다', async () => {
  const { server, port } = await startServer();
  try {
    for (const path of ['/', '/api/me', '/pc-statusx', '/pc-status/../x']) {
      const res = await request(port, path);
      assert.equal(res.body, 'original', path);
    }
  } finally { server.close(); }
});

test('서버: 화면 파일 목록 밖의 경로는 제공하지 않는다', async () => {
  const { server, port } = await startServer();
  try {
    assert.equal((await request(port, '/pc-status/package.json')).body, 'original');
    assert.equal((await request(port, '/pc-status/../package.json')).body, 'original');
  } finally { server.close(); }
});
