// 내 PC 상태 화면. DOM은 createElement 와 textContent 로만 만든다.
const AUTO_INTERVAL_MS = 5000;
const FAST_TIMEOUT_MS = 8000;
const SECURITY_TIMEOUT_MS = 25000;

const METRICS = [
  { key: 'cpu', title: 'CPU 사용률', unit: '%', scaleMax: () => 100 },
  { key: 'memory', title: '메모리 사용량', unit: 'GB', scaleMax: (cell) => cell && cell.totalGb },
  { key: 'disk', title: '디스크 남은 공간', unit: 'GB', scaleMax: (cell) => cell && cell.totalGb },
];
const NEXT_STEP = {
  FIRST_SAMPLE: '「다시 조회」를 한 번 더 누르세요.',
  SHORT_INTERVAL: '잠시 뒤 「다시 조회」를 누르세요.',
  TIMEOUT: '잠시 뒤 「다시 조회」를 누르세요.',
  PERMISSION: '관리자 권한이 필요한 항목이라 읽지 않습니다. 값을 바꾸거나 권한을 올리지 않으며, 필요하면 담당자에게 문의하세요.',
  READ_FAILED: '「다시 조회」를 눌러 보세요. 계속되면 작업 관리자나 Windows 보안 앱에서 직접 확인하세요.',
  REQUEST_FAILED: '서버가 켜져 있는지 확인하고(tools\\start-final.ps1 실행) 「다시 조회」를 누르세요.',
};
const ACTION_LABEL = { Block: '차단', Allow: '허용', NotConfigured: '지정 안 됨' };
const DIRECTION = { up: '증가', down: '감소', same: '변화 없음' };

const $ = (id) => document.getElementById(id);
// 화면 코드가 불러와졌다면(서버로 연 경우) 파일을 직접 열었을 때 쓰는 안내는 지운다.
$('open-hint')?.remove();
const state = {
  auto: false, timer: null, busy: false, metric: 'cpu',
  fast: null, fastFailed: false, security: null, securityFailed: false,
  loading: { fast: false, security: false },
};

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}
const hhmm = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }); };
const hhmmss = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleTimeString('ko-KR'); };
const numberText = (value, unit) => (typeof value === 'number' ? `${value} ${unit}` : '확인 불가');
const nextStepFor = (code) => NEXT_STEP[code] || NEXT_STEP.READ_FAILED;

// ---------- 1. 지금 상태: 상단 4칸 ----------
function card({ title, kind, tagText, value, sub, time, next }) {
  const root = node('article', null, `card card-${kind}`);
  root.append(node('h3', title), node('p', tagText, `tag tag-${kind === 'measured' ? 'ok' : kind === 'unavailable' ? 'warn' : 'idle'}`), node('p', value, 'value'));
  if (sub) root.append(node('p', sub, 'sub'));
  if (time) root.append(node('p', time, 'time'));
  if (next) root.append(node('p', `다음에 할 일: ${next}`, 'next'));
  return root;
}

function loadingCard(title) {
  const root = card({ title, kind: 'loading', tagText: '조회 중', value: '…', sub: '이 PC에서 읽는 중입니다.' });
  root.querySelector('.tag').prepend(node('span', null, 'spinner'));
  return root;
}
const idleCard = (title) => card({ title, kind: 'idle', tagText: '조회 전', value: '—', sub: '「다시 조회」를 누르면 읽습니다.' });
const failedCard = (title, code = 'REQUEST_FAILED', at = new Date().toISOString()) => card({
  title, kind: 'unavailable', tagText: '확인 불가', value: '확인 불가',
  sub: '조회 요청이 실패했습니다. 예시 값으로 대신 표시하지 않습니다.', time: `요청 실패 시각 ${hhmmss(at)}`, next: nextStepFor(code),
});

function metricCard(metric) {
  if (state.loading.fast) return loadingCard(metric.title);
  if (state.fastFailed) return failedCard(metric.title);
  if (!state.fast) return idleCard(metric.title);
  const cell = state.fast.sample[metric.key];
  if (cell.status !== 'measured') {
    return card({ title: metric.title, kind: 'unavailable', tagText: '확인 불가', value: '확인 불가', sub: cell.reason, time: `조회 시각 ${hhmmss(cell.measuredAt)}`, next: nextStepFor(cell.code) });
  }
  const sub = metric.key === 'cpu' ? `직전 조회 이후 ${cell.windowSeconds}초 구간 평균`
    : metric.key === 'memory' ? `전체 ${cell.totalGb} GB 중 ${cell.percent}% 사용`
      : `${cell.drive} 드라이브, 전체 ${cell.totalGb} GB`;
  return card({ title: metric.title, kind: 'measured', tagText: '실측', value: `${cell.value} ${metric.unit}`, sub, time: `잰 시각 ${hhmmss(cell.measuredAt)}` });
}

function firewallCard() {
  const title = '방화벽';
  if (state.loading.security) return loadingCard(title);
  if (state.securityFailed) return failedCard(title);
  if (!state.security) return idleCard(title);
  const cell = state.security.firewall;
  if (cell.status !== 'measured') {
    return card({ title, kind: 'unavailable', tagText: '확인 불가', value: '확인 불가', sub: cell.reason, time: `조회 시각 ${hhmmss(cell.measuredAt)}`, next: nextStepFor(cell.code) });
  }
  const on = cell.profiles.filter((profile) => profile.enabled === 'on').length;
  const notOn = cell.profiles.filter((profile) => profile.enabled !== 'on').map((profile) => `${profile.name}(${profile.enabled === 'off' ? '꺼짐' : '확인 불가'})`);
  return card({
    title, kind: 'measured', tagText: '실측', value: `${on}/${cell.profiles.length} 켜짐`,
    sub: notOn.length === 0 ? `${cell.profiles.map((profile) => profile.name).join('·')} 모두 켜짐` : `켜지지 않은 프로필: ${notOn.join(', ')}`,
    time: `읽은 시각 ${hhmmss(cell.measuredAt)} · 읽기만 함`,
  });
}

function renderCards() {
  const busy = state.loading.fast || state.loading.security;
  $('cards').setAttribute('aria-busy', String(busy));
  $('cards').replaceChildren(...METRICS.map(metricCard), firewallCard());
}

// ---------- 2. 시간에 따른 변화 ----------
function renderChart() {
  const picker = $('metric-picker');
  picker.replaceChildren(...METRICS.map((metric) => {
    const button = node('button', metric.title);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(state.metric === metric.key));
    button.addEventListener('click', () => { state.metric = metric.key; renderChart(); });
    return button;
  }));

  const target = $('chart');
  const history = state.fast && state.fast.history;
  if (state.fastFailed) { target.replaceChildren(node('p', '조회 요청이 실패해 그래프를 표시하지 않습니다. 이전 값을 현재 값처럼 보여 주지 않습니다.', 'empty'), node('p', `다음에 할 일: ${NEXT_STEP.REQUEST_FAILED}`, 'next')); return; }
  if (!history || history.count === 0) { target.replaceChildren(node('p', '조회 기록이 없어 그래프를 그릴 수 없습니다. 「다시 조회」를 누르세요.', 'empty')); return; }

  const metric = METRICS.find((item) => item.key === state.metric);
  const trend = history.trend[metric.key];
  const cell = state.fast.sample[metric.key];
  const measuredValues = trend.series.filter((value) => value !== null);
  const fromCell = cell && cell.status === 'measured' ? metric.scaleMax(cell) : null;
  const scale = typeof fromCell === 'number' && fromCell > 0 ? fromCell : Math.max(1, ...measuredValues);

  const bars = node('div', null, 'bars');
  bars.setAttribute('role', 'img');
  bars.setAttribute('aria-label', `${metric.title} 최근 조회 ${trend.series.length}회 막대 그래프. 가장 최근 값 ${numberText(trend.latest, metric.unit)}`);
  for (const value of trend.series) {
    const bar = node('span', null, value === null ? 'bar bar-gap' : 'bar');
    if (value !== null) bar.style.height = `${Math.max(2, Math.min(100, (value / scale) * 100))}%`;
    bar.setAttribute('title', value === null ? '확인 불가' : `${value} ${metric.unit}`);
    bars.append(bar);
  }
  const axis = node('div', null, 'axis');
  axis.append(node('span', `${scale} ${metric.unit}`), node('span', `0 ${metric.unit}`));
  const wrap = node('div', null, 'chart-wrap');
  wrap.append(axis, bars);

  const notes = node('ul', null, 'notes');
  notes.append(node('li', trend.delta === null ? '직전 대비: 직전 조회가 없거나 확인 불가라 비교하지 않습니다.' : `직전 대비: ${trend.delta > 0 ? '+' : ''}${trend.delta} ${metric.unit} (${DIRECTION[trend.direction]})`));
  notes.append(node('li', trend.measuredCount > 0 ? `최근 실측 ${trend.measuredCount}회 중 최소 ${trend.min} ${metric.unit} ~ 최대 ${trend.max} ${metric.unit}` : '최근 실측 값이 없습니다.'));
  notes.append(node('li', '막대 한 개는 조회 1회입니다. 짧은 주황색 막대는 그 회차가 확인 불가였다는 뜻입니다.'));
  target.replaceChildren(wrap, notes);
}

// ---------- 3. 최근 기록과 연결·이벤트 ----------
function renderHistory() {
  const wrap = $('history');
  const history = state.fast && state.fast.history;
  if (state.fastFailed) { wrap.replaceChildren(node('p', '조회 요청이 실패해 기록을 표시하지 않습니다.', 'empty')); return; }
  if (!history || history.rows.length === 0) { wrap.replaceChildren(node('p', '아직 기록이 없습니다.', 'empty')); return; }
  const table = node('table');
  const thead = node('thead');
  const head = node('tr');
  for (const name of ['잰 시각', 'CPU(%)', '메모리(GB)', '디스크 남은(GB)']) head.append(node('th', name));
  thead.append(head);
  const body = node('tbody');
  for (const row of [...history.rows].reverse().slice(0, 10)) {
    const tr = node('tr');
    tr.append(node('td', hhmmss(row.measuredAt)), node('td', numberText(row.cpu, '%')), node('td', numberText(row.memory, 'GB')), node('td', numberText(row.disk, 'GB')));
    body.append(tr);
  }
  table.append(thead, body);
  wrap.replaceChildren(table);
}

function block(title, ...children) {
  const root = node('section', null, 'detail-block');
  root.append(node('h4', title), ...children);
  return root;
}
function unavailableLines(cell) {
  return [node('p', `확인 불가: ${cell.reason}`), node('p', `다음에 할 일: ${nextStepFor(cell.code)}`, 'next')];
}

function networkBlock(cell) {
  if (cell.status !== 'measured') return block('네트워크 구성', ...unavailableLines(cell));
  const list = node('ul');
  for (const adapter of cell.adapters) list.append(node('li', `${adapter.name} · IPv4 ${adapter.hasIPv4 ? '있음' : '없음'}${adapter.hasIPv6 ? ' · IPv6 있음' : ''}`));
  return block('네트워크 구성', node('p', `외부 어댑터 ${cell.adapters.length}개 중 IPv4 연결 ${cell.connectedCount}개 (실측 ${hhmmss(cell.measuredAt)})`), list, node('p', cell.basis, 'time'));
}

function firewallBlock(cell) {
  if (cell.status !== 'measured') return block('방화벽 설정(읽기만)', ...unavailableLines(cell));
  const list = node('ul');
  for (const profile of cell.profiles) {
    const state_ = profile.enabled === 'on' ? '켜짐' : profile.enabled === 'off' ? '꺼짐' : `확인 불가(원래 값 ${profile.rawEnabled})`;
    list.append(node('li', `${profile.name}: ${state_} · 수신 기본 ${ACTION_LABEL[profile.inbound] || profile.inbound} · 송신 기본 ${ACTION_LABEL[profile.outbound] || profile.outbound}`));
  }
  const notes = [list, node('p', cell.basis, 'time')];
  if (cell.profiles.some((profile) => profile.inbound === 'NotConfigured' || profile.outbound === 'NotConfigured')) {
    notes.push(node('p', '"지정 안 됨"은 Windows가 이 설정값을 따로 지정하지 않았다고 알려 준 값입니다. 허용이나 안전을 뜻하지 않으며, 이 화면은 그 의미를 판단하지 않습니다.', 'time'));
  }
  return block('방화벽 설정(읽기만)', ...notes);
}

function eventsBlock(events) {
  const table = node('table');
  const thead = node('thead');
  const head = node('tr');
  for (const name of ['Windows 기록', '오류', '경고']) head.append(node('th', name));
  thead.append(head);
  const body = node('tbody');
  const problems = [];
  const countText = (count, label, log) => {
    if (count.status === 'measured') return `${count.value}건${count.capped ? ' 이상' : ''}`;
    problems.push(`${log} ${label}: ${count.reason} 다음에 할 일: ${nextStepFor(count.code)}`);
    return '확인 불가';
  };
  for (const log of ['System', 'Application']) {
    const entry = events.logs[log];
    const tr = node('tr');
    tr.append(node('td', log), node('td', countText(entry.errors, '오류', log)), node('td', countText(entry.warnings, '경고', log)));
    body.append(tr);
  }
  table.append(thead, body);
  const children = [node('p', `최근 ${events.hours}시간, 읽은 시각 ${hhmmss(events.measuredAt)}`), node('div', null, 'table-wrap')];
  children[1].append(table);
  if (problems.length > 0) { const list = node('ul'); for (const text of problems) list.append(node('li', text)); children.push(list); }
  children.push(node('p', '이 건수는 침해나 공격 탐지 결과가 아니라 Windows가 남긴 경고·오류 기록의 개수입니다. 기록 내용은 읽어 오지 않습니다.', 'time'));
  return block('Windows 기록(System·Application)', ...children);
}

function sdpBlock(sdp) {
  const root = node('section', null, 'detail-block sdp');
  root.append(node('h4', 'SDP 연결 (이 PC에서 읽은 값과 별개)'), node('p', sdp.label), node('p', sdp.reason, 'time'));
  return root;
}

function renderDetail() {
  const box = $('detail');
  if (state.loading.security) {
    const p = node('p', '연결·방화벽·Windows 기록을 읽는 중입니다. 최대 25초 걸릴 수 있습니다.', 'empty');
    p.prepend(node('span', null, 'spinner'));
    box.replaceChildren(p);
    return;
  }
  if (state.securityFailed) { box.replaceChildren(block('조회 요청 실패', node('p', '연결·방화벽·Windows 기록 조회 요청이 실패했습니다. 예시 값으로 대신 표시하지 않습니다.'), node('p', `다음에 할 일: ${NEXT_STEP.REQUEST_FAILED}`, 'next'))); return; }
  if (!state.security) { box.replaceChildren(node('p', '조회 전입니다. 「다시 조회」를 누르면 읽습니다.', 'empty')); return; }
  box.replaceChildren(networkBlock(state.security.network), firewallBlock(state.security.firewall), eventsBlock(state.security.events), sdpBlock(state.security.sdp));
}

function renderAll() { renderCards(); renderChart(); renderHistory(); renderDetail(); }

// ---------- 조회 ----------
function setPill(kind, text) { const pill = $('status-pill'); pill.className = `pill pill-${kind}`; pill.textContent = text; }
function setNotice(text) { $('notice').textContent = text; }

function setAuto(on) {
  state.auto = on;
  const button = $('auto-toggle');
  button.setAttribute('aria-pressed', String(on));
  button.textContent = on ? '자동 조회: 켜짐(5초 간격)' : '자동 조회: 꺼짐';
  clearTimeout(state.timer);
  state.timer = null;
}

async function fetchJson(path, timeoutMs, valid) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { cache: 'no-store', headers: { accept: 'application/json' }, signal: controller.signal });
    const body = await response.json().catch(() => null);
    if (!response.ok || !body || body.ok !== true || !body.data || !valid(body.data)) throw Error('REQUEST_FAILED');
    return body.data;
  } finally { clearTimeout(timeout); }
}
const validFast = (data) => Boolean(data.sample && data.sample.cpu && data.sample.memory && data.sample.disk && data.history && data.history.trend);
const validSecurity = (data) => Boolean(data.network && data.firewall && data.events && data.events.logs && data.sdp);

function unavailableNames() {
  const names = [];
  if (state.fastFailed) names.push('CPU·메모리·디스크(요청 실패)');
  else if (state.fast) for (const metric of METRICS) if (state.fast.sample[metric.key].status !== 'measured') names.push(metric.title);
  if (state.securityFailed) names.push('방화벽·연결·Windows 기록(요청 실패)');
  else if (state.security) {
    if (state.security.firewall.status !== 'measured') names.push('방화벽');
    if (state.security.network.status !== 'measured') names.push('네트워크 구성');
    const logs = state.security.events.logs;
    const partial = ['System', 'Application'].some((log) => logs[log].errors.status !== 'measured' || logs[log].warnings.status !== 'measured');
    if (state.security.events.status !== 'measured') names.push('Windows 기록');
    else if (partial) names.push('Windows 기록 일부');
  }
  return names;
}

async function refresh(manual) {
  if (state.busy) return;
  state.busy = true;
  clearTimeout(state.timer);
  state.timer = null;
  state.loading = { fast: true, security: manual };
  const button = $('refresh');
  button.disabled = true;
  button.textContent = '조회 중…';
  setPill('busy', '조회 중…');
  setNotice('조회 중입니다. 잠시만 기다리세요.');
  renderAll();

  const tasks = [fetchJson('/api/pc-status', FAST_TIMEOUT_MS, validFast).then((data) => { state.fast = data; state.fastFailed = false; }, () => { state.fast = null; state.fastFailed = true; })];
  if (manual) tasks.push(fetchJson('/api/pc-security', SECURITY_TIMEOUT_MS, validSecurity).then((data) => { state.security = data; state.securityFailed = false; }, () => { state.security = null; state.securityFailed = true; }));
  await Promise.all(tasks);

  state.loading = { fast: false, security: false };
  state.busy = false;
  button.disabled = false;
  button.textContent = '다시 조회';
  renderAll();

  const now = new Date().toISOString();
  const missing = unavailableNames();
  const allFailed = state.fastFailed && (!manual || state.securityFailed);
  if (allFailed) { setPill('fail', `조회 실패 ${hhmm(now)}`); setNotice('조회 요청이 실패했습니다. 값은 확인 불가입니다. 각 칸의 "다음에 할 일"을 보세요.'); }
  else if (missing.length > 0) { setPill('part', `일부 확인 불가 ${hhmm(now)}`); setNotice(`확인 불가: ${missing.join(', ')}. 각 칸의 "다음에 할 일"을 보세요.`); }
  else { setPill('ok', `다시 조회 성공 ${hhmm(now)}`); setNotice(`조회 완료 ${hhmmss(now)}`); }

  if (state.fastFailed && state.auto) { setAuto(false); setNotice('요청이 실패해 자동 조회를 껐습니다. 값은 확인 불가입니다.'); }
  if (state.auto) state.timer = setTimeout(() => refresh(false), AUTO_INTERVAL_MS);
}

$('refresh').addEventListener('click', () => { refresh(true); });
$('auto-toggle').addEventListener('click', () => {
  const next = !state.auto;
  setAuto(next);
  if (next) refresh(false);
});

renderAll();
