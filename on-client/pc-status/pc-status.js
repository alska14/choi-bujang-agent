// 내 PC 상태 화면. DOM은 createElement 와 textContent 로만 만든다.
const AUTO_INTERVAL_MS = 5000;
const REQUEST_TIMEOUT_MS = 8000;
const METRICS = [
  { key: 'cpu', title: 'CPU 사용률', unit: '%', scaleMax: () => 100 },
  { key: 'memory', title: '메모리 사용량', unit: 'GB', scaleMax: (cell) => cell.totalGb },
  { key: 'disk', title: '디스크 남은 공간', unit: 'GB', scaleMax: (cell) => cell.totalGb },
];
const DIRECTION = { up: '증가', down: '감소', same: '변화 없음' };

const $ = (id) => document.getElementById(id);
const state = { auto: false, timer: null, busy: false };

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function timeText(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? String(iso) : `${date.toLocaleTimeString('ko-KR')} (${iso})`;
}

const numberText = (value, unit) => (typeof value === 'number' ? `${value} ${unit}` : '확인 불가');

function sparkline(series, scaleMax, label) {
  const box = node('div', null, 'spark');
  box.setAttribute('role', 'img');
  box.setAttribute('aria-label', label);
  for (const value of series) {
    const bar = node('span', null, value === null ? 'bar bar-gap' : 'bar');
    if (value !== null && scaleMax > 0) bar.style.height = `${Math.max(2, Math.min(100, (value / scaleMax) * 100))}%`;
    box.append(bar);
  }
  return box;
}

function trendLines(metric, trend, unit) {
  const lines = [];
  if (trend.delta === null) {
    lines.push('직전 대비: 직전 측정이 없거나 확인 불가라 비교하지 않습니다.');
  } else {
    const sign = trend.delta > 0 ? '+' : '';
    lines.push(`직전 대비: ${sign}${trend.delta} ${unit} (${DIRECTION[trend.direction]})`);
  }
  lines.push(trend.measuredCount > 0
    ? `최근 ${trend.measuredCount}회 실측 중 최소 ${trend.min} ${unit} ~ 최대 ${trend.max} ${unit}`
    : '최근 실측 값이 없습니다.');
  return lines;
}

function card(metric, cell, trend) {
  const root = node('article', null, `card ${cell.status === 'measured' ? 'card-measured' : 'card-unavailable'}`);
  root.dataset.metric = metric.key;
  root.append(
    node('h3', metric.title),
    node('p', cell.status === 'measured' ? '실측' : '확인 불가', 'tag'),
    node('p', cell.status === 'measured' ? `${cell.value} ${metric.unit}` : '확인 불가', 'value'),
  );
  const notes = node('ul', null, 'notes');
  notes.append(node('li', `${cell.timeLabel || '잰 시각'}: ${timeText(cell.measuredAt)}`));
  if (cell.status === 'measured') {
    if (metric.key === 'cpu') notes.append(node('li', `기준: ${cell.basis}(${cell.windowSeconds}초 구간)`));
    if (metric.key === 'memory') notes.append(node('li', `전체 ${cell.totalGb} GB 중 ${cell.percent}% 사용`));
    if (metric.key === 'disk') notes.append(node('li', `${cell.drive} 드라이브, 전체 ${cell.totalGb} GB`));
    if (metric.key !== 'cpu') notes.append(node('li', `기준: ${cell.basis}`));
  } else {
    notes.append(node('li', `이유: ${cell.reason}`));
    notes.append(node('li', '예시 값으로 대신 표시하지 않습니다.'));
  }
  root.append(notes);
  if (trend) {
    const scale = metric.scaleMax(cell);
    root.append(sparkline(trend.series, scale, `${metric.title} 최근 측정 ${trend.series.length}회 막대 그래프`));
    const lines = node('ul', null, 'notes');
    for (const line of trendLines(metric, trend, metric.unit)) lines.append(node('li', line));
    root.append(lines);
  }
  return root;
}

function renderCards(data) {
  const container = $('cards');
  const children = METRICS.map((metric) => card(metric, data.sample[metric.key], data.history.trend[metric.key]));
  container.replaceChildren(...children);
}

function renderHistory(history) {
  const wrap = $('history');
  if (history.rows.length === 0) { wrap.replaceChildren(node('p', '기록이 없습니다.')); return; }
  const table = node('table');
  const head = node('tr');
  for (const name of ['잰 시각', 'CPU 사용률(%)', '메모리 사용량(GB)', '디스크 남은 공간(GB)']) head.append(node('th', name));
  table.append(node('thead')); table.firstChild.append(head);
  const body = node('tbody');
  for (const row of [...history.rows].reverse()) {
    const tr = node('tr');
    tr.append(node('td', timeText(row.measuredAt)), node('td', numberText(row.cpu, '%')), node('td', numberText(row.memory, 'GB')), node('td', numberText(row.disk, 'GB')));
    body.append(tr);
  }
  table.append(body);
  wrap.replaceChildren(table);
}

// 요청이 실패하면 이전 값을 현재 값처럼 남기지 않는다.
function renderFailure() {
  const failedAt = new Date().toISOString();
  const children = METRICS.map((metric) => card(metric, { status: 'unavailable', timeLabel: '요청 실패 시각', measuredAt: failedAt, reason: '측정 요청이 실패했습니다.' }, null));
  $('cards').replaceChildren(...children);
  $('history').replaceChildren(node('p', '측정 요청이 실패해 기록을 표시하지 않습니다. 다시 측정하세요.'));
}

function setNotice(text) { $('notice').textContent = text; }

function setAuto(on) {
  state.auto = on;
  const button = $('auto-toggle');
  button.setAttribute('aria-pressed', String(on));
  button.textContent = on ? '자동 측정: 켜짐(5초 간격)' : '자동 측정: 꺼짐';
  clearTimeout(state.timer);
  state.timer = null;
}

async function measure() {
  if (state.busy) return;
  state.busy = true;
  setNotice('측정 중입니다.');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch('/api/pc-status', { cache: 'no-store', headers: { accept: 'application/json' }, signal: controller.signal });
    const body = await response.json().catch(() => null);
    if (!response.ok || !body || body.ok !== true || !body.data || !body.data.sample || !body.data.history) throw Error('PC_STATUS_REQUEST_FAILED');
    renderCards(body.data);
    renderHistory(body.data.history);
    setNotice(`측정 완료: ${timeText(body.data.sample.measuredAt)}`);
  } catch {
    renderFailure();
    setNotice('측정 요청이 실패했습니다. 값은 확인 불가입니다.');
    if (state.auto) { setAuto(false); setNotice('측정 요청이 실패해 자동 측정을 껐습니다. 값은 확인 불가입니다.'); }
  } finally {
    clearTimeout(timeout);
    state.busy = false;
    if (state.auto) state.timer = setTimeout(measure, AUTO_INTERVAL_MS);
  }
}

$('measure-now').addEventListener('click', () => { measure(); });
$('auto-toggle').addEventListener('click', () => {
  const next = !state.auto;
  setAuto(next);
  if (next) measure();
});
