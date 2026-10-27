// 보안 관제 화면. 서버가 실시간으로 밀어 주는 값을 받아, 화면을 통째로 다시 그리지 않고 바뀐 부분만 제자리에서 고친다.
// DOM은 createElement 와 textContent 로만 만든다.
const SEV = {
  critical: { rank: 4, label: '긴급', glyph: '■' },
  high: { rank: 3, label: '높음', glyph: '◆' },
  medium: { rank: 2, label: '주의', glyph: '▲' },
  low: { rank: 1, label: '낮음', glyph: '◇' },
  info: { rank: 0, label: '정보', glyph: '◇' },
};
const LEVEL = { normal: { label: '정상', glyph: '●' }, warn: { label: '주의', glyph: '▲' }, critical: { label: '이상', glyph: '■' }, unknown: { label: '확인 불가', glyph: '○' } };
const SOURCE = { metrics: '측정', security: '보안 점검', ports: '수신 포트', winlog: 'Windows 기록', agent: 'LLM 에이전트', files: '폴더 변경', test: '시험', ioc: '위협 인텔(IOC)', ttp: '위협 인텔(TTP)', network: '네트워크', iam: '계정·접근' };
const DOMAIN = { network: '네트워크', endpoint: '엔드포인트', iam: '계정·접근', test: '시험' };
const STALE_MS = 8000;
const SPARK_POINTS = 60;

const $ = (id) => document.getElementById(id);
$('open-hint')?.remove();

const state = {
  events: new Map(), counts: null, points: [], anomaly: null, security: null, collectors: null, intel: null,
  filter: 'all', domainFilter: 'all', pipMode: location.hash === '#pip' || location.hash === '#pip-desktop', connected: false, gotSnapshot: false, lastMessageAt: 0, soundOn: false, muted: false, alarmKey: '', view: 'dashboard',
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}
const setText = (node, text) => { if (node.textContent !== text) node.textContent = text; };
const setClass = (node, className) => { if (node.className !== className) node.className = className; };
const setHidden = (node, hidden) => { if (node.hidden !== hidden) node.hidden = hidden; };
// 아이콘 버튼은 안쪽 .tool-label 글자만 바꾼다(아이콘 이미지는 그대로).
const toolText = (button, text) => { const label = button.querySelector('.tool-label'); setText(label || button, text); button.title = text; };
const icon = (name, size = 30) => { const img = document.createElement('img'); img.className = 'icon'; img.src = `/pc-status/icons/${name}.svg`; img.alt = ''; img.width = size; img.height = size; return img; };
const hhmmss = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleTimeString('ko-KR'); };
// 오늘이 아닌 사건(서버를 다시 켜도 남아 있는 지난 기록)은 날짜도 붙인다.
function whenText(iso) { const d = new Date(iso); const t = new Date(); return d.toDateString() === t.toDateString() ? hhmmss(iso) : `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${hhmmss(iso)}`; }
const clip = (text, max) => (String(text).length > max ? `${String(text).slice(0, max - 1)}…` : String(text));
const post = (path, body = {}) => fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), cache: 'no-store' });
window.socUi = { el, setText, setClass, setHidden, hhmmss, clip, post, state, SEV, LEVEL };
if (state.pipMode) document.title = '보안 관제 PiP · Djoković';

// ---------- 상단 전체 상태 ----------
function metricLevels() { return state.anomaly ? ['cpu', 'memory', 'disk'].map((key) => state.anomaly[key].level) : []; }

function unackedCounts() {
  const unacked = { critical: 0, high: 0, medium: 0 };
  for (const e of state.events.values()) if (!e.ack && unacked[e.severity] !== undefined) unacked[e.severity] += 1;
  return unacked;
}

function computePosture() {
  const stale = Date.now() - state.lastMessageAt > STALE_MS;
  if (!state.gotSnapshot || stale || !state.connected) return { level: 'unknown', label: '○ 확인 불가', detail: state.gotSnapshot ? '서버에서 데이터를 받지 못하고 있습니다. 평온하다는 뜻이 아닙니다' : '서버에 연결하는 중입니다' };
  const unacked = unackedCounts();
  const levels = metricLevels();
  if (unacked.critical > 0) return { level: 'critical', label: '■ 위험', detail: `미확인 긴급 ${unacked.critical}건` };
  if (unacked.high > 0 || levels.includes('critical')) return { level: 'high', label: '◆ 경계', detail: unacked.high > 0 ? `미확인 높음 ${unacked.high}건` : '측정값이 이상 범위입니다' };
  if (unacked.medium > 0 || levels.includes('warn')) return { level: 'warn', label: '▲ 주의', detail: unacked.medium > 0 ? `미확인 주의 ${unacked.medium}건` : '측정값이 평소와 다릅니다' };
  return { level: 'normal', label: '● 평온', detail: `이상 없음 · 미확인 사건 0건${state.counts && state.counts.total ? ` (기록 ${state.counts.total}건)` : ''}` };
}

function renderPosture() {
  const posture = computePosture();
  setClass($('posture'), `posture lv-${posture.level}`);
  setText($('posture-label'), posture.label);
  setText($('posture-detail'), posture.detail);
  return posture;
}

const countChips = new Map();
function renderCounts() {
  const unacked = unackedCounts();
  const box = $('counts');
  for (const key of ['critical', 'high', 'medium']) {
    let chip = countChips.get(key);
    if (!chip) { chip = el('span', 'count'); countChips.set(key, chip); box.append(chip); }
    setText(chip, `${SEV[key].glyph} ${SEV[key].label} ${unacked[key]}`);
    setClass(chip, `count ${unacked[key] > 0 ? `sev-${key}` : 'sev-zero'}`);
  }
}

// ---------- 상태 타일 ----------
const NS = 'http://www.w3.org/2000/svg';
function buildSpark() {
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 30');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('class', 'spark');
  svg.setAttribute('aria-hidden', 'true');
  const area = document.createElementNS(NS, 'path');
  area.setAttribute('class', 'area');
  const line = document.createElementNS(NS, 'path');
  line.setAttribute('class', 'line');
  const dot = document.createElementNS(NS, 'circle');
  dot.setAttribute('r', '2.6');
  svg.append(area, line, dot);
  return { svg, area, line, dot };
}
// 점 사이를 부드러운 곡선으로 잇고 아래를 옅게 채운다.
function updateSpark(spark, values, min, max) {
  const span = max - min || 1;
  const pts = [];
  values.forEach((value, index) => {
    if (typeof value !== 'number') return;
    const x = values.length < 2 ? 60 : (index / (values.length - 1)) * 118 + 1;
    const y = 28 - ((Math.min(max, Math.max(min, value)) - min) / span) * 26;
    pts.push([x, y]);
  });
  if (!pts.length) { spark.line.setAttribute('d', ''); spark.area.setAttribute('d', ''); spark.dot.setAttribute('hidden', ''); return; }
  const n = (v) => v.toFixed(1);
  let d = `M${n(pts[0][0])},${n(pts[0][1])}`;
  for (let i = 1; i < pts.length; i += 1) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i];
    const cx = (x0 + x1) / 2;
    d += ` C${n(cx)},${n(y0)} ${n(cx)},${n(y1)} ${n(x1)},${n(y1)}`;
  }
  const last = pts[pts.length - 1];
  spark.line.setAttribute('d', d);
  spark.area.setAttribute('d', `${d} L${n(last[0])},30 L${n(pts[0][0])},30 Z`);
  spark.dot.setAttribute('cx', n(last[0])); spark.dot.setAttribute('cy', n(last[1])); spark.dot.removeAttribute('hidden');
}

// ---------- 자원 사용 추이(CPU·메모리 곡선과 디스크 값) ----------
const trendRefs = { chips: {}, series: {} };
function svgNode(tag, attrs) { const node = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v)); return node; }
function smoothPath(pts) {
  const n = (v) => v.toFixed(1);
  let d = `M${n(pts[0][0])},${n(pts[0][1])}`;
  for (let i = 1; i < pts.length; i += 1) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i];
    const cx = (x0 + x1) / 2;
    d += ` C${n(cx)},${n(y0)} ${n(cx)},${n(y1)} ${n(x1)},${n(y1)}`;
  }
  return d;
}
function buildTrend() {
  const card = el('article', 'trend-card');
  const head = el('div', 'card-head');
  head.append(el('h3', null, '자원 사용 추이'), el('span', 'time', '최근 2분 · 2초마다 실측'));
  const chips = el('div', 'trend-chips');
  for (const [key, label] of [['cpu', 'CPU'], ['memory', '메모리'], ['disk', '디스크 남은 공간']]) {
    const chip = el('div', `metric m-${key} lv-unknown`);
    const value = el('strong', 'metric-value', '—');
    const level = el('span', 'chip', '○ 확인 불가');
    chip.append(el('span', 'metric-name', label), value, level);
    chips.append(chip);
    trendRefs.chips[key] = { chip, value, level };
  }
  const svg = svgNode('svg', { viewBox: '0 0 600 160', preserveAspectRatio: 'none', class: 'trend', 'aria-hidden': 'true' });
  for (const y of [10, 80, 150]) svg.append(svgNode('line', { x1: 0, x2: 600, y1: y, y2: y, class: 'grid' }));
  for (const key of ['memory', 'cpu']) {
    const area = svgNode('path', { class: `t-area t-${key}` });
    const line = svgNode('path', { class: `t-line t-${key}` });
    const dot = svgNode('circle', { r: 4, class: `t-dot t-${key}` });
    svg.append(area, line, dot);
    trendRefs.series[key] = { area, line, dot };
  }
  const axis = el('div', 'trend-axis');
  axis.append(el('span', null, '100%'), el('span', null, '50%'), el('span', null, '0%'));
  const plot = el('div', 'trend-plot');
  plot.append(axis, svg);
  const foot = el('div', 'trend-foot');
  trendRefs.reason = el('p', 'trend-reason');
  trendRefs.when = el('p', 'time');
  foot.append(trendRefs.reason, trendRefs.when);
  card.append(head, chips, plot, foot);
  $('w-trend').append(card);
}
buildTrend();
function renderTrend() {
  const latest = state.points[state.points.length - 1] || null;
  const a = state.anomaly;
  const read = { cpu: (p) => (typeof p.cpu === 'number' ? `${p.cpu}%` : null), memory: (p) => (typeof p.memoryPercent === 'number' ? `${p.memoryPercent}%` : null), disk: (p) => (typeof p.diskFreeGb === 'number' ? `${p.diskFreeGb} GB` : null) };
  const levels = {};
  for (const key of ['cpu', 'memory', 'disk']) {
    const ref = trendRefs.chips[key];
    const text = latest ? read[key](latest) : null;
    const level = text && a ? a[key].level : 'unknown';
    levels[key] = level;
    setClass(ref.chip, `metric m-${key} lv-${level}`);
    setText(ref.value, text ?? '확인 불가');
    setText(ref.level, `${LEVEL[level].glyph} ${LEVEL[level].label}`);
  }
  const count = state.points.length;
  for (const [key, field] of [['cpu', 'cpu'], ['memory', 'memoryPercent']]) {
    const pts = [];
    state.points.forEach((p, i) => { const v = p[field]; if (typeof v === 'number') pts.push([count < 2 ? 600 : (i / (count - 1)) * 600, 150 - (Math.min(100, Math.max(0, v)) / 100) * 140]); });
    const s = trendRefs.series[key];
    s.line.setAttribute('class', `t-line t-${key} lv-${levels[key]}`);
    if (!pts.length) { s.line.setAttribute('d', ''); s.area.setAttribute('d', ''); s.dot.setAttribute('hidden', ''); continue; }
    const d = smoothPath(pts);
    const last = pts[pts.length - 1];
    s.line.setAttribute('d', d);
    s.area.setAttribute('d', `${d} L${last[0].toFixed(1)},150 L${pts[0][0].toFixed(1)},150 Z`);
    s.dot.setAttribute('cx', last[0].toFixed(1)); s.dot.setAttribute('cy', last[1].toFixed(1)); s.dot.removeAttribute('hidden');
  }
  const reasons = a ? ['cpu', 'memory', 'disk'].flatMap((k) => a[k].reasons.map((r) => `${r.ruleId}: ${r.text}`)) : [];
  setText(trendRefs.reason, !latest ? '측정값을 기다리는 중입니다' : reasons.length ? reasons[0] : a && a.cpu.learning ? `기준 수집 중(${a.cpu.baselineCount ?? 0}/6) · 급증 판정은 기준이 모인 뒤부터` : 'CPU·메모리·디스크 모두 평소 범위입니다');
  setClass(trendRefs.reason, `trend-reason${reasons.length ? ' alert' : ''}`);
  setText(trendRefs.when, latest ? `잰 시각 ${hhmmss(latest.at)}` : '');
}

// ---------- 사건 목록(키 기준으로 제자리 갱신) ----------
function buildRow(event) {
  const tr = el('tr', 'row');
  tr.dataset.eventId = String(event.id);
  const time = el('td', 'cell-time');
  const sev = el('td', 'cell-sev');
  const src = el('td', 'cell-src');
  const msg = el('td', 'cell-msg');
  const title = el('div', 'msg-title');
  const detail = el('div', 'msg-detail');
  const rule = el('div', 'msg-rule');
  const attack = el('div', 'msg-rule');
  msg.append(title, detail, rule, attack);
  const act = el('td', 'cell-act');
  const button = el('button', null, '확인');
  button.type = 'button';
  button.addEventListener('click', () => { button.disabled = true; post('/api/soc/ack', { id: event.id }).catch(() => { button.disabled = false; }); });
  const accept = el('button', 'quiet', '수용');
  accept.type = 'button';
  accept.title = '오탐이거나 알고 받아들이는 상태입니다. 같은 사건은 더 이상 올리지 않습니다.';
  accept.addEventListener('click', () => {
    accept.disabled = true;
    post('/api/soc/ti/feedback', { eventId: event.id, verdict: 'benign' })
      .then((response) => { if (!response.ok) { accept.disabled = false; return; } const e = state.events.get(event.id); if (e) { e.verdict = 'benign'; e.ack = true; } renderAll(); })
      .catch(() => { accept.disabled = false; });
  });
  act.append(button, accept);
  tr.append(time, sev, src, msg, act);
  return { tr, time, sev, src, title, detail, rule, attack, button, accept };
}
function patchRow(row, event) {
  setClass(row.tr, `row sev-${event.severity}${event.ack ? ' acked' : ''}${event.test ? ' test' : ''}`);
  setText(row.time, whenText(event.lastAt));
  setText(row.sev, `${SEV[event.severity].glyph} ${SEV[event.severity].label}`);
  setText(row.src, [DOMAIN[event.domain], SOURCE[event.source] || event.source].filter(Boolean).join(' · '));
  setText(row.title, event.count > 1 ? `${event.title}  ×${event.count}` : event.title);
  setText(row.detail, event.detail);
  setHidden(row.detail, !event.detail);
  setText(row.rule, event.rule ? `규칙 ${event.rule.id}: ${event.rule.text}` : '');
  setHidden(row.rule, !event.rule);
  const techniques = event.attack && event.attack.length ? `ATT&CK ${event.attack.map((t) => `${t.id} ${t.name}`).join(' · ')}` : '';
  setText(row.attack, techniques);
  setHidden(row.attack, !techniques);
  setHidden(row.button, event.ack);
  setHidden(row.accept, event.ack || event.test || !event.key);
}

const sortedEvents = () => [...state.events.values()].sort((a, b) => Date.parse(b.lastAt) - Date.parse(a.lastAt) || b.id - a.id);
// 목록 하나 = tbody 하나. 같은 사건이라도 목록마다 행을 따로 가진다.
function createFeed(bodyId, emptyId, pick, limit) {
  const rows = new Map();
  return (list) => {
    const body = $(bodyId);
    if (!body) return;
    const wanted = pick(list).slice(0, limit);
    const keep = new Set(wanted.map((e) => e.id));
    for (const [id, row] of rows) if (!keep.has(id)) { row.tr.remove(); rows.delete(id); }
    wanted.forEach((event, index) => {
      let row = rows.get(event.id);
      if (!row) { row = buildRow(event); rows.set(event.id, row); }
      patchRow(row, event);
      if (body.children[index] !== row.tr) body.insertBefore(row.tr, body.children[index] || null);
    });
    setHidden($(emptyId), wanted.length > 0);
  };
}
const feeds = [
  createFeed('feed-body', 'feed-empty', (list) => {
    let out = list;
    if (state.domainFilter !== 'all') out = out.filter((e) => e.domain === state.domainFilter);
    if (state.filter === 'high') out = out.filter((e) => SEV[e.severity].rank >= 3);
    if (state.filter === 'unacked') out = out.filter((e) => !e.ack);
    return out;
  }, 120),
  createFeed('issues-body', 'issues-empty', (list) => list.filter((e) => !e.ack && SEV[e.severity].rank >= 2).sort((a, b) => SEV[b.severity].rank - SEV[a.severity].rank || Date.parse(b.lastAt) - Date.parse(a.lastAt)), 8),
  ...['network', 'endpoint', 'iam'].map((key) => createFeed(`feed-${key}-body`, `feed-${key}-empty`, (list) => list.filter((e) => e.domain === key), 80)),
  createFeed('wfeed-body', 'wfeed-empty', (list) => list, 40),
];
function renderFeed() { const list = sortedEvents(); for (const render of feeds) render(list); }

const FILTERS = [['all', '전체'], ['high', '긴급·높음'], ['unacked', '미확인만']];
const filterButtons = new Map();
for (const [key, label] of FILTERS) {
  const button = el('button', null, label);
  button.type = 'button';
  button.setAttribute('aria-pressed', String(state.filter === key));
  button.addEventListener('click', () => { state.filter = key; for (const [k, b] of filterButtons) b.setAttribute('aria-pressed', String(k === key)); renderFeed(); });
  filterButtons.set(key, button);
  $('filters').append(button);
}

const DOMAIN_FILTERS = [['all', '모든 영역'], ['network', '네트워크'], ['endpoint', '엔드포인트'], ['iam', '계정·접근']];
const domainButtons = new Map();
for (const [key, label] of DOMAIN_FILTERS) {
  const button = el('button', null, label);
  button.type = 'button';
  button.setAttribute('aria-pressed', String(state.domainFilter === key));
  button.addEventListener('click', () => { state.domainFilter = key; for (const [k, b] of domainButtons) b.setAttribute('aria-pressed', String(k === key)); renderFeed(); });
  domainButtons.set(key, button);
  $('domain-filters').append(button);
}

// ---------- 수집기 패널(에이전트·폴더) ----------
const AGENT_STATE = { active: ['normal', '수집 중'], no_data: ['unknown', '기록 없음'], stale: ['warn', '오래됨'], not_configured: ['unknown', '수집 안 함'] };
const agentRefs = {};
function buildAgentPanel() {
  const panel = $('agent-panel');
  const head = el('div', 'panel-head');
  agentRefs.state = el('span', 'state lv-unknown', '○ 수집 안 함');
  head.append(el('h2', 'mini', 'LLM 에이전트 활동'), agentRefs.state);
  agentRefs.msg = el('p', 'note');
  agentRefs.kv = el('dl', 'kv');
  agentRefs.values = {};
  for (const [key, label] of [['calls', '도구 호출(5분)'], ['reads', '파일 읽기류'], ['writes', '파일 쓰기류'], ['outside', '작업 폴더 밖'], ['sensitive', '민감 경로']]) {
    const dd = el('dd', null, '—'); agentRefs.values[key] = dd; agentRefs.kv.append(el('dt', null, label), dd);
  }
  agentRefs.lines = el('ul', 'lines');
  // 이 PC의 Claude Code·Codex 설정에 감사 훅을 등록한다(다른 PC에 새로 설치했을 때 한 번 누르면 됨).
  agentRefs.hookBox = el('div', 'hook-connect');
  agentRefs.hookText = el('p', 'note', '감사 훅 연결 상태를 확인하는 중…');
  agentRefs.hookBtn = el('button', 'solid-accent', '이 PC에 감시 연결');
  agentRefs.hookBtn.type = 'button';
  agentRefs.hookBtn.addEventListener('click', connectHooks);
  agentRefs.hookBox.append(agentRefs.hookText, agentRefs.hookBtn);
  const how = el('details');
  how.append(el('summary', null, '수집을 켜는 방법·한계'),
    el('p', 'note', 'Windows는 일반 권한 앱에게 다른 프로그램의 파일 읽기를 알려 주지 않습니다. 그래서 이 패널은 에이전트의 훅(hook)이 남긴 기록만 볼 수 있습니다. 훅이 없으면 에이전트의 파일 접근은 보이지 않으며, 보이지 않는다고 안전하다는 뜻이 아닙니다.'),
    el('p', 'note', '켜려면 Claude Code 설정(settings.json)의 PreToolUse 훅에 tools\\agent-audit-hook.mjs 를 등록합니다. 자세한 방법은 docs/SOC_GUIDE.md.'));
  panel.append(head, agentRefs.msg, agentRefs.hookBox, agentRefs.kv, agentRefs.lines, how);
}
buildAgentPanel();
async function loadHookStatus() {
  try {
    const res = await fetch('/api/soc/agent-hooks', { cache: 'no-store' });
    const body = await res.json();
    if (!body.ok) throw Error();
    const s = body.data;
    const part = (name, x) => (!x.found ? `${name} 설치 안 됨` : x.connected ? `${name} 연결됨` : `${name} 연결 안 됨`);
    setText(agentRefs.hookText, `${part('Claude Code', s.claude)} · ${part('Codex CLI', s.codex)}${s.runner === 'none' ? ' · Node.js 없음' : ''}`);
    agentRefs.hookBtn.textContent = (s.claude.found && !s.claude.connected) || (s.codex.found && !s.codex.connected) ? '이 PC에 감시 연결' : '다시 연결';
  } catch { setText(agentRefs.hookText, '감사 훅 연결 상태를 확인하지 못했습니다.'); }
}
async function connectHooks() {
  const ok = window.confirm('이 PC의 Claude Code 설정(%USERPROFILE%\\.claude\\settings.json)과 Codex 설정(%USERPROFILE%\\.codex\\hooks.json)에 감사 훅을 등록합니다.\n\n- 에이전트가 도구를 쓸 때 대상 경로·명령 일부를 이 PC의 감사 파일에 한 줄 남깁니다(에이전트 동작은 막지 않음).\n- 다른 설정은 건드리지 않고, 처음 바꾸기 전 원본을 .djokovic-backup 으로 남깁니다.\n- Codex 는 연결 뒤 /hooks 에서 신뢰로 한 번 표시해야 합니다.\n\n연결할까요?');
  if (!ok) return;
  agentRefs.hookBtn.disabled = true;
  try {
    const res = await post('/api/soc/agent-hooks/install', {});
    const body = await res.json();
    if (!body.ok) throw Error(body.error && body.error.message);
    window.alert(body.data.results.map((r) => `${r.ok ? '✔' : '✖'} ${r.agent}: ${r.message}`).join('\n'));
  } catch (e) { window.alert(`연결하지 못했습니다. ${e.message || ''}`); }
  agentRefs.hookBtn.disabled = false;
  loadHookStatus();
}
if (!state.pipMode) loadHookStatus();

function renderAgent() {
  const agent = state.collectors && state.collectors.agent;
  if (!agent) return;
  const [level, label] = AGENT_STATE[agent.state] || AGENT_STATE.not_configured;
  setClass(agentRefs.state, `state lv-${level}`);
  setText(agentRefs.state, `${LEVEL[level].glyph} ${label}`);
  const messages = {
    not_configured: '파일 접근 기록 안 됨: 에이전트 감사 훅이 아직 연결되지 않았습니다. 에이전트가 실행 중인지는 위 「실행 중인 AI 에이전트」로 보이지만, 어떤 파일을 읽는지는 훅을 붙여야 보입니다(보이지 않는다고 안전하다는 뜻이 아님).',
    no_data: '감사 파일은 있지만 아직 읽은 기록이 없습니다.',
    stale: `마지막 기록이 ${agent.lastRecordAt ? hhmmss(agent.lastRecordAt) : '오래 전'}입니다. 10분 넘게 새 기록이 없습니다.`,
    active: `마지막 기록 ${hhmmss(agent.lastRecordAt)}. 훅이 남긴 기록만 반영합니다.`,
  };
  setText(agentRefs.msg, messages[agent.state] || '');
  const counts = agent.counts || {};
  for (const key of Object.keys(agentRefs.values)) setText(agentRefs.values[key], agent.state === 'not_configured' ? '—' : String(counts[key] ?? 0));
  const latest = agent.latest || [];
  const signature = JSON.stringify(latest.map((l) => [l.at, l.tool, l.rule]));
  if (agentRefs.lines.dataset.sig !== signature) {
    agentRefs.lines.dataset.sig = signature;
    agentRefs.lines.replaceChildren(...latest.map((line) => {
      const target = (line.targets && line.targets[0]) || line.command || '';
      return el('li', line.severity === 'critical' ? 'sev-critical' : line.severity === 'medium' ? 'sev-medium' : '', `${hhmmss(line.at)} ${line.tool} ${clip(target, 70)}${line.rule ? ` [${line.rule}]` : ''}`);
    }));
  }
}

const filesRefs = {};
function buildFilesPanel() {
  const panel = $('files-panel');
  const head = el('div', 'panel-head');
  filesRefs.state = el('span', 'state lv-unknown', '○ 감시 없음');
  head.append(el('h2', 'mini', '폴더 변경 감시 · 알림 상태'), filesRefs.state);
  filesRefs.list = el('ul', 'lines');
  filesRefs.native = el('p', 'note');
  filesRefs.note = el('p', 'note');
  panel.append(head, filesRefs.list, filesRefs.note, filesRefs.native);
}
buildFilesPanel();
function renderFiles() {
  const c = state.collectors;
  if (!c) return;
  const watching = c.files.watching || [];
  setClass(filesRefs.state, `state lv-${watching.length ? 'normal' : 'unknown'}`);
  setText(filesRefs.state, watching.length ? `● ${watching.length}개 감시 중` : '○ 감시 없음');
  const signature = JSON.stringify(watching);
  if (filesRefs.list.dataset.sig !== signature) {
    filesRefs.list.dataset.sig = signature;
    filesRefs.list.replaceChildren(...(watching.length ? watching.map((w) => el('li', w.sensitive ? 'sev-critical' : '', `[${WATCH_KIND[w.kind] || '지정 폴더'}] ${w.dir}`)) : [el('li', null, '감시 중인 폴더가 없습니다(.ssh, .aws 가 없거나 ON_SOC_WATCH_DIRS 가 비어 있음)')]));
  }
  setText(filesRefs.note, `${c.files.note || '변경만 감지하며 파일 열람은 감지하지 못합니다.'} 감지 ${c.files.events ?? 0}건`);
  const native = c.native || {};
  setText(filesRefs.native, native.enabled ? `Windows 긴급 팝업: 켜짐 (발송 ${native.launched ?? 0}회, 간격 제한으로 막은 횟수 ${native.suppressed ?? 0}회)` : 'Windows 긴급 팝업: 꺼짐');
}

// ---------- 보안 영역별 상태(네트워크 / 엔드포인트 / 계정·접근) ----------
const domainRefs = {};
const WATCH_KIND = { keys: '민감 키 폴더(.ssh·.aws)', startup: '시작 프로그램 폴더', hosts: 'hosts 파일', custom: '지정 폴더' };
// 실행 중인 AI 에이전트(프로세스 이름·명령줄로 판단)
const runningAgents = () => { const p = state.intel && state.intel.scans && state.intel.scans.processes; return p && p.status === 'measured' && Array.isArray(p.agents) ? p.agents : null; };
const agentListText = (list) => (list.length ? list.map((a) => a.name).join(', ') : '없음');
const DOMAIN_TITLE = { network: '네트워크 보안', endpoint: '엔드포인트 보안', iam: '계정·접근 관리' };
const GLYPH = { normal: '●', warn: '▲', critical: '■', unknown: '○' };
const LEVEL_ORDER = { unknown: 0, normal: 1, warn: 2, critical: 3 };
function buildDomainCard(container, key, compact) {
  const root = el('article', `domain${compact ? ' compact' : ''} lv-unknown`);
  const head = el('div', 'domain-head');
  const chip = el('span', 'chip');
  const title = el('div', 'domain-title');
  title.append(icon(key, 28), el('h3', null, DOMAIN_TITLE[key]));
  head.append(title, chip);
  const list = el('ul', 'dlines');
  const ref = { root, chip, list, lines: new Map(), compact };
  root.append(head);
  if (compact) {
    const tally = el('div', 'dtally');
    ref.tally = {};
    for (const sev of ['critical', 'high', 'medium']) { const span = el('span', 'count sev-zero'); ref.tally[sev] = span; tally.append(span); }
    const more = el('button', 'quiet dmore', '자세히 보기 →');
    more.type = 'button';
    more.addEventListener('click', () => showView(key));
    root.append(tally, list, more);
  } else {
    const folded = el('details');
    ref.more = el('p', 'more');
    folded.append(el('summary', null, '한계·설명'), ref.more);
    root.append(list, folded);
  }
  container.append(root);
  return ref;
}
function buildDomains() {
  const widgetId = { network: 'w-net-detail', endpoint: 'w-end-detail', iam: 'w-iam-detail' };
  for (const key of ['network', 'endpoint', 'iam']) domainRefs[key] = { detail: buildDomainCard($(`d-${key}`), key, false), summary: buildDomainCard($('w-domains'), key, true), widget: buildDomainCard($(widgetId[key]), key, false) };
}
buildDomains();

function unavailableText(cell) {
  if (!cell) return '확인 불가: 아직 읽은 값이 없습니다. 「지금 점검」을 눌러 보세요.';
  const next = { PERMISSION: '관리자 권한이 필요한 항목이라 읽지 않습니다.', TIMEOUT: '잠시 뒤 「지금 점검」을 누르세요.' }[cell.code] || '「지금 점검」을 눌러 보세요.';
  return `확인 불가: ${cell.reason} ${next}`;
}
const bad = (cell) => !cell || cell.status !== 'measured';
const onOff = (value) => (value === true ? '켜짐' : value === false ? '꺼짐' : '확인 불가');

// 한 줄 = { key, label, level, text }. 키 기준으로 제자리 갱신한다.
function paintLines(ref, lines) {
  const keep = new Set(lines.map((l) => l.key));
  for (const [key, row] of ref.lines) if (!keep.has(key)) { row.li.remove(); ref.lines.delete(key); }
  lines.forEach((line, index) => {
    let row = ref.lines.get(line.key);
    if (!row) {
      const li = el('li');
      const mark = el('span', 'mark'), label = el('span', 'dlabel'), text = el('span', 'dtext');
      li.append(mark, label, text);
      row = { li, mark, label, text };
      ref.lines.set(line.key, row);
    }
    setClass(row.li, `dline lv-${line.level}`);
    setText(row.mark, GLYPH[line.level]);
    setText(row.label, line.label);
    setText(row.text, line.text);
    if (ref.list.children[index] !== row.li) ref.list.insertBefore(row.li, ref.list.children[index] || null);
  });
}

function domainLevel(lines, domain) {
  let level = 'unknown';
  const consider = (candidate) => { if (LEVEL_ORDER[candidate] > LEVEL_ORDER[level]) level = candidate; };
  for (const line of lines) consider(line.level);
  for (const e of state.events.values()) if (!e.ack && e.domain === domain) consider(e.severity === 'critical' || e.severity === 'high' ? 'critical' : e.severity === 'medium' ? 'warn' : 'normal');
  return level;
}

function networkLines() {
  const s = state.security, n = s && s.net;
  const fw = s && s.firewall;
  const lines = [];
  lines.push({ key: 'fw', label: '방화벽', level: bad(fw) ? 'unknown' : fw.profiles.every((p) => p.enabled === 'off') ? 'critical' : fw.profiles.some((p) => p.enabled === 'off') ? 'warn' : 'normal',
    text: !s ? '점검 중…' : bad(fw) ? unavailableText(fw) : fw.profiles.map((p) => `${p.name} ${p.enabled === 'on' ? '켜짐' : p.enabled === 'off' ? '꺼짐' : '확인 불가'}`).join(' · ') });
  const rules = n && n.fwRules;
  lines.push({ key: 'fwrules', label: '인바운드 허용 규칙', level: bad(rules) ? 'unknown' : 'normal', text: !n ? '점검 중…' : bad(rules) ? unavailableText(rules) : `${rules.count}개 켜짐 · 시작 이후 새로 생기면 사건으로 알림` });
  const ips = n && n.ips;
  lines.push({ key: 'ips', label: 'IPS(호스트 기준)', level: bad(ips) ? 'unknown' : ips.nis === false || ips.detections.length > 0 ? 'warn' : 'normal',
    text: !n ? '점검 중…' : bad(ips) ? unavailableText(ips) : `Defender 네트워크 검사 ${onOff(ips.nis)} · 네트워크 보호 ${{ off: '꺼짐(기본값)', on: '켜짐', audit: '감사 모드', unknown: '확인 불가' }[ips.netProtection] || '확인 불가'} · 위협 탐지 이력 ${ips.detections.length}건` });
  const vpn = n && n.vpn;
  const vpnCount = vpn && !bad(vpn) ? vpn.profiles.length + vpn.adapters.length : 0;
  lines.push({ key: 'vpn', label: 'VPN', level: bad(vpn) ? 'unknown' : [...vpn.profiles.map((p) => p.connected), ...vpn.adapters.map((a) => a.up)].some((up) => !up) ? 'warn' : 'normal',
    text: !n ? '점검 중…' : bad(vpn) ? unavailableText(vpn) : vpnCount === 0 ? '사용 안 함(VPN 프로필·어댑터 없음) · 해당 없음' : `프로필 ${vpn.profiles.length}개(연결 ${vpn.profiles.filter((p) => p.connected).length}) · 어댑터 ${vpn.adapters.length}개(켜짐 ${vpn.adapters.filter((a) => a.up).length})` });
  const nac = n && n.nac;
  const def = s && s.defender;
  const fwOk = !bad(fw) && fw.profiles.every((p) => p.enabled === 'on');
  lines.push({ key: 'nac', label: 'NAC(단말 상태)', level: bad(nac) ? 'unknown' : 'normal',
    text: !n ? '점검 중…' : bad(nac) ? unavailableText(nac) : `네트워크 위치 ${nac.categories.join('·') || '확인 불가'} · 802.1X ${nac.dot1x ? '사용' : '미사용'} · 주변 장치 ${nac.neighborCount}개 · 단말 상태 방화벽 ${fwOk ? '정상' : '확인 필요'}, Defender ${def && !bad(def) && def.realTime === true ? '정상' : '확인 필요'}` });
  const ports = s && s.ports;
  lines.push({ key: 'ports', label: '수신 대기 포트', level: bad(ports) ? 'unknown' : 'normal', text: !s ? '점검 중…' : bad(ports) ? unavailableText(ports) : `외부 접근 가능 ${ports.exposedCount}개 / 전체 ${ports.total}개 · 새로 열리면 사건으로 알림` });
  const net = state.intel && state.intel.scans && state.intel.scans.network;
  lines.push({ key: 'conn', label: '연결·IOC 대조', level: !net || net.status !== 'measured' ? 'unknown' : net.matches > 0 ? 'critical' : 'normal',
    text: !net ? '스캔 전' : net.status !== 'measured' ? `확인 불가: ${net.reason}` : `현재 연결 ${net.connections}개(외부 ${net.external}개) 중 침해지표 일치 ${net.matches}건 · ${hhmmss(net.at)}` });
  return lines;
}

function endpointLines() {
  const s = state.security, d = s && s.defender, a = state.anomaly;
  const lines = [];
  lines.push({ key: 'def', label: 'Defender', level: bad(d) ? 'unknown' : d.realTime === false || d.antivirus === false ? 'critical' : d.signatureAgeDays > 7 ? 'warn' : 'normal',
    text: !s ? '점검 중…' : bad(d) ? unavailableText(d) : `실시간 보호 ${onOff(d.realTime)} · 백신 ${onOff(d.antivirus)} · 서명 ${d.signatureAgeDays === null ? '확인 불가' : `${d.signatureAgeDays}일 전`}` });
  const names = { cpu: 'CPU', memory: '메모리', disk: '디스크' };
  const worst = a ? ['cpu', 'memory', 'disk'].map((k) => a[k].level).reduce((x, y) => (LEVEL_ORDER[y] > LEVEL_ORDER[x] ? y : x), 'unknown') : 'unknown';
  lines.push({ key: 'res', label: '자원 이상 탐지', level: worst,
    text: !a ? '측정 중…' : worst === 'normal' ? 'CPU·메모리·디스크 모두 평소 범위(2초마다 판정)' : worst === 'unknown' ? '기준 수집 중' : ['cpu', 'memory', 'disk'].filter((k) => a[k].reasons.length).map((k) => `${names[k]} ${a[k].reasons[0].ruleId}`).join(' · ') });
  const proc = state.intel && state.intel.scans && state.intel.scans.processes;
  lines.push({ key: 'proc', label: '프로세스·TTP 감시', level: !proc || proc.status !== 'measured' ? 'unknown' : proc.matches > 0 ? 'critical' : 'normal',
    text: !proc ? '스캔 전' : proc.status !== 'measured' ? `확인 불가: ${proc.reason}` : `프로세스 ${proc.total}개 중 명령줄 보임 ${proc.withCommandLine}개 · TTP 규칙 ${state.intel.ruleCount}개 · 탐지 ${proc.matches}건 · 실행 파일 해시 검사 ${proc.hashedTotal}개(대기 ${proc.hashPending})` });
  const ev = s && s.events;
  const cnt = (c) => (c && c.status === 'measured' ? c.value : '확인 불가');
  lines.push({ key: 'winlog', label: 'Windows 기록(24시간)', level: !ev || !ev.logs ? 'unknown' : 'normal',
    text: !ev || !ev.logs ? '점검 중…' : `System 오류 ${cnt(ev.logs.System.errors)}·경고 ${cnt(ev.logs.System.warnings)} / Application 오류 ${cnt(ev.logs.Application.errors)}·경고 ${cnt(ev.logs.Application.warnings)} (건수일 뿐 침해 탐지가 아님)` });
  const files = state.collectors && state.collectors.files;
  lines.push({ key: 'files', label: '폴더 변경 감시', level: files && files.watching.length ? 'normal' : 'unknown',
    text: !files ? '확인 중…' : files.watching.length ? `${files.watching.map((w) => WATCH_KIND[w.kind] || '지정 폴더').join(' · ')} 감시 중 · 바뀌면 바로 알림(열람은 감지 못함)` : '감시 중인 폴더 없음(.ssh, .aws 가 없거나 지정 안 함)' });
  const inv = state.collectors && state.collectors.inventory;
  const invText = (part, noun) => (!inv ? '확인 중…' : part.status === 'pending' ? '첫 점검 중…' : part.status !== 'measured' ? `확인 불가: ${part.reason}` : `${noun} ${part.count}개 · ${inv.baseline.firstRun && !part.added.length ? '기준 목록을 이번에 처음 만들었습니다(지금 있는 것은 알리지 않음)' : '기준 목록에 없던 것이 생기면 사건으로 알림'}${part.added.length ? ` · 최근 새로 생김: ${part.added.slice(0, 2).map((x) => x.name).join(', ')}` : ''} · ${Math.round(inv.intervals.softwareSeconds / 60)}분마다`);
  lines.push({ key: 'programs', label: '설치 프로그램', level: !inv || inv.programs.status !== 'measured' ? 'unknown' : inv.programs.added.length ? 'warn' : 'normal', text: inv ? invText(inv.programs, '설치됨') : '확인 중…' });
  lines.push({ key: 'tasks', label: '예약 작업', level: !inv || inv.tasks.status !== 'measured' ? 'unknown' : inv.tasks.added.length ? 'warn' : 'normal', text: inv ? invText(inv.tasks, '보이는 작업') : '확인 중…' });
  const usb = inv && inv.usb;
  lines.push({ key: 'usb', label: 'USB 저장장치', level: !usb || usb.status !== 'measured' ? 'unknown' : 'normal',
    text: !usb || usb.status === 'pending' ? '확인 중…' : usb.status !== 'measured' ? `확인 불가: ${usb.reason}` : usb.devices.length ? `연결됨: ${usb.devices.map((d) => `${d.model}${d.letters.length ? ` (${d.letters.join(', ')})` : ''}${d.sizeGb !== null ? ` ${d.sizeGb}GB` : ''}`).join(' · ')} · 새로 꽂으면 사건으로 알림` : `연결된 장치 없음 · ${inv.intervals.usbSeconds}초마다 확인, 새로 꽂으면 사건으로 알림` });
  return lines;
}

function iamLines() {
  const s = state.security, iam = s && s.iam;
  const lines = [];
  if (!s || !iam) lines.push({ key: 'acc', label: '로컬 계정', level: 'unknown', text: '점검 중…' });
  else if (bad(iam)) lines.push({ key: 'acc', label: '로컬 계정', level: 'unknown', text: unavailableText(iam) });
  else {
    const enabled = iam.users.filter((u) => u.enabled).length;
    const noPw = iam.users.filter((u) => u.enabled && !u.pwRequired).length;
    lines.push({ key: 'acc', label: '로컬 계정', level: 'normal', text: `${iam.users.length}개(활성 ${enabled}) · 관리자 ${iam.admins.length}명 · 새 계정·새 관리자는 사건으로 알림` });
    // 사건에서 「수용」(알고 받아들임)으로 판정한 설정은 주의 대신 정상으로 보이되, 수용했다는 사실을 글로 남긴다.
    const accepted = (ruleId) => [...state.events.values()].some((e) => e.rule && e.rule.id === ruleId && e.verdict === 'benign');
    const autoOk = accepted('IAM-AUTOLOGON');
    lines.push({ key: 'auto', label: '자동 로그인', level: iam.autoLogon && !autoOk ? 'warn' : 'normal', text: !iam.autoLogon ? '꺼짐' : autoOk ? '켜짐 · 수용함(알고 받아들인 설정)' : '켜짐: 부팅하면 비밀번호 없이 로그인됩니다. PC를 만질 수 있는 사람이면 누구나 같은 권한을 얻습니다. 의도한 설정이면 사건에서 「수용」을 누르세요' });
    lines.push({ key: 'uac', label: '사용자 계정 컨트롤', level: iam.uac === false ? 'critical' : iam.uac === true ? 'normal' : 'unknown', text: onOff(iam.uac) });
    const noPwOk = accepted('IAM-NO-PWREQ');
    lines.push({ key: 'nopw', label: '빈 비밀번호 허용', level: noPw > 0 && !noPwOk ? 'warn' : 'normal', text: noPw === 0 ? '없음' : noPwOk ? `활성 계정 ${noPw}개 · 수용함(알고 받아들인 설정)` : `활성 계정 ${noPw}개는 비밀번호를 비워 둬도 되게 설정돼 있습니다(Windows의 "암호 필요" 옵션 꺼짐). 지금 비밀번호가 비어 있는지는 읽지 않아 모릅니다. 비밀번호를 쓰고 있다면 위험은 낮습니다. 의도했다면 사건에서 「수용」을 누르세요` });
    lines.push({ key: 'elev', label: '이 앱의 실행 권한', level: iam.elevated ? 'warn' : 'normal', text: iam.elevated ? '관리자 권한으로 실행 중(권장하지 않음)' : '일반 권한으로 실행 중' });
  }
  const agent = state.collectors && state.collectors.agent;
  const idle = !agent || agent.state === 'not_configured' || agent.state === 'no_data';
  const agents = runningAgents();
  lines.push({ key: 'agents-running', label: '실행 중인 AI 에이전트', level: agents ? 'normal' : 'unknown',
    text: agents ? `${agentListText(agents)} (프로세스 이름·명령줄로 확인, 15초마다)` : '프로세스 스캔 전' });
  lines.push({ key: 'agent', label: 'AI 에이전트 파일 접근', level: idle ? 'unknown' : agent.counts.sensitive > 0 ? 'critical' : agent.counts.outside > 0 ? 'warn' : 'normal',
    text: !agent ? '확인 중…' : agent.state === 'not_configured' ? '기록 안 됨: 에이전트에 감사 훅을 붙여야 어떤 파일을 읽는지 보입니다(Windows가 다른 프로그램의 파일 읽기를 알려 주지 않음)' : agent.state === 'no_data' ? '감사 파일은 있으나 기록 없음' : `최근 5분 도구 호출 ${agent.counts.calls}회 · 작업 폴더 밖 ${agent.counts.outside} · 민감 경로 ${agent.counts.sensitive}` });
  const hooked = new Map(((agent && agent.agents) || []).map((x) => [x.agent, x.lastAt]));
  const hookText = (id, name) => (hooked.has(id) ? `${name} 기록 중(마지막 ${hhmmss(hooked.get(id))})` : `${name} 기록 없음`);
  lines.push({ key: 'agent-hooks', label: '감사 훅 연결', level: hooked.size ? 'normal' : 'unknown',
    text: `${hookText('claude-code', 'Claude Code')} · ${hookText('codex-cli', 'Codex CLI')} · 훅이 없는 에이전트는 실행 여부만 보입니다(Codex 는 설치 뒤 Codex 의 /hooks 에서 신뢰 표시 필요)` });
  return lines;
}

const DOMAIN_NOTES = {
  network: 'IPS·NAC는 원래 네트워크 장비 쪽 기능입니다. 이 앱은 이 PC가 보고하는 상태(Defender 네트워크 검사, VPN 어댑터, 802.1X·네트워크 위치, 주변 장치)만 읽고 차단·격리는 하지 않습니다. 침해지표 일치는 탐지이며 차단이 아닙니다.',
  endpoint: '관리자 권한이 필요한 프로세스(명령줄·실행 경로가 안 보이는 것)는 관측하지 못하고, 주기적으로 읽으므로 짧게 끝난 프로세스는 놓칠 수 있습니다.',
  iam: '로컬 계정만 대상입니다(도메인·클라우드 계정은 아님). 비교 규칙의 기준선은 앱을 켠 시점이라 앱이 꺼져 있던 동안의 변경은 알 수 없습니다.',
};
let domainLevels = { network: 'unknown', endpoint: 'unknown', iam: 'unknown' };
const openCount = (domain) => { let n = 0; for (const e of state.events.values()) if (!e.ack && SEV[e.severity].rank >= 2 && (!domain || e.domain === domain)) n += 1; return n; };
function paintBadge(view, count, level) {
  const tab = document.querySelector(`[data-view-tab="${view}"]`);
  const badge = tab && tab.querySelector('.badge');
  if (!badge) return;
  setHidden(badge, count === 0);
  setText(badge, count > 99 ? '99+' : String(count));
  setClass(badge, `badge lv-${level}`);
  if (tab.getAttribute('data-level') !== level) tab.setAttribute('data-level', level);
}
function renderDomains() {
  const sets = { network: networkLines(), endpoint: endpointLines(), iam: iamLines() };
  for (const key of ['network', 'endpoint', 'iam']) {
    const { detail, summary, widget } = domainRefs[key];
    const lines = sets[key];
    const level = domainLevel(lines, key);
    domainLevels[key] = level;
    for (const ref of [detail, summary, widget]) {
      setClass(ref.root, `domain${ref.compact ? ' compact' : ''} lv-${level}`);
      setText(ref.chip, `${LEVEL[level].glyph} ${LEVEL[level].label}`);
    }
    paintLines(detail, lines);
    setText(detail.more, DOMAIN_NOTES[key]);
    paintLines(widget, lines);
    setText(widget.more, DOMAIN_NOTES[key]);
    // 요약 카드: 문제 있는 항목만 위로(최대 3개), 없으면 한 줄 요약
    const problems = lines.filter((l) => l.level === 'critical' || l.level === 'warn').sort((a, b) => LEVEL_ORDER[b.level] - LEVEL_ORDER[a.level]).slice(0, 3);
    const unknown = lines.filter((l) => l.level === 'unknown').length;
    if (!problems.length) problems.push({ key: '_summary', label: '점검 항목', level: unknown === lines.length ? 'unknown' : 'normal', text: unknown ? `${lines.length - unknown}개 이상 없음 · 확인 불가 ${unknown}개` : `${lines.length}개 모두 이상 없음` });
    paintLines(summary, problems);
    for (const sev of ['critical', 'high', 'medium']) {
      let n = 0;
      for (const e of state.events.values()) if (!e.ack && e.domain === key && e.severity === sev) n += 1;
      setText(summary.tally[sev], `${SEV[sev].glyph} ${SEV[sev].label} ${n}`);
      setClass(summary.tally[sev], `count ${n > 0 ? `sev-${sev}` : 'sev-zero'}`);
    }
    paintBadge(key, openCount(key), level);
  }
  const all = openCount(null);
  const u = unackedCounts();
  paintBadge('events', all, u.critical || u.high ? 'critical' : u.medium ? 'warn' : 'normal');
}

// ---------- 현황 수치(KPI) ----------
const KPI = [['unacked', '미확인 사건'], ['firewall', '방화벽 · Defender'], ['ports', '외부 접근 포트'], ['detect', '침해지표·TTP 탐지']];
const kpiRefs = {};
function buildKpi() {
  const box = el('div', 'kpi');
  for (const [key, label] of KPI) {
    const cell = el('div', 'kpi-cell lv-unknown');
    const value = el('p', 'kpi-value', '—');
    const sub = el('p', 'kpi-sub');
    const badge = el('span', 'kpi-icon');
    badge.append(icon(key, 34));
    cell.append(badge, el('p', 'kpi-label', label), value, sub);
    box.append(cell);
    kpiRefs[key] = { cell, value, sub };
  }
  $('w-kpi').append(box);
}
buildKpi();
function paintKpi(key, level, value, sub) {
  const ref = kpiRefs[key];
  setClass(ref.cell, `kpi-cell lv-${level}`);
  setText(ref.value, value);
  setText(ref.sub, sub);
}
function renderKpi() {
  const u = unackedCounts();
  paintKpi('unacked', !state.gotSnapshot ? 'unknown' : u.critical || u.high ? 'critical' : u.medium ? 'warn' : 'normal', state.gotSnapshot ? String(u.critical + u.high + u.medium) : '—', `긴급 ${u.critical} · 높음 ${u.high} · 주의 ${u.medium}`);
  const s = state.security;
  const ports = s && s.ports;
  paintKpi('ports', bad(ports) ? 'unknown' : 'normal', bad(ports) ? '확인 불가' : String(ports.exposedCount), bad(ports) ? (s ? '읽지 못함' : '점검 중') : `전체 ${ports.total}개 중 · 새로 열리면 알림`);
  const fw = s && s.firewall;
  const def = s && s.defender;
  const on = bad(fw) ? 0 : fw.profiles.filter((x) => x.enabled === 'on').length;
  const defOff = !bad(def) && (def.realTime === false || def.antivirus === false);
  const fwLevel = bad(fw) ? 'unknown' : on === 0 || defOff ? 'critical' : on < fw.profiles.length ? 'warn' : 'normal';
  paintKpi('firewall', fwLevel, bad(fw) ? '확인 불가' : `${on}/${fw.profiles.length}`, bad(def) ? 'Defender 확인 불가' : `Defender 실시간 보호 ${def.realTime === true ? '켜짐' : def.realTime === false ? '꺼짐' : '확인 불가'}`);
  const intel = state.intel;
  const net = intel && intel.scans && intel.scans.network;
  const proc = intel && intel.scans && intel.scans.processes;
  const okNet = Boolean(net && net.status === 'measured'), okProc = Boolean(proc && proc.status === 'measured');
  const hits = (okNet ? net.matches : 0) + (okProc ? proc.matches : 0);
  paintKpi('detect', !okNet && !okProc ? 'unknown' : hits > 0 ? 'critical' : 'normal', !okNet && !okProc ? '확인 불가' : String(hits), `연결 ${okNet ? net.connections : '?'}개 · 프로세스 ${okProc ? proc.total : '?'}개 · 지표 ${intel ? intel.stats.active : '?'}개 대조`);
}

// ---------- 사건 구성(도넛) ----------
const DONUT_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const donutRefs = { segs: {}, rows: {} };
function ring() {
  const c = document.createElementNS(NS, 'circle');
  c.setAttribute('cx', '21'); c.setAttribute('cy', '21'); c.setAttribute('r', '15.915'); c.setAttribute('fill', 'none'); c.setAttribute('stroke-width', '5');
  return c;
}
function buildDonut() {
  const card = el('article', 'donut-card');
  const head = el('div', 'domain-head');
  head.append(el('h3', null, '사건 구성'), el('span', 'time', '기록된 사건 기준'));
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 42 42');
  svg.setAttribute('class', 'donut');
  svg.setAttribute('aria-hidden', 'true');
  const track = ring();
  track.setAttribute('class', 'donut-track');
  svg.append(track);
  for (const sev of DONUT_ORDER) { const c = ring(); c.setAttribute('class', `donut-seg sev-${sev}`); svg.append(c); donutRefs.segs[sev] = c; }
  const center = el('div', 'donut-center');
  donutRefs.num = el('strong', null, '—');
  center.append(donutRefs.num, el('span', null, '미확인'));
  const holder = el('div', 'donut-holder');
  holder.append(svg, center);
  const legend = el('ul', 'donut-legend');
  for (const sev of DONUT_ORDER) {
    const li = el('li', `sev-${sev}`);
    const bar = el('span', 'dl-bar');
    const fill = el('span', 'dl-fill');
    bar.append(fill);
    const n = el('span', 'dl-n', '0');
    li.append(el('span', 'dl-name', `${SEV[sev].glyph} ${SEV[sev].label}`), bar, n);
    legend.append(li);
    donutRefs.rows[sev] = { fill, n };
  }
  const wrap = el('div', 'donut-wrap');
  wrap.append(holder, legend);
  card.append(head, wrap);
  $('w-donut').append(card);
}
buildDonut();
function renderDonut() {
  const counts = Object.fromEntries(DONUT_ORDER.map((sev) => [sev, 0]));
  for (const e of state.events.values()) if (counts[e.severity] !== undefined) counts[e.severity] += 1;
  const total = DONUT_ORDER.reduce((sum, sev) => sum + counts[sev], 0);
  let offset = 0;
  for (const sev of DONUT_ORDER) {
    const pct = total ? (counts[sev] / total) * 100 : 0;
    const seg = donutRefs.segs[sev];
    seg.setAttribute('stroke-dasharray', `${pct.toFixed(2)} ${(100 - pct).toFixed(2)}`);
    seg.setAttribute('stroke-dashoffset', (25 - offset).toFixed(2));
    offset += pct;
    setText(donutRefs.rows[sev].n, String(counts[sev]));
    donutRefs.rows[sev].fill.style.width = `${Math.round(pct)}%`;
  }
  const u = unackedCounts();
  setText(donutRefs.num, state.gotSnapshot ? String(u.critical + u.high + u.medium) : '—');
}

// ---------- 추가 위젯: 위협 인텔리전스 요약 ----------
const tiRefs = {};
function kvList(container, rows) {
  const dl = el('dl', 'kv');
  const refs = {};
  for (const [key, label] of rows) { const dd = el('dd', null, '—'); dl.append(el('dt', null, label), dd); refs[key] = dd; }
  container.append(dl);
  return refs;
}
function buildTiSummary() {
  const box = $('w-ti-summary');
  const head = el('div', 'card-head');
  const open = el('button', 'quiet', '탭 열기 →');
  open.type = 'button';
  open.addEventListener('click', () => showView('ti'));
  head.append(el('h3', null, '위협 인텔리전스 요약'), open);
  box.append(head);
  tiRefs.kv = kvList(box, [['ioc', '활성 침해지표'], ['rules', '공격 수법 규칙'], ['net', '연결 대조'], ['proc', '프로그램 대조'], ['verdict', '판정 반영']]);
  box.append(el('p', 'note', '최근에 걸린 것'));
  tiRefs.list = el('ul', 'lines');
  box.append(tiRefs.list);
}
buildTiSummary();
function renderTiSummary() {
  const intel = state.intel;
  const net = intel && intel.scans && intel.scans.network, proc = intel && intel.scans && intel.scans.processes;
  setText(tiRefs.kv.ioc, intel ? `${intel.stats.active}개${intel.stats.active === 0 ? ' (목록이 비어 있음)' : ''}` : '불러오는 중');
  setText(tiRefs.kv.rules, intel ? `${intel.ruleCount}개` : '—');
  setText(tiRefs.kv.net, !net ? '스캔 전' : net.status !== 'measured' ? '확인 불가' : `${net.connections}개 중 일치 ${net.matches} · ${hhmmss(net.at)}`);
  setText(tiRefs.kv.proc, !proc ? '스캔 전' : proc.status !== 'measured' ? '확인 불가' : `${proc.total}개 중 탐지 ${proc.matches}`);
  setText(tiRefs.kv.verdict, intel ? `악성 확정 ${intel.feedback.malicious} · 오탐 ${intel.feedback.benign} · 억제 ${intel.feedback.suppressed}` : '—');
  const hits = sortedEvents().filter((e) => e.source === 'ioc' || e.source === 'ttp').slice(0, 5);
  const sig = JSON.stringify(hits.map((e) => [e.id, e.count, e.ack]));
  if (tiRefs.list.dataset.sig !== sig) {
    tiRefs.list.dataset.sig = sig;
    tiRefs.list.replaceChildren(...(hits.length ? hits.map((e) => el('li', e.severity === 'critical' ? 'sev-critical' : e.severity === 'medium' ? 'sev-medium' : '', `${hhmmss(e.lastAt)} ${SEV[e.severity].glyph} ${clip(e.title, 70)}${e.test ? ' [시험]' : ''}`)) : [el('li', null, '아직 걸린 것이 없습니다(이상이 없다는 뜻은 아님)')]));
  }
}

// ---------- 추가 위젯: AI 에이전트 활동 ----------
const agentLive = {};
function buildAgentLive() {
  const box = $('w-agent-live');
  const head = el('div', 'card-head');
  agentLive.state = el('span', 'state lv-unknown', '○ 확인 중');
  head.append(el('h3', null, 'AI 에이전트 활동'), agentLive.state);
  box.append(head);
  agentLive.kv = kvList(box, [['running', '실행 중'], ['calls', '도구 호출(5분)'], ['outside', '작업 폴더 밖'], ['sensitive', '민감 경로']]);
  agentLive.list = el('ul', 'lines');
  box.append(el('p', 'note', '최근 파일·명령 접근(훅 기록)'), agentLive.list);
}
buildAgentLive();
function renderAgentLive() {
  const agent = state.collectors && state.collectors.agent;
  const agents = runningAgents();
  setText(agentLive.kv.running, agents ? agentListText(agents) : '스캔 전');
  const active = Boolean(agent && agent.counts && agent.state !== 'not_configured' && agent.state !== 'no_data');
  const level = !active ? 'unknown' : agent.counts.sensitive > 0 ? 'critical' : agent.counts.outside > 0 ? 'warn' : 'normal';
  setClass(agentLive.state, `state lv-${level}`);
  setText(agentLive.state, !agent ? '○ 확인 중' : agent.state === 'not_configured' ? '○ 기록 안 됨' : agent.state === 'no_data' ? '○ 기록 없음' : agent.state === 'stale' ? '▲ 오래됨' : '● 기록 중');
  for (const key of ['calls', 'outside', 'sensitive']) setText(agentLive.kv[key], active ? String(agent.counts[key] ?? 0) : '—');
  const latest = (agent && agent.latest) || [];
  const sig = JSON.stringify(latest.map((l) => [l.at, l.tool, l.rule]));
  if (agentLive.list.dataset.sig !== sig) {
    agentLive.list.dataset.sig = sig;
    agentLive.list.replaceChildren(...(latest.length ? latest.map((line) => el('li', line.severity === 'critical' ? 'sev-critical' : line.severity === 'medium' ? 'sev-medium' : '', `${hhmmss(line.at)} ${line.tool} ${clip((line.targets && line.targets[0]) || line.command || '', 70)}${line.rule ? ` [${line.rule}]` : ''}`)) : [el('li', null, agent && agent.state === 'not_configured' ? '에이전트 감사 훅이 연결되지 않았습니다' : '아직 기록이 없습니다')]));
  }
}

// ---------- 사건 기록 보관 상태 ----------
function renderHistory() {
  const h = state.collectors && state.collectors.history;
  setText($('history-note'), !h ? '사건 기록 보관: 꺼짐(서버 메모리에만 있어 서버를 끄면 사라집니다)'
    : `사건 기록 보관: ${h.file} 에 ${h.maxAgeDays}일·최대 ${h.max}건까지 남깁니다${h.restored ? ` · 이번 실행 때 지난 사건 ${h.restored}건을 되살림` : ''}${h.savedAt ? ` · 마지막 저장 ${hhmmss(h.savedAt)}` : ''}${h.error ? ` · ${h.error}` : ''}`);
}
// ---------- 실시간 알림(오른쪽 위 토스트): 새 주의·높음 사건 ----------
// 알림의 「자세히」: 그 사건이 있는 영역 탭으로 가서 해당 줄로 스크롤하고 잠깐 강조한다.
// 영역 탭 목록에 없으면(필터·개수 제한) 사건 기록 탭에서 필터를 풀고 찾는다.
function focusEvent(id) {
  const event = state.events.get(id);
  const find = () => document.querySelector(`main[data-view]:not([hidden]) tr[data-event-id="${id}"]`);
  const flash = (row) => {
    row.scrollIntoView({ block: 'center', behavior: 'smooth' });
    // 줄의 class 는 화면 갱신 때마다 다시 쓰이므로 강조는 data 속성으로 붙인다
    row.removeAttribute('data-flash');
    void row.offsetWidth; // 같은 줄을 연달아 눌러도 다시 깜빡이게 한다
    row.setAttribute('data-flash', '');
    setTimeout(() => row.removeAttribute('data-flash'), 2600);
  };
  const domain = event && ['network', 'endpoint', 'iam'].includes(event.domain) ? event.domain : null;
  if (domain) { showView(domain); renderAll(); const row = find(); if (row) { flash(row); return; } }
  showView('events');
  for (const b of document.querySelectorAll('#domain-filters button, #filters button')) if (/^(모든 영역|전체)$/.test(b.textContent) && b.getAttribute('aria-pressed') !== 'true') b.click();
  renderAll();
  const row = find();
  if (row) flash(row);
  else setText($('live'), '그 사건은 목록 개수 제한으로 화면에 없습니다. 사건 기록 탭에서 시각으로 찾아보세요.');
}

function toast(event) {
  if (state.pipMode) return;
  const box = $('toasts');
  const sev = SEV[event.severity];
  const item = el('div', `toast sev-${event.severity}`);
  const actions = el('div', 'toast-actions');
  let timer = null;
  const close = () => { clearTimeout(timer); item.remove(); };
  const go = el('button', null, '자세히');
  go.type = 'button';
  go.addEventListener('click', () => { close(); focusEvent(event.id); });
  const dismiss = el('button', 'quiet', '닫기');
  dismiss.type = 'button';
  dismiss.addEventListener('click', close);
  actions.append(go, dismiss);
  item.append(el('p', 'toast-head', `${sev.glyph} ${sev.label} · ${DOMAIN[event.domain] || '기타'} · ${hhmmss(event.lastAt)}`), el('p', 'toast-title', clip(`${event.test ? '[시험] ' : ''}${event.title}`, 120)), actions);
  box.prepend(item);
  while (box.children.length > 4) box.lastElementChild.remove();
  timer = setTimeout(close, event.severity === 'high' ? 15000 : 8000);
}

// ---------- 긴급 경보(화면 전체 경고창·소리·제목 깜빡임·바탕화면 알림) ----------
let audio = null, beepTimer = null, titleTimer = null, tone = false, wasAlarm = false;
const BASE_TITLE = '보안 관제 · Djoković';

function beep() {
  if (!audio) return;
  const osc = audio.createOscillator(), gain = audio.createGain();
  tone = !tone;
  osc.type = 'square'; osc.frequency.value = tone ? 880 : 660; gain.gain.value = 0.07;
  osc.connect(gain); gain.connect(audio.destination);
  osc.start(); osc.stop(audio.currentTime + 0.28);
}
function unackedCritical() { return [...state.events.values()].filter((e) => e.severity === 'critical' && !e.ack).sort((a, b) => b.id - a.id); }

function renderAlarm() {
  if (state.pipMode) { setHidden($('alarm'), true); return; }
  const list = unackedCritical();
  const active = list.length > 0;
  const key = list.map((e) => `${e.id}:${e.count}`).join(',');
  setHidden($('alarm'), !active);
  if (active && key !== state.alarmKey) {
    state.alarmKey = key;
    $('alarm-list').replaceChildren(...list.slice(0, 4).map((e) => { const li = el('li', null, e.title); li.append(el('small', null, `${hhmmss(e.lastAt)} · ${e.rule ? e.rule.id : ''} ${e.detail}`)); return li; }), ...(list.length > 4 ? [el('li', null, `외 ${list.length - 4}건`)] : []));
    setText($('alarm-title'), list.length === 1 ? '긴급 사건이 발생했습니다' : `긴급 사건 ${list.length}건이 발생했습니다`);
    setHidden($('alarm-test'), !list.every((e) => e.test));
  }
  if (!active) state.alarmKey = '';
  if (active && !wasAlarm) { state.muted = false; setText($('alarm-mute'), '소리 끄기'); $('alarm-ack').focus(); }
  wasAlarm = active;
  const wantSound = active && state.soundOn && !state.muted && Boolean(audio);
  if (wantSound && !beepTimer) { beep(); beepTimer = setInterval(beep, 1200); }
  if (!wantSound && beepTimer) { clearInterval(beepTimer); beepTimer = null; }
  if (active && !titleTimer) { let flip = false; titleTimer = setInterval(() => { flip = !flip; document.title = flip ? `[긴급 ${unackedCritical().length}] ${BASE_TITLE}` : '■■■ 긴급 보안 경보 ■■■'; }, 900); }
  if (!active && titleTimer) { clearInterval(titleTimer); titleTimer = null; document.title = BASE_TITLE; }
}

function notifyDesktop(event) {
  if (state.pipMode) return;
  if (!state.notifyOn || !('Notification' in window) || Notification.permission !== 'granted') return;
  try { const n = new Notification(`긴급 보안 경보${event.test ? ' (시험)' : ''}`, { body: event.title, tag: `soc-${event.id}`, requireInteraction: true }); n.onclick = () => { window.focus(); n.close(); focusEvent(event.id); }; } catch { /* 알림 생성 실패는 화면 경보에 영향을 주지 않는다 */ }
}

// ---------- 소리·알림 설정 ----------
function readSetting(key) { try { return localStorage.getItem(key); } catch { return null; } }
function writeSetting(key, value) { try { localStorage.setItem(key, value); } catch { /* 저장 실패는 무시 */ } }
function ensureAudio() {
  if (!audio) { try { audio = new (window.AudioContext || window.webkitAudioContext)(); } catch { audio = null; } }
  if (audio && audio.state === 'suspended') audio.resume().catch(() => {});
}
function setToolIcon(button, name) { const img = button.querySelector('img.icon'); if (img) img.src = `/pc-status/icons/${name}.svg`; }
function paintSound() { const b = $('sound-toggle'); b.setAttribute('aria-pressed', String(state.soundOn)); toolText(b, state.soundOn ? '경보 소리 켜짐 · 누르면 끔' : '경보 소리 꺼짐 · 누르면 켬'); setToolIcon(b, state.soundOn ? 'sound' : 'sound-off'); }
// 브라우저 알림 권한은 한 번 허용하면 페이지가 되돌릴 수 없다. 그래서 켜기·끄기는 이 앱의 설정(soc.notify)으로 따로 둔다.
function paintNotify() {
  const b = $('notify-toggle');
  if (!('Notification' in window)) { toolText(b, '바탕화면 알림 지원 안 됨'); b.disabled = true; setToolIcon(b, 'notify-off'); return; }
  const permission = Notification.permission;
  const on = state.notifyOn && permission === 'granted';
  toolText(b, permission === 'denied' ? '바탕화면 알림 차단됨(브라우저 사이트 설정에서 허용 필요)' : on ? '바탕화면 알림 켜짐 · 누르면 끔' : '바탕화면 알림 꺼짐 · 누르면 켬');
  b.setAttribute('aria-pressed', String(on));
  setToolIcon(b, on ? 'notify' : 'notify-off');
}
state.soundOn = !state.pipMode && readSetting('soc.sound') === '1';
state.notifyOn = readSetting('soc.notify') !== '0';
paintSound(); paintNotify();
$('sound-toggle').addEventListener('click', () => {
  state.soundOn = !state.soundOn; writeSetting('soc.sound', state.soundOn ? '1' : '0');
  if (state.soundOn) { ensureAudio(); beep(); }
  paintSound(); renderAlarm();
});
document.addEventListener('pointerdown', () => { if (state.soundOn) ensureAudio(); });
$('notify-toggle').addEventListener('click', async () => {
  if (!('Notification' in window)) return;
  if (state.notifyOn && Notification.permission === 'granted') state.notifyOn = false;
  else {
    state.notifyOn = true;
    if (Notification.permission === 'default') { try { await Notification.requestPermission(); } catch { /* 사용자가 닫음 */ } }
  }
  writeSetting('soc.notify', state.notifyOn ? '1' : '0');
  paintNotify();
});
$('alarm-ack').addEventListener('click', () => { post('/api/soc/ack', { all: true, minRank: 4 }).catch(() => {}); });
$('alarm-mute').addEventListener('click', () => { state.muted = true; setText($('alarm-mute'), '소리 꺼짐'); renderAlarm(); });
$('test-alarm').addEventListener('click', async () => {
  const button = $('test-alarm'); button.disabled = true;
  try { const response = await post('/api/soc/test-alert'); if (response.status === 429) setText($('live'), '시험 경보는 5초에 한 번만 보낼 수 있습니다'); } catch { /* 연결 상태는 상단 표시가 알려 준다 */ }
  setTimeout(() => { button.disabled = false; }, 1500);
});
$('refresh-security').addEventListener('click', async () => {
  const button = $('refresh-security'); button.disabled = true; toolText(button, '점검 중…');
  try { await post('/api/soc/refresh-security'); } catch { /* 실패해도 기존 값은 읽은 시각과 함께 남는다 */ }
  button.disabled = false; toolText(button, '지금 점검');
});

// ---------- 화면 전환(왼쪽 탭): 페이지를 새로 읽지 않는다 ----------
const VIEWS = ['dashboard', 'network', 'endpoint', 'iam', 'events', 'ti', 'audit'];
const VIEW_TITLE = { dashboard: '대시보드', network: '네트워크 보안', endpoint: '엔드포인트 보안', iam: '계정·접근 관리', events: '사건 기록', ti: '위협 인텔리전스', audit: 'PC 보안 점검' };
function showView(name) {
  const view = VIEWS.includes(name) ? name : 'dashboard';
  state.view = view;
  writeSetting('soc.tab', view);
  setText($('view-title'), VIEW_TITLE[view]);
  for (const tab of document.querySelectorAll('[data-view-tab]')) tab.setAttribute('aria-pressed', String(tab.dataset.viewTab === view));
  for (const main of document.querySelectorAll('[data-view]')) setHidden(main, main.dataset.view !== view);
  setHidden($('layout-edit'), view !== 'dashboard');
  if (view === 'ti' && window.socTi) window.socTi.refresh();
}
for (const tab of document.querySelectorAll('[data-view-tab]')) tab.addEventListener('click', () => showView(tab.dataset.viewTab));

// ---------- 밝은 유리 / 어두운 유리 ----------
function paintTheme() {
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  const button = $('theme-toggle');
  button.setAttribute('aria-pressed', String(dark));
  toolText(button, dark ? '밝은 화면' : '어두운 화면');
}
$('theme-toggle').addEventListener('click', () => {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  writeSetting('soc.theme', next);
  paintTheme();
  window.socPip?.setTheme?.(next);
});
paintTheme();

// ---------- 바탕화면 비침: 켜기·끄기 버튼(아이콘이 바뀜)과 투명도 버튼(반투명 / 완전 투과) ----------
// data-glass: on(반투명) · clear(완전 투과) · off(바탕화면 끔, 불투명한 판). 끌 때도 투명도 선택은 기억해 두었다가 다시 켤 때 쓴다.
function glassMode() { const v = document.documentElement.getAttribute('data-glass'); return v === 'clear' || v === 'off' ? v : 'on'; }
function glassLevel() { const v = readSetting('soc.glassLevel'); return v === 'clear' ? 'clear' : 'on'; }
function applyGlass(next) {
  document.documentElement.setAttribute('data-glass', next);
  writeSetting('soc.glass', next);
  paintGlass();
  window.socPip?.setGlass?.(next);
}
function paintGlass() {
  const mode = glassMode();
  const on = mode !== 'off';
  const wall = $('glass-toggle');
  wall.setAttribute('aria-pressed', String(on));
  const img = $('glass-icon');
  const src = `/pc-status/icons/${on ? 'wall-on' : 'wall-off'}.svg`;
  if (!img.src.endsWith(src)) img.src = src;
  toolText(wall, on ? '바탕화면 비침 켜짐 · 누르면 끔' : '바탕화면 비침 꺼짐 · 누르면 켬');
  const level = $('glass-level');
  level.disabled = !on;
  level.setAttribute('aria-pressed', String(mode === 'clear'));
  toolText(level, !on ? '투명도(바탕화면을 켜면 고를 수 있음)' : mode === 'clear' ? '투명도: 완전 투과 · 누르면 반투명' : '투명도: 반투명 · 누르면 완전 투과');
}
// 바탕화면 그림의 평균 밝기를 재서 data-wall-tone(dark/light)을 정한다. 판 불투명도를 맞춰 글자가 묻히지 않게 한다.
const wallImages = { on: null, clear: null };
function paintWallpaper() {
  const mode = document.documentElement.getAttribute('data-glass');
  const image = mode === 'on' ? wallImages.on : mode === 'clear' ? wallImages.clear : null;
  document.body.style.backgroundImage = image ? `${image}, var(--scene)` : '';
}
new MutationObserver(paintWallpaper).observe(document.documentElement, { attributes: true, attributeFilter: ['data-glass'] });
function measureWallpaper() {
  const img = new Image();
  img.onload = () => {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 32; canvas.height = 18;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, 32, 18);
      const data = ctx.getImageData(0, 0, 32, 18).data;
      let sum = 0;
      for (let i = 0; i < data.length; i += 4) sum += 0.2126 * data[i] + 0.7152 * data[i + 1] + 0.0722 * data[i + 2];
      document.documentElement.setAttribute('data-wall-tone', sum / (data.length / 4) / 255 < 0.5 ? 'dark' : 'light');
    } catch { /* 밝기를 못 재면 기본 불투명도를 쓴다 */ }
    // 렉 줄이기: 판마다 뒤 화면을 실시간으로 흐리게(backdrop-filter) 하면 프레임마다 다시 계산해서 매우 느리다(이 PC 실측 초당 1프레임).
    // 그래서 바탕화면 그림을 한 번만 흐리게 그려 작은 그림(JPEG)으로 만들고, 판은 반투명 색만 쓴다. 반투명=강한 흐림, 완전 투과=약한 흐림.
    try {
      const scale = Math.min(1, 1600 / img.naturalWidth);
      const w = Math.round(img.naturalWidth * scale), h = Math.round(img.naturalHeight * scale);
      const render = (blur, saturate) => {
        const c = document.createElement('canvas');
        c.width = w; c.height = h;
        const g = c.getContext('2d');
        g.filter = `blur(${blur}px) saturate(${saturate}%)`;
        const pad = blur * 3; // 가장자리가 흐려져 비지 않게 조금 크게 그린다
        g.drawImage(img, -pad, -pad, w + pad * 2, h + pad * 2);
        return `url("${c.toDataURL('image/jpeg', 0.82)}")`;
      };
      // CSS 변수(var)에 그림을 넣으면 화면 갱신·애니메이션 때마다 그림을 다시 해석해서 느려진다(실측). body 의 style 에 직접 넣는다.
      wallImages.on = render(26, 150);
      wallImages.clear = render(3, 115);
      paintWallpaper();
    } catch { /* 그리지 못하면 그라데이션 배경을 쓴다 */ }
  };
  img.src = '/api/soc/wallpaper';
}
measureWallpaper();
$('glass-toggle').addEventListener('click', () => applyGlass(glassMode() === 'off' ? glassLevel() : 'off'));
$('glass-level').addEventListener('click', () => {
  if (glassMode() === 'off') return;
  const next = glassMode() === 'clear' ? 'on' : 'clear';
  writeSetting('soc.glassLevel', next);
  applyGlass(next);
});
paintGlass();

// ---------- 화면 갱신(짧은 간격으로 묶어서 한 번만) ----------
// requestAnimationFrame 은 탭이 가려져 있으면 멈추므로 쓰지 않는다. 다른 창을 보고 있을 때도 경보 화면·소리·제목 깜빡임이 동작해야 한다.
let scheduled = false;
const renderHooks = new Set();
function paintAll() {
  scheduled = false;
  // 한 영역의 오류가 다른 영역, 특히 긴급 경보 그리기를 막지 않게 하나씩 따로 그린다.
  for (const render of [renderAlarm, renderTrend, renderFeed, renderCounts, renderAgent, renderFiles, renderDomains, renderKpi, renderDonut, renderTiSummary, renderAgentLive, renderHistory]) {
    try { render(); } catch (error) { console.error(`화면 일부를 그리지 못했습니다(${render.name})`, error); }
  }
  const posture = renderPosture();
  setText($('sr'), posture.level === 'critical' ? `긴급 사건 ${unackedCritical().length}건` : '');
  for (const hook of renderHooks) { try { hook(); } catch { /* 한 화면의 오류가 다른 화면 갱신을 막지 않게 한다 */ } }
}
// 가려진 탭은 타이머가 늦춰지므로 서버가 보낸 순간 바로 그린다(PiP 창·경보가 늦어지지 않게).
function renderAll() {
  if (document.hidden) { paintAll(); return; }
  if (scheduled) return;
  scheduled = true;
  setTimeout(paintAll, 30);
}

// ---------- 서버 실시간 연결 ----------
function setLive(connected) {
  state.connected = connected;
  setClass($('live'), `live ${connected ? 'live-on' : 'live-off'}`);
  setText($('live'), connected ? '● 실시간 연결됨 · 서버가 2초마다 값을 보내 줍니다' : '○ 연결 끊김 · 자동으로 다시 연결하는 중입니다');
  renderAll();
}

function connect() {
  const source = new EventSource('/api/soc/stream');
  source.onopen = () => setLive(true);
  source.onerror = () => { setLive(false); if (!state.gotSnapshot) setText($('connecting-text'), '서버에 연결할 수 없습니다. 서버가 켜져 있는지 확인하세요(tools\\start-final.ps1). 자동으로 다시 시도합니다…'); };
  const touch = () => { state.lastMessageAt = Date.now(); };
  source.addEventListener('snapshot', (message) => {
    touch();
    const data = JSON.parse(message.data);
    state.events = new Map(data.events.map((e) => [e.id, e]));
    state.counts = data.counts; state.points = data.points; state.anomaly = data.anomaly; state.security = data.security; state.collectors = data.collectors; state.intel = data.intel;
    state.gotSnapshot = true;
    $('connecting').hidden = true;
    setLive(true);
  });
  source.addEventListener('metrics', (message) => {
    touch();
    const data = JSON.parse(message.data);
    state.points.push(data.point); while (state.points.length > SPARK_POINTS) state.points.shift();
    state.anomaly = data.anomaly; state.counts = data.counts;
    renderAll();
  });
  source.addEventListener('event', (message) => {
    touch();
    const data = JSON.parse(message.data);
    state.events.set(data.event.id, data.event); state.counts = data.counts;
    if (data.event.severity === 'critical' && data.event.count === 1 && !data.event.ack) notifyDesktop(data.event);
    if (state.gotSnapshot && data.event.count === 1 && !data.event.ack && (data.event.severity === 'high' || data.event.severity === 'medium')) toast(data.event);
    renderAll();
    if (data.event.source === 'ioc' || data.event.source === 'ttp') window.socTi?.touch();
  });
  source.addEventListener('ack', (message) => {
    touch();
    const data = JSON.parse(message.data);
    for (const id of data.ids) { const e = state.events.get(id); if (e) e.ack = true; }
    state.counts = data.counts;
    renderAll();
  });
  source.addEventListener('security', (message) => {
    touch();
    const data = JSON.parse(message.data);
    state.security = data.security; state.counts = data.counts;
    renderAll();
  });
}

// 수집기 상태(에이전트·폴더)는 가끔만 바뀌므로 몇 초마다 가져온다(화면 전체를 다시 그리지 않는다).
async function pullCollectors() {
  try {
    const response = await fetch('/api/soc/snapshot', { cache: 'no-store' });
    const body = await response.json();
    if (body && body.ok) { state.collectors = body.data.collectors; state.intel = body.data.intel; renderAll(); }
  } catch { /* 연결 끊김은 상단 표시가 알려 준다 */ }
}
setInterval(pullCollectors, 5000);
setInterval(() => renderPosture(), 1000);

// 보조 화면(배치 위젯·PiP)이 쓰는 값과 갱신 연결
Object.assign(window.socUi, {
  buildSpark, updateSpark, showView, unackedCounts, unackedCritical, computePosture, domainLevels: () => ({ ...domainLevels }), onRender: (hook) => { renderHooks.add(hook); return () => renderHooks.delete(hook); },
  pipData: () => ({
    posture: computePosture(), counts: unackedCounts(), points: state.points, anomaly: state.anomaly, connected: state.connected, lastAt: state.lastMessageAt,
    events: [...state.events.values()].sort((a, b) => Date.parse(b.lastAt) - Date.parse(a.lastAt) || b.id - a.id), domains: { ...domainLevels }, agent: state.collectors && state.collectors.agent, critical: unackedCritical(),
  }),
});
showView(readSetting('soc.tab') || 'dashboard');
connect();
renderAll();
