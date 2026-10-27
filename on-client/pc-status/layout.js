// 관제 화면 위젯 배치: 끌어서 옮기고, 모서리를 끌어서 크기를 바꾸고, 위젯을 숨기거나 다시 넣고, 배치를 프리셋으로 저장한다.
// 12칸 격자에 놓이며, 겹치면 아래로 밀린 뒤 위로 당겨져 빈틈이 생기지 않는다. 저장 위치는 이 브라우저(localStorage)이다.
const { setText, setHidden } = window.socUi;
const $ = (id) => document.getElementById(id);

const COLS = 12;
const ROW_H = 34;
const GAP = 10;
const WIDGETS = {
  kpi: { title: '현황 수치', min: [4, 2] },
  trend: { title: '자원 사용 추이', min: [4, 4] },
  donut: { title: '사건 구성', min: [3, 4] },
  issues: { title: '지금 확인할 이슈', min: [4, 4] },
  domains: { title: '보안 영역 요약', min: [3, 5] },
  // 다른 탭의 내용을 대시보드에 붙이는 추가 위젯(기본은 숨김, 「숨긴 위젯 추가」로 넣는다)
  'net-detail': { title: '네트워크 보안 상세', min: [3, 5] },
  'end-detail': { title: '엔드포인트 보안 상세', min: [3, 5] },
  'iam-detail': { title: '계정·접근 관리 상세', min: [3, 5] },
  'events-all': { title: '전체 사건 기록', min: [4, 4] },
  'ti-summary': { title: '위협 인텔리전스 요약', min: [3, 5] },
  'agent-live': { title: 'AI 에이전트 활동', min: [3, 5] },
};
const IDS = Object.keys(WIDGETS);
const BASE = new Set(['kpi', 'trend', 'donut', 'issues', 'domains']);
const FALLBACK = {
  kpi: [0, 0, 12, 3], trend: [0, 3, 8, 6], donut: [8, 3, 4, 6], issues: [0, 9, 8, 7], domains: [8, 9, 4, 7],
  'net-detail': [0, 16, 4, 8], 'end-detail': [4, 16, 4, 8], 'iam-detail': [8, 16, 4, 8], 'events-all': [0, 24, 8, 8], 'ti-summary': [8, 24, 4, 8], 'agent-live': [0, 32, 6, 7],
};
// 메뉴 막대 위치: 도구 막대(왼쪽·오른쪽·위), 탭 막대(아래·위)
const MENU_DEFAULT = { tools: 'left', dock: 'bottom' };
const sanitizeMenus = (raw) => ({ tools: ['left', 'right', 'top'].includes(raw && raw.tools) ? raw.tools : 'left', dock: ['bottom', 'top'].includes(raw && raw.dock) ? raw.dock : 'bottom' });

// 배치 = { 위젯id: { x, y, w, h, v } }  (v: 보이는지)
function build(shown) {
  const layout = {};
  for (const id of IDS) {
    const [x, y, w, h] = shown[id] || FALLBACK[id];
    layout[id] = { x, y, w, h, v: Boolean(shown[id]) };
  }
  layout._menus = { ...MENU_DEFAULT };
  return layout;
}
const pick = (ids) => Object.fromEntries(ids.map((id) => [id, FALLBACK[id]]));
const BUILTIN = {
  '기본 관제': build(pick([...BASE])),
  '영역 상세': build({ kpi: [0, 0, 12, 3], 'net-detail': [0, 3, 4, 13], 'end-detail': [4, 3, 4, 13], 'iam-detail': [8, 3, 4, 13] }),
  '이슈 중심': build({ kpi: [0, 0, 12, 3], issues: [0, 3, 8, 13], donut: [8, 3, 4, 5], domains: [8, 8, 4, 8] }),
  '자원 감시': build({ kpi: [0, 0, 12, 3], trend: [0, 3, 12, 8], issues: [0, 11, 12, 5] }),
  '영역별 점검': build({ kpi: [0, 0, 12, 3], domains: [0, 3, 5, 13], issues: [5, 3, 7, 13] }),
};
const DEFAULT_NAME = '기본 관제';

const readJson = (key) => { try { const text = localStorage.getItem(key); return text ? JSON.parse(text) : null; } catch { return null; } };
const writeJson = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; } };

const int = (value, fallback) => (Number.isInteger(value) ? value : fallback);
// 저장된 값이 망가졌거나 오래된 형식이어도 화면이 깨지지 않게 항상 다듬는다.
function sanitize(raw) {
  const out = {};
  for (const id of IDS) {
    const base = FALLBACK[id];
    const item = raw && typeof raw === 'object' && raw[id] && typeof raw[id] === 'object' ? raw[id] : null;
    const [minW, minH] = WIDGETS[id].min;
    const w = Math.min(COLS, Math.max(minW, int(item && item.w, base[2])));
    const h = Math.min(60, Math.max(minH, int(item && item.h, base[3])));
    out[id] = { x: Math.min(COLS - w, Math.max(0, int(item && item.x, base[0]))), y: Math.min(200, Math.max(0, int(item && item.y, base[1]))), w, h, v: item ? item.v !== false : BASE.has(id) };
  }
  out._menus = sanitizeMenus(raw && raw._menus);
  return out;
}

const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
// fixedId 가 있으면 그 위젯은 제자리에 두고 나머지를 위에서부터 빈 곳에 채운다.
function compact(layout, fixedId = null) {
  const out = {};
  const placed = [];
  if (fixedId && layout[fixedId] && layout[fixedId].v) { out[fixedId] = { ...layout[fixedId] }; placed.push(out[fixedId]); }
  const rest = IDS.filter((id) => layout[id].v && id !== fixedId).sort((a, b) => layout[a].y - layout[b].y || layout[a].x - layout[b].x);
  for (const id of rest) {
    const item = { ...layout[id] };
    item.y = 0;
    while (placed.some((other) => overlaps(other, item))) item.y += 1;
    out[id] = item;
    placed.push(item);
  }
  for (const id of IDS) if (!layout[id].v) out[id] = { ...layout[id] };
  out._menus = sanitizeMenus(layout._menus);
  return out;
}
const clone = (layout) => JSON.parse(JSON.stringify(layout));
const same = (a, b) => sanitizeMenus(a._menus).tools === sanitizeMenus(b._menus).tools && sanitizeMenus(a._menus).dock === sanitizeMenus(b._menus).dock && IDS.every((id) => a[id].v === b[id].v && (!a[id].v || (a[id].x === b[id].x && a[id].y === b[id].y && a[id].w === b[id].w && a[id].h === b[id].h)));

// ---------- 상태 ----------
const board = $('board');
board.style.gridAutoRows = `${ROW_H}px`;
board.style.gap = `${GAP}px`;
const els = Object.fromEntries(IDS.map((id) => [id, board.querySelector(`[data-widget="${id}"]`)]));

let presets = (() => {
  const saved = readJson('soc.layout.presets.v3');
  const out = {};
  if (saved && typeof saved === 'object') for (const [name, value] of Object.entries(saved)) if (!(name in BUILTIN) && Object.keys(out).length < 30) out[String(name).slice(0, 24)] = sanitize(value);
  return out;
})();
const savedCurrent = readJson('soc.layout.v3');
let layout = compact(sanitize(savedCurrent && savedCurrent.layout ? savedCurrent.layout : BUILTIN[DEFAULT_NAME]));
let activeName = savedCurrent && typeof savedCurrent.name === 'string' ? savedCurrent.name : DEFAULT_NAME;
let editing = false;

const persistCurrent = () => writeJson('soc.layout.v3', { layout, name: activeName });
const persistPresets = () => writeJson('soc.layout.presets.v3', presets);
const message = (text) => { setText($('layout-msg'), text); };
const presetLayout = (name) => (BUILTIN[name] ? clone(BUILTIN[name]) : presets[name] ? clone(presets[name]) : null);

// ---------- 그리기 ----------
function paintMenus(menus) {
  const m = sanitizeMenus(menus);
  const root = document.documentElement;
  if (root.getAttribute('data-tools') !== m.tools) root.setAttribute('data-tools', m.tools);
  if (root.getAttribute('data-dock') !== m.dock) root.setAttribute('data-dock', m.dock);
  const tools = $('menu-tools'), dock = $('menu-dock');
  if (tools && tools.value !== m.tools) tools.value = m.tools;
  if (dock && dock.value !== m.dock) dock.value = m.dock;
}
function paint(target, draggingId = null) {
  paintMenus(target._menus);
  for (const id of IDS) {
    const node = els[id];
    if (!node) continue;
    const item = target[id];
    setHidden(node, !item.v);
    if (!item.v) continue;
    node.style.gridColumn = `${item.x + 1} / span ${item.w}`;
    node.style.gridRow = `${item.y + 1} / span ${item.h}`;
    if (id !== draggingId) node.style.transform = '';
  }
}

function paintAddList() {
  const select = $('widget-add');
  const hidden = IDS.filter((id) => !layout[id].v);
  select.replaceChildren(new Option(hidden.length ? `숨긴 위젯 ${hidden.length}개…` : '숨긴 위젯 없음', ''), ...hidden.map((id) => new Option(WIDGETS[id].title, id)));
  select.disabled = hidden.length === 0;
}

function paintPresets() {
  const select = $('preset-select');
  const current = [...Object.keys(BUILTIN), ...Object.keys(presets)].find((name) => { const l = presetLayout(name); return l && same(l, layout); });
  const options = [];
  if (!current) options.push(new Option('현재 배치(저장 안 됨)', ''));
  for (const name of Object.keys(BUILTIN)) options.push(new Option(`${name} (기본 제공)`, name));
  for (const name of Object.keys(presets)) options.push(new Option(name, name));
  select.replaceChildren(...options);
  select.value = current || '';
  $('preset-delete').disabled = !current || Boolean(BUILTIN[current]);
  if (current) activeName = current;
}

function commit(next, note) {
  layout = compact(next);
  paint(layout);
  persistCurrent();
  paintAddList();
  paintPresets();
  if (note) message(note);
}

// ---------- 끌기 ----------
function metrics() {
  const rect = board.getBoundingClientRect();
  const cell = (rect.width - GAP * (COLS - 1)) / COLS;
  return { px: cell + GAP, py: ROW_H + GAP };
}

function startGesture(id, mode, event) {
  if (event.button !== undefined && event.button !== 0) return;
  event.preventDefault();
  const handle = event.currentTarget;
  const node = els[id];
  const origin = { ...layout[id] };
  const { px, py } = metrics();
  const [minW, minH] = WIDGETS[id].min;
  const startX = event.clientX, startY = event.clientY;
  let working = layout;
  try { handle.setPointerCapture(event.pointerId); } catch { /* 포인터 포착 실패해도 끌기는 동작한다 */ }
  node.classList.add('dragging');
  const move = (e) => {
    const dx = e.clientX - startX, dy = e.clientY - startY;
    const next = { ...origin };
    if (mode === 'move') {
      next.x = Math.min(COLS - origin.w, Math.max(0, origin.x + Math.round(dx / px)));
      next.y = Math.max(0, origin.y + Math.round(dy / py));
    } else {
      next.w = Math.min(COLS - origin.x, Math.max(minW, origin.w + Math.round(dx / px)));
      next.h = Math.max(minH, origin.h + Math.round(dy / py));
    }
    working = compact({ ...layout, [id]: next }, id);
    paint(working, id);
    if (mode === 'move') node.style.transform = `translate(${dx - (working[id].x - origin.x) * px}px, ${dy - (working[id].y - origin.y) * py}px)`;
  };
  const finish = () => {
    handle.removeEventListener('pointermove', move);
    handle.removeEventListener('pointerup', finish);
    handle.removeEventListener('pointercancel', finish);
    node.classList.remove('dragging');
    node.style.transform = '';
    commit(working);
  };
  handle.addEventListener('pointermove', move);
  handle.addEventListener('pointerup', finish);
  handle.addEventListener('pointercancel', finish);
}

// 키보드: 이동 막대에서 방향키는 이동, Shift+방향키는 크기 조절
function keyGesture(id, event) {
  const step = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
  if (!step) return;
  event.preventDefault();
  const item = { ...layout[id] };
  const [minW, minH] = WIDGETS[id].min;
  if (event.shiftKey) { item.w = Math.min(COLS - item.x, Math.max(minW, item.w + step[0])); item.h = Math.max(minH, item.h + step[1]); }
  else { item.x = Math.min(COLS - item.w, Math.max(0, item.x + step[0])); item.y = Math.max(0, item.y + step[1]); }
  layout = compact({ ...layout, [id]: item }, id);
  paint(layout); persistCurrent(); paintPresets();
}

// ---------- 위젯마다 편집용 막대·손잡이를 붙인다(편집 중에만 보인다) ----------
for (const id of IDS) {
  const node = els[id];
  if (!node) continue;
  const bar = document.createElement('div');
  bar.className = 'wbar';
  bar.tabIndex = 0;
  bar.setAttribute('role', 'button');
  bar.setAttribute('aria-label', `${WIDGETS[id].title} 위치 이동. 방향키로 이동, Shift와 방향키로 크기 조절`);
  const title = document.createElement('span');
  title.textContent = `⠿ ${WIDGETS[id].title}`;
  const hide = document.createElement('button');
  hide.type = 'button';
  hide.className = 'whide';
  hide.textContent = '숨기기';
  hide.addEventListener('pointerdown', (e) => e.stopPropagation());
  hide.addEventListener('click', () => commit({ ...layout, [id]: { ...layout[id], v: false } }, `${WIDGETS[id].title} 위젯을 숨겼습니다. 위의 "숨긴 위젯 추가"로 되돌립니다.`));
  bar.append(title, hide);
  bar.addEventListener('pointerdown', (e) => startGesture(id, 'move', e));
  bar.addEventListener('keydown', (e) => keyGesture(id, e));
  const grip = document.createElement('div');
  grip.className = 'wresize';
  grip.setAttribute('aria-hidden', 'true');
  grip.title = '끌어서 크기 조절';
  grip.addEventListener('pointerdown', (e) => startGesture(id, 'resize', e));
  node.append(bar, grip);
}

// ---------- 편집 모드와 프리셋 조작 ----------
function setEditing(on) {
  editing = on;
  board.classList.toggle('editing', on);
  document.documentElement.setAttribute('data-editing', on ? 'on' : 'off');
  setHidden($('layoutbar'), !on);
  $('layout-edit').setAttribute('aria-pressed', String(on));
  const label = $('layout-edit').querySelector('.tool-label');
  setText(label || $('layout-edit'), on ? '배치 편집 중' : '배치 편집');
  message(on ? '위젯 위쪽 막대를 끌면 옮겨지고, 오른쪽 아래 모서리를 끌면 크기가 바뀝니다. 도구 막대·탭 막대는 ⠿ 손잡이를 끌어 옮깁니다. 바뀐 배치는 자동으로 기억됩니다.' : '');
}
$('layout-edit').addEventListener('click', () => setEditing(!editing));
$('layout-done').addEventListener('click', () => setEditing(false));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && editing && !e.defaultPrevented) setEditing(false); });

$('preset-select').addEventListener('change', (e) => {
  const next = presetLayout(e.target.value);
  if (next) { activeName = e.target.value; commit(sanitize(next), `"${e.target.value}" 배치를 적용했습니다.`); }
});
$('preset-save').addEventListener('click', () => {
  const name = $('preset-name').value.trim().slice(0, 24);
  if (!name) { message('저장할 프리셋 이름을 먼저 적으세요.'); return; }
  if (name in BUILTIN) { message('기본 제공 프리셋 이름은 쓸 수 없습니다. 다른 이름을 적으세요.'); return; }
  if (!(name in presets) && Object.keys(presets).length >= 30) { message('프리셋은 30개까지 저장할 수 있습니다. 안 쓰는 것을 삭제하세요.'); return; }
  const existed = name in presets;
  presets[name] = clone(layout);
  activeName = name;
  const stored = persistPresets();
  persistCurrent(); paintPresets();
  $('preset-name').value = '';
  message(stored ? `"${name}" 프리셋을 ${existed ? '덮어써서 ' : ''}저장했습니다.` : '이 브라우저가 저장을 막아서 프리셋이 이번 접속 동안만 유지됩니다.');
});
$('preset-delete').addEventListener('click', () => {
  const name = $('preset-select').value;
  if (!name || BUILTIN[name] || !(name in presets)) return;
  delete presets[name];
  persistPresets(); paintPresets();
  message(`"${name}" 프리셋을 삭제했습니다. 지금 배치는 그대로입니다.`);
});
$('widget-add').addEventListener('change', (e) => {
  const id = e.target.value;
  if (!id) return;
  const bottom = Math.max(0, ...IDS.filter((x) => layout[x].v).map((x) => layout[x].y + layout[x].h));
  const [, , w, h] = FALLBACK[id];
  commit({ ...layout, [id]: { x: 0, y: bottom, w, h, v: true } }, `${WIDGETS[id].title} 위젯을 맨 아래에 추가했습니다. 끌어서 원하는 곳에 놓으세요.`);
});
// ---------- 메뉴 막대 옮기기: 위치 선택 상자 또는 편집 중 ⠿ 손잡이 끌기 ----------
function setMenus(patch, note) { commit({ ...layout, _menus: { ...sanitizeMenus(layout._menus), ...patch } }, note); }
$('menu-tools').addEventListener('change', (e) => setMenus({ tools: e.target.value }, '도구 막대 위치를 바꿨습니다.'));
$('menu-dock').addEventListener('change', (e) => setMenus({ dock: e.target.value }, '탭 막대 위치를 바꿨습니다.'));
function addMenuGrip(container, kind) {
  const grip = document.createElement('button');
  grip.type = 'button';
  grip.className = 'menu-grip';
  grip.textContent = '⠿';
  grip.setAttribute('aria-label', kind === 'tools' ? '도구 막대 옮기기(끌어서 왼쪽·오른쪽·위에 놓기)' : '탭 막대 옮기기(끌어서 위·아래에 놓기)');
  grip.title = grip.getAttribute('aria-label');
  grip.addEventListener('pointerdown', (event) => {
    if (!editing) return;
    event.preventDefault();
    try { grip.setPointerCapture(event.pointerId); } catch { /* 포착 실패해도 동작 */ }
    const frame = document.querySelector('.frame').getBoundingClientRect();
    const decide = (e) => {
      if (kind === 'dock') return { dock: e.clientY < frame.top + frame.height / 2 ? 'top' : 'bottom' };
      if (e.clientY < frame.top + frame.height * 0.22) return { tools: 'top' };
      return { tools: e.clientX < frame.left + frame.width / 2 ? 'left' : 'right' };
    };
    const move = (e) => paintMenus({ ...sanitizeMenus(layout._menus), ...decide(e) });
    const up = (e) => {
      grip.removeEventListener('pointermove', move);
      grip.removeEventListener('pointerup', up);
      grip.removeEventListener('pointercancel', up);
      setMenus(decide(e), kind === 'tools' ? '도구 막대를 옮겼습니다.' : '탭 막대를 옮겼습니다.');
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', up);
    grip.addEventListener('pointercancel', up);
  });
  container.prepend(grip);
}
addMenuGrip(document.querySelector('.tools'), 'tools');
addMenuGrip(document.querySelector('.dock'), 'dock');

$('layout-reset').addEventListener('click', () => { activeName = DEFAULT_NAME; commit(sanitize(BUILTIN[DEFAULT_NAME]), '기본 배치로 되돌렸습니다. 저장한 프리셋은 그대로입니다.'); });

// 다른 창(예: 같은 주소의 다른 탭)에서 바꾼 프리셋 목록을 따라간다.
window.addEventListener('storage', (e) => {
  if (e.key !== 'soc.layout.presets.v3') return;
  const saved = readJson('soc.layout.presets.v3');
  presets = {};
  if (saved && typeof saved === 'object') for (const [name, value] of Object.entries(saved)) if (!(name in BUILTIN)) presets[String(name).slice(0, 24)] = sanitize(value);
  paintPresets();
});

paint(layout); paintAddList(); paintPresets();
window.socLayout = { get: () => clone(layout), IDS };
