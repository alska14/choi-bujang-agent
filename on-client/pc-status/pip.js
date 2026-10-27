// PiP(항상 위) 미니 창: 다른 앱 위에 작게 띄워 두는 관제 화면. 보여 줄 정보와 모양을 사용자가 고르고 프리셋으로 저장한다.
// 크롬·엣지의 Document Picture-in-Picture 를 쓰고, 지원하지 않는 브라우저에서는 일반 작은 창(항상 위는 아님)으로 연다.
// 긴급 경보 띠는 어떤 설정에서도 항상 보인다(끌 수 없다).
const ui = window.socUi;
const { el, setText, setClass, setHidden, hhmmss, clip, post } = ui;
const $ = (id) => document.getElementById(id);

const ITEMS = [
  ['status', '전체 상태(평온·주의·경계·위험)'],
  ['counts', '미확인 사건 수'],
  ['cpu', 'CPU 사용률'],
  ['memory', '메모리 사용량'],
  ['disk', '디스크 남은 공간'],
  ['events', '최근 사건 목록'],
  ['network', '네트워크 보안 상태'],
  ['endpoint', '엔드포인트 보안 상태'],
  ['iam', '계정·접근 관리 상태'],
  ['agent', 'LLM 에이전트 수집 상태'],
  ['time', '마지막 갱신·연결 상태'],
];
const ITEM_IDS = ITEMS.map(([id]) => id);
const LABEL = Object.fromEntries(ITEMS);
const SCALE = { S: ['작게', 0.85], M: ['보통', 1], L: ['크게', 1.3], XL: ['아주 크게', 1.7] };
const SHAPES = { tall: ['세로로 좁게', 320, 480], strip: ['가로 띠', 620, 170], square: ['정사각형', 440, 440], wide: ['넓게', 760, 520] };
const MIN_RANK = { 0: '모두', 2: '주의 이상', 3: '높음 이상', 4: '긴급만' };

const DEFAULT = {
  order: ITEM_IDS.slice(),
  on: { status: true, counts: true, cpu: true, memory: true, disk: true, events: true, network: false, endpoint: false, iam: false, agent: false, time: true },
  scale: 'M', columns: 'auto', shape: 'tall', spark: true, eventCount: 4, minRank: 2, unackedOnly: true,
};
const onOnly = (ids) => Object.fromEntries(ITEM_IDS.map((id) => [id, ids.includes(id)]));
const BUILTIN = {
  '기본': DEFAULT,
  '상태만 크게': { ...DEFAULT, on: onOnly(['status', 'counts']), scale: 'XL', shape: 'strip' },
  '자원 감시': { ...DEFAULT, on: onOnly(['status', 'cpu', 'memory', 'disk', 'time']), scale: 'M', shape: 'strip', spark: true },
  '사건 중심': { ...DEFAULT, on: onOnly(['status', 'counts', 'events', 'time']), eventCount: 8, minRank: 0, unackedOnly: false, shape: 'wide' },
  '영역 요약': { ...DEFAULT, on: onOnly(['status', 'network', 'endpoint', 'iam', 'agent', 'time']), shape: 'tall' },
  '전부 보기': { ...DEFAULT, on: onOnly(ITEM_IDS), scale: 'S', eventCount: 6, shape: 'wide' },
};

const readJson = (key) => { try { const text = localStorage.getItem(key); return text ? JSON.parse(text) : null; } catch { return null; } };
const writeJson = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; } };
const oneOf = (value, allowed, fallback) => (allowed.includes(value) ? value : fallback);

// 저장된 값이 망가졌거나 오래된 형식이어도 항상 안전한 값으로 다듬는다.
function sanitize(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const order = Array.isArray(input.order) ? input.order.filter((id, i, all) => ITEM_IDS.includes(id) && all.indexOf(id) === i) : [];
  for (const id of ITEM_IDS) if (!order.includes(id)) order.push(id);
  const on = {};
  for (const id of ITEM_IDS) on[id] = input.on && typeof input.on[id] === 'boolean' ? input.on[id] : DEFAULT.on[id];
  return {
    order, on,
    scale: oneOf(input.scale, Object.keys(SCALE), DEFAULT.scale),
    columns: oneOf(input.columns, ['auto', '1'], DEFAULT.columns),
    shape: oneOf(input.shape, Object.keys(SHAPES), DEFAULT.shape),
    spark: typeof input.spark === 'boolean' ? input.spark : DEFAULT.spark,
    eventCount: oneOf(input.eventCount, [2, 3, 4, 5, 6, 8, 10], DEFAULT.eventCount),
    minRank: oneOf(input.minRank, [0, 2, 3, 4], DEFAULT.minRank),
    unackedOnly: typeof input.unackedOnly === 'boolean' ? input.unackedOnly : DEFAULT.unackedOnly,
  };
}

let options = sanitize(readJson('soc.pip.v1'));
let userPresets = (() => {
  const saved = readJson('soc.pip.presets.v1');
  const out = {};
  if (saved && typeof saved === 'object') for (const [name, value] of Object.entries(saved)) if (!(name in BUILTIN) && Object.keys(out).length < 30) out[String(name).slice(0, 24)] = sanitize(value);
  return out;
})();
const presetOptions = (name) => (BUILTIN[name] ? sanitize(BUILTIN[name]) : userPresets[name] ? sanitize(userPresets[name]) : null);
const sameOptions = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ---------- 보기(미리보기와 PiP 창이 같은 코드로 그려진다) ----------
const DOMAIN_LABEL = { network: '네트워크', endpoint: '엔드포인트', iam: '계정·접근' };
const LV = { normal: ['●', '정상'], warn: ['▲', '주의'], critical: ['■', '이상'], unknown: ['○', '확인 불가'] };
const SEV = { critical: ['■', '긴급'], high: ['◆', '높음'], medium: ['▲', '주의'], low: ['◇', '낮음'], info: ['◇', '정보'] };
const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function createView() {
  const root = el('div', 'pipview');
  root.setAttribute('role', 'region');
  root.setAttribute('aria-label', '보안 관제 요약');
  const alarm = el('div', 'pip-alarm');
  alarm.setAttribute('role', 'alert');
  alarm.hidden = true;
  const alarmTitle = el('strong');
  const alarmText = el('span', 'pip-alarm-text');
  const alarmAck = el('button', 'solid-red', '확인했음');
  alarmAck.type = 'button';
  alarmAck.addEventListener('click', () => { post('/api/soc/ack', { all: true, minRank: 4 }).catch(() => {}); });
  alarm.append(alarmTitle, alarmText, alarmAck);
  const body = el('div', 'pip-body');
  root.append(alarm, body);

  const parts = {};
  // 상태
  { const node = el('section', 'pip-item pip-status'); const label = el('div', 'pip-status-label'); const detail = el('div', 'pip-status-detail'); node.append(label, detail); parts.status = { node, update(d) { setClass(node, `pip-item pip-status lv-${d.posture.level}`); setText(label, d.posture.label); setText(detail, d.posture.detail); } }; }
  // 사건 수
  { const node = el('section', 'pip-item pip-counts'); const chips = ['critical', 'high', 'medium'].map((k) => { const c = el('span', 'count'); node.append(c); return [k, c]; }); parts.counts = { node, update(d) { for (const [k, c] of chips) { setText(c, `${SEV[k][0]} ${SEV[k][1]} ${d.counts[k]}`); setClass(c, `count ${d.counts[k] > 0 ? `sev-${k}` : 'sev-zero'}`); } } }; }
  // 자원 3종
  const meter = (key, title) => {
    const node = el('section', 'pip-item pip-meter lv-unknown');
    const head = el('div', 'pip-meter-head'); const name = el('span', 'pip-name', title); const chip = el('span', 'chip');
    head.append(name, chip);
    const value = el('div', 'pip-value');
    const spark = ui.buildSpark();
    node.append(head, value, spark.svg);
    parts[key] = {
      node, spark,
      update(d, opts) {
        const latest = d.points[d.points.length - 1] || null;
        const level = latest && d.anomaly ? d.anomaly[key].level : 'unknown';
        setClass(node, `pip-item pip-meter lv-${level}`);
        setText(chip, `${LV[level][0]} ${LV[level][1]}`);
        let text = '확인 불가', series = [], min = 0, max = 100;
        if (latest && key === 'cpu' && typeof latest.cpu === 'number') { text = `${latest.cpu}%`; series = d.points.map((p) => p.cpu); }
        if (latest && key === 'memory' && typeof latest.memoryPercent === 'number') { text = `${latest.memoryPercent}%`; series = d.points.map((p) => p.memoryPercent); }
        if (latest && key === 'disk' && typeof latest.diskFreeGb === 'number') { text = `${latest.diskFreeGb} GB 남음`; series = d.points.map((p) => p.diskFreeGb); const nums = series.filter((v) => typeof v === 'number'); min = Math.min(...nums) - 2; max = Math.max(...nums) + 2; }
        setText(value, text);
        setHidden(spark.svg, !opts.spark);
        if (opts.spark) ui.updateSpark(spark, series, min, max);
      },
    };
  };
  meter('cpu', 'CPU'); meter('memory', '메모리'); meter('disk', '디스크');
  // 사건 목록
  { const node = el('section', 'pip-item pip-events'); const list = el('ul'); const empty = el('p', 'pip-empty'); node.append(list, empty);
    let signature = '';
    parts.events = { node, update(d, opts) {
      const rows = d.events.filter((e) => RANK[e.severity] >= opts.minRank && (!opts.unackedOnly || !e.ack)).slice(0, opts.eventCount);
      const sig = JSON.stringify([rows.map((e) => [e.id, e.count, e.ack, e.lastAt]), opts.eventCount]);
      if (sig !== signature) {
        signature = sig;
        list.replaceChildren(...rows.map((e) => { const li = el('li', `sev-${e.severity}${e.ack ? ' acked' : ''}`); li.append(el('span', 'pip-ev-mark', SEV[e.severity][0]), el('span', 'pip-ev-time', hhmmss(e.lastAt)), el('span', 'pip-ev-title', clip(e.count > 1 ? `${e.title} ×${e.count}` : e.title, 80))); li.title = e.detail || e.title; return li; }));
      }
      setText(empty, rows.length ? '' : `표시할 사건 없음(${MIN_RANK[opts.minRank]}${opts.unackedOnly ? ', 미확인만' : ''}). 이상이 없다는 뜻은 아닙니다`);
      setHidden(empty, rows.length > 0);
    } }; }
  // 영역 3종
  for (const key of ['network', 'endpoint', 'iam']) {
    const node = el('section', 'pip-item pip-domain lv-unknown'); const name = el('span', 'pip-name', DOMAIN_LABEL[key]); const chip = el('span', 'chip'); node.append(name, chip);
    parts[key] = { node, update(d) { const level = d.domains[key] || 'unknown'; setClass(node, `pip-item pip-domain lv-${level}`); setText(chip, `${LV[level][0]} ${LV[level][1]}`); } };
  }
  // 에이전트
  { const node = el('section', 'pip-item pip-agent'); const name = el('span', 'pip-name', 'LLM 에이전트'); const text = el('span', 'pip-agent-text'); node.append(name, text);
    parts.agent = { node, update(d) {
      const a = d.agent; let level = 'unknown', msg = '확인 중';
      if (a) {
        if (a.state === 'not_configured') msg = '수집 안 함(훅 없음)';
        else if (a.state === 'no_data') msg = '기록 없음';
        else { level = a.counts.sensitive > 0 ? 'critical' : a.counts.outside > 0 ? 'warn' : 'normal'; msg = `5분 ${a.counts.calls}회 · 밖 ${a.counts.outside} · 민감 ${a.counts.sensitive}`; }
      }
      setClass(node, `pip-item pip-agent lv-${level}`); setText(text, `${LV[level][0]} ${msg}`);
    } }; }
  // 시각
  { const node = el('section', 'pip-item pip-time'); parts.time = { node, update(d) { setClass(node, `pip-item pip-time ${d.connected ? 'live-on' : 'live-off'}`); setText(node, d.connected ? `● 연결됨 · 갱신 ${d.lastAt ? hhmmss(new Date(d.lastAt).toISOString()) : '—'}` : '○ 연결 끊김 · 값이 오래됐을 수 있음'); } }; }

  let orderSig = '';
  return {
    root,
    render(opts) {
      const data = ui.pipData();
      root.style.setProperty('--pip-scale', String(SCALE[opts.scale][1]));
      setClass(root, `pipview cols-${opts.columns}`);
      const critical = data.critical;
      setHidden(alarm, critical.length === 0);
      if (critical.length) {
        setText(alarmTitle, `■ 긴급 ${critical.length}건`);
        setText(alarmText, clip(critical[0].title, 60));
      }
      const shown = opts.order.filter((id) => opts.on[id]);
      const sig = shown.join(',');
      if (sig !== orderSig) { orderSig = sig; body.replaceChildren(...shown.map((id) => parts[id].node)); }
      for (const id of shown) parts[id].update(data, opts);
      if (!shown.length) { if (!body.firstChild || body.firstChild.className !== 'pip-empty') body.replaceChildren(el('p', 'pip-empty', '보여 줄 항목이 없습니다. 설정에서 항목을 켜세요.')); orderSig = ''; }
    },
  };
}

// ---------- 열려 있는 보기 모음 ----------
const views = new Set();
function renderViews() { for (const view of views) view.render(options); }
ui.onRender(renderViews);

function setOptions(next, note) {
  options = sanitize(next);
  writeJson('soc.pip.v1', options);
  renderViews();
  paintDrawer();
  if (note) say(note);
}

// ---------- PiP 창 열기 ----------
let pipWindow = null;
let pipView = null;
const supportsDocPip = 'documentPictureInPicture' in window;
function say(text) { const node = $('pip-msg'); if (node) setText(node, text); }

function closePip() {
  if (pipView) { views.delete(pipView); pipView = null; }
  if (pipWindow && !pipWindow.closed) { try { pipWindow.close(); } catch { /* 이미 닫힘 */ } }
  pipWindow = null;
  paintDrawer();
}

async function openPip() {
  if (pipWindow && !pipWindow.closed) { try { pipWindow.focus(); } catch { /* 무시 */ } return; }
  let failure = '';
  const [, width, height] = SHAPES[options.shape];
  if (supportsDocPip) {
    try {
      const win = await window.documentPictureInPicture.requestWindow({ width, height });
      win.document.documentElement.lang = 'ko';
      win.document.documentElement.setAttribute('data-theme', document.documentElement.getAttribute('data-theme') || 'light');
      win.document.documentElement.setAttribute('data-glass', document.documentElement.getAttribute('data-glass') || 'on');
      win.document.title = '보안 관제 PiP';
      const link = win.document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/pc-status/pc-status.css';
      win.document.head.append(link);
      win.document.body.className = 'pip-win';
      const view = createView();
      win.document.body.append(view.root);
      views.add(view); pipView = view; pipWindow = win;
      view.render(options);
      win.addEventListener('pagehide', () => { views.delete(view); if (pipView === view) { pipView = null; pipWindow = null; } paintDrawer(); });
      say('PiP 창을 열었습니다. 다른 앱 위에 떠 있고, 모서리를 끌어 크기를 바꿀 수 있습니다.');
      paintDrawer();
      return;
    } catch (error) {
      failure = `PiP 창을 열지 못했습니다(${error && error.name ? error.name : '오류'}: ${error && error.message ? error.message : ''}). `;
    }
  }
  const win = window.open('/pc-status#pip', 'soc-pip', `popup=yes,width=${width},height=${height}`);
  if (!win) { say(`${failure}브라우저가 작은 창을 막았습니다. 주소창의 팝업 차단을 풀고 다시 누르세요.`); return; }
  pipWindow = win;
  say(`${failure}일반 작은 창으로 열었습니다. 이 방식은 다른 앱 위에 고정되지 않습니다.`);
  const timer = setInterval(() => { if (win.closed) { clearInterval(timer); pipWindow = null; paintDrawer(); } }, 1000);
  paintDrawer();
}
window.addEventListener('pagehide', () => { if (pipWindow && !pipWindow.closed) { try { pipWindow.close(); } catch { /* 무시 */ } } });

// ---------- 설정 서랍(실시간 미리보기 포함) ----------
const drawer = $('pip-drawer');
let previewView = null;
const refs = {};
function buildDrawer() {
  const head = el('div', 'drawer-head');
  const title = el('h2', null, 'PiP·미니 창 설정');
  title.id = 'pip-title';
  const close = el('button', null, '닫기');
  close.type = 'button';
  close.addEventListener('click', () => closeDrawer());
  head.append(title, close);

  const open = el('button', 'solid-accent', 'PiP 창 열기');
  open.type = 'button';
  open.addEventListener('click', () => { if (pipWindow && !pipWindow.closed) closePip(); else openPip(); });
  refs.open = open;
  const support = el('p', 'note', supportsDocPip ? '이 브라우저는 항상 위 PiP 창을 지원합니다. 창 가장자리를 끌어 크기를 바꿀 수 있습니다.' : '이 브라우저는 항상 위 PiP 창(Document PiP)을 지원하지 않아 일반 작은 창으로 열립니다. 크롬·엣지 116 이상에서 PiP로 열립니다.');
  const msg = el('p', 'note'); msg.id = 'pip-msg'; msg.setAttribute('role', 'status');

  // 프리셋
  const presetRow = el('div', 'drow');
  const presetLabel = el('label', null, '프리셋 ');
  refs.preset = document.createElement('select');
  refs.preset.addEventListener('change', () => { const next = presetOptions(refs.preset.value); if (next) setOptions(next, `"${refs.preset.value}" 프리셋을 적용했습니다.`); });
  presetLabel.append(refs.preset);
  refs.name = document.createElement('input'); refs.name.type = 'text'; refs.name.placeholder = '새 프리셋 이름'; refs.name.maxLength = 24; refs.name.setAttribute('aria-label', '새 PiP 프리셋 이름');
  const save = el('button', null, '현재 설정 저장'); save.type = 'button';
  save.addEventListener('click', () => {
    const name = refs.name.value.trim().slice(0, 24);
    if (!name) { say('저장할 프리셋 이름을 먼저 적으세요.'); return; }
    if (name in BUILTIN) { say('기본 제공 프리셋 이름은 쓸 수 없습니다.'); return; }
    if (!(name in userPresets) && Object.keys(userPresets).length >= 30) { say('프리셋은 30개까지 저장할 수 있습니다.'); return; }
    userPresets[name] = sanitize(options);
    writeJson('soc.pip.presets.v1', userPresets);
    refs.name.value = '';
    paintDrawer();
    say(`"${name}" 프리셋을 저장했습니다.`);
  });
  refs.del = el('button', null, '삭제'); refs.del.type = 'button';
  refs.del.addEventListener('click', () => { const name = refs.preset.value; if (name in userPresets) { delete userPresets[name]; writeJson('soc.pip.presets.v1', userPresets); paintDrawer(); say(`"${name}" 프리셋을 삭제했습니다.`); } });
  presetRow.append(presetLabel, refs.name, save, refs.del);

  // 항목 목록
  const itemsBox = el('fieldset', 'ditems');
  itemsBox.append(el('legend', null, '보여 줄 정보(체크로 켜고 끄기, 화살표로 순서 바꾸기)'));
  refs.items = el('ul', 'ditem-list');
  itemsBox.append(refs.items);

  // 모양
  const look = el('div', 'drow');
  const select = (label, key, entries, parse = (v) => v) => {
    const wrap = el('label', null, `${label} `);
    const node = document.createElement('select');
    for (const [value, text] of entries) node.append(new Option(text, String(value)));
    node.addEventListener('change', () => setOptions({ ...options, [key]: parse(node.value) }));
    wrap.append(node);
    refs[key] = node;
    return wrap;
  };
  look.append(
    select('글자 크기', 'scale', Object.entries(SCALE).map(([k, v]) => [k, v[0]])),
    select('열', 'columns', [['auto', '창 너비에 맞춰 자동'], ['1', '한 줄에 하나씩']]),
    select('창 모양', 'shape', Object.entries(SHAPES).map(([k, v]) => [k, `${v[0]} (${v[1]}×${v[2]})`])),
  );
  const events = el('div', 'drow');
  events.append(
    select('사건 개수', 'eventCount', [2, 3, 4, 5, 6, 8, 10].map((n) => [n, `${n}개`]), Number),
    select('사건 등급', 'minRank', Object.entries(MIN_RANK), Number),
  );
  const check = (label, key) => {
    const wrap = el('label', 'dcheck'); const box = document.createElement('input'); box.type = 'checkbox';
    box.addEventListener('change', () => setOptions({ ...options, [key]: box.checked }));
    wrap.append(box, document.createTextNode(` ${label}`)); refs[key] = box; return wrap;
  };
  events.append(check('미확인 사건만', 'unackedOnly'), check('그래프 표시', 'spark'));

  const previewTitle = el('h3', null, '미리보기(실제 PiP 창과 같은 모양, 실시간 값)');
  refs.preview = el('div', 'pip-preview');
  const rule = el('p', 'note', '긴급 경보 띠는 설정과 관계없이 항상 맨 위에 나타납니다. 값은 이 앱이 이 PC에서 읽은 실측이며, 읽지 못한 항목은 "확인 불가"로 표시됩니다. 설정은 이 브라우저에 저장됩니다.');
  drawer.replaceChildren(head, open, support, msg, presetRow, itemsBox, look, events, previewTitle, refs.preview, rule);
}

function paintDrawer() {
  if (drawer.hidden || !refs.items) return;
  const current = [...Object.keys(BUILTIN), ...Object.keys(userPresets)].find((name) => { const o = presetOptions(name); return o && sameOptions(o, options); });
  refs.preset.replaceChildren(...[...(current ? [] : [new Option('현재 설정(저장 안 됨)', '')]), ...Object.keys(BUILTIN).map((n) => new Option(`${n} (기본 제공)`, n)), ...Object.keys(userPresets).map((n) => new Option(n, n))]);
  refs.preset.value = current || '';
  refs.del.disabled = !current || Boolean(BUILTIN[current]);
  refs.items.replaceChildren(...options.order.map((id, index) => {
    const li = el('li');
    const label = el('label'); const box = document.createElement('input'); box.type = 'checkbox'; box.checked = options.on[id];
    box.addEventListener('change', () => setOptions({ ...options, on: { ...options.on, [id]: box.checked } }));
    label.append(box, document.createTextNode(` ${LABEL[id]}`));
    const move = (delta) => { const order = options.order.slice(); const to = index + delta; if (to < 0 || to >= order.length) return; [order[index], order[to]] = [order[to], order[index]]; setOptions({ ...options, order }); };
    const up = el('button', 'quiet', '↑'); up.type = 'button'; up.disabled = index === 0; up.setAttribute('aria-label', `${LABEL[id]} 위로`); up.addEventListener('click', () => move(-1));
    const down = el('button', 'quiet', '↓'); down.type = 'button'; down.disabled = index === options.order.length - 1; down.setAttribute('aria-label', `${LABEL[id]} 아래로`); down.addEventListener('click', () => move(1));
    li.append(label, up, down);
    return li;
  }));
  for (const key of ['scale', 'columns', 'shape', 'eventCount', 'minRank']) refs[key].value = String(options[key]);
  refs.unackedOnly.checked = options.unackedOnly; refs.spark.checked = options.spark;
  setText(refs.open, pipWindow && !pipWindow.closed ? 'PiP 창 닫기' : 'PiP 창 열기');
  if (!previewView) { previewView = createView(); views.add(previewView); refs.preview.append(previewView.root); }
  previewView.render(options);
}

function openDrawer() { if (!refs.items) buildDrawer(); drawer.hidden = false; paintDrawer(); $('pip-open').setAttribute('aria-expanded', 'true'); }
function closeDrawer() { drawer.hidden = true; if (previewView) { views.delete(previewView); previewView = null; if (refs.preview) refs.preview.replaceChildren(); } $('pip-open').setAttribute('aria-expanded', 'false'); }
$('pip-open').setAttribute('aria-expanded', 'false');
$('pip-open').addEventListener('click', () => { if (drawer.hidden) openDrawer(); else closeDrawer(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !drawer.hidden && !e.defaultPrevented) closeDrawer(); });

// ---------- 일반 작은 창(#pip)으로 열렸을 때: 이 창 전체가 미니 보기 ----------
if (ui.state.pipMode) {
  document.body.classList.add('pip-mode');
  // 데스크톱 미니 창(pip-desktop, 막대 없는 Electron 창): 화면 아무 곳이나 끌어 창을 옮기고, 위쪽에 마우스를 올리면 투명도·닫기 버튼이 나온다.
  if (location.hash === '#pip-desktop') {
    document.body.classList.add('pip-desktop');
    const readAlpha = () => { try { const v = Number(localStorage.getItem('soc.pipDeskAlpha')); return v >= 0.2 && v <= 1 ? v : 0.85; } catch { return 0.85; } };
    let alpha = readAlpha();
    const applyAlpha = () => { document.documentElement.style.setProperty('--desk-alpha', String(alpha)); try { localStorage.setItem('soc.pipDeskAlpha', String(alpha)); } catch { /* 저장 실패 무시 */ } };
    const bar = el('div', 'pip-desk-bar');
    const btn = (text, label, handler) => { const b = el('button', null, text); b.type = 'button'; b.title = label; b.setAttribute('aria-label', label); b.addEventListener('click', handler); bar.append(b); return b; };
    btn('◐−', '더 투명하게', () => { alpha = Math.max(0.2, Math.round((alpha - 0.1) * 10) / 10); applyAlpha(); });
    btn('◐+', '덜 투명하게', () => { alpha = Math.min(1, Math.round((alpha + 0.1) * 10) / 10); applyAlpha(); });
    btn('✕', '미니 창 닫기', () => window.close());
    $('pip-standalone').append(bar);
    applyAlpha();
  }
  const view = createView();
  $('pip-standalone').append(view.root);
  views.add(view);
  view.render(options);
  // 큰 창에서 설정을 바꾸면 바로 따라간다.
  window.addEventListener('storage', (e) => {
    if (e.key === 'soc.pip.v1') { options = sanitize(readJson('soc.pip.v1')); renderViews(); }
    if (e.key === 'soc.theme' && (e.newValue === 'dark' || e.newValue === 'light')) document.documentElement.setAttribute('data-theme', e.newValue);
    if (e.key === 'soc.glass' && ['on', 'clear', 'off'].includes(e.newValue)) document.documentElement.setAttribute('data-glass', e.newValue);
  });
}
// 큰 창에서 테마를 바꾸면 열려 있는 PiP 창도 같이 바꾼다.
function setTheme(theme) { if (pipWindow && !pipWindow.closed && pipWindow.document) pipWindow.document.documentElement.setAttribute('data-theme', theme); }
function setGlass(glass) { if (pipWindow && !pipWindow.closed && pipWindow.document) pipWindow.document.documentElement.setAttribute('data-glass', glass); }
window.socPip = { get: () => sanitize(options), supportsDocPip, setTheme, setGlass };
