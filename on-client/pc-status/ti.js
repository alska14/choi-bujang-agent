// 위협 인텔리전스 화면: 수집 → 공유 → 탐지 → 반영. 화면을 통째로 다시 그리지 않고 바뀐 부분만 제자리에서 고친다.
const ui = window.socUi;
const { el, setText, setClass, setHidden, hhmmss, clip, post, state, SEV } = ui;
const $ = (id) => document.getElementById(id);

const ti = { data: null, stale: true, visible: false, busy: new Set() };
const SEV_LABEL = { critical: '긴급', high: '높음', medium: '주의', low: '낮음', info: '정보' };
const TYPE_LABEL = { ipv4: 'IPv4', cidr4: 'CIDR', domain: '도메인', sha256: 'SHA-256', process: '프로세스', path: '경로' };
const TACTIC_ORDER = ['TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0112', 'TA0006', 'TA0007', 'TA0009', 'TA0011', 'TA0040'];
const scanStatus = (scan) => (!scan ? '아직 스캔 전' : scan.status === 'measured' ? `읽은 시각 ${hhmmss(scan.at)}` : `확인 불가(${scan.reason})`);

// ---------- 처리 흐름 4단계 ----------
const stages = {};
function buildStage(key, number, title, desc) {
  const root = el('article', 'stage');
  const head = el('h3', null, `${number} ${title}`);
  const body = el('div', 'stage-body');
  const actions = el('div', 'stage-actions');
  root.append(head, el('p', 'stage-desc', desc), body, actions);
  $('ti-pipeline').append(root);
  stages[key] = { root, body, actions };
  return stages[key];
}
const collect = buildStage('collect', '①', '목록 넣기(수집)', '나쁜 주소·파일·프로그램 이름을 내 목록에 모읍니다.');
const share = buildStage('share', '②', '주고받기(공유)', '받은 목록을 가져오거나, 내 목록을 STIX 파일로 내보냅니다.');
const detect = buildStage('detect', '③', '자동 대조(탐지)', '15초마다 이 PC의 연결·프로그램과 목록·수법 규칙을 맞춰 봅니다.');
const reflect = buildStage('reflect', '④', '판정 반영(학습)', '걸린 사건을 악성 확정·오탐으로 정하면 목록에 반영됩니다.');
const collectRefs = { a: el('p'), b: el('p'), c: el('p', 'note') };
collect.body.append(collectRefs.a, collectRefs.b, collectRefs.c);
const shareRefs = { a: el('p'), b: el('p', 'note'), result: el('p', 'note') };
share.body.append(shareRefs.a, shareRefs.b, shareRefs.result);
const detectRefs = { a: el('p'), b: el('p'), c: el('p', 'note'), result: el('p', 'note') };
detect.body.append(detectRefs.a, detectRefs.b, detectRefs.c, detectRefs.result);
const reflectRefs = { a: el('p'), b: el('p', 'note') };
reflect.body.append(reflectRefs.a, reflectRefs.b);

function actionButton(parent, label, handler) {
  const button = el('button', null, label);
  button.type = 'button';
  button.addEventListener('click', async () => { button.disabled = true; const old = button.textContent; button.textContent = `${old}…`; try { await handler(); } finally { button.disabled = false; button.textContent = old; } });
  parent.append(button);
  return button;
}

// 가져오기: 파일 선택 또는 붙여넣기
const importBox = el('details', 'import-box');
const importArea = el('textarea');
importArea.rows = 4;
importArea.placeholder = 'STIX 2.1 번들(JSON) 또는 한 줄에 하나씩 IP·CIDR·도메인·SHA-256 을 붙여 넣으세요. # 으로 시작하는 줄은 주석입니다.';
importArea.setAttribute('aria-label', '가져올 내용');
const fileInput = el('input');
fileInput.type = 'file';
fileInput.accept = '.json,.txt,.csv,.stix';
fileInput.setAttribute('aria-label', '가져올 파일 선택');
fileInput.addEventListener('change', () => { const file = fileInput.files && fileInput.files[0]; if (!file) return; const reader = new FileReader(); reader.onload = () => { importArea.value = String(reader.result ?? ''); }; reader.readAsText(file); });
importBox.append(el('summary', null, '가져오기(붙여넣기·파일)'), fileInput, importArea);
share.body.append(importBox);

actionButton(share.actions, '가져오기 실행', async () => {
  const content = importArea.value;
  if (!content.trim()) { setText(shareRefs.result, '가져올 내용이 비어 있습니다.'); return; }
  const response = await post('/api/soc/ti/import', { content });
  const body = await response.json().catch(() => null);
  if (!response.ok || !body || !body.ok) { setText(shareRefs.result, `가져오기 실패: ${(body && body.error && body.error.message) || '응답을 확인할 수 없습니다.'}`); return; }
  const d = body.data;
  setText(shareRefs.result, `가져오기 결과(${d.format}): 새로 ${d.added}개, 이미 있음 ${d.duplicates}개, 거부 ${d.rejected.length}개${d.rejected.length ? ` — 예: ${d.rejected[0].value} (${d.rejected[0].reason})` : ''}`);
  if (d.added > 0) importArea.value = '';
  await refresh();
});
actionButton(share.actions, 'STIX 2.1 내보내기', async () => {
  const response = await fetch('/api/soc/ti/export', { cache: 'no-store' });
  if (!response.ok) { setText(shareRefs.result, '내보내기에 실패했습니다.'); return; }
  const blob = await response.blob();
  const link = el('a');
  link.href = URL.createObjectURL(blob);
  link.download = (response.headers.get('content-disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'djokovic-ioc.stix.json';
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
  setText(shareRefs.result, `내보냈습니다: 지표 ${response.headers.get('x-ioc-exported')}개, 표현할 수 없어 제외 ${response.headers.get('x-ioc-skipped')}개. 파일을 보내기 전에 내용을 확인하세요.`);
});
actionButton(detect.actions, '지금 스캔', async () => { await post('/api/soc/ti/scan'); await refresh(); });
actionButton(detect.actions, '탐지 시험', async () => {
  const response = await post('/api/soc/ti/test-detect');
  const body = await response.json().catch(() => null);
  const d = body && body.data;
  setText(detectRefs.result, !d || !d.ok ? `탐지 시험 실패: ${(d && d.reason) || '응답을 확인할 수 없습니다.'}` : d.detected ? `탐지 시험 성공: 시험용 IOC(127.0.0.1)가 현재 연결에서 일치해 사건 #${d.eventId}이(가) 생겼습니다. 시험 표시가 붙은 사건이며 실제 위협이 아닙니다.` : `탐지 시험 실패: 일치가 없었습니다(연결 ${d.connections ?? '확인 불가'}개).`);
  await refresh();
});

// ---------- IOC 표(키 기준 제자리 갱신) ----------
const iocRows = new Map();
function buildIocRow(ioc) {
  const tr = el('tr');
  const cells = Object.fromEntries(['type', 'value', 'source', 'sev', 'tlp', 'conf', 'hits', 'share'].map((key) => [key, el('td')]));
  const del = el('td');
  const button = el('button', null, '삭제');
  button.type = 'button';
  button.addEventListener('click', async () => { button.disabled = true; await post('/api/soc/ti/ioc-delete', { id: ioc.id }); await refresh(); });
  del.append(button);
  tr.append(...Object.values(cells), del);
  return { tr, cells };
}
function renderIocs(list) {
  const body = $('ioc-body');
  const keep = new Set(list.map((i) => i.id));
  for (const [id, row] of iocRows) if (!keep.has(id)) { row.tr.remove(); iocRows.delete(id); }
  list.forEach((ioc, index) => {
    let row = iocRows.get(ioc.id);
    if (!row) { row = buildIocRow(ioc); iocRows.set(ioc.id, row); }
    setClass(row.tr, `${ioc.test ? 'test ' : ''}${ioc.active ? '' : 'acked'}`.trim());
    setText(row.cells.type, TYPE_LABEL[ioc.type] || ioc.type);
    setText(row.cells.value, clip(ioc.value, 60));
    row.cells.value.title = `${ioc.value}${ioc.description ? ` — ${ioc.description}` : ''}`;
    setText(row.cells.source, ioc.source);
    setText(row.cells.sev, `${SEV[ioc.severity].glyph} ${SEV_LABEL[ioc.severity]}`);
    setClass(row.cells.sev, `cell-sev sev-${ioc.severity}`);
    setText(row.cells.tlp, `TLP:${ioc.tlp.toUpperCase()}`);
    setText(row.cells.conf, String(ioc.confidence));
    setText(row.cells.hits, String(ioc.hits));
    setText(row.cells.share, ioc.shareable ? '예' : '아니오(내 PC 정보)');
    if (body.children[index] !== row.tr) body.insertBefore(row.tr, body.children[index] || null);
  });
  setHidden($('ioc-empty'), list.length > 0);
}

$('ioc-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const response = await post('/api/soc/ti/ioc', { type: $('ioc-type').value, value: $('ioc-value').value, severity: $('ioc-severity').value, description: $('ioc-desc').value });
  const body = await response.json().catch(() => null);
  if (!response.ok || !body || !body.ok) { setText($('ioc-msg'), `추가하지 못했습니다: ${(body && body.error && body.error.message) || '응답을 확인할 수 없습니다.'}`); return; }
  setText($('ioc-msg'), body.data.duplicate ? '이미 있는 지표입니다.' : '추가했습니다. 다음 스캔부터 대조합니다.');
  $('ioc-value').value = ''; $('ioc-desc').value = '';
  await refresh();
});

// ---------- ATT&CK 탐지 범위 ----------
const attackCells = new Map();
function renderAttack(data) {
  const grid = $('attack-grid');
  setText($('attack-version'), `ATT&CK ${data.attack.version} · ${data.attack.checkedOn} 확인`);
  const eventCounts = {};
  for (const event of state.events.values()) for (const t of event.attack || []) eventCounts[t.id] = (eventCounts[t.id] || 0) + 1;
  for (const tactic of TACTIC_ORDER) {
    let column = grid.querySelector(`[data-tactic="${tactic}"]`);
    if (!column) {
      column = el('div', 'tactic'); column.dataset.tactic = tactic;
      column.append(el('h4', null, data.attack.tactics[tactic] || tactic), el('p', 'time', tactic));
      grid.append(column);
    }
    for (const [id, tech] of Object.entries(data.attack.techniques)) {
      if (!tech.tactics.includes(tactic)) continue;
      const key = `${tactic}:${id}`;
      let cell = attackCells.get(key);
      if (!cell) { cell = el('a', 'tech'); cell.href = tech.url; cell.target = '_blank'; cell.rel = 'noopener noreferrer'; attackCells.set(key, cell); column.append(cell); }
      const covered = Boolean(data.coverage[id]) || ['T1686.003', 'T1685', 'T1552.001', 'T1552.004', 'T1555.003', 'T1083', 'T1005', 'T1571', 'T1496.001'].includes(id);
      setClass(cell, `tech ${covered ? 'covered' : 'open'}${eventCounts[id] ? ' hit' : ''}`);
      setText(cell, `${covered ? '●' : '○'} ${id}${eventCounts[id] ? ` ×${eventCounts[id]}` : ''}`);
      cell.title = `${tech.name}${data.coverage[id] ? ` — 규칙: ${data.coverage[id].join(', ')}` : covered ? ' — 사건 규칙과 연결됨(가능성)' : ' — 아직 덮지 못함'}`;
      cell.setAttribute('aria-label', `${id} ${tech.name} ${covered ? '덮음' : '덮지 못함'}${eventCounts[id] ? `, 사건 ${eventCounts[id]}건` : ''}`);
    }
  }
}

// ---------- 최근 탐지와 판정 ----------
const sightRows = new Map();
function buildSight(sight) {
  const li = el('li');
  const text = el('span');
  const verdict = el('span', 'verdict');
  const bad = el('button', null, '악성 확정'); bad.type = 'button';
  const good = el('button', null, '오탐'); good.type = 'button';
  const act = async (value) => { bad.disabled = good.disabled = true; const response = await post('/api/soc/ti/feedback', { eventId: sight.eventId, verdict: value }); const body = await response.json().catch(() => null); setText(verdict, body && body.ok ? (value === 'malicious' ? (body.data.added.length ? `지표 ${body.data.added.length}개 저장함` : body.data.note || '판정 기록함') : '허용 목록에 추가함') : '판정 실패'); await refresh(); };
  bad.addEventListener('click', () => act('malicious'));
  good.addEventListener('click', () => act('benign'));
  li.append(text, bad, good, verdict);
  return { li, text, bad, good, verdict };
}
function renderSightings(list) {
  const root = $('sight-list');
  const keep = new Set(list.map((s) => s.eventId));
  for (const [id, row] of sightRows) if (!keep.has(id)) { row.li.remove(); sightRows.delete(id); }
  list.forEach((sight, index) => {
    let row = sightRows.get(sight.eventId);
    if (!row) { row = buildSight(sight); sightRows.set(sight.eventId, row); }
    const event = state.events.get(sight.eventId);
    setClass(row.li, `sev-${sight.severity}${event && event.ack ? ' acked' : ''}`);
    setText(row.text, `${hhmmss(sight.at)} ${SEV[sight.severity].glyph} ${SEV_LABEL[sight.severity]} · ${sight.kind === 'ioc' ? 'IOC' : 'TTP'} · ${sight.title}${sight.test ? ' [시험]' : ''}${event && event.attack && event.attack.length ? ` · ${event.attack.map((t) => t.id).join(', ')}` : ''}`);
    const judged = event && event.verdict;
    setHidden(row.bad, Boolean(judged) || sight.test);
    setHidden(row.good, Boolean(judged) || sight.test);
    if (judged) setText(row.verdict, judged === 'malicious' ? '악성으로 확정함' : '오탐으로 처리함');
    if (root.children[index] !== row.li) root.insertBefore(row.li, root.children[index] || null);
  });
  setHidden($('sight-empty'), list.length > 0);
}

// ---------- 전체 갱신 ----------
function paint(data) {
  const stats = data.stats;
  setText(collectRefs.a, `IOC ${stats.active}개 활성 (전체 ${stats.total}, 만료 ${stats.expired})`);
  setText(collectRefs.b, `TTP 규칙 ${data.rules.length}개 · ATT&CK ${Object.keys(data.attack.techniques).length}개 기법 수록`);
  setText(collectRefs.c, `출처: ${Object.entries(stats.bySource).map(([k, v]) => `${k} ${v}`).join(', ') || '없음'}. 저장 위치: ${stats.file || '저장 안 함'}${stats.loadError ? ` (오류 ${stats.loadError})` : ''}`);
  setText(shareRefs.a, '가져오기: STIX 2.1 번들, 줄 단위 텍스트. 내보내기: STIX 2.1(공유 가능 지표만).');
  setText(shareRefs.b, '네트워크·해시 지표만 내보냅니다. 프로세스 이름·경로는 내 PC 정보라 기본으로 공유하지 않습니다. 파일 교환 방식이며 TAXII 서버 연동은 하지 않습니다.');
  const net = data.scans.network, proc = data.scans.processes, dns = data.scans.dns;
  setText(detectRefs.a, `연결 ${scanStatus(net)}${net && net.status === 'measured' ? ` · ${net.connections}개(외부 ${net.external}개)` : ''}`);
  setText(detectRefs.b, `프로세스 ${scanStatus(proc)}${proc && proc.status === 'measured' ? ` · ${proc.total}개 중 명령줄 보임 ${proc.withCommandLine}개, 해시 검사 ${proc.hashedTotal}개(남음 ${proc.hashPending})` : ''} · DNS ${dns && dns.status === 'measured' ? `${dns.entries}건` : '확인 불가'}`);
  setText(detectRefs.c, data.limits[0]);
  setText(reflectRefs.a, `악성 확정 ${data.feedback.malicious}건 · 오탐 ${data.feedback.benign}건 · 허용 목록 ${data.feedback.allow}개 · 억제된 탐지 ${data.feedback.suppressed}건`);
  setText(reflectRefs.b, '"악성 확정"은 그 사건의 IP·도메인·해시를 새 지표로 저장해 다음 탐지에 반영하고, "오탐"은 같은 탐지를 더는 사건으로 올리지 않습니다.');
  renderIocs(data.iocs);
  renderAttack(data);
  renderSightings(data.sightings);
}

async function refresh() {
  try {
    const response = await fetch('/api/soc/ti/state', { cache: 'no-store' });
    const body = await response.json();
    if (body && body.ok) { ti.data = body.data; ti.stale = false; paint(ti.data); }
  } catch { /* 연결 끊김은 상단 표시가 알려 준다 */ }
}

window.socTi = { refresh, touch() { ti.stale = true; if (!$('ti-main').hidden) refresh(); } };
setInterval(() => { if (!$('ti-main').hidden) refresh(); }, 5000);
