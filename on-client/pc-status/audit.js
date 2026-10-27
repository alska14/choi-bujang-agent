// PC 보안 점검 탭(KISA PC-01~18): 점검 실행 → 결과 표 → 항목별 「설정 열기」·「자동 조치」(확인 창 + 필요하면 Windows 권한 확인) → 조치 기록·되돌리기.
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };
const VERDICT = { good: ['양호', 'lv-normal', '●'], vuln: ['취약', 'lv-critical', '■'], review: ['판단 필요', 'lv-warn', '▲'], manual: ['수동 확인', 'lv-unknown', '○'], na: ['해당 없음', 'lv-unknown', '–'] };
const OPEN_LABEL = { secpol: '로컬 보안 정책', fsmgmt: '공유 폴더 관리', services: '서비스', apps: '설치된 앱', drives: '내 PC', msconfig: '시스템 구성', edgeclear: 'Edge 설정', update: 'Windows 업데이트', netplwiz: '사용자 계정', defender: '바이러스 방지', firewall: '방화벽', screensaver: '화면 보호기', autoplay: '자동 실행', remote: '원격 설정' };
const ui = { result: null, history: [], busy: false, pending: null, filter: 'all' };

async function api(path, body) {
  const res = await fetch(path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const json = await res.json().catch(() => null);
  if (!json || !json.ok) throw Error((json && json.error && json.error.message) || `요청 실패(${res.status})`);
  return json.data;
}
const msg = (text) => { $('audit-msg').textContent = text; };
const when = (iso) => (iso ? new Date(iso).toLocaleString('ko-KR') : '');

function renderSummary() {
  const r = ui.result;
  const box = $('audit-summary');
  if (!r || r.status !== 'measured') { box.replaceChildren(); return; }
  const chip = (key, label, count, cls) => {
    const b = el('button', `audit-chip ${cls}`, `${label} ${count}`);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(ui.filter === key));
    b.addEventListener('click', () => { ui.filter = ui.filter === key ? 'all' : key; render(); });
    return b;
  };
  const high = r.items.filter((i) => i.verdict === 'vuln' && i.importance === '상').length;
  box.replaceChildren(
    chip('all', '전체', r.items.length, ''),
    ...Object.entries(VERDICT).filter(([k]) => r.counts[k] > 0).map(([k, [label, cls]]) => chip(k, label, r.counts[k], cls)),
    el('span', 'note', `중요도 "상" 중 취약 ${high}개 · 점검 ${when(r.at)} · ${(r.durationMs / 1000).toFixed(1)}초${r.elevated ? ' · 관리자 권한으로 실행 중' : ' · 일반 권한으로 읽음'}`),
  );
}

function fixButton(item, fix) {
  const b = el('button', 'solid-accent', `${fix.label}${fix.admin ? ' (관리자)' : ''}`);
  b.type = 'button';
  b.title = fix.admin ? '누르면 확인 창이 뜨고, 실행할 때 Windows 권한 확인(UAC) 창이 한 번 더 뜹니다.' : '누르면 확인 창이 뜹니다.';
  b.addEventListener('click', () => askConfirm({ code: item.code, fixId: fix.id }));
  return b;
}

function renderTable() {
  const r = ui.result;
  const body = $('audit-body');
  const items = r && r.items ? r.items.filter((i) => ui.filter === 'all' || i.verdict === ui.filter) : [];
  $('audit-empty').hidden = Boolean(r && r.items && r.items.length);
  if (r && r.status === 'unavailable') $('audit-empty').textContent = `점검하지 못했습니다: ${r.reason}`;
  body.replaceChildren(...items.map((item) => {
    const [label, cls, glyph] = VERDICT[item.verdict] || VERDICT.manual;
    const tr = el('tr', `audit-row v-${item.verdict}`);
    tr.dataset.code = item.code;
    const name = el('td', 'audit-name');
    name.append(el('strong', null, item.title), el('small', null, `${item.category} · 양호 기준: ${item.good}`));
    const evidence = el('td', 'audit-evidence');
    evidence.append(el('div', null, item.evidence || ''), ...(item.reason ? [el('small', null, item.reason)] : []));
    // 표 칸(td)에 flex 를 주면 표 줄 맞춤이 깨지므로 안쪽 div 에 준다.
    const actCell = el('td', 'audit-act');
    const act = el('div', 'audit-act-inner');
    actCell.append(act);
    for (const fix of item.fixes || []) act.append(fixButton(item, fix));
    for (const target of item.opens || []) {
      const b = el('button', 'quiet', `${OPEN_LABEL[target] || '설정'} 열기`);
      b.type = 'button';
      b.title = '해당 Windows 설정 화면만 엽니다(아무것도 바꾸지 않음).';
      b.addEventListener('click', async () => { try { const d = await api('/api/soc/audit/open', { target }); msg(d.opened ? `「${d.label}」 화면을 열었습니다.` : `「${d.label}」 화면을 열지 못했습니다(이 Windows 에디션에 없을 수 있음).`); } catch (e) { msg(e.message); } });
      act.append(b);
    }
    tr.append(el('td', 'audit-code', item.code), name, el('td', 'audit-imp', item.importance), el('td', `audit-verdict ${cls}`, `${glyph} ${label}`), evidence, actCell);
    return tr;
  }));
}

function renderHistory() {
  const list = $('audit-history');
  list.replaceChildren(...(ui.history.length ? ui.history.map((h) => {
    const li = el('li', null, `${when(h.at)} · ${h.code} ${h.label || h.fixId}${h.admin ? ' (관리자)' : ''}${h.undoneAt ? ` · 되돌림(${when(h.undoneAt)})` : ''}`);
    if (!h.undoneAt) {
      const b = el('button', 'quiet', '되돌리기');
      b.type = 'button';
      b.addEventListener('click', () => askConfirm({ undoId: h.id }));
      li.append(' ', b);
    }
    return li;
  }) : [el('li', null, '아직 조치한 것이 없습니다.')]));
}

function render() { renderSummary(); renderTable(); renderHistory(); $('audit-run').disabled = ui.busy; $('audit-csv').disabled = !(ui.result && ui.result.items && ui.result.items.length); }

async function load() {
  try { const d = await api('/api/soc/audit/state'); ui.result = d.result; ui.history = d.history || []; render(); } catch (e) { msg(e.message); }
}

async function runAudit() {
  if (ui.busy) return;
  ui.busy = true; render(); msg('점검 중입니다… (보통 5~10초, 설정을 읽기만 합니다)');
  try { ui.result = await api('/api/soc/audit/run', {}); msg(ui.result.status === 'measured' ? '점검을 마쳤습니다.' : `점검하지 못했습니다: ${ui.result.reason}`); } catch (e) { msg(e.message); }
  ui.busy = false; await load();
}

// 조치 확인 창: 무엇을 바꾸는지, 관리자 권한이 필요한지, 실제로 실행할 명령, 되돌릴 수 있는지 보여 준다.
async function askConfirm(request) {
  let p;
  try { p = await api('/api/soc/audit/preview', request); } catch (e) { msg(e.message); return; }
  ui.pending = p.token;
  ui.pendingCode = p.code;
  $('audit-dlg-title').textContent = `${p.code} · ${p.label}`;
  $('audit-dlg-warn').textContent = p.warn || '';
  $('audit-dlg-warn').hidden = !p.warn;
  $('audit-dlg-admin').textContent = p.admin ? '관리자 권한이 필요한 조치입니다. 「실행」을 누르면 Windows 권한 확인(UAC) 창이 뜨고, 거기서 「예」를 눌러야 실제로 바뀝니다.' : '현재 사용자 설정만 바꿉니다(관리자 권한 필요 없음).';
  $('audit-dlg-undo').textContent = request.undoId ? '' : p.undoable ? '바꾸기 전 값을 기록해 두어 「조치 기록」에서 되돌릴 수 있습니다.' : '이 조치는 자동으로 되돌릴 수 없습니다.';
  $('audit-dlg-script').textContent = p.script;
  $('audit-dlg-ok').disabled = false;
  $('audit-confirm').showModal();
}

$('audit-dlg-ok').addEventListener('click', async () => {
  const token = ui.pending; ui.pending = null;
  const code = ui.pendingCode;
  $('audit-dlg-ok').disabled = true;
  $('audit-confirm').close();
  if (!token) return;
  msg('실행 중입니다… 관리자 조치라면 Windows 권한 확인 창을 확인하세요.');
  try {
    const d = await api('/api/soc/audit/apply', { token });
    const after = d.item ? ` 다시 점검한 결과: ${d.code} ${VERDICT[d.item.verdict] ? VERDICT[d.item.verdict][0] : ''}.` : '';
    msg(`${d.message}${after}`);
  } catch (e) { msg(e.message); }
  await load();
  const row = document.querySelector(`#audit-body tr[data-code="${code}"]`);
  if (row) row.scrollIntoView({ block: 'nearest' });
});
$('audit-dlg-cancel').addEventListener('click', () => { ui.pending = null; $('audit-confirm').close(); msg('조치를 취소했습니다. 바뀐 것은 없습니다.'); });

// 워크시트 「점검표」에 옮겨 적기 쉬운 CSV(엑셀에서 한글이 깨지지 않게 BOM 포함). 양호(부분)는 양호로 적는다는 워크시트 규칙과 같다.
$('audit-csv').addEventListener('click', () => {
  const r = ui.result;
  if (!r || !r.items) return;
  const cell = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const auto = (v) => ({ good: '양호', vuln: '취약', review: '판단 필요', manual: '판단 필요', na: '해당 없음' }[v] || '');
  const rows = [['코드', '분류', '점검 항목', '중요도', '자동 판정', '증적(확인한 값)', '판단 근거'], ...r.items.map((i) => [i.code, i.category, i.title, i.importance, auto(i.verdict), i.evidence, `${i.verdict === 'manual' ? '[수동 확인 필요] ' : ''}${i.reason || ''}`])];
  const blob = new Blob([`﻿${rows.map((row) => row.map(cell).join(',')).join('\r\n')}`], { type: 'text/csv;charset=utf-8' });
  const a = el('a');
  a.href = URL.createObjectURL(blob);
  a.download = `PC보안점검_자동판정_${r.at.slice(0, 10)}.csv`;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  msg('CSV 를 저장했습니다. 계정명·IP 같은 개인정보가 들어 있는지 확인한 뒤 공유하세요.');
});

$('audit-run').addEventListener('click', runAudit);
// 탭을 처음 열 때 결과가 없으면 저절로 점검한다.
document.querySelector('[data-view-tab="audit"]').addEventListener('click', async () => { await load(); if (!ui.result && !ui.busy) runAudit(); });
if (!(location.hash === '#pip' || location.hash === '#pip-desktop')) load().then(() => { if (!ui.result && document.querySelector('main[data-view="audit"]:not([hidden])')) runAudit(); });
