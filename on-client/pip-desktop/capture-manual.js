// 사용 설명서 그림 만들기: 켜져 있는 관제 화면을 실제로 열어 장면별로 찍고, 설명 번호(①②…)와 테두리를 얹어 PNG로 저장한다.
// 화면 값은 이 PC의 실측이라 그대로 찍히므로, 기본으로 이 PC의 값은 흐리게 가린다(REDACT_JS). 바탕화면 비침은 끈 상태(불투명)로 찍어 배경 사진이 들어가지 않게 한다.
// 실행(앱 폴더에서, 관제 서버가 켜져 있어야 함):
//   pip-desktop\node_modules\electron\dist\electron.exe pip-desktop\capture-manual.js
// 결과: pc-status/manual/*.png
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.SOC_PORT) > 0 ? Number(process.env.SOC_PORT) : 5189;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const OUT = path.join(__dirname, '..', 'pc-status', 'manual');
const W = 1440, H = 900;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// 미니 창(main.js)의 저장 설정과 섞이지 않게 촬영용 임시 프로필을 따로 쓴다.
app.setPath('userData', path.join(require('node:os').tmpdir(), 'djokovic-manual-capture'));

// 장면: view(탭), prep(찍기 전 화면 조작), marks([선택자, 글자 포함 조건, 번호]), clip(잘라 낼 영역)
const SHOTS = [
  { name: 'overview', view: 'dashboard', marks: [['#posture', null, 1], ['#counts', null, 2], ['nav.tools', null, 3], ['nav.dock', null, 4], ['#w-kpi', null, 5], ['#w-trend', null, 6], ['#w-donut', null, 7], ['#w-issues', null, 8], ['#w-domains', null, 9]] },
  { name: 'tools', view: 'dashboard', prep: 'showToolLabels', clip: { x: 0, y: 0, width: 520, height: H } },
  { name: 'network', view: 'network', marks: [['#d-network .domain-head', null, 1], ['#d-network li', '방화벽', 2], ['#d-network li', '수신 대기 포트', 3], ['main[data-view="network"] .area-feed', null, 4], ['nav.dock button[data-view-tab="network"]', null, 5]] },
  { name: 'endpoint', view: 'endpoint', marks: [['#d-endpoint li', 'Defender', 1], ['#d-endpoint li', '설치 프로그램', 2], ['#d-endpoint li', '예약 작업', 3], ['#d-endpoint li', 'USB', 4], ['#files-panel', null, 5], ['main[data-view="endpoint"] .area-feed', null, 6]] },
  { name: 'iam', view: 'iam', marks: [['#d-iam li', '로컬 계정', 1], ['#d-iam li', '자동 로그인', 2], ['#d-iam li', '실행 중인 AI', 3], ['#d-iam li', '감사 훅', 4], ['#agent-panel', null, 5]] },
  { name: 'events', view: 'events', marks: [['#domain-filters', null, 1], ['#filters', null, 2], ['#feed-body tr', null, 3], ['#feed-body tr td:last-child', null, 4], ['#history-note', null, 5]] },
  { name: 'ti', view: 'ti', marks: [['.ti-intro .ti-steps', null, 1], ['#ti-pipeline', null, 2], ['#ioc-form', null, 3], ['#ti-pipeline button', '탐지 시험', 4]] },
  { name: 'audit', view: 'audit', wait: 12000, marks: [['#audit-run', null, 1], ['#audit-summary', null, 2], ['#audit-body tr.v-vuln td.audit-act', null, 3], ['#audit-csv', null, 4], ['.audit-log', null, 5]] },
  { name: 'alarm', view: 'dashboard', prep: 'showAlarmExample', marks: [['#alarm-title', null, 1], ['#alarm-ack', null, 2], ['#alarm-mute', null, 3]] },
  { name: 'layout', view: 'dashboard', prep: 'startLayoutEdit', marks: [['#preset-select', null, 1], ['#widget-add', null, 2], ['#menu-tools', null, 3], ['#w-trend .wbar', null, 4], ['#w-trend .wresize', null, 5], ['#layout-done', null, 6]] },
  { name: 'pip', view: 'dashboard', prep: 'openPipDrawer', marks: [['#pip-drawer .drawer-head', null, 1], ['#pip-drawer fieldset', null, 2], ['#pip-drawer .pip-preview', null, 3], ['#pip-drawer .solid-accent', null, 4]] },
];

// 페이지 안에서 실행할 조작들(문자열로 넘긴다)
const PREP = {
  // 마우스를 올려야 보이는 버튼 이름을 모두 펼쳐 보이게 그 옆에 이름표를 붙인다.
  showToolLabels: `(() => {
    const layer = document.createElement('div'); layer.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:99998';
    for (const b of document.querySelectorAll('nav.tools .tool')) {
      const r = b.getBoundingClientRect(); const label = b.querySelector('.tool-label');
      const tag = document.createElement('div'); tag.textContent = label ? label.textContent : '';
      tag.style.cssText = 'position:fixed;left:' + (r.right + 12) + 'px;top:' + (r.top + r.height / 2 - 14) + 'px;height:28px;line-height:28px;padding:0 12px;border-radius:10px;background:#fff;color:#172140;font:700 13px "Malgun Gothic",sans-serif;box-shadow:0 4px 14px rgba(40,55,110,.25);white-space:nowrap;border:1px solid rgba(40,60,120,.15)';
      layer.append(tag);
    }
    document.body.append(layer);
  })()`,
  showAlarmExample: `(() => {
    // 화면 갱신이 경보 창을 다시 숨기지 않게, 찍는 동안만 보이게 고정한다.
    // (화면 보안 정책이 <style> 삽입을 막으므로 요소의 style 속성으로 고정한다)
    const a = document.getElementById('alarm'); a.hidden = false;
    a.style.setProperty('display', 'grid', 'important'); a.style.setProperty('animation', 'none', 'important');
    document.getElementById('alarm-title').textContent = '긴급 사건이 발생했습니다';
    const li = document.createElement('li'); li.textContent = '[예시 화면] 방화벽이 모든 프로필에서 꺼짐';
    const sm = document.createElement('small'); sm.textContent = '12:00:00 · FW-OFF-ALL 이 그림은 설명용 예시입니다. 실제 경보는 같은 모양으로 뜹니다.'; li.append(sm);
    document.getElementById('alarm-list').replaceChildren(li);
    document.getElementById('alarm-test').style.setProperty('display', 'none', 'important');
  })()`,
  startLayoutEdit: `document.getElementById('layout-edit').click()`,
  openPipDrawer: `document.getElementById('pip-open').click()`,
};

// 공개 저장소에 올라가는 그림이므로 이 PC의 값(점검 결과, 사건 내용, 계정 이름·사용자 폴더 경로)은 흐리게 가린다.
// 항목 이름·버튼은 그대로 둔다. CAPTURE_REAL=1 이면 가리지 않는다.
const REDACT_JS = `(() => {
  const blur = (e) => e.style.setProperty('filter', 'blur(4.5px)');
  const sel = ['.dtext', 'td.cell-msg', '.audit-evidence', '.audit-verdict', '#agent-panel ul', '#agent-panel .lines', '.pip-ev-title', '#w-agent-live ul', '#w-ti-summary ul', '.posture-detail'];
  document.querySelectorAll(sel.join(',')).forEach(blur);
  const re = /[a-z]:[\\\\/]users[\\\\/]|\\buser\\b/i;
  for (const e of document.querySelectorAll('body *')) if (!e.children.length && re.test(e.textContent)) blur(e);
  return true;
})()`;

const MARK_JS = (marks) => `(() => {
  const marks = ${JSON.stringify(marks)};
  const layer = document.createElement('div');
  layer.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:99999';
  const missing = [];
  for (const [sel, text, n] of marks) {
    const el = [...document.querySelectorAll(sel)].find((e) => (!text || e.textContent.includes(text)) && e.getClientRects().length);
    if (!el) { missing.push(sel + (text ? '(' + text + ')' : '')); continue; }
    const r = el.getBoundingClientRect();
    const box = document.createElement('div');
    box.style.cssText = 'position:fixed;left:' + (r.left - 3) + 'px;top:' + (r.top - 3) + 'px;width:' + (r.width + 6) + 'px;height:' + (r.height + 6) + 'px;border:3px solid #ff3b5c;border-radius:12px;box-shadow:0 0 0 2px rgba(255,255,255,.85)';
    const badge = document.createElement('div');
    badge.textContent = String(n);
    const bx = Math.max(4, Math.min(innerWidth - 34, r.left - 14)), by = Math.max(4, Math.min(innerHeight - 34, r.top - 14));
    badge.style.cssText = 'position:fixed;left:' + bx + 'px;top:' + by + 'px;width:30px;height:30px;border-radius:50%;background:#ff3b5c;color:#fff;font:800 16px/30px "Malgun Gothic",sans-serif;text-align:center;border:2px solid #fff;box-shadow:0 2px 6px rgba(0,0,0,.35)';
    layer.append(box, badge);
  }
  document.body.append(layer);
  return missing;
})()`;

// 화면 합성기가 가끔 한 번 실패한다(UnknownVizError). 잠시 뒤 다시 찍는다.
async function capture(win, rect, file) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      win.show();
      const image = await win.webContents.capturePage(rect);
      if (image.isEmpty()) throw Error('EMPTY_CAPTURE');
      fs.writeFileSync(file, image.toPNG());
      return;
    } catch (error) {
      if (attempt >= 4) throw error;
      await sleep(1500);
    }
  }
}

async function run() {
  fs.mkdirSync(OUT, { recursive: true });
  const win = new BrowserWindow({ width: W, height: H, useContentSize: true, show: true, x: 20, y: 20, frame: false, webPreferences: { contextIsolation: true, sandbox: true } });
  // 설정을 먼저 심고(밝은 화면·불투명·설명서 이미 봄·기본 배치) 다시 연다.
  await win.loadURL(`${ORIGIN}/pc-status`);
  await win.webContents.executeJavaScript(`localStorage.clear(); localStorage.setItem('soc.theme','light'); localStorage.setItem('soc.glass','off'); localStorage.setItem('soc.manual.v1','seen'); true`);
  const report = [];
  for (const shot of SHOTS) {
    await win.webContents.executeJavaScript(`localStorage.setItem('soc.tab', ${JSON.stringify(shot.view)}); true`);
    await win.loadURL(`${ORIGIN}/pc-status`);
    await sleep(6000); // 스트림 연결·첫 점검 결과가 그려질 때까지
    await win.webContents.executeJavaScript(`(() => { const b = document.querySelector('[data-view-tab="${shot.view}"]'); if (b) b.click(); return true; })()`);
    await sleep(shot.wait || 800);
    // 오른쪽 위 실시간 알림(토스트)이 설명할 부분을 가리지 않게 찍는 동안 숨긴다.
    await win.webContents.executeJavaScript(`(() => { document.getElementById('toasts').style.setProperty('display', 'none', 'important'); return true; })()`);
    if (shot.prep) { await win.webContents.executeJavaScript(PREP[shot.prep]); await sleep(900); }
    if (process.env.CAPTURE_REAL !== '1') await win.webContents.executeJavaScript(REDACT_JS);
    const missing = shot.marks ? await win.webContents.executeJavaScript(MARK_JS(shot.marks)) : [];
    await sleep(150);
    await capture(win, shot.clip, path.join(OUT, `${shot.name}.png`));
    report.push(`${shot.name}${missing.length ? ` (표시 못 한 곳: ${missing.join(', ')})` : ''}`);
  }
  // 막대 없는 미니 창 모습
  const mini = new BrowserWindow({ width: 360, height: 520, useContentSize: true, show: true, x: 1500, y: 20, frame: false, webPreferences: { contextIsolation: true, sandbox: true } });
  await mini.loadURL(`${ORIGIN}/pc-status#pip-desktop`);
  await sleep(6000);
  if (process.env.CAPTURE_REAL !== '1') await mini.webContents.executeJavaScript(REDACT_JS);
  await capture(mini, undefined, path.join(OUT, 'mini.png'));
  report.push('mini');
  console.log(report.join('\n'));
}

app.whenReady().then(run).then(() => app.quit(), (error) => { console.error(error); app.exit(1); });
