// 보안 관제 미니 창: 제목 막대·주소 막대가 없고 항상 다른 창 위에 뜨는 데스크톱 창.
// 관제 서버(기본 http://127.0.0.1:5189)의 /pc-status#pip-desktop 화면을 그대로 보여 준다. 서버 코드는 바꾸지 않는다.
// 보안: 이 창은 관제 서버 주소(같은 출처)만 열고, 다른 주소로 이동하거나 새 창을 여는 것은 막는다. 페이지에 Node 기능을 주지 않는다.
const { app, BrowserWindow, screen } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.SOC_PORT) > 0 ? Number(process.env.SOC_PORT) : 5189;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const PAGE = `${ORIGIN}/pc-status#pip-desktop`;
const stateFile = () => path.join(app.getPath('userData'), 'window.json');

function loadBounds() {
  try {
    const saved = JSON.parse(fs.readFileSync(stateFile(), 'utf8'));
    const ok = ['x', 'y', 'width', 'height'].every((k) => Number.isInteger(saved[k]));
    if (!ok) return null;
    // 저장된 위치가 지금 연결된 화면 밖이면 쓰지 않는다(모니터를 뺀 경우)
    const visible = screen.getAllDisplays().some((d) => saved.x < d.workArea.x + d.workArea.width - 40 && saved.x + saved.width > d.workArea.x + 40 && saved.y >= d.workArea.y - 10 && saved.y < d.workArea.y + d.workArea.height - 40);
    return visible ? saved : null;
  } catch { return null; }
}

function createWindow() {
  const work = screen.getPrimaryDisplay().workArea;
  const bounds = loadBounds() || { width: 360, height: 520, x: work.x + work.width - 380, y: work.y + 20 };
  const win = new BrowserWindow({
    ...bounds,
    minWidth: 220,
    minHeight: 120,
    frame: false,
    transparent: true,
    backgroundColor: '#00000000',
    alwaysOnTop: true,
    skipTaskbar: false,
    resizable: true,
    hasShadow: true,
    title: '보안 관제 미니 창',
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: false },
  });
  // 전체 화면 앱 위에도 뜨게 한다(예: 전체 화면 동영상·발표)
  win.setAlwaysOnTop(true, 'screen-saver');
  win.setVisibleOnAllWorkspaces(true);

  // 관제 서버 밖으로는 이동·새 창을 허용하지 않는다
  win.webContents.on('will-navigate', (event, url) => { if (!url.startsWith(`${ORIGIN}/`)) event.preventDefault(); });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  // 서버가 아직 꺼져 있으면 안내 화면을 보이고 5초마다 다시 연결한다
  win.webContents.on('did-fail-load', (_event, code, desc, url) => {
    if (!url.startsWith(ORIGIN)) return;
    const html = `<!doctype html><meta charset="utf-8"><body style="margin:0;font:13px 'Malgun Gothic',sans-serif;color:#eef0ff;background:rgba(20,24,56,.92);-webkit-app-region:drag;display:grid;place-items:center;height:100vh;text-align:center"><div>관제 서버(${ORIGIN})에 연결할 수 없습니다.<br>서버를 켜면 자동으로 다시 연결합니다.<br><small>(${desc})</small></div></body>`;
    win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    setTimeout(() => { if (!win.isDestroyed()) win.loadURL(PAGE); }, 5000);
  });

  const save = () => { try { fs.mkdirSync(path.dirname(stateFile()), { recursive: true }); fs.writeFileSync(stateFile(), JSON.stringify(win.getBounds())); } catch { /* 위치 저장 실패는 무시 */ } };
  win.on('moved', save);
  win.on('resized', save);
  win.loadURL(PAGE);
}

// 같은 창을 두 번 띄우지 않는다
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { const [win] = BrowserWindow.getAllWindows(); if (win) { win.show(); win.focus(); } });
  app.whenReady().then(createWindow);
  app.on('window-all-closed', () => app.quit());
}
