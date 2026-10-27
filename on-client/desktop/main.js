// Djokovic 보안 관제 데스크톱 앱.
// - 관제 서버를 앱 안에서 직접 켠다(이미 같은 포트에서 관제 서버가 돌고 있으면 그것을 쓴다). 앱을 끝내면 앱이 켠 서버도 끈다.
// - 관제 화면 창, 막대 없는 미니 창, 알림 영역(트레이) 아이콘을 띄운다. 트레이 아이콘 색은 미확인 사건 상태를 따른다.
// - 창을 닫아도 트레이에서 감시는 계속된다. 완전히 끝내려면 트레이 메뉴의 「끝내기」.
// 보안: 화면은 관제 서버 주소만 열고(다른 주소로 이동·새 창 금지, https 링크는 기본 브라우저로), 페이지에 Node 기능을 주지 않는다.
const { app, BrowserWindow, Tray, Menu, nativeImage, shell, Notification, screen, dialog, net: enet } = require('electron');
const { createUpdater, RELEASE_BASE } = require('./updater');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

// 기본 포트는 5189. 다른 프로그램(예: 같은 포트를 쓰는 다른 앱)이 쓰고 있으면 5190~5199 중 빈 포트로 저절로 옮긴다.
const BASE_PORT = Number(process.env.SOC_PORT) > 0 ? Number(process.env.SOC_PORT) : 5189;
let PORT = BASE_PORT;
let ORIGIN = `http://127.0.0.1:${PORT}`;
let serverReady = false;
const setPort = (port) => { PORT = port; ORIGIN = `http://127.0.0.1:${port}`; };
const HIDDEN = process.argv.includes('--hidden');
const SERVER_ROOT = app.isPackaged ? path.join(process.resourcesPath, 'server') : path.join(__dirname, '..');
const DATA_DIR = path.join(process.env.LOCALAPPDATA || app.getPath('temp'), 'djokovic-soc');
const asset = (name) => path.join(__dirname, 'assets', name);
const SECRET_ENV = /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|^ON_AI_|^OPENAI|^ANTHROPIC|^SUPABASE)/i;

let mainWin = null;
let miniWin = null;
let tray = null;
let child = null;
let ownServer = false;
let quitting = false;
let restarts = 0;
let status = { level: 'unknown', text: '관제 서버에 연결하는 중' };
let settings = { lastPort: null, mini: true, loginInitialized: false, closeHintShown: false, miniBounds: null, mainBounds: null };

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');
function loadSettings() { try { settings = { ...settings, ...JSON.parse(fs.readFileSync(settingsFile(), 'utf8')) }; } catch { /* 처음 실행 */ } }
function saveSettings() { try { fs.mkdirSync(path.dirname(settingsFile()), { recursive: true }); fs.writeFileSync(settingsFile(), JSON.stringify(settings)); } catch { /* 저장 실패는 무시 */ } }

function getJson(url, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; if (data.length > 8_000_000) req.destroy(); });
      res.on('end', () => { let json = null; try { json = JSON.parse(data); } catch { json = null; } resolve({ status: res.statusCode, json }); });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}
const socAlive = async (port = PORT, timeoutMs = 3000) => { const r = await getJson(`http://127.0.0.1:${port}/api/soc/snapshot`, timeoutMs); return r && r.status === 200 && r.json && r.json.ok ? r.json.data : null; };
// 그 포트에서 무언가 연결을 받는지(= 누군가 쓰고 있는지)
const portInUse = (port) => new Promise((resolve) => {
  const s = net.connect({ port, host: '127.0.0.1' });
  s.setTimeout(1500);
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('timeout', () => { s.destroy(); resolve(true); });
  s.once('error', () => resolve(false));
});

// ---------- 관제 서버 ----------
function startServer() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const logPath = path.join(DATA_DIR, 'app-server.log');
  try { if (fs.statSync(logPath).size > 2 * 1024 * 1024) fs.renameSync(logPath, `${logPath}.1`); } catch { /* 없음 */ }
  const log = fs.openSync(logPath, 'a');
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!SECRET_ENV.test(k)) env[k] = v;
  env.ELECTRON_RUN_AS_NODE = '1';
  env.ON_PORT = String(PORT);
  // Electron 안의 Node 로 서버 진입점을 실행한다(따로 Node.js 를 설치하지 않아도 됨).
  // 작업 폴더를 프로그램 폴더 밖(데이터 폴더)으로 둔다. 서버가 띄운 점검 PowerShell 이 프로그램 폴더를 쥐고 있으면 업데이트 때 폴더를 바꿀 수 없기 때문이다.
  child = spawn(process.execPath, [path.join(SERVER_ROOT, 'src', 'final-app.mjs')], { cwd: DATA_DIR, env, windowsHide: true, stdio: ['ignore', log, log] });
  ownServer = true;
  child.on('exit', (code) => {
    child = null;
    if (quitting) return;
    status = { level: 'unknown', text: `관제 서버가 멈췄습니다(코드 ${code}). 다시 켜는 중` };
    paintTray();
    serverReady = false;
    if (restarts < 5) { restarts += 1; setTimeout(() => ensureServer().catch(() => {}), 5000); }
  });
}

// 관제 서버를 찾거나 켠다. 순서: 5189 → 지난번에 쓴 포트 → 5190 … 5199.
// 관제 서버가 이미 있으면 그것을 쓰고, 다른 프로그램이 쓰는 포트는 건너뛰고, 처음 만난 빈 포트에서 서버를 켠다.
async function ensureServer() {
  const before = ORIGIN;
  const candidates = [...new Set([BASE_PORT, settings.lastPort, ...Array.from({ length: 10 }, (_, i) => BASE_PORT + 1 + i)].filter((p) => Number.isInteger(p) && p >= 1024 && p <= 65535))];
  const skipped = [];
  for (const port of candidates) {
    // 바쁜 관제 서버를 다른 프로그램으로 오인해 서버를 하나 더 켜지 않도록 넉넉히 기다린다.
    if (await socAlive(port, 8000)) { setPort(port); ownServer = Boolean(child); return finishReady(before, skipped); }
    if (await portInUse(port)) { skipped.push(port); continue; }
    setPort(port);
    startServer();
    for (let i = 0; i < 40; i += 1) { await new Promise((r) => setTimeout(r, 1000)); if (await socAlive()) { restarts = 0; return finishReady(before, skipped); } }
    return false;
  }
  dialog.showErrorBox('빈 포트를 찾지 못했습니다', `포트 ${candidates.join(', ')}를 모두 다른 프로그램이 쓰고 있습니다. 그중 하나를 끄거나 SOC_PORT 환경 변수로 다른 포트를 지정하세요.`);
  return false;
}
function finishReady(before, skipped) {
  serverReady = true;
  if (settings.lastPort !== PORT) { settings.lastPort = PORT; saveSettings(); }
  if (skipped.length && Notification.isSupported()) new Notification({ title: 'Djokovic 보안 관제', body: `포트 ${skipped.join(', ')}를 다른 프로그램이 쓰고 있어서 ${PORT}번으로 열었습니다.`, icon: asset('icon.png') }).show();
  // 서버 주소가 바뀌었으면(재시작 뒤 다른 포트) 열려 있는 창을 새 주소로 다시 연다.
  if (before !== ORIGIN) {
    if (mainWin && !mainWin.isDestroyed()) mainWin.loadURL(`${ORIGIN}/pc-status`);
    if (miniWin && !miniWin.isDestroyed()) miniWin.loadURL(`${ORIGIN}/pc-status#pip-desktop`);
  }
  paintTray();
  return true;
}

// ---------- 창 ----------
const SECURE_WEB = { contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: false };
function lockDown(win) {
  win.webContents.on('will-navigate', (event, url) => { if (!url.startsWith(`${ORIGIN}/`)) event.preventDefault(); });
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https:\/\//.test(url)) shell.openExternal(url); return { action: 'deny' }; });
}
function visible(b) {
  return b && screen.getAllDisplays().some((d) => b.x < d.workArea.x + d.workArea.width - 40 && b.x + b.width > d.workArea.x + 40 && b.y >= d.workArea.y - 10 && b.y < d.workArea.y + d.workArea.height - 40);
}
function retryOnFail(win, page) {
  win.webContents.on('did-fail-load', (_e, _code, desc, url) => {
    if (!url.startsWith(ORIGIN)) return;
    const html = `<!doctype html><meta charset="utf-8"><body style="margin:0;font:14px 'Malgun Gothic',sans-serif;color:#eef0ff;background:#141838;display:grid;place-items:center;height:100vh;text-align:center"><div>관제 서버(${ORIGIN})에 연결하는 중입니다.<br>잠시 뒤 자동으로 다시 연결합니다.<br><small>(${desc})</small></div></body>`;
    win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    setTimeout(() => { if (!win.isDestroyed()) win.loadURL(page); }, 4000);
  });
}

function showMain(then) {
  if (!serverReady) return; // 관제 서버가 아닌 곳을 열지 않는다
  if (mainWin && !mainWin.isDestroyed()) {
    if (mainWin.isMinimized()) mainWin.restore();
    mainWin.show(); mainWin.focus();
    if (then) then(mainWin);
    return;
  }
  const b = visible(settings.mainBounds) ? settings.mainBounds : { width: 1440, height: 900 };
  // 흰 Windows 제목 막대 대신 화면 위에 최소화·최대화·닫기 버튼만 겹쳐 그린다(titleBarOverlay). 창 옮기기는 화면 위쪽 머리 부분을 끌면 된다.
  mainWin = new BrowserWindow({ ...b, minWidth: 900, minHeight: 600, show: false, title: 'Djokovic 보안 관제', icon: asset('icon.png'), autoHideMenuBar: true, backgroundColor: '#dfe5ef',
    titleBarStyle: 'hidden', titleBarOverlay: { color: '#00000000', symbolColor: '#172140', height: 34 }, webPreferences: SECURE_WEB });
  // 페이지에 "앱 안에서 보는 중" 표시를 붙여(제목 막대 자리 비우기·끌기 영역) 앱 전용 모양을 켜고, 밝은·어두운 화면에 맞춰 버튼 색을 바꾼다.
  let shellTheme = null;
  const syncShell = () => {
    if (!mainWin || mainWin.isDestroyed()) return;
    mainWin.webContents.executeJavaScript("document.documentElement.setAttribute('data-shell', 'app'); document.documentElement.getAttribute('data-theme')").then((theme) => {
      if (theme === shellTheme || mainWin.isDestroyed()) return;
      shellTheme = theme;
      mainWin.setTitleBarOverlay({ color: '#00000000', symbolColor: theme === 'dark' ? '#eef0ff' : '#172140', height: 34 });
    }).catch(() => {});
  };
  mainWin.webContents.on('dom-ready', () => { shellTheme = null; syncShell(); });
  const shellTimer = setInterval(syncShell, 1500);
  mainWin.on('closed', () => clearInterval(shellTimer));
  mainWin.setMenu(null);
  lockDown(mainWin);
  retryOnFail(mainWin, `${ORIGIN}/pc-status`);
  mainWin.once('ready-to-show', () => mainWin.show());
  if (then) mainWin.webContents.once('did-finish-load', () => setTimeout(() => then(mainWin), 800));
  const save = () => { if (!mainWin.isMaximized() && !mainWin.isMinimized()) { settings.mainBounds = mainWin.getBounds(); saveSettings(); } };
  mainWin.on('moved', save);
  mainWin.on('resized', save);
  // 창을 닫아도 앱은 트레이에서 계속 감시한다.
  mainWin.on('close', (event) => {
    if (quitting) return;
    event.preventDefault();
    mainWin.hide();
    if (!settings.closeHintShown && Notification.isSupported()) {
      new Notification({ title: 'Djokovic 보안 관제', body: '창을 닫아도 감시는 계속됩니다. 작업 표시줄 오른쪽 알림 영역의 아이콘에서 다시 열거나 끝낼 수 있습니다.', icon: asset('icon.png') }).show();
      settings.closeHintShown = true; saveSettings();
    }
  });
  mainWin.loadURL(`${ORIGIN}/pc-status`);
}

function showMini(on) {
  if (on && !serverReady) return;
  settings.mini = on; saveSettings();
  if (!on) { if (miniWin && !miniWin.isDestroyed()) miniWin.close(); miniWin = null; paintTray(); return; }
  if (miniWin && !miniWin.isDestroyed()) { miniWin.show(); return; }
  const work = screen.getPrimaryDisplay().workArea;
  const b = visible(settings.miniBounds) ? settings.miniBounds : { width: 360, height: 520, x: work.x + work.width - 380, y: work.y + 20 };
  miniWin = new BrowserWindow({ ...b, minWidth: 220, minHeight: 120, frame: false, transparent: true, backgroundColor: '#00000000', alwaysOnTop: true, skipTaskbar: true, resizable: true, title: '보안 관제 미니 창', icon: asset('icon.png'), webPreferences: SECURE_WEB });
  miniWin.setAlwaysOnTop(true, 'screen-saver');
  lockDown(miniWin);
  retryOnFail(miniWin, `${ORIGIN}/pc-status#pip-desktop`);
  const save = () => { settings.miniBounds = miniWin.getBounds(); saveSettings(); };
  miniWin.on('moved', save);
  miniWin.on('resized', save);
  // 미니 창 안의 「✕」(window.close)로 닫으면 미니 창 설정도 끈다.
  miniWin.on('closed', () => { miniWin = null; if (!quitting) { settings.mini = false; saveSettings(); paintTray(); } });
  miniWin.loadURL(`${ORIGIN}/pc-status#pip-desktop`);
  paintTray();
}

const clickInPage = (selector) => (win) => win.webContents.executeJavaScript(`(() => { const b = document.querySelector(${JSON.stringify(selector)}); if (b) b.click(); return Boolean(b); })()`).catch(() => {});

// ---------- 자동 업데이트 ----------
// 앱을 켜고 30초 뒤, 그다음 6시간마다 GitHub Releases 에서 새 버전을 확인한다. 새 버전이 있으면 알림을 띄우고,
// 사용자가 트레이 메뉴에서 「업데이트 설치」를 누를 때만 받아서(서명·해시 검사) 설치 프로그램을 실행한다.
// 시험용으로 SOC_UPDATE_MANIFEST_URL·SOC_UPDATE_DOWNLOAD_PREFIX 환경 변수로 주소를 바꿀 수 있다.
const updater = createUpdater({
  fetchFn: (url, opts) => enet.fetch(url, opts),
  currentVersion: app.getVersion(),
  publicKeyPem: fs.readFileSync(path.join(__dirname, 'update-key.pub.pem'), 'utf8'),
  tmpDir: path.join(app.getPath('temp'), 'djokovic-soc-update'),
  ...(process.env.SOC_UPDATE_MANIFEST_URL ? { manifestUrl: process.env.SOC_UPDATE_MANIFEST_URL, downloadPrefix: process.env.SOC_UPDATE_DOWNLOAD_PREFIX || `${RELEASE_BASE}/download/` } : {}),
});
let update = { state: 'idle', manifest: null, progress: 0, error: null, notified: null };
const notify = (body) => { if (Notification.isSupported()) new Notification({ title: 'Djokovic 보안 관제', body, icon: asset('icon.png') }).show(); };

async function checkUpdates(manual = false) {
  if (update.state === 'checking' || update.state === 'downloading') return;
  update = { ...update, state: 'checking', error: null };
  paintTray();
  const r = await updater.check();
  if (r.error) update = { ...update, state: 'error', error: r.error };
  else if (r.available) update = { ...update, state: 'available', manifest: r.manifest };
  else update = { ...update, state: 'latest', manifest: r.manifest || null };
  paintTray();
  if (update.state === 'available' && (manual || update.notified !== update.manifest.version)) {
    update.notified = update.manifest.version;
    notify(`새 버전 ${update.manifest.version}이 있습니다(지금 ${app.getVersion()}). 알림 영역 아이콘 메뉴의 「업데이트 설치」를 누르세요.`);
  } else if (manual) notify(update.state === 'error' ? update.error : `지금 버전(${app.getVersion()})이 최신입니다.`);
}

async function installUpdate() {
  const m = update.manifest;
  if (!m || update.state !== 'available') return;
  const choice = await dialog.showMessageBox({ type: 'info', buttons: ['받아서 설치', '나중에'], defaultId: 0, cancelId: 1, title: '업데이트', message: `새 버전 ${m.version}을 받아 설치합니다.`, detail: `${m.notes ? `${m.notes}\n\n` : ''}받은 파일의 서명과 지문을 확인한 뒤 설치 프로그램을 엽니다. 설치 비밀번호를 입력해야 설치되고, 설치하는 동안 앱은 잠시 꺼집니다. 사건 기록과 설정은 그대로 남습니다.` });
  if (choice.response !== 0) return;
  update = { ...update, state: 'downloading', progress: 0 };
  paintTray();
  let file;
  try {
    let last = 0;
    file = await updater.download(m, (p) => { update.progress = p; if (p - last >= 0.05) { last = p; paintTray(); } });
  } catch (error) {
    update = { ...update, state: 'available', error: String(error.message || error) };
    paintTray();
    dialog.showErrorBox('업데이트를 받지 못했습니다', update.error);
    return;
  }
  // 설치 프로그램이 앱을 끄고 새 버전으로 바꾼 뒤 다시 실행한다.
  spawn(file, [], { detached: true, stdio: 'ignore' }).unref();
  quitting = true;
  app.quit();
}

function updateMenuItem() {
  if (update.state === 'downloading') return { label: `업데이트 받는 중 ${Math.round(update.progress * 100)}%`, enabled: false };
  if (update.state === 'available') return { label: `업데이트 설치(새 버전 ${update.manifest.version})`, click: () => { installUpdate().catch(() => {}); } };
  if (update.state === 'checking') return { label: '업데이트 확인 중…', enabled: false };
  return { label: `업데이트 확인(지금 ${app.getVersion()}${update.state === 'latest' ? ', 최신' : update.state === 'error' ? ', 확인 실패' : ''})`, click: () => { checkUpdates(true).catch(() => {}); } };
}

// ---------- 트레이 ----------
const TRAY_ICON = {};
function trayIcon(level) { if (!TRAY_ICON[level]) TRAY_ICON[level] = nativeImage.createFromPath(asset(`tray-${level}.png`)); return TRAY_ICON[level]; }
const loginSupported = () => app.isPackaged;
function paintTray() {
  if (!tray) return;
  tray.setImage(trayIcon(status.level));
  tray.setToolTip(`Djokovic 보안 관제\n${status.text}`.slice(0, 127));
  const login = loginSupported() ? app.getLoginItemSettings({ args: ['--hidden'] }).openAtLogin : false;
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: status.text, enabled: false },
    { type: 'separator' },
    { label: '관제 화면 열기', click: () => showMain() },
    { label: 'PC 보안 점검(KISA)', click: () => showMain(clickInPage('[data-view-tab="audit"]')) },
    { label: '미니 창 보이기', type: 'checkbox', checked: Boolean(miniWin), click: (item) => showMini(item.checked) },
    { label: '사용 설명서', click: () => showMain(clickInPage('#manual-open')) },
    { type: 'separator' },
    { label: '로그인할 때 자동 실행', type: 'checkbox', checked: login, enabled: loginSupported(), click: (item) => { app.setLoginItemSettings({ openAtLogin: item.checked, args: ['--hidden'] }); paintTray(); } },
    updateMenuItem(),
    { label: `서버: ${ownServer ? '앱이 켠 서버' : '이미 켜져 있던 서버 사용'} · ${ORIGIN}`, enabled: false },
    { type: 'separator' },
    ...(app.isPackaged && fs.existsSync(path.join(path.dirname(process.execPath), 'Uninstall.exe')) ? [{ label: '프로그램 제거…', click: () => { spawn(path.join(path.dirname(process.execPath), 'Uninstall.exe'), [], { detached: true, stdio: 'ignore' }).unref(); quitting = true; app.quit(); } }] : []),
    { label: '끝내기(감시 중지)', click: () => { quitting = true; app.quit(); } },
  ]));
}

// 미확인 사건으로 트레이 아이콘 색을 정한다: 긴급 → 빨강, 높음·주의 → 노랑, 없으면 초록, 서버 연결 안 됨 → 회색.
async function pollStatus() {
  const data = await socAlive();
  if (!data) status = { level: 'unknown', text: '관제 서버에 연결되지 않음' };
  else {
    const open = (data.events || []).filter((e) => !e.ack && !e.test);
    const n = (sev) => open.filter((e) => e.severity === sev).length;
    const crit = n('critical'), high = n('high'), med = n('medium');
    status = { level: crit ? 'critical' : high || med ? 'warn' : 'normal', text: crit || high || med ? `미확인 긴급 ${crit} · 높음 ${high} · 주의 ${med}` : '미확인 이상 없음' };
  }
  paintTray();
}

// ---------- 시작 ----------
// Node.js 가 없는 PC에서 Claude Code 감사 훅을 이 앱으로 실행한다(Djokovic SOC.exe --audit-hook claude).
// 창·트레이·서버를 띄우지 않고 훅 기록 한 줄만 남기고 바로 끝낸다(단일 실행 잠금도 잡지 않음).
const HOOK_AT = process.argv.indexOf('--audit-hook');
if (HOOK_AT >= 0) {
  const hookFile = path.join(process.env.LOCALAPPDATA || app.getPath('temp'), 'djokovic-soc', 'hooks', 'agent-audit-hook.mjs');
  import(require('node:url').pathToFileURL(hookFile).href)
    .then((m) => { let text = ''; try { text = fs.readFileSync(0, 'utf8'); } catch { text = ''; } return m.runHook(process.argv[HOOK_AT + 1], text); })
    .catch(() => { /* 감사 기록 실패가 에이전트 동작을 막으면 안 된다 */ })
    .finally(() => app.exit(0));
} else if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => showMain());
  app.on('window-all-closed', (e) => { /* 트레이에서 계속 동작 */ });
  app.on('before-quit', () => { quitting = true; if (ownServer && child) child.kill(); });
  app.whenReady().then(async () => {
    app.setAppUserModelId('kr.aleph.djokovic.soc');
    loadSettings();
    // 설치한 앱을 처음 켤 때 로그인 자동 실행을 켠다(트레이 메뉴에서 끌 수 있음).
    if (loginSupported() && !settings.loginInitialized) { app.setLoginItemSettings({ openAtLogin: true, args: ['--hidden'] }); settings.loginInitialized = true; saveSettings(); }
    tray = new Tray(trayIcon('unknown'));
    tray.on('click', () => showMain());
    paintTray();
    const ok = await ensureServer();
    if (!ok) status = { level: 'unknown', text: '관제 서버를 켜지 못했습니다(기록: %LOCALAPPDATA%\\djokovic-soc\\app-server.log)' };
    await pollStatus();
    setInterval(() => { pollStatus().catch(() => {}); }, 10000).unref?.();
    if (!HIDDEN) showMain();
    if (settings.mini) showMini(true);
    // 업데이트로 버전이 바뀌었으면 한 번 알려 준다.
    // (1.0.1 은 버전을 기록하지 않았으므로, 전에 쓰던 흔적이 있으면 「이전 버전」으로 적는다)
    const prevVersion = settings.lastVersion || (settings.loginInitialized ? '이전 버전' : null);
    if (prevVersion && prevVersion !== app.getVersion()) notify(`업데이트를 마쳤습니다: ${prevVersion} → ${app.getVersion()}`);
    if (settings.lastVersion !== app.getVersion()) { settings.lastVersion = app.getVersion(); saveSettings(); }
    setTimeout(() => { checkUpdates().catch(() => {}); }, 30000);
    setInterval(() => { checkUpdates().catch(() => {}); }, 6 * 3600 * 1000).unref?.();
  });
}
