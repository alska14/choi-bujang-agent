// 앱 아이콘 만들기: 관제 화면의 로고(pc-status/icons/logo.svg)를 여러 크기 PNG로 그려 icon.ico·icon.png 와
// 상태별 알림 영역 아이콘(tray-정상·주의·위험·확인 불가)을 만든다. 외부 도구 없이 Electron 의 그리기 기능만 쓴다.
// 실행(desktop 폴더에서): npx electron make-icons.js
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const SVG = fs.readFileSync(path.join(__dirname, '..', 'pc-status', 'icons', 'logo.svg'), 'utf8');
const OUT = path.join(__dirname, 'assets');
const ICO_SIZES = [16, 24, 32, 48, 64, 128, 256];
const TRAY = { normal: '#17a673', warn: '#f2b100', critical: '#d6203f', unknown: '#8a93b3' };

// 페이지 안에서 SVG 를 캔버스에 그려 PNG(base64)로 돌려준다. dot 이 있으면 오른쪽 아래에 상태 점을 얹는다.
const RENDER = (svg, size, dot) => `(async () => {
  const img = new Image();
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(${JSON.stringify(svg)});
  await img.decode();
  const c = document.createElement('canvas'); c.width = c.height = ${size};
  const g = c.getContext('2d');
  g.drawImage(img, 0, 0, ${size}, ${size});
  ${dot ? `const r = ${size} * 0.24, x = ${size} - r - 1, y = ${size} - r - 1;
  g.beginPath(); g.arc(x, y, r + ${size} * 0.06, 0, Math.PI * 2); g.fillStyle = '#ffffff'; g.fill();
  g.beginPath(); g.arc(x, y, r, 0, Math.PI * 2); g.fillStyle = '${dot}'; g.fill();` : ''}
  return c.toDataURL('image/png').split(',')[1];
})()`;

// PNG 여러 장을 담은 ICO 파일(Windows Vista 이후 형식)
function ico(pngs) {
  const header = Buffer.alloc(6); header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(pngs.length, 4);
  const entries = [];
  let offset = 6 + 16 * pngs.length;
  for (const { size, data } of pngs) {
    const e = Buffer.alloc(16);
    e.writeUInt8(size >= 256 ? 0 : size, 0); e.writeUInt8(size >= 256 ? 0 : size, 1);
    e.writeUInt16LE(1, 4); e.writeUInt16LE(32, 6); e.writeUInt32LE(data.length, 8); e.writeUInt32LE(offset, 12);
    entries.push(e); offset += data.length;
  }
  return Buffer.concat([header, ...entries, ...pngs.map((p) => p.data)]);
}

app.whenReady().then(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const win = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true } });
  await win.loadURL('about:blank');
  const draw = async (size, dot) => Buffer.from(await win.webContents.executeJavaScript(RENDER(SVG, size, dot)), 'base64');
  const pngs = [];
  for (const size of ICO_SIZES) pngs.push({ size, data: await draw(size) });
  fs.writeFileSync(path.join(OUT, 'icon.ico'), ico(pngs));
  fs.writeFileSync(path.join(OUT, 'icon.png'), pngs.at(-1).data);
  for (const [name, color] of Object.entries(TRAY)) fs.writeFileSync(path.join(OUT, `tray-${name}.png`), await draw(32, color));
  console.log('ok', fs.readdirSync(OUT).join(', '));
  app.quit();
}).catch((error) => { console.error(error); app.exit(1); });
