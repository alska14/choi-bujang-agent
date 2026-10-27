// 제공 서버(src/server.mjs)를 수정하지 않고, 같은 포트에 관제 화면(/pc-status, /soc)과 /api/pc-*, /api/soc/* 만 덧붙인다.
// 그 밖의 모든 요청은 제공 서버의 요청 처리기에 그대로 넘긴다.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { exportBundle, parseAuto } from '../soc/ti/stix.mjs';

const PAGE_DIR = fileURLToPath(new URL('../../pc-status/', import.meta.url));
const FILES = new Map([
  ['/pc-status', ['index.html', 'text/html; charset=utf-8']],
  ['/pc-status/', ['index.html', 'text/html; charset=utf-8']],
  ['/soc', ['index.html', 'text/html; charset=utf-8']],
  ['/pc-status/pc-status.js', ['pc-status.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/ti.js', ['ti.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/link.css', ['link.css', 'text/css; charset=utf-8']],
  ['/pc-status/theme.js', ['theme.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/icons/glass.svg', ['icons/glass.svg', 'image/svg+xml']],
  ['/pc-status/icons/wall-on.svg', ['icons/wall-on.svg', 'image/svg+xml']],
  ['/pc-status/icons/wall-off.svg', ['icons/wall-off.svg', 'image/svg+xml']],
  ['/pc-status/icons/alarm.svg', ['icons/alarm.svg', 'image/svg+xml']],
  ['/pc-status/icons/dashboard.svg', ['icons/dashboard.svg', 'image/svg+xml']],
  ['/pc-status/icons/detect.svg', ['icons/detect.svg', 'image/svg+xml']],
  ['/pc-status/icons/endpoint.svg', ['icons/endpoint.svg', 'image/svg+xml']],
  ['/pc-status/icons/events.svg', ['icons/events.svg', 'image/svg+xml']],
  ['/pc-status/icons/firewall.svg', ['icons/firewall.svg', 'image/svg+xml']],
  ['/pc-status/icons/iam.svg', ['icons/iam.svg', 'image/svg+xml']],
  ['/pc-status/icons/layout.svg', ['icons/layout.svg', 'image/svg+xml']],
  ['/pc-status/icons/logo.svg', ['icons/logo.svg', 'image/svg+xml']],
  ['/pc-status/icons/network.svg', ['icons/network.svg', 'image/svg+xml']],
  ['/pc-status/icons/notify.svg', ['icons/notify.svg', 'image/svg+xml']],
  ['/pc-status/icons/pip.svg', ['icons/pip.svg', 'image/svg+xml']],
  ['/pc-status/icons/ports.svg', ['icons/ports.svg', 'image/svg+xml']],
  ['/pc-status/icons/refresh.svg', ['icons/refresh.svg', 'image/svg+xml']],
  ['/pc-status/icons/sound.svg', ['icons/sound.svg', 'image/svg+xml']],
  ['/pc-status/icons/theme.svg', ['icons/theme.svg', 'image/svg+xml']],
  ['/pc-status/icons/ti.svg', ['icons/ti.svg', 'image/svg+xml']],
  ['/pc-status/icons/unacked.svg', ['icons/unacked.svg', 'image/svg+xml']],
  ['/pc-status/layout.js', ['layout.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/pip.js', ['pip.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/manual.js', ['manual.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/audit.js', ['audit.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/pc-status.css', ['pc-status.css', 'text/css; charset=utf-8']],
  ...['notify-off', 'sound-off', 'help', 'usb', 'program', 'task', 'audit'].map((name) => [`/pc-status/icons/${name}.svg`, [`icons/${name}.svg`, 'image/svg+xml']]),
  // 사용 설명서 그림(pip-desktop/capture-manual.js 가 실제 화면을 찍어 만든 것)
  ...['overview', 'tools', 'network', 'endpoint', 'iam', 'events', 'ti', 'alarm', 'layout', 'pip', 'mini', 'audit'].map((name) => [`/pc-status/manual/${name}.png`, [`manual/${name}.png`, 'image/png']]),
]);
// 제공 서버가 보내는 것과 같은 보안 정책이다.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'";
const SOC_GET = new Set(['/api/soc/snapshot', '/api/soc/stream', '/api/soc/wallpaper']);
const TI_GET = new Set(['/api/soc/ti/state', '/api/soc/ti/export']);
const TI_POST = new Set(['/api/soc/ti/ioc', '/api/soc/ti/ioc-delete', '/api/soc/ti/import', '/api/soc/ti/test-detect', '/api/soc/ti/feedback', '/api/soc/ti/scan']);
const SOC_POST = new Set(['/api/soc/ack', '/api/soc/test-alert', '/api/soc/refresh-security']);
// PC 보안 점검(KISA PC-01~18). 조치는 preview 가 준 일회용 승인 표(token)로만 apply 한다.
const AUDIT_GET = new Set(['/api/soc/audit/state']);
const AUDIT_POST = new Set(['/api/soc/audit/run', '/api/soc/audit/preview', '/api/soc/audit/apply', '/api/soc/audit/open']);

function send(res, status, type, body) {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'content-security-policy': CSP, 'x-content-type-options': 'nosniff' });
  res.end(body);
}
const sendJson = (res, status, payload) => send(res, status, 'application/json; charset=utf-8', JSON.stringify(payload));
const fail = (res, status, code, message) => sendJson(res, status, { ok: false, error: { code, message, retryable: false } });

// 실제 SDP 연결 여부는 PC 조회 결과와 섞지 않고 따로 알려 준다.
function sdpStatus(mode) {
  if (mode === 'connected') return { status: 'connected', label: '연결됨(어댑터가 연결 상태로 보고함)', reason: '이 화면은 접속 성공 여부를 따로 확인하지 않습니다.' };
  if (mode === 'demo') return { status: 'demo', label: '예제 모드', reason: '예제 자료로 동작하며 실제 SDP 서버에 연결된 것이 아닙니다.' };
  return { status: 'not_connected', label: 'SDP 미연결', reason: '기존 서버·에이전트(SDP) 연결 설정이 없습니다. 이 PC에서 읽은 값과는 별개입니다.' };
}

function readJsonBody(req, limit = 2048) {
  return new Promise((resolveBody, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => { size += chunk.length; if (size > limit) { reject(Object.assign(new Error('TOO_LARGE'), { code: 'TOO_LARGE' })); req.destroy(); return; } chunks.push(chunk); });
    req.on('end', () => { try { resolveBody(size === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('BAD_JSON'), { code: 'BAD_JSON' })); } });
    req.on('error', reject);
  });
}

function serveStream(req, res, soc) {
  res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', connection: 'keep-alive', 'content-security-policy': CSP, 'x-accel-buffering': 'no' });
  const write = (event, data) => { try { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); } catch { /* 끊긴 연결은 close 처리에서 정리한다 */ } };
  res.write('retry: 3000\n\n');
  write('snapshot', soc.monitor.snapshot());
  const offStore = soc.store.subscribe((type, payload) => write(type === 'ack' ? 'ack' : 'event', type === 'ack' ? { ids: payload, counts: soc.store.counts() } : { event: payload, counts: soc.store.counts() }));
  const offMonitor = soc.monitor.subscribe((type, payload) => write(type, payload));
  const heartbeat = setInterval(() => { try { res.write(': hb\n\n'); } catch { /* close 에서 정리 */ } }, 15000);
  heartbeat.unref?.();
  const cleanup = () => { clearInterval(heartbeat); offStore(); offMonitor(); };
  req.on('close', cleanup);
  res.on('error', cleanup);
}


// 제공된 메인 화면 파일(public/)은 고치지 않는다. 응답이 나갈 때만 "보안 관제 열기" 링크 한 줄을 덧붙인다.
// 링크 스타일은 외부 CSS 파일로 불러오므로 제공 서버의 보안 정책(CSP)을 그대로 지킨다. ON_SOC_LINK=0 이면 덧붙이지 않는다.
const LINK_HTML = '<link rel="stylesheet" href="/pc-status/link.css"><a class="soc-link" href="/pc-status">보안 관제 열기</a>';
function serveWithLink(original, server, req, res) {
  if (process.env.ON_SOC_LINK === '0') { original.call(server, req, res); return; }
  const chunks = [];
  const write = res.write.bind(res);
  const end = res.end.bind(res);
  const writeHead = res.writeHead.bind(res);
  let head = null;
  res.writeHead = (status, ...rest) => { head = [status, ...rest]; return res; };
  res.write = (chunk, ...rest) => { if (chunk != null) chunks.push(Buffer.from(chunk, typeof rest[0] === 'string' ? rest[0] : undefined)); return true; };
  res.end = (chunk, ...rest) => {
    if (chunk != null && typeof chunk !== 'function') chunks.push(Buffer.from(chunk, typeof rest[0] === 'string' ? rest[0] : undefined));
    res.writeHead = writeHead; res.write = write; res.end = end;
    let body = Buffer.concat(chunks);
    const status = head ? head[0] : res.statusCode;
    const headers = head ? head.find((x) => x && typeof x === 'object' && !Array.isArray(x)) || {} : {};
    const type = String(headers['content-type'] ?? headers['Content-Type'] ?? res.getHeader('content-type') ?? '');
    if (status === 200 && type.includes('text/html')) {
      const html = body.toString('utf8');
      if (html.includes('</body>')) {
        body = Buffer.from(html.replace('</body>', `${LINK_HTML}</body>`), 'utf8');
        for (const name of Object.keys(headers)) if (name.toLowerCase() === 'content-length') delete headers[name];
        res.removeHeader('content-length');
      }
    }
    if (head) writeHead(head[0], ...head.slice(1)); 
    return end(body);
  };
  original.call(server, req, res);
}

// 유리 효과용 배경: 이 PC의 현재 바탕화면 그림(Windows가 만들어 두는 TranscodedWallpaper)을 읽기만 해서 보낸다.
// 브라우저 페이지는 운영체제 창을 실제로 투명하게 만들 수 없어서, 같은 그림을 배경으로 깔아 바탕화면이 비쳐 보이게 한다.
async function serveWallpaper(res) {
  const file = process.env.APPDATA ? resolve(process.env.APPDATA, 'Microsoft', 'Windows', 'Themes', 'TranscodedWallpaper') : null;
  let data = null;
  try { if (file) data = await readFile(file); } catch { data = null; }
  if (!data || data.length > 40 * 1024 * 1024) { fail(res, 404, 'WALLPAPER_UNAVAILABLE', '바탕화면 그림을 읽지 못했습니다.'); return; }
  const type = data[0] === 0x89 && data[1] === 0x50 ? 'image/png' : data[0] === 0xff && data[1] === 0xd8 ? 'image/jpeg' : data[0] === 0x42 && data[1] === 0x4d ? 'image/bmp' : null;
  if (!type) { fail(res, 415, 'WALLPAPER_FORMAT', '바탕화면 그림 형식을 알 수 없습니다.'); return; }
  res.writeHead(200, { 'content-type': type, 'cache-control': 'private, max-age=300', 'content-security-policy': CSP, 'x-content-type-options': 'nosniff' });
  res.end(data);
}

export function attachPcStatus(server, { sampler, history, securityReader, soc = null, ti = null, audit = null, engineMode = () => 'disconnected', clock = () => new Date() }) {
  const originals = server.listeners('request');
  if (originals.length !== 1) throw Error('PC_STATUS_ATTACH_FAILED');
  const original = originals[0];
  server.removeAllListeners('request');

  server.on('request', async (req, res) => {
    let url;
    try { url = new URL(req.url, 'http://127.0.0.1'); } catch { original.call(server, req, res); return; }
    const isPage = FILES.has(url.pathname);
    const isApi = url.pathname === '/api/pc-status';
    const isSecurityApi = url.pathname === '/api/pc-security' && Boolean(securityReader);
    const isSocGet = Boolean(soc) && SOC_GET.has(url.pathname);
    const isSocPost = Boolean(soc) && SOC_POST.has(url.pathname);
    const isTiGet = Boolean(ti) && TI_GET.has(url.pathname);
    const isTiPost = Boolean(ti) && TI_POST.has(url.pathname);
    const isAuditGet = Boolean(audit) && AUDIT_GET.has(url.pathname);
    const isAuditPost = Boolean(audit) && AUDIT_POST.has(url.pathname);
    if (!isPage && !isApi && !isSecurityApi && !isSocGet && !isSocPost && !isTiGet && !isTiPost && !isAuditGet && !isAuditPost) {
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) { serveWithLink(original, server, req, res); return; }
      original.call(server, req, res);
      return;
    }

    try {
      const port = req.socket.localPort;
      const host = req.headers.host;
      if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(host)) { fail(res, 403, 'HOST_REJECTED', '로컬 실행 주소를 확인하세요.'); return; }
      if (url.search) { fail(res, 400, 'QUERY_REJECTED', '지원하지 않는 요청입니다.'); return; }
      if (url.pathname.startsWith('/api/') && req.headers['sec-fetch-site'] === 'cross-site') { fail(res, 403, 'ORIGIN_REJECTED', '앱 화면에서 다시 요청하세요.'); return; }

      if (isTiPost) {
        if (req.method !== 'POST') { fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST만 지원합니다.'); return; }
        if (req.headers.origin !== `http://${host}`) { fail(res, 403, 'ORIGIN_REJECTED', '앱 화면에서 다시 요청하세요.'); return; }
        if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) { fail(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'JSON만 지원합니다.'); return; }
        let body;
        try { body = await readJsonBody(req, url.pathname === '/api/soc/ti/import' ? 1_200_000 : 4096); } catch (error) { fail(res, error.code === 'TOO_LARGE' ? 413 : 400, error.code || 'BAD_REQUEST', '요청 본문을 확인하세요.'); return; }
        const ok = (data) => sendJson(res, 200, { ok: true, data });
        const bad = (message, status = 400) => fail(res, status, 'REJECTED', message);
        if (url.pathname === '/api/soc/ti/ioc') {
          const result = ti.iocs.add({ ...body, source: 'manual' });
          if (result.error) { bad(result.error); return; }
          ok({ ioc: result.ioc, duplicate: Boolean(result.duplicate) }); return;
        }
        if (url.pathname === '/api/soc/ti/ioc-delete') { if (typeof body.id !== 'string') { bad('id가 필요합니다.'); return; } ok({ removed: ti.iocs.remove(body.id) }); return; }
        if (url.pathname === '/api/soc/ti/import') {
          if (typeof body.content !== 'string' || body.content.length === 0) { bad('가져올 내용이 비어 있습니다.'); return; }
          const parsed = parseAuto(body.content);
          if (parsed.error) { bad(parsed.error); return; }
          const source = String(body.source || (parsed.format === 'stix' ? 'stix-import' : 'text-import')).replace(/[\u0000-\u001f]/g, ' ').slice(0, 60);
          const summary = ti.iocs.addMany(parsed.items.map((item) => ({ ...item, source })), { severity: 'high' });
          ok({ format: parsed.format, parsed: parsed.items.length, ...summary, rejected: [...parsed.rejected, ...summary.rejected].slice(0, 20) }); return;
        }
        if (url.pathname === '/api/soc/ti/test-detect') { ok(await ti.intel.testDetection({ port })); return; }
        if (url.pathname === '/api/soc/ti/scan') { await ti.intel.scanNetwork(); await ti.intel.scanProcesses(); ok({ scans: ti.intel.snapshot().scans }); return; }
        if (url.pathname === '/api/soc/ti/feedback') {
          if (!Number.isInteger(body.eventId) || !['malicious', 'benign'].includes(body.verdict)) { bad('eventId 와 verdict(malicious|benign)가 필요합니다.'); return; }
          const result = body.verdict === 'malicious' ? ti.intel.markMalicious(body.eventId) : ti.intel.markBenign(body.eventId);
          if (result.error) { bad(result.error, 404); return; }
          ok(result); return;
        }
      }
      if (isAuditPost) {
        if (req.method !== 'POST') { fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST만 지원합니다.'); return; }
        if (req.headers.origin !== `http://${host}`) { fail(res, 403, 'ORIGIN_REJECTED', '앱 화면에서 다시 요청하세요.'); return; }
        if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) { fail(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'JSON만 지원합니다.'); return; }
        let body;
        try { body = await readJsonBody(req); } catch (error) { fail(res, error.code === 'TOO_LARGE' ? 413 : 400, error.code || 'BAD_REQUEST', '요청 본문을 확인하세요.'); return; }
        const reply = (data) => (data && data.error ? fail(res, 400, 'REJECTED', data.error) : sendJson(res, 200, { ok: true, data }));
        if (url.pathname === '/api/soc/audit/run') { reply(await audit.run()); return; }
        if (url.pathname === '/api/soc/audit/preview') { reply(audit.preview({ code: typeof body.code === 'string' ? body.code : null, fixId: typeof body.fixId === 'string' ? body.fixId : null, undoId: typeof body.undoId === 'string' ? body.undoId : null })); return; }
        if (url.pathname === '/api/soc/audit/apply') { if (typeof body.token !== 'string') { fail(res, 400, 'REJECTED', '승인 표가 없습니다.'); return; } reply(await audit.apply(body.token)); return; }
        if (typeof body.target !== 'string') { fail(res, 400, 'REJECTED', '열 화면을 지정하세요.'); return; }
        reply(await audit.open(body.target));
        return;
      }
      if (isSocPost) {
        if (req.method !== 'POST') { fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST만 지원합니다.'); return; }
        if (req.headers.origin !== `http://${host}`) { fail(res, 403, 'ORIGIN_REJECTED', '앱 화면에서 다시 요청하세요.'); return; }
        if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) { fail(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'JSON만 지원합니다.'); return; }
        let body;
        try { body = await readJsonBody(req); } catch (error) { fail(res, error.code === 'TOO_LARGE' ? 413 : 400, error.code || 'BAD_REQUEST', '요청 본문을 확인하세요.'); return; }
        if (url.pathname === '/api/soc/ack') {
          if (body && body.all === true) { const ids = soc.store.ackAll(Number.isInteger(body.minRank) ? body.minRank : 0); sendJson(res, 200, { ok: true, data: { acked: ids, counts: soc.store.counts() } }); return; }
          if (body && Number.isInteger(body.id)) { const done = soc.store.ack(body.id); sendJson(res, done ? 200 : 404, done ? { ok: true, data: { acked: [body.id], counts: soc.store.counts() } } : { ok: false, error: { code: 'NOT_FOUND', message: '이미 확인했거나 없는 사건입니다.', retryable: false } }); return; }
          fail(res, 400, 'BAD_REQUEST', 'id 또는 all 을 지정하세요.'); return;
        }
        if (url.pathname === '/api/soc/test-alert') {
          const event = soc.monitor.testAlert();
          sendJson(res, event ? 200 : 429, event ? { ok: true, data: { event } } : { ok: false, error: { code: 'TOO_FREQUENT', message: '시험 경보는 5초에 한 번만 보낼 수 있습니다.', retryable: true } });
          return;
        }
        const security = await soc.monitor.slowTick();
        sendJson(res, 200, { ok: true, data: { security } });
        return;
      }

      if (req.method !== 'GET') { fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET만 지원합니다.'); return; }
      if (isAuditGet) { sendJson(res, 200, { ok: true, data: audit.state() }); return; }
      if (isTiGet) {
        if (url.pathname === '/api/soc/ti/state') { sendJson(res, 200, { ok: true, data: ti.intel.snapshot() }); return; }
        const shareable = ti.iocs.exportable();
        const { bundle, exported, skipped } = exportBundle(shareable, { now: clock });
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': CSP, 'x-content-type-options': 'nosniff', 'content-disposition': `attachment; filename="djokovic-ioc-${clock().toISOString().slice(0, 10)}.stix.json"`, 'x-ioc-exported': String(exported), 'x-ioc-skipped': String(skipped.length) });
        res.end(JSON.stringify(bundle, null, 1));
        return;
      }
      if (isSocGet) {
        if (url.pathname === '/api/soc/stream') { serveStream(req, res, soc); return; }
        if (url.pathname === '/api/soc/wallpaper') { await serveWallpaper(res); return; }
        sendJson(res, 200, { ok: true, data: soc.monitor.snapshot() });
        return;
      }
      if (isPage) {
        const [name, type] = FILES.get(url.pathname);
        send(res, 200, type, await readFile(resolve(PAGE_DIR, name)));
        return;
      }
      if (isSecurityApi) {
        const data = await securityReader.read();
        sendJson(res, 200, {
          ok: true,
          data: { ...data, sdp: sdpStatus(engineMode()) },
          meta: { checkedAt: clock().toISOString(), source: '이 PC에서 읽기만 한 값(설정을 바꾸지 않음, 예시 값 없음)' },
        });
        return;
      }
      const sample = sampler.sample();
      history.add(sample);
      sendJson(res, 200, {
        ok: true,
        data: { sample, history: history.snapshot() },
        meta: { checkedAt: clock().toISOString(), source: '이 PC에서 방금 실측한 값(예시 값 없음)' },
      });
    } catch {
      if (!res.headersSent) fail(res, 500, 'PC_STATUS_FAILED', '이 PC의 상태를 읽는 중 오류가 났습니다. 값은 확인 불가로 봅니다.');
      else res.end();
    }
  });
}
