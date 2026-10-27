// 제공 서버(src/server.mjs)를 수정하지 않고, 같은 포트에 /pc-status 화면과 GET /api/pc-status만 덧붙인다.
// 그 밖의 모든 요청은 제공 서버의 요청 처리기에 그대로 넘긴다.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const PAGE_DIR = fileURLToPath(new URL('../../pc-status/', import.meta.url));
const FILES = new Map([
  ['/pc-status', ['index.html', 'text/html; charset=utf-8']],
  ['/pc-status/', ['index.html', 'text/html; charset=utf-8']],
  ['/pc-status/pc-status.js', ['pc-status.js', 'text/javascript; charset=utf-8']],
  ['/pc-status/pc-status.css', ['pc-status.css', 'text/css; charset=utf-8']],
]);
// 제공 서버가 보내는 것과 같은 보안 정책이다.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'";

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

export function attachPcStatus(server, { sampler, history, securityReader, engineMode = () => 'disconnected', clock = () => new Date() }) {
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
    if (!isPage && !isApi && !isSecurityApi) { original.call(server, req, res); return; }

    try {
      const port = req.socket.localPort;
      if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(req.headers.host)) { fail(res, 403, 'HOST_REJECTED', '로컬 실행 주소를 확인하세요.'); return; }
      if (url.search) { fail(res, 400, 'QUERY_REJECTED', '지원하지 않는 요청입니다.'); return; }
      if ((isApi || isSecurityApi) && req.headers['sec-fetch-site'] === 'cross-site') { fail(res, 403, 'ORIGIN_REJECTED', '앱 화면에서 다시 요청하세요.'); return; }
      if (req.method !== 'GET') { fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET만 지원합니다.'); return; }

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
