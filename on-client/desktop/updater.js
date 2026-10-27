// 자동 업데이트: GitHub Releases 의 최신 버전 정보(latest.json)와 서명(latest.json.sig)을 받아 확인한다.
// - latest.json 은 이 프로젝트의 업데이트 서명 열쇠(Ed25519, 개인 열쇠는 배포하는 PC에만 있음)로 서명돼 있어야 한다.
//   앱에 들어 있는 공개 열쇠로 서명을 검사하므로, 누군가 가짜 latest.json·설치 파일을 올려도 받지 않는다.
// - 설치 파일은 latest.json 에 적힌 SHA-256·크기와 맞아야 실행한다.
// - 설치 파일은 설치 비밀번호로 암호화돼 있어서, 받은 뒤에도 비밀번호를 알아야 설치된다.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const REPO = 'alska14/choi-bujang-agent';
const RELEASE_BASE = `https://github.com/${REPO}/releases`;
const MANIFEST_URL = `${RELEASE_BASE}/latest/download/latest.json`;

// 1.2.3 형식만 비교한다(앞이 크면 양수).
function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i += 1) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}

// 서명과 내용 형식을 모두 검사한다. 하나라도 어긋나면 업데이트로 쓰지 않는다.
function verifyManifest(text, signatureB64, publicKeyPem, { downloadPrefix = `${RELEASE_BASE}/download/` } = {}) {
  let valid = false;
  try { valid = crypto.verify(null, Buffer.from(text, 'utf8'), crypto.createPublicKey(publicKeyPem), Buffer.from(String(signatureB64).trim(), 'base64')); } catch { valid = false; }
  if (!valid) return { ok: false, error: '업데이트 정보의 서명이 맞지 않습니다(위조됐거나 손상됨).' };
  let m;
  try { m = JSON.parse(text); } catch { return { ok: false, error: '업데이트 정보 형식이 잘못됐습니다.' }; }
  const okShape = m && /^\d{1,4}\.\d{1,4}\.\d{1,6}$/.test(m.version) && /^[\w.-]{1,120}\.exe$/.test(m.file) && /^[0-9a-f]{64}$/.test(m.sha256)
    && Number.isInteger(m.size) && m.size > 0 && m.size < 1_000_000_000 && typeof m.url === 'string' && m.url.startsWith(downloadPrefix) && m.url.endsWith(`/${m.file}`);
  if (!okShape) return { ok: false, error: '업데이트 정보 내용이 올바르지 않습니다.' };
  return { ok: true, manifest: { version: m.version, file: m.file, url: m.url, sha256: m.sha256, size: m.size, notes: typeof m.notes === 'string' ? m.notes.slice(0, 500) : '', publishedAt: typeof m.publishedAt === 'string' ? m.publishedAt : null } };
}

function createUpdater({ fetchFn, currentVersion, publicKeyPem, tmpDir, manifestUrl = MANIFEST_URL, downloadPrefix = `${RELEASE_BASE}/download/` }) {
  async function getText(url) {
    const res = await fetchFn(url, { cache: 'no-store' });
    if (!res.ok) throw Object.assign(Error(`HTTP ${res.status}`), { status: res.status });
    return res.text();
  }
  return {
    // { available, manifest } 또는 { error }. 아직 올린 버전이 없으면(404) available=false.
    async check() {
      let text, sig;
      try { [text, sig] = await Promise.all([getText(manifestUrl), getText(`${manifestUrl}.sig`)]); } catch (error) {
        return error.status === 404 ? { available: false, none: true } : { error: '업데이트 서버에 연결하지 못했습니다(인터넷 연결을 확인하세요).' };
      }
      const v = verifyManifest(text, sig, publicKeyPem, { downloadPrefix });
      if (!v.ok) return { error: v.error };
      return { available: compareVersions(v.manifest.version, currentVersion) > 0, manifest: v.manifest };
    },
    // 받으면서 SHA-256 을 계산하고, 크기·해시가 맞을 때만 경로를 돌려준다.
    async download(manifest, onProgress = () => {}) {
      fs.mkdirSync(tmpDir, { recursive: true });
      const target = path.join(tmpDir, manifest.file);
      const partial = `${target}.part`;
      const res = await fetchFn(manifest.url);
      if (!res.ok || !res.body) throw Error(`설치 파일을 받지 못했습니다(HTTP ${res.status}).`);
      const hash = crypto.createHash('sha256');
      const out = fs.createWriteStream(partial);
      let received = 0;
      try {
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          received += value.length;
          if (received > manifest.size) throw Error('설치 파일 크기가 업데이트 정보와 다릅니다.');
          hash.update(value);
          if (!out.write(Buffer.from(value))) await new Promise((r) => out.once('drain', r));
          onProgress(received / manifest.size);
        }
      } finally { await new Promise((r) => out.end(r)); }
      const digest = hash.digest('hex');
      if (received !== manifest.size || digest !== manifest.sha256) { fs.rmSync(partial, { force: true }); throw Error('받은 설치 파일이 업데이트 정보와 다릅니다(손상 또는 변조). 실행하지 않았습니다.'); }
      fs.rmSync(target, { force: true });
      fs.renameSync(partial, target);
      return target;
    },
  };
}

module.exports = { compareVersions, verifyManifest, createUpdater, MANIFEST_URL, RELEASE_BASE, REPO };
