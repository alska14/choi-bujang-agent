import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const { compareVersions, verifyManifest, createUpdater } = require('../desktop/updater.js');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' });
const PREFIX = 'https://github.com/alska14/choi-bujang-agent/releases/download/';
const payload = Buffer.from('fake installer bytes');
const manifest = (over = {}) => JSON.stringify({ version: '1.0.2', file: 'Djokovic-SOC-Setup-1.0.2.exe', url: `${PREFIX}v1.0.2/Djokovic-SOC-Setup-1.0.2.exe`, sha256: createHash('sha256').update(payload).digest('hex'), size: payload.length, notes: '고침', ...over });
const sig = (text, key = privateKey) => sign(null, Buffer.from(text), key).toString('base64');

test('업데이트: 버전 비교', () => {
  assert.ok(compareVersions('1.0.10', '1.0.9') > 0);
  assert.equal(compareVersions('1.0.1', '1.0.1'), 0);
  assert.ok(compareVersions('0.9.9', '1.0.0') < 0);
});

test('업데이트: 서명이 맞아야 하고, 내용을 한 글자라도 바꾸거나 다른 열쇠로 서명하면 거부한다', () => {
  const text = manifest();
  assert.equal(verifyManifest(text, sig(text), PUB).ok, true);
  assert.equal(verifyManifest(text.replace('1.0.2', '9.9.9'), sig(text), PUB).ok, false);
  assert.equal(verifyManifest(text, sig(text, generateKeyPairSync('ed25519').privateKey), PUB).ok, false);
  const evil = manifest({ url: 'https://evil.example/Djokovic-SOC-Setup-1.0.2.exe' });
  assert.equal(verifyManifest(evil, sig(evil), PUB).ok, false, '서명이 맞아도 정해진 주소 밖의 파일은 받지 않는다');
});

const fakeFetch = (files) => async (url) => {
  if (!(url in files)) return { ok: false, status: 404, text: async () => '' };
  const body = files[url];
  return { ok: true, status: 200, text: async () => String(body), body: { getReader() { let sent = false; return { read: async () => (sent ? { done: true } : (sent = true, { done: false, value: new Uint8Array(Buffer.from(body)) })) }; } } };
};

test('업데이트: 새 버전을 찾고, 받은 파일의 지문이 맞을 때만 경로를 돌려준다', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'upd-'));
  try {
    const text = manifest();
    const m = JSON.parse(text);
    const files = { 'M': text, 'M.sig': sig(text), [m.url]: payload };
    const u = createUpdater({ fetchFn: fakeFetch(files), currentVersion: '1.0.1', publicKeyPem: PUB, tmpDir: dir, manifestUrl: 'M' });
    const r = await u.check();
    assert.equal(r.available, true);
    const path = await u.download(r.manifest);
    assert.ok(existsSync(path));
    files[m.url] = Buffer.from('tampered installer!!');
    await assert.rejects(u.download(r.manifest), /다릅니다/);
    const same = createUpdater({ fetchFn: fakeFetch(files), currentVersion: '1.0.2', publicKeyPem: PUB, tmpDir: dir, manifestUrl: 'M' });
    assert.equal((await same.check()).available, false);
    const none = createUpdater({ fetchFn: fakeFetch({}), currentVersion: '1.0.1', publicKeyPem: PUB, tmpDir: dir, manifestUrl: 'M' });
    assert.equal((await none.check()).none, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
