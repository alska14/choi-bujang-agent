// 최종 앱 진입점. 제공 서버(createOnServer)를 그대로 쓰고 같은 포트에 /pc-status 를 덧붙인다.
// 지원: 기본 실행(연결 없음)과 --demo. SDP·계정 연결 설정 옵션은 이 진입점이 받지 않는다(기존 start-alekov.ps1을 쓴다).
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createOnServer } from './server.mjs';
import { demoEngine, loadEngine } from './engine.mjs';
import { createProjectScanner } from './vulnerabilities/project-scan.mjs';
import { createSampler } from './pc-status/sampler.mjs';
import { createHistory } from './pc-status/history.mjs';
import { createSecurityReader } from './pc-status/security-reader.mjs';
import { attachPcStatus } from './pc-status/routes.mjs';

export function createFinalApp({ engine, scanner, sampler = createSampler(), history = createHistory(), securityReader = createSecurityReader() } = {}) {
  const server = createOnServer({ engine, scanner });
  attachPcStatus(server, { sampler, history, securityReader, engineMode: () => (engine && engine.evidenceMode) || 'disconnected' });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const unknown = args.filter((arg) => arg !== '--demo');
  if (unknown.length > 0) throw Error('UNSUPPORTED_ARGUMENT: 이 진입점은 --demo 만 지원합니다');
  const demo = args.includes('--demo');
  const port = Number(process.env.ON_PORT ?? 5189);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error('INVALID_PORT');

  let approvedPublicPackages = [];
  if (process.env.ON_APPROVED_PUBLIC_PACKAGES) {
    try { approvedPublicPackages = JSON.parse(process.env.ON_APPROVED_PUBLIC_PACKAGES); } catch { throw Error('INVALID_PUBLIC_PACKAGE_LIST'); }
    if (!Array.isArray(approvedPublicPackages)) throw Error('INVALID_PUBLIC_PACKAGE_LIST');
  }
  const engine = demo ? demoEngine() : await loadEngine(process.env.ON_ENGINE_ADAPTER);
  const scanner = createProjectScanner({ projectDirectory: process.env.ON_PROJECT_DIRECTORY, approvedPublicPackages });
  const server = createFinalApp({ engine, scanner });
  server.listen(port, '127.0.0.1', () => {
    console.log(`케셰브 ${demo ? '예제' : '연결 확인'}: http://127.0.0.1:${port}`);
    console.log(`내 PC 상태: http://127.0.0.1:${port}/pc-status`);
  });
}
