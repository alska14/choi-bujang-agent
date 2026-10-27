// 최종 앱 진입점. 제공 서버(createOnServer)를 그대로 쓰고 같은 포트에 보안 관제 화면(/pc-status, /soc)을 덧붙인다.
// 지원: 기본 실행(연결 없음)과 --demo. SDP·계정 연결 설정 옵션은 이 진입점이 받지 않는다(기존 start-alekov.ps1을 쓴다).
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createOnServer } from './server.mjs';
import { demoEngine, loadEngine } from './engine.mjs';
import { createProjectScanner } from './vulnerabilities/project-scan.mjs';
import { createSampler } from './pc-status/sampler.mjs';
import { createHistory } from './pc-status/history.mjs';
import { createSecurityReader } from './pc-status/security-reader.mjs';
import { attachPcStatus } from './pc-status/routes.mjs';
import { createAnomalyDetector } from './soc/anomaly.mjs';
import { createEventStore } from './soc/events.mjs';
import { createChecks } from './soc/checks.mjs';
import { createHostChecks } from './soc/host-checks.mjs';
import { createMonitor } from './soc/monitor.mjs';
import { createNativeAlerter } from './soc/alerts.mjs';
import { createAgentAudit } from './soc/agent-audit.mjs';
import { createFileWatcher, defaultWatchTargets } from './soc/file-watch.mjs';
import { createIocStore } from './soc/ti/ioc-store.mjs';
import { createIntel } from './soc/ti/engine.mjs';
import { createEventLog } from './soc/event-log.mjs';
import { createInventory } from './soc/inventory.mjs';
import { createKisaAudit } from './soc/kisa-audit.mjs';

const list = (value) => String(value ?? '').split(';').map((item) => item.trim()).filter(Boolean);

export function createFinalApp({ engine, scanner, sampler = createSampler(), history = createHistory(), securityReader = createSecurityReader(), soc = true, env = process.env } = {}) {
  const server = createOnServer({ engine, scanner });
  let socParts = null;
  let tiParts = null;
  let audit = null;
  if (soc) {
    const dataDir = join(env.LOCALAPPDATA || env.TEMP || '.', 'djokovic-soc');
    // 쿨다운은 60초 점검 주기보다 길어야 한다. 짧으면 계속 켜져 있는 설정(예: 자동 로그인)이 점검 때마다 새 사건으로 쌓인다.
    const store = createEventStore({ max: 2000, cooldownMs: 180000 });
    // 지난 사건을 파일에서 되살린다(ON_SOC_HISTORY=0 이면 메모리에만 둔다).
    const eventLog = env.ON_SOC_HISTORY === '0' ? null : createEventLog({ file: env.ON_SOC_HISTORY_FILE || join(dataDir, 'events.json'), store });
    eventLog?.load();
    eventLog?.start();
    const alerter = createNativeAlerter({ enabled: env.ON_SOC_NATIVE_ALERT !== '0' });
    const auditFile = env.ON_SOC_AUDIT_FILE || join(dataDir, 'agent-audit.jsonl');
    const iocFile = env.ON_SOC_IOC_FILE || join(dataDir, 'ioc-store.json');
    const iocs = createIocStore({ file: iocFile });
    iocs.load();
    const intel = createIntel({ events: store, iocs });
    tiParts = { intel, iocs };
    const agentAudit = createAgentAudit({ file: auditFile, store, allowedRoots: list(env.ON_SOC_ALLOWED_ROOTS), intel, replayQuiet: Boolean(eventLog) });
    const inventory = env.ON_SOC_INVENTORY === '0' ? null : createInventory({ store, file: join(dataDir, 'inventory-baseline.json') });
    const fileWatcher = createFileWatcher({ targets: defaultWatchTargets({ extra: list(env.ON_SOC_WATCH_DIRS) }), store });
    const monitor = createMonitor({ sampler, store, anomaly: createAnomalyDetector(), securityReader, checks: createChecks(), agentAudit, fileWatcher, alerter, intel, hostChecks: createHostChecks(), inventory, eventLog });
    socParts = { store, monitor };
    // PC 보안 점검기: 조치 전 값(되돌리기용)만 파일에 남긴다
    audit = createKisaAudit({ logFile: join(dataDir, 'remediation-log.json') });
    server.once('listening', () => monitor.start());
    server.once('close', () => monitor.stop());
  }
  attachPcStatus(server, { sampler, history, securityReader, soc: socParts, ti: tiParts, audit, engineMode: () => (engine && engine.evidenceMode) || 'disconnected' });
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
    console.log(`보안 관제: http://127.0.0.1:${port}/pc-status`);
  });
}
