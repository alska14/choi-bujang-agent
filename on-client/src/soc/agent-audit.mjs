// LLM 에이전트(예: Claude Code)가 도구로 파일·명령에 접근한 기록을 읽어 규칙으로 판정한다.
// 기록은 에이전트의 훅이 남긴 JSONL 파일에서만 얻는다. Windows는 일반 권한 앱에게 다른 프로그램의 파일 읽기를 알려 주지 않으므로,
// 훅이 없으면 에이전트의 파일 접근은 관제할 수 없다. 이 모듈은 그 사실을 '수집 안 함' 상태로 그대로 알린다.
import { statSync, openSync, readSync, closeSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { attackForSensitivePath, attackRefs, RULE_TO_ATTACK } from './ti/attack.mjs';

export const RULES = Object.freeze({
  'AGENT-SENSITIVE': 'LLM 에이전트가 민감한 경로나 파일(키, 인증 정보, 브라우저 저장소 등)에 접근함',
  'AGENT-OUTSIDE': 'LLM 에이전트가 작업 폴더(cwd)와 허용 폴더 밖의 경로에 접근함',
  'AGENT-BURST': 'LLM 에이전트가 1분 안에 파일 도구를 100회 이상 호출함',
});

const SENSITIVE_PATH = [
  /\/\.ssh(\/|$)/, /\/\.aws(\/|$)/, /\/\.gnupg(\/|$)/, /\/\.kube(\/|$)/, /\/\.config\/gcloud(\/|$)/, /\/\.azure(\/|$)/,
  /\/appdata\/local\/google\/chrome\/user data(\/|$)/, /\/appdata\/local\/microsoft\/edge\/user data(\/|$)/, /\/appdata\/roaming\/mozilla\/firefox\/profiles(\/|$)/,
  /\/windows\/system32\/config(\/|$)/, /\/ntuser\.dat/, /\/\.env(\.[^/]*)?$/, /\/id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/,
  /\.(pem|pfx|p12|kdbx|keystore|jks)$/, /\/(credentials|credentials\.json|secrets?(\.[a-z]+)?|\.netrc|\.npmrc|\.pypirc|login data|cookies|wallet\.dat)$/,
];
const READ_COMMAND = /\b(cat|type|get-content|gc|less|more|head|tail|dir|ls|get-childitem|gci|find|tree|findstr|grep|rg|select-string|copy|cp|xcopy|robocopy|compress-archive|zip|tar|certutil|reg)\b/i;
const FILE_TOOLS = new Set(['Read', 'Glob', 'Grep', 'LS', 'NotebookRead']);
const WRITE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'apply_patch']);

export const normalizePath = (value) => String(value ?? '').replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase();
const isAbsolute = (value) => /^[a-z]:\//.test(value) || value.startsWith('//');
const under = (path, root) => path === root || path.startsWith(root.endsWith('/') ? root : `${root}/`);

export const isSensitivePath = (value) => { const path = normalizePath(value); return SENSITIVE_PATH.some((pattern) => pattern.test(path)); };

function commandPaths(command) {
  const found = [];
  for (const match of String(command ?? '').matchAll(/"([^"]+)"|'([^']+)'|([A-Za-z]:[\\/][^\s"']+|~[\\/][^\s"']+|(?:\.{0,2}[\\/])[^\s"']+)/g)) {
    const token = match[1] ?? match[2] ?? match[3];
    if (token && /[\\/]/.test(token)) found.push(token);
  }
  return found.slice(0, 12);
}

// 한 기록을 판정한다. record: { at, agent, session, tool, cwd, targets[], command? }
export function classifyRecord(record, { allowedRoots = [] } = {}) {
  const findings = [];
  const cwd = normalizePath(record.cwd);
  const roots = [cwd, ...allowedRoots.map(normalizePath)].filter(Boolean);
  const targets = Array.isArray(record.targets) ? record.targets.slice(0, 8) : [];
  const isShell = record.tool === 'Bash' || record.tool === 'PowerShell';
  const readLike = FILE_TOOLS.has(record.tool) || (isShell && READ_COMMAND.test(String(record.command ?? '')));
  const candidates = [...targets, ...(isShell ? commandPaths(record.command) : [])];

  const sensitive = candidates.find((path) => isSensitivePath(path)) ?? (isShell && isSensitivePath(String(record.command ?? '')) ? record.command : null);
  if (sensitive) findings.push({ ruleId: 'AGENT-SENSITIVE', severity: 'critical', path: String(sensitive).slice(0, 300) });
  else {
    const outside = candidates.map((path) => ({ raw: path, norm: normalizePath(path) }))
      .find(({ norm }) => isAbsolute(norm) && roots.length > 0 && !roots.some((root) => under(norm, root)));
    if (outside) findings.push({ ruleId: 'AGENT-OUTSIDE', severity: 'medium', path: String(outside.raw).slice(0, 300) });
  }
  return { findings, readLike, write: WRITE_TOOLS.has(record.tool) };
}

function validRecord(value) {
  return value && typeof value === 'object' && typeof value.at === 'string' && !Number.isNaN(Date.parse(value.at))
    && typeof value.tool === 'string' && value.tool.length <= 40 && typeof value.agent === 'string' && value.agent.length <= 40;
}

// replayQuiet: 서버를 다시 켰을 때 이미 읽었던 기록으로 사건을 또 만들지 않도록, 처음 읽는 끝부분(최대 256KB)은 화면 목록에만 넣고 판정하지 않는다.
export function createAgentAudit({ file, store, allowedRoots = [], now = () => Date.now(), burstLimit = 100, windowMs = 300000, intel = null, replayQuiet = false } = {}) {
  let position = 0;
  let everRead = false;
  let lastRecordAt = null;
  const recent = [];
  const reads = [];
  const lastByAgent = new Map(); // 에이전트별 마지막 기록 시각(어느 에이전트의 훅이 살아 있는지 보이기 위함)

  const trim = () => { const cutoff = now() - windowMs; while (recent.length && recent[0].t < cutoff) recent.shift(); while (reads.length && reads[0] < now() - 60000) reads.shift(); };

  function handle(record, quiet = false) {
    const t = Date.parse(record.at);
    lastRecordAt = record.at;
    lastByAgent.set(record.agent, record.at);
    const classified = classifyRecord(record, { allowedRoots });
    const { readLike, write } = classified;
    const findings = quiet ? [] : classified.findings;
    const line = { t, at: record.at, agent: record.agent, tool: record.tool, targets: (record.targets || []).slice(0, 3), command: typeof record.command === 'string' ? record.command.slice(0, 160) : undefined, readLike, write, severity: findings[0] ? findings[0].severity : 'info', rule: findings[0] ? findings[0].ruleId : null };
    recent.push(line);
    if (quiet) return;
    if (readLike) reads.push(now());
    for (const finding of findings) {
      // 작업 폴더 밖 접근은 같은 상위 폴더(드라이브부터 4단계)끼리 한 사건으로 묶어 횟수(×N)만 늘린다. 민감 경로는 파일마다 따로 알린다.
      const scope = finding.ruleId === 'AGENT-OUTSIDE' ? normalizePath(finding.path).split('/').slice(0, 5).join('/') : normalizePath(finding.path);
      store.add({
        severity: finding.severity, source: 'agent',
        title: finding.ruleId === 'AGENT-OUTSIDE' ? `${record.agent}: 작업 폴더 밖 접근 (${scope})` : `${record.agent}: ${record.tool} → ${finding.path}`,
        detail: finding.ruleId === 'AGENT-SENSITIVE' ? '민감한 경로나 파일에 접근하는 도구 호출이 기록됐습니다.' : `작업 폴더와 허용 폴더 밖의 경로에 접근하는 도구 호출이 기록됐습니다. 마지막: ${record.tool} → ${finding.path}`,
        evidence: { agent: record.agent, tool: record.tool, path: finding.path, cwd: record.cwd, session: record.session }, rule: { id: finding.ruleId, text: RULES[finding.ruleId] },
        key: `${finding.ruleId}:${scope}`,
        attack: finding.ruleId === 'AGENT-SENSITIVE' ? attackRefs(attackForSensitivePath(finding.path)) : [],
      });
    }
    if (intel) { try { intel.inspectAgentRecord(record); } catch { /* 위협 인텔 검사 실패가 감사 수집을 멈추지 않게 한다 */ } }
    if (reads.length >= burstLimit) {
      store.add({ severity: 'high', source: 'agent', title: `${record.agent}: 1분 안에 파일 도구 ${reads.length}회 호출`, detail: '짧은 시간에 많은 파일 접근이 기록됐습니다. 의도한 작업인지 확인하세요.', evidence: { count: reads.length, windowSeconds: 60 }, rule: { id: 'AGENT-BURST', text: RULES['AGENT-BURST'] }, key: 'AGENT-BURST', attack: attackRefs(RULE_TO_ATTACK['AGENT-BURST']) });
    }
  }

  function poll() {
    if (!file || !existsSync(file)) return;
    let size;
    try { size = statSync(file).size; } catch { return; }
    if (size < position) position = 0;
    const quiet = replayQuiet && !everRead;
    let skipFirst = false;
    if (quiet && size - position > 262144) { position = size - 262144; skipFirst = true; }
    if (size === position) { trim(); return; }
    const length = Math.min(size - position, 262144);
    const buffer = Buffer.alloc(length);
    let fd;
    try { fd = openSync(file, 'r'); readSync(fd, buffer, 0, length, position); } catch { return; } finally { if (fd !== undefined) closeSync(fd); }
    let start = 0;
    if (skipFirst) { const nl = buffer.indexOf(10); if (nl < 0) return; start = nl + 1; position += start; } // 중간부터 읽었으니 잘린 첫 줄은 버린다
    const text = buffer.subarray(start).toString('utf8');
    const lastNewline = text.lastIndexOf('\n');
    if (lastNewline < 0) return;
    position += Buffer.byteLength(text.slice(0, lastNewline + 1), 'utf8');
    everRead = true;
    for (const raw of text.slice(0, lastNewline).split('\n')) {
      if (!raw.trim()) continue;
      let record;
      try { record = JSON.parse(raw); } catch { continue; }
      if (validRecord(record)) handle(record, quiet);
    }
    trim();
  }

  return Object.freeze({
    poll,
    // 수집 상태를 있는 그대로 알린다. 기록이 없다고 해서 에이전트가 파일에 접근하지 않았다는 뜻이 아니다.
    status() {
      trim();
      const fileExists = Boolean(file) && existsSync(file);
      const age = lastRecordAt ? now() - Date.parse(lastRecordAt) : null;
      const state = !fileExists ? 'not_configured' : !everRead ? 'no_data' : age !== null && age <= 600000 ? 'active' : 'stale';
      const inWindow = recent.filter((line) => line.t >= now() - 300000);
      return {
        state, file: file ? join(file) : null, lastRecordAt, windowMinutes: 5,
        counts: { calls: inWindow.length, reads: inWindow.filter((l) => l.readLike).length, writes: inWindow.filter((l) => l.write).length, outside: inWindow.filter((l) => l.rule === 'AGENT-OUTSIDE').length, sensitive: inWindow.filter((l) => l.rule === 'AGENT-SENSITIVE').length },
        latest: recent.slice(-8).reverse().map(({ t, ...rest }) => rest),
        agents: [...lastByAgent].map(([agent, at]) => ({ agent, lastAt: at })),
      };
    },
  });
}
