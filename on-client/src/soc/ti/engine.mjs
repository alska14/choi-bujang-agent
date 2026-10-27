// 위협 인텔리전스 엔진. 수집한 IOC·TTP 규칙을 이 PC에서 관측한 값(연결, DNS, 프로세스, 에이전트 명령)과 대조해 사건으로 올린다.
// 읽기 전용이다. 관리자 권한이 필요한 프로세스(명령줄·실행 파일 경로를 볼 수 없는 것)는 관측하지 못하며, 그 범위를 상태로 알린다.
import { createReadStream, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import net from 'node:net';
import { runPowerShell } from '../../pc-status/security-reader.mjs';
import { TTP_RULES, evaluateTtp, coverage } from './ttp-rules.mjs';
import { ATTACK_VERSION, ATTACK_CHECKED_ON, TACTICS, TECHNIQUES, attackRefs } from './attack.mjs';
import { isPrivateOrLocal } from './ioc-store.mjs';

const QUIET_MS = 10 * 60 * 1000;
const MAX_HASH_PER_SCAN = 20;
const MAX_HASH_BYTES = 64 * 1024 * 1024;

const NET_SCRIPT = `try { $names = @{}
$rows = @(Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
  $id = [int]$_.OwningProcess
  if (-not $names.ContainsKey($id)) { $p = Get-Process -Id $id -ErrorAction SilentlyContinue; $names[$id] = if ($p) { [string]$p.ProcessName } else { $null } }
  [ordered]@{ remote = [string]$_.RemoteAddress; port = [int]$_.RemotePort; pid = $id; process = $names[$id] } })
ConvertTo-Json -InputObject $rows -Compress -Depth 3 }
catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }`;

const DNS_SCRIPT = `try { $rows = @(Get-DnsClientCache -ErrorAction Stop | Select-Object -First 1000 | ForEach-Object { [string]$_.Entry })
ConvertTo-Json -InputObject $rows -Compress }
catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }`;

// 실행 중인 AI 코딩 에이전트를 프로세스 이름·명령줄로 알아본다. 무엇을 읽는지는 알 수 없고 "실행 중"만 안다.
export const AGENT_PROCESSES = Object.freeze([
  ['Claude(Code·데스크톱)', /@anthropic-ai[\\/]claude-code|(^|[\\/\s])claude(\.exe)?(\s|$)/i],
  ['Codex CLI', /@openai[\\/]codex|(^|[\\/\s])codex(\.exe)?(\s|$)/i],
  ['Gemini CLI', /@google[\\/]gemini-cli|(^|[\\/\s])gemini(\.exe)?(\s|$)/i],
  ['Cursor', /(^|[\\/\s])cursor(\.exe)?(\s|$)/i],
  ['Windsurf', /(^|[\\/\s])windsurf(\.exe)?(\s|$)/i],
  ['GitHub Copilot', /copilot-language-server|copilot-agent/i],
  ['Aider', /(^|[\\/\s])aider(\.exe)?(\s|$)/i],
  ['Ollama', /(^|[\\/\s])ollama(\.exe)?(\s|$)/i],
]);
export function detectAgentProcesses(rows) {
  const found = new Map();
  for (const row of rows) {
    if (!row) continue;
    const text = `${row.name ?? ''} ${row.cmd ?? ''}`;
    for (const [label, pattern] of AGENT_PROCESSES) if (pattern.test(text)) { found.set(label, (found.get(label) ?? 0) + 1); break; }
  }
  return [...found].map(([name, count]) => ({ name, count }));
}

const PROC_SCRIPT = `try { $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
  [ordered]@{ pid = [int]$_.ProcessId; name = [string]$_.Name; path = if ($_.ExecutablePath) { [string]$_.ExecutablePath } else { $null }; cmd = if ($_.CommandLine) { $_.CommandLine.Substring(0, [Math]::Min(600, $_.CommandLine.Length)) } else { $null } } })
ConvertTo-Json -InputObject $rows -Compress -Depth 3 }
catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }`;

const parse = (text) => { try { return JSON.parse(String(text).trim()); } catch { return undefined; } };
const asArray = (data) => (Array.isArray(data) ? data : data && typeof data === 'object' && !data.error ? [data] : null);

export function hashFile(path) {
  return new Promise((resolve) => {
    let size;
    try { size = statSync(path).size; } catch { resolve(null); return; }
    if (size > MAX_HASH_BYTES) { resolve(null); return; }
    const hash = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', () => resolve(null));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

export function createIntel({ events, iocs, run = runPowerShell, hasher = hashFile, rules = TTP_RULES, now = () => new Date(), selfPid = process.pid } = {}) {
  const sightings = [];
  const hashCache = new Map();
  const scans = { network: null, dns: null, processes: null };
  const feedback = { malicious: 0, benign: 0 };
  let suppressed = 0;

  const pushSighting = (entry) => { sightings.unshift(entry); while (sightings.length > 100) sightings.pop(); };

  // 탐지 하나를 사건으로 올린다. 허용 목록에 있으면 올리지 않는다.
  function raise({ kind, severity, title, detail, evidence, rule, attack = [], key, iocId = null, test = false }) {
    if (key && iocs.isAllowed(key)) { suppressed += 1; return null; }
    const result = events.add({ severity, source: kind, title, detail, evidence, rule, attack, key, test, quietMs: QUIET_MS });
    if (iocId) iocs.recordHit(iocId);
    if (result.created) pushSighting({ at: now().toISOString(), kind, severity, title, eventId: result.event.id, ruleId: rule ? rule.id : null, test });
    return result.event;
  }

  function iocFinding(ioc, observed, where, extra = {}) {
    const attack = attackRefs(ioc.ttps.map((id) => [id, ioc.confidence]));
    return raise({
      kind: 'ioc', severity: ioc.severity, test: ioc.test,
      title: `IOC 일치: ${ioc.type} ${ioc.value}${extra.process ? ` (${extra.process})` : ''}`,
      detail: `${where}에서 알려진 침해지표와 일치했습니다. ${ioc.description ? `${ioc.description} ` : ''}출처 ${ioc.source}, 신뢰도 ${ioc.confidence}, TLP:${ioc.tlp.toUpperCase()}.`,
      evidence: { ioc: { id: ioc.id, type: ioc.type, value: ioc.value, source: ioc.source }, observed, where, ...extra },
      rule: { id: 'IOC-MATCH', text: '관측값이 수집한 침해지표(IOC)와 일치함' }, attack, key: `ioc:${ioc.id}:${extra.process ?? ''}:${observed}`, iocId: ioc.id,
    });
  }

  function ttpFindings(text, where, extra = {}) {
    const out = [];
    for (const hit of evaluateTtp(text, { rules })) {
      out.push(raise({
        kind: 'ttp', severity: hit.rule.severity, title: `TTP 탐지: ${hit.rule.name}`,
        detail: `${where}에서 알려진 공격 절차 패턴이 보였습니다. ${hit.rule.description} (신뢰도 ${hit.rule.confidence}, 오탐 가능성이 있으면 "오탐"으로 처리하세요)`,
        evidence: { snippet: hit.snippet, where, ...extra }, rule: { id: hit.rule.id, text: hit.rule.name }, attack: hit.attack,
        key: `ttp:${hit.rule.id}:${extra.process ?? extra.agent ?? ''}:${hit.snippet.slice(0, 60)}`,
      }));
    }
    return out.filter(Boolean);
  }

  // 문자열 안의 IP·도메인·SHA-256 을 IOC 와 대조한다(에이전트 명령 등).
  function textObservables(text) {
    const value = String(text ?? '').slice(0, 2000);
    const found = [];
    for (const m of value.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) found.push({ type: 'ip', value: m[0] });
    for (const m of value.matchAll(/\b[a-f0-9]{64}\b/gi)) found.push({ type: 'sha256', value: m[0] });
    for (const m of value.matchAll(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi)) found.push({ type: 'domain', value: m[0] });
    found.push({ type: 'text', value });
    return found;
  }

  const api = {
    // 에이전트 감사 기록 한 줄을 검사한다. 반환값은 만들어진 사건 목록.
    inspectAgentRecord(record) {
      const created = [];
      const where = `LLM 에이전트(${record.agent}) ${record.tool} 호출`;
      const parts = [record.command, ...(record.targets || [])].filter((v) => typeof v === 'string');
      for (const part of parts) {
        for (const observable of textObservables(part)) for (const ioc of iocs.match(observable)) created.push(iocFinding(ioc, observable.value.slice(0, 120), where, { agent: record.agent, tool: record.tool }));
      }
      if (typeof record.command === 'string') created.push(...ttpFindings(record.command, where, { agent: record.agent, tool: record.tool }));
      return created.filter(Boolean);
    },

    async scanNetwork() {
      const at = now().toISOString();
      let rows = null, dns = null, netError = null, dnsError = null;
      try { rows = asArray(parse(await run(NET_SCRIPT, { timeoutMs: 15000 }))); } catch (error) { netError = error.code || 'FAILED'; }
      try { dns = asArray(parse(await run(DNS_SCRIPT, { timeoutMs: 15000 }))); } catch (error) { dnsError = error.code || 'FAILED'; }
      let matches = 0;
      if (rows) {
        for (const row of rows) {
          if (!row || typeof row.remote !== 'string') continue;
          for (const ioc of iocs.match({ type: 'ip', value: row.remote })) { if (iocFinding(ioc, row.remote, '현재 TCP 연결', { process: row.process ?? null, pid: row.pid, port: row.port })) matches += 1; }
        }
      }
      if (dns) for (const entry of dns) if (typeof entry === 'string') for (const ioc of iocs.match({ type: 'domain', value: entry.replace(/\.$/, '') })) { if (iocFinding(ioc, entry, 'DNS 캐시')) matches += 1; }
      scans.network = { at, status: rows ? 'measured' : 'unavailable', reason: rows ? null : `읽지 못했습니다(${netError ?? 'READ_FAILED'})`, connections: rows ? rows.length : null, external: rows ? rows.filter((r) => r && typeof r.remote === 'string' && !isPrivateOrLocal(r.remote) && r.remote !== '::1').length : null, matches };
      scans.dns = { at, status: dns ? 'measured' : 'unavailable', reason: dns ? null : `읽지 못했습니다(${dnsError ?? 'READ_FAILED'})`, entries: dns ? dns.length : null };
      return scans;
    },

    async scanProcesses() {
      const at = now().toISOString();
      let rows = null, error = null;
      try { rows = asArray(parse(await run(PROC_SCRIPT, { timeoutMs: 20000 }))); } catch (e) { error = e.code || 'FAILED'; }
      if (!rows) { scans.processes = { at, status: 'unavailable', reason: `읽지 못했습니다(${error ?? 'READ_FAILED'})`, total: null }; return scans; }
      let withCmd = 0, withPath = 0, matches = 0, hashed = 0;
      const pending = [];
      for (const row of rows) {
        if (!row || row.pid === selfPid) continue;
        if (row.cmd) withCmd += 1;
        if (row.path) withPath += 1;
        for (const ioc of iocs.match({ type: 'process', value: String(row.name ?? '') })) { if (iocFinding(ioc, String(row.name), '실행 중인 프로세스', { process: row.name, pid: row.pid })) matches += 1; }
        if (row.cmd) matches += ttpFindings(row.cmd, `실행 중인 프로세스 ${row.name}`, { process: row.name, pid: row.pid }).length;
        if (row.path && !hashCache.has(row.path)) pending.push(row);
      }
      // 실행 파일 해시는 한 번에 일부만 계산하고(최대 20개), 이미 계산한 경로는 다시 계산하지 않는다.
      for (const row of pending.slice(0, MAX_HASH_PER_SCAN)) {
        const digest = await hasher(row.path);
        hashCache.set(row.path, digest);
        hashed += 1;
        if (digest) for (const ioc of iocs.match({ type: 'sha256', value: digest })) { if (iocFinding(ioc, digest, '실행 중인 프로세스의 실행 파일', { process: row.name, pid: row.pid })) matches += 1; }
      }
      const known = [...hashCache.values()].filter(Boolean).length;
      scans.processes = { at, status: 'measured', reason: null, agents: detectAgentProcesses(rows), total: rows.length, withCommandLine: withCmd, withPath, hashedTotal: known, hashPending: Math.max(0, rows.filter((r) => r && r.path).length - hashCache.size), hashedThisScan: hashed, matches };
      return scans;
    },

    // 탐지 시험: 이 앱 서버에 loopback 연결을 하나 열고, 그 주소를 시험용 IOC 로 등록해 탐지가 끝까지 되는지 확인한다.
    async testDetection({ port }) {
      const added = iocs.add({ type: 'ipv4', value: '127.0.0.1', severity: 'high', source: 'self-test', description: '탐지 시험용 지표(실제 위협 아님)', test: true, shareable: false, validUntil: new Date(now().getTime() + 120000).toISOString(), ttps: ['T1571'] });
      if (added.error) return { ok: false, reason: added.error };
      const socket = net.connect({ host: '127.0.0.1', port });
      await new Promise((resolve) => { socket.once('connect', resolve); socket.once('error', resolve); setTimeout(resolve, 1500); });
      const before = scans.network ? scans.network.matches : 0;
      await api.scanNetwork();
      socket.destroy();
      iocs.remove(added.ioc.id);
      const hit = sightings.find((s) => s.test && s.kind === 'ioc');
      return { ok: true, detected: Boolean(hit), eventId: hit ? hit.eventId : null, connections: scans.network ? scans.network.connections : null, previousMatches: before };
    },

    // 반영: 사용자의 판정으로 저장소를 고친다.
    markMalicious(eventId) {
      const event = events.get(eventId);
      if (!event) return { error: '사건을 찾을 수 없습니다.' };
      const evidence = event.evidence || {};
      const candidates = [];
      const observed = evidence.observed;
      if (evidence.where === '현재 TCP 연결' && typeof observed === 'string') candidates.push({ type: 'ipv4', value: observed });
      if (evidence.where === 'DNS 캐시' && typeof observed === 'string') candidates.push({ type: 'domain', value: observed.replace(/\.$/, '') });
      if (typeof observed === 'string' && /^[a-f0-9]{64}$/i.test(observed)) candidates.push({ type: 'sha256', value: observed });
      if (evidence.ioc && evidence.ioc.type && evidence.ioc.value && evidence.ioc.source !== 'self-test') candidates.push({ type: evidence.ioc.type, value: evidence.ioc.value });
      const ttps = (event.attack || []).map((t) => t.id);
      const added = [];
      for (const candidate of candidates) {
        const result = iocs.add({ ...candidate, source: 'local-incident', severity: 'high', confidence: 80, tlp: 'amber', description: `사건 #${event.id}를 악성으로 확정함: ${event.title}`.slice(0, 200), ttps }, { severity: 'high' });
        if (result.ioc && !result.duplicate) added.push({ type: result.ioc.type, value: result.ioc.value });
      }
      events.setVerdict(eventId, 'malicious');
      events.ack(eventId);
      feedback.malicious += 1;
      return { ok: true, added, note: added.length === 0 ? '이 사건에서 지표로 저장할 수 있는 관측값(IP, 도메인, 해시)이 없었습니다. 판정만 기록했습니다.' : null };
    },

    markBenign(eventId) {
      const event = events.get(eventId);
      if (!event) return { error: '사건을 찾을 수 없습니다.' };
      if (event.key) iocs.allowKey(event.key, `사건 #${event.id} 오탐 처리`);
      events.setVerdict(eventId, 'benign');
      events.ack(eventId);
      feedback.benign += 1;
      return { ok: true, allowed: Boolean(event.key) };
    },

    // 관제 화면의 영역 요약용 가벼운 상태(ATT&CK 목록·IOC 목록 제외)
    summary() { const stats = iocs.stats(); return { scans, stats: { active: stats.active, total: stats.total }, ruleCount: rules.length, feedback: { ...feedback, suppressed } }; },
    snapshot() {
      const cover = coverage(rules);
      return {
        attack: { version: ATTACK_VERSION, checkedOn: ATTACK_CHECKED_ON, tactics: TACTICS, techniques: Object.fromEntries(Object.entries(TECHNIQUES).map(([id, t]) => [id, { name: t.name, tactics: t.tactics, url: t.url }])) },
        stats: iocs.stats(), iocs: iocs.list().map((x) => ({ id: x.id, type: x.type, value: x.value, source: x.source, severity: x.severity, tlp: x.tlp, confidence: x.confidence, hits: x.hits, lastHit: x.lastHit, validUntil: x.validUntil, active: x.active, shareable: x.shareable, test: x.test, ttps: x.ttps, description: x.description })).slice(0, 500),
        rules: rules.map((r) => ({ id: r.id, name: r.name, attack: r.attack, severity: r.severity, confidence: r.confidence })), coverage: cover,
        sightings: sightings.slice(0, 30), scans, feedback: { ...feedback, suppressed, allow: iocs.allowList().length },
        limits: ['관리자 권한이 필요한 프로세스(명령줄·실행 경로를 볼 수 없는 것)는 관측하지 못합니다.', '프로세스·연결은 주기적으로 읽으므로 그 사이에 끝난 짧은 프로세스나 연결은 놓칠 수 있습니다.', 'TTP 규칙은 알려진 패턴 일치이며 오탐 가능성이 있습니다. 규칙과 기법의 연결은 가능성이지 확정이 아닙니다.'],
      };
    },
    textObservables,
  };
  return Object.freeze(api);
}
