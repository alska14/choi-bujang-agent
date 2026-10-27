// 읽기 전용 보안 점검(Defender, 수신 대기 포트)과, 점검 결과를 사건으로 바꾸는 규칙. 설정은 바꾸지 않는다.
import { runPowerShell } from '../pc-status/security-reader.mjs';

export const RULES = Object.freeze({
  'FW-OFF-ALL': 'Windows 방화벽의 모든 프로필이 꺼져 있음',
  'FW-OFF': 'Windows 방화벽의 일부 프로필이 꺼져 있음',
  'DEF-RT-OFF': 'Microsoft Defender 실시간 보호가 꺼져 있음',
  'DEF-AV-OFF': 'Microsoft Defender 바이러스 백신이 꺼져 있음',
  'DEF-SIG-OLD': 'Microsoft Defender 서명이 7일 넘게 갱신되지 않음',
  'PORT-NEW-EXPOSED': '기준선에 없던 수신 대기 포트가 외부(모든 주소)에서 접근 가능하게 열림',
  'LOG-SURGE': 'Windows 기록의 오류 건수가 기준선보다 10건 이상 늘어남',
});

const DEFENDER_SCRIPT = `try { $m = Get-MpComputerStatus -ErrorAction Stop
[ordered]@{ realTime = [string]$m.RealTimeProtectionEnabled; antivirus = [string]$m.AntivirusEnabled; signatureUpdated = if ($m.AntivirusSignatureLastUpdated) { $m.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { $null } } | ConvertTo-Json -Compress }
catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }`;

const PORTS_SCRIPT = `try { $rows = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [ordered]@{ port = [int]$_.LocalPort; address = [string]$_.LocalAddress; process = if ($p) { [string]$p.ProcessName } else { $null } } })
ConvertTo-Json -InputObject $rows -Compress -Depth 3 }
catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }`;

const at = (now) => now().toISOString();
const unavailable = (reason, measuredAt, code) => ({ status: 'unavailable', measuredAt, reason, code });
const parse = (text) => { try { return JSON.parse(String(text).trim()); } catch { return undefined; } };
const denied = (name) => /^(UnauthorizedAccess|Security|Access)/.test(String(name));
const fail = (error, measuredAt) => (error && error.code === 'TIMEOUT' ? unavailable('제한 시간 안에 읽지 못했습니다.', measuredAt, 'TIMEOUT') : unavailable('읽는 도중 오류가 났습니다.', measuredAt, 'READ_FAILED'));
const EXPOSED = new Set(['0.0.0.0', '::']);
const BOOL = { True: true, False: false };

export function createChecks({ run = runPowerShell, now = () => new Date() } = {}) {
  return Object.freeze({
    async readDefender() {
      const measuredAt = at(now);
      let output;
      try { output = await run(DEFENDER_SCRIPT, { timeoutMs: 15000 }); } catch (error) { return fail(error, measuredAt); }
      const data = parse(output);
      if (!data || typeof data !== 'object') return unavailable('응답 형식을 확인할 수 없습니다.', measuredAt, 'READ_FAILED');
      if (typeof data.error === 'string') return denied(data.error) ? unavailable('이 계정 권한으로는 읽을 수 없습니다. 관리자 권한이 필요한 항목이라 읽지 않습니다.', measuredAt, 'PERMISSION') : unavailable('읽지 못했습니다.', measuredAt, 'READ_FAILED');
      const signature = typeof data.signatureUpdated === 'string' ? Date.parse(data.signatureUpdated) : NaN;
      return { status: 'measured', measuredAt, realTime: data.realTime in BOOL ? BOOL[data.realTime] : null, antivirus: data.antivirus in BOOL ? BOOL[data.antivirus] : null, signatureAgeDays: Number.isNaN(signature) ? null : Math.max(0, Math.floor((now().getTime() - signature) / 86400000)) };
    },
    async readPorts() {
      const measuredAt = at(now);
      let output;
      try { output = await run(PORTS_SCRIPT, { timeoutMs: 15000 }); } catch (error) { return fail(error, measuredAt); }
      const data = parse(output);
      if (data && !Array.isArray(data) && typeof data === 'object' && typeof data.error === 'string') return denied(data.error) ? unavailable('이 계정 권한으로는 읽을 수 없습니다.', measuredAt, 'PERMISSION') : unavailable('읽지 못했습니다.', measuredAt, 'READ_FAILED');
      const rows = Array.isArray(data) ? data : data && typeof data === 'object' ? [data] : null;
      if (!rows || rows.some((row) => !row || !Number.isInteger(row.port) || typeof row.address !== 'string')) return unavailable('응답 형식을 확인할 수 없습니다.', measuredAt, 'READ_FAILED');
      const ports = rows.map((row) => ({ port: row.port, address: row.address.slice(0, 45), process: typeof row.process === 'string' ? row.process.slice(0, 60) : null, exposed: EXPOSED.has(row.address) }));
      return { status: 'measured', measuredAt, ports, exposedCount: new Set(ports.filter((p) => p.exposed).map((p) => p.port)).size, total: ports.length };
    },
  });
}

// ---- 점검 결과 → 사건 규칙 (순수 함수) ----
export function firewallFindings(cell) {
  if (!cell || cell.status !== 'measured') return [];
  const off = cell.profiles.filter((profile) => profile.enabled === 'off');
  if (off.length === 0) return [];
  const all = off.length === cell.profiles.length;
  return [{ severity: all ? 'critical' : 'high', ruleId: all ? 'FW-OFF-ALL' : 'FW-OFF', title: all ? 'Windows 방화벽이 모두 꺼져 있습니다' : `Windows 방화벽 일부가 꺼져 있습니다: ${off.map((p) => p.name).join(', ')}`, detail: '방화벽 설정은 바꾸지 않았습니다. Windows 보안 앱에서 직접 확인하세요.', evidence: { off: off.map((p) => p.name) } }];
}

export function defenderFindings(cell) {
  if (!cell || cell.status !== 'measured') return [];
  const out = [];
  if (cell.realTime === false) out.push({ severity: 'critical', ruleId: 'DEF-RT-OFF', title: 'Microsoft Defender 실시간 보호가 꺼져 있습니다', detail: '설정은 바꾸지 않았습니다. Windows 보안 앱에서 직접 확인하세요.', evidence: { realTime: false } });
  if (cell.antivirus === false) out.push({ severity: 'critical', ruleId: 'DEF-AV-OFF', title: 'Microsoft Defender 바이러스 백신이 꺼져 있습니다', detail: '설정은 바꾸지 않았습니다.', evidence: { antivirus: false } });
  if (typeof cell.signatureAgeDays === 'number' && cell.signatureAgeDays > 7) out.push({ severity: 'medium', ruleId: 'DEF-SIG-OLD', title: `Defender 서명이 ${cell.signatureAgeDays}일 동안 갱신되지 않았습니다`, detail: 'Windows 업데이트에서 서명 갱신을 확인하세요.', evidence: { signatureAgeDays: cell.signatureAgeDays } });
  return out;
}

export const portKey = (row) => `${row.port}/${row.process ?? '?'}`;
export function newExposedPorts(baseline, current) {
  if (!baseline || !current || current.status !== 'measured') return [];
  const known = new Set(baseline.map(portKey));
  const seen = new Set();
  const found = [];
  for (const row of current.ports) {
    if (!row.exposed) continue;
    const key = portKey(row);
    if (known.has(key) || seen.has(key)) continue;
    seen.add(key);
    found.push({ severity: 'high', ruleId: 'PORT-NEW-EXPOSED', title: `새로 열린 외부 접근 가능 포트: ${row.port} (${row.process ?? '프로세스 확인 불가'})`, detail: '기준선(시작 시점)에 없던 수신 대기 포트입니다. 의도한 프로그램인지 확인하세요.', evidence: { port: row.port, address: row.address, process: row.process } });
  }
  return found;
}

export function eventLogFindings(baselineErrors, events) {
  if (!events || events.status !== 'measured' || baselineErrors === null) return [];
  const total = ['System', 'Application'].reduce((sum, log) => sum + (events.logs[log].errors.status === 'measured' ? events.logs[log].errors.value : 0), 0);
  if (total - baselineErrors < 10) return [];
  return [{ severity: 'medium', ruleId: 'LOG-SURGE', title: `Windows 기록의 오류가 ${total - baselineErrors}건 늘었습니다`, detail: '기준선(시작 시점) 대비 증가입니다. 건수일 뿐 침해 탐지 결과가 아닙니다.', evidence: { baselineErrors, currentErrors: total } }];
}

export const countErrors = (events) => (events && events.status === 'measured'
  ? ['System', 'Application'].reduce((sum, log) => sum + (events.logs[log].errors.status === 'measured' ? events.logs[log].errors.value : 0), 0) : null);
