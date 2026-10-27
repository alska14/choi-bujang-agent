// 네트워크 구성, 방화벽 설정, Windows 기록(System·Application)의 경고·오류 건수를 읽기만 한다.
// 설정을 바꾸지 않고, 관리자 권한이 필요한 항목은 우회하지 않고 '확인 불가'로 둔다.
// 실행하는 명령은 아래 고정 문자열뿐이며 사용자 입력을 끼워 넣지 않는다.
import os from 'node:os';
import { execFile } from 'node:child_process';

const EVENT_HOURS = 24;
const EVENT_CAP = 5000;
const FIREWALL_PROFILES = new Set(['Domain', 'Private', 'Public']);
const EVENT_LOGS = ['System', 'Application'];

const FIREWALL_SCRIPT = [
  "try { Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction } } | ConvertTo-Json -Compress }",
  "catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }",
].join('\n');

const EVENT_SCRIPT = `$since = (Get-Date).AddHours(-${EVENT_HOURS})
$result = [ordered]@{}
foreach ($log in 'System','Application') {
  $item = [ordered]@{}
  foreach ($pair in @(@('errors',2),@('warnings',3))) {
    try { $item[$pair[0]] = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = $pair[1]; StartTime = $since } -MaxEvents ${EVENT_CAP} -ErrorAction Stop).Count }
    catch { if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { $item[$pair[0]] = 0 } else { $item[$pair[0]] = $_.Exception.GetType().Name } }
  }
  $result[$log] = $item
}
$result | ConvertTo-Json -Compress -Depth 4`;

const measured = (fields, measuredAt) => ({ status: 'measured', measuredAt, ...fields });
const unavailable = (reason, measuredAt, code) => ({ status: 'unavailable', measuredAt, reason, code });

// 고정 스크립트를 PowerShell 로 실행한다. 창을 띄우지 않고 제한 시간 안에 끝나지 않으면 중단한다.
export function runPowerShell(script, { timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 262144, encoding: 'utf8' },
      (error, stdout) => {
        if (error) {
          const code = error.killed || error.signal ? 'TIMEOUT' : error.code === 'ENOENT' ? 'NOT_FOUND' : 'FAILED';
          reject(Object.assign(new Error(code), { code }));
          return;
        }
        resolve(stdout);
      });
  });
}

function parseJson(text) {
  try { return JSON.parse(String(text).trim()); } catch { return undefined; }
}

function failureFor(error, at) {
  const code = error && error.code;
  if (code === 'TIMEOUT') return unavailable('제한 시간 안에 읽지 못했습니다.', at, 'TIMEOUT');
  if (code === 'NOT_FOUND') return unavailable('이 PC에서 PowerShell 을 찾지 못했습니다.', at, 'READ_FAILED');
  return unavailable('읽는 도중 오류가 났습니다.', at, 'READ_FAILED');
}

const permissionDenied = (name) => /^(UnauthorizedAccess|Security|Access)/.test(name);
const safeTypeName = (name) => (typeof name === 'string' && /^[A-Za-z][A-Za-z0-9.]{0,59}$/.test(name) ? name : '알 수 없음');

export function createSecurityReader({ osModule = os, run = runPowerShell, now = () => new Date() } = {}) {
  function readNetwork() {
    const at = now().toISOString();
    let interfaces;
    try { interfaces = osModule.networkInterfaces(); } catch { return unavailable('네트워크 어댑터 정보를 읽지 못했습니다.', at, 'READ_FAILED'); }
    if (!interfaces || typeof interfaces !== 'object') return unavailable('네트워크 어댑터 정보 형식이 올바르지 않습니다.', at, 'READ_FAILED');
    // 주소와 MAC 은 화면에 싣지 않는다. 어댑터 이름과 IPv4 보유 여부만 보인다.
    const adapters = Object.entries(interfaces)
      .map(([name, rows]) => {
        const list = Array.isArray(rows) ? rows : [];
        return { name: String(name).slice(0, 80), internal: list.some((row) => row && row.internal === true), hasIPv4: list.some((row) => row && row.family === 'IPv4'), hasIPv6: list.some((row) => row && row.family === 'IPv6') };
      })
      .filter((adapter) => !adapter.internal);
    return measured({ adapters, connectedCount: adapters.filter((adapter) => adapter.hasIPv4).length, basis: '운영체제가 알려 주는 어댑터 목록(루프백 제외). IP 주소와 MAC 주소는 표시하지 않습니다.' }, at);
  }

  async function readFirewall() {
    const at = now().toISOString();
    let output;
    try { output = await run(FIREWALL_SCRIPT, { timeoutMs: 15000 }); } catch (error) { return failureFor(error, at); }
    const data = parseJson(output);
    if (data && !Array.isArray(data) && typeof data === 'object' && typeof data.error === 'string') {
      const name = safeTypeName(data.error);
      return permissionDenied(name)
        ? unavailable('이 계정 권한으로는 방화벽 설정을 읽을 수 없습니다. 관리자 권한이 필요한 항목이라 읽지 않습니다.', at, 'PERMISSION')
        : unavailable(`방화벽 설정을 읽지 못했습니다(원인: ${name}).`, at, 'READ_FAILED');
    }
    const rows = Array.isArray(data) ? data : data && typeof data === 'object' ? [data] : null;
    if (!rows || rows.length === 0 || rows.some((row) => !row || !FIREWALL_PROFILES.has(row.name) || typeof row.enabled !== 'string')) {
      return unavailable('방화벽 설정 응답 형식을 확인할 수 없습니다.', at, 'READ_FAILED');
    }
    const profiles = rows.map((row) => ({
      name: row.name,
      enabled: row.enabled === 'True' ? 'on' : row.enabled === 'False' ? 'off' : 'unknown',
      rawEnabled: row.enabled.slice(0, 20),
      inbound: typeof row.inbound === 'string' ? row.inbound.slice(0, 20) : '확인 불가',
      outbound: typeof row.outbound === 'string' ? row.outbound.slice(0, 20) : '확인 불가',
    }));
    return measured({ profiles, basis: 'Get-NetFirewallProfile 로 읽기만 했습니다. 방화벽 설정은 바꾸지 않습니다.' }, at);
  }

  async function readEvents() {
    const at = now().toISOString();
    let output;
    try { output = await run(EVENT_SCRIPT, { timeoutMs: 20000 }); } catch (error) { const failed = failureFor(error, at); return { status: 'unavailable', measuredAt: at, hours: EVENT_HOURS, logs: Object.fromEntries(EVENT_LOGS.map((log) => [log, failed])) }; }
    const data = parseJson(output);
    const logs = {};
    for (const log of EVENT_LOGS) {
      const entry = data && typeof data === 'object' ? data[log] : undefined;
      const readCount = (value) => {
        if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return { status: 'measured', value, capped: value >= EVENT_CAP };
        if (typeof value === 'string') {
          const name = safeTypeName(value);
          return permissionDenied(name)
            ? { status: 'unavailable', code: 'PERMISSION', reason: '이 계정 권한으로는 읽을 수 없습니다. 관리자 권한이 필요한 항목이라 읽지 않습니다.' }
            : { status: 'unavailable', code: 'READ_FAILED', reason: `읽지 못했습니다(원인: ${name}).` };
        }
        return { status: 'unavailable', code: 'READ_FAILED', reason: '응답 형식을 확인할 수 없습니다.' };
      };
      logs[log] = entry && typeof entry === 'object'
        ? { errors: readCount(entry.errors), warnings: readCount(entry.warnings) }
        : { errors: readCount(undefined), warnings: readCount(undefined) };
    }
    const anyMeasured = EVENT_LOGS.some((log) => logs[log].errors.status === 'measured' || logs[log].warnings.status === 'measured');
    return { status: anyMeasured ? 'measured' : 'unavailable', measuredAt: at, hours: EVENT_HOURS, cap: EVENT_CAP, logs, basis: 'Windows 기록(System·Application)의 최근 24시간 경고·오류 건수만 셉니다. 기록 내용은 읽어 오지 않습니다.' };
  }

  return Object.freeze({
    async read() {
      const [firewall, events] = await Promise.all([readFirewall(), readEvents()]);
      return { network: readNetwork(), firewall, events };
    },
    readNetwork,
    readFirewall,
    readEvents,
  });
}
