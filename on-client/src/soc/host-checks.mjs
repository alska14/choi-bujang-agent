// 네트워크 보안(방화벽 규칙·IPS·VPN·NAC)과 계정·접근 관리 상태를 읽기만 해서 규칙으로 판정한다. 설정은 바꾸지 않는다.
// 정직한 범위: IPS와 NAC는 원래 네트워크 장비·서버 쪽 기능이다. 이 모듈은 이 PC가 보고하는 상태(Defender 네트워크 검사,
// VPN 어댑터, 802.1X 서비스·네트워크 위치, 주변 장치 발견)만 읽으며 차단·격리는 하지 않는다.
import { runPowerShell } from '../pc-status/security-reader.mjs';

export const RULES = Object.freeze({
  'NET-FWRULE-NEW': '시작 시점에 없던 인바운드 허용 방화벽 규칙이 새로 켜짐',
  'NET-IPS-NIS-OFF': 'Microsoft Defender 네트워크 검사 시스템(NIS)이 꺼져 있음',
  'NET-IPS-DETECTION': 'Microsoft Defender 가 새 위협을 탐지함',
  'NET-VPN-DOWN': '연결돼 있던 VPN 어댑터·프로필이 끊어짐',
  'NET-NAC-NEWDEVICE': '시작 시점에 없던 장치가 같은 네트워크에서 새로 발견됨',
  'IAM-NEW-ACCOUNT': '시작 시점에 없던 로컬 계정이 생김',
  'IAM-ADMIN-ADDED': 'Administrators 그룹에 시작 시점에 없던 구성원이 추가됨',
  'IAM-GUEST-ENABLED': '게스트 계정이 활성화돼 있음',
  'IAM-NO-PWREQ': '활성 계정 중 비밀번호를 비워 둬도 되게 허용된 계정이 있음(Windows의 "암호 필요" 옵션이 꺼짐)',
  'IAM-AUTOLOGON': '자동 로그인(AutoAdminLogon)이 켜져 있음',
  'IAM-UAC-OFF': '사용자 계정 컨트롤(UAC)이 꺼져 있음',
  'IAM-ELEVATED': '이 관제 앱이 관리자 권한으로 실행 중임',
});

const CATCH = "catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }";

const FWRULES_SCRIPT = `try { $r = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop | ForEach-Object { [string]$_.DisplayName })
ConvertTo-Json -InputObject $r -Compress } ${CATCH}`;

const IPS_SCRIPT = `try { $m = Get-MpComputerStatus -ErrorAction Stop; $p = Get-MpPreference -ErrorAction Stop
$d = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object { [ordered]@{ id = [string]$_.ThreatID; at = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToUniversalTime().ToString('o') } else { $null }; process = [string]$_.ProcessName; success = [string]$_.ActionSuccess } })
[ordered]@{ nis = [string]$m.NISEnabled; netProtection = [string]$p.EnableNetworkProtection; detections = $d } | ConvertTo-Json -Compress -Depth 4 } ${CATCH}`;

const VPN_SCRIPT = `try { $v = @(Get-VpnConnection -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; status = [string]$_.ConnectionStatus } })
$a = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceDescription -match 'TAP|Wintun|WireGuard|OpenVPN|AnyConnect|Tailscale|NordLynx|WARP|Fortinet|GlobalProtect|ZeroTier' } | ForEach-Object { [ordered]@{ name = [string]$_.Name; status = [string]$_.Status } })
[ordered]@{ profiles = $v; adapters = $a } | ConvertTo-Json -Compress -Depth 4 } ${CATCH}`;

const NAC_SCRIPT = `try { $c = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ category = [string]$_.NetworkCategory } })
$s = @(Get-Service dot3svc, wlansvc -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ name = [string]$_.Name; status = [string]$_.Status } })
$n = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -in 'Reachable', 'Stale', 'Permanent' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF' -and $_.IPAddress -notmatch '^(224|239|255)\\.' } | ForEach-Object { [string]$_.LinkLayerAddress })
[ordered]@{ profiles = $c; services = $s; neighbors = $n } | ConvertTo-Json -Compress -Depth 4 } ${CATCH}`;

// 비밀번호 값(DefaultPassword)은 읽지 않는다. 자동 로그인이 켜져 있는지(AutoAdminLogon)만 본다.
const IAM_SCRIPT = `try { $u = @(Get-LocalUser -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; pwRequired = [bool]$_.PasswordRequired; lastLogon = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { $null } } })
$g = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
$auto = [string](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction Stop).AutoAdminLogon
$uac = [string](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction Stop).EnableLUA
$elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[ordered]@{ users = $u; admins = $g; autoLogon = $auto; uac = $uac; elevated = [bool]$elev; domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } | ConvertTo-Json -Compress -Depth 4 } ${CATCH}`;

const parse = (text) => { try { return JSON.parse(String(text).trim()); } catch { return undefined; } };
const denied = (name) => /^(UnauthorizedAccess|Security|Access)/.test(String(name));
const unavailable = (reason, measuredAt, code) => ({ status: 'unavailable', measuredAt, reason, code });
const fail = (error, measuredAt) => (error && error.code === 'TIMEOUT' ? unavailable('제한 시간 안에 읽지 못했습니다.', measuredAt, 'TIMEOUT') : unavailable('읽는 도중 오류가 났습니다.', measuredAt, 'READ_FAILED'));
const arr = (value) => (Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : []);
const maskMac = (mac) => `**-**-**-${String(mac).split(/[-:]/).slice(-2).join('-').toLowerCase()}`;

export function createHostChecks({ run = runPowerShell, now = () => new Date() } = {}) {
  async function read(script, build, timeoutMs = 20000) {
    const measuredAt = now().toISOString();
    let output;
    try { output = await run(script, { timeoutMs }); } catch (error) { return fail(error, measuredAt); }
    const data = parse(output);
    if (data === undefined) return unavailable('응답 형식을 확인할 수 없습니다.', measuredAt, 'READ_FAILED');
    if (data && !Array.isArray(data) && typeof data === 'object' && typeof data.error === 'string') {
      return denied(data.error) ? unavailable('이 계정 권한으로는 읽을 수 없습니다. 관리자 권한이 필요한 항목이라 읽지 않습니다.', measuredAt, 'PERMISSION') : unavailable(`읽지 못했습니다(원인: ${/^[A-Za-z][A-Za-z0-9.]{0,59}$/.test(data.error) ? data.error : '알 수 없음'}).`, measuredAt, 'READ_FAILED');
    }
    try { return { status: 'measured', measuredAt, ...build(data) }; } catch { return unavailable('응답 형식을 확인할 수 없습니다.', measuredAt, 'READ_FAILED'); }
  }

  return Object.freeze({
    readFirewallRules: () => read(FWRULES_SCRIPT, (d) => { const names = arr(d).filter((x) => typeof x === 'string').map((x) => x.slice(0, 120)); return { names, count: names.length }; }),
    readIps: () => read(IPS_SCRIPT, (d) => ({
      nis: d.nis === 'True' ? true : d.nis === 'False' ? false : null,
      netProtection: { '0': 'off', '1': 'on', '2': 'audit' }[String(d.netProtection)] ?? 'unknown',
      detections: arr(d.detections).filter((x) => x && typeof x.id === 'string').map((x) => ({ id: x.id.slice(0, 20), at: typeof x.at === 'string' ? x.at : null, process: typeof x.process === 'string' ? x.process.slice(0, 60) : null, success: x.success === 'True' ? true : x.success === 'False' ? false : null })),
    })),
    readVpn: () => read(VPN_SCRIPT, (d) => ({
      profiles: arr(d.profiles).filter((x) => x && typeof x.name === 'string').map((x) => ({ name: x.name.slice(0, 60), connected: x.status === 'Connected' })),
      adapters: arr(d.adapters).filter((x) => x && typeof x.name === 'string').map((x) => ({ name: x.name.slice(0, 60), up: x.status === 'Up' })),
    })),
    readNac: () => read(NAC_SCRIPT, (d) => {
      const services = arr(d.services).filter((x) => x && typeof x.name === 'string');
      const neighbors = [...new Set(arr(d.neighbors).filter((x) => typeof x === 'string').map((x) => x.toLowerCase()))];
      return {
        categories: arr(d.profiles).map((x) => String(x.category)),
        dot1x: services.some((x) => x.name === 'dot3svc' && x.status === 'Running') || services.some((x) => x.name === 'wlansvc' && x.status === 'Running'),
        services: services.map((x) => ({ name: x.name, running: x.status === 'Running' })),
        neighborCount: neighbors.length, neighborMacs: neighbors, // 화면과 사건에는 마스크한 값만 보낸다
      };
    }, 25000),
    readAccounts: () => read(IAM_SCRIPT, (d) => ({
      users: arr(d.users).filter((x) => x && typeof x.name === 'string').map((x) => ({ name: x.name.slice(0, 60), enabled: Boolean(x.enabled), pwRequired: Boolean(x.pwRequired), lastLogon: typeof x.lastLogon === 'string' ? x.lastLogon : null })),
      admins: arr(d.admins).filter((x) => typeof x === 'string').map((x) => x.slice(0, 80)),
      autoLogon: d.autoLogon === '1', uac: d.uac === '1' ? true : d.uac === '0' ? false : null, elevated: Boolean(d.elevated), domain: Boolean(d.domain),
    })),
  });
}

// ---- 판정 규칙(순수 함수). baseline 은 첫 읽기 결과이며, 없으면 비교 규칙은 건너뛰고 상태 규칙만 평가한다. ----
const f = (severity, ruleId, title, detail, evidence) => ({ severity, ruleId, title, detail, evidence });

export function fwRuleFindings(baselineNames, cell) {
  if (!baselineNames || !cell || cell.status !== 'measured') return [];
  const known = new Set(baselineNames);
  const fresh = cell.names.filter((name) => !known.has(name));
  return fresh.slice(0, 5).map((name) => f('high', 'NET-FWRULE-NEW', `새 인바운드 허용 방화벽 규칙: ${name}`, '시작 시점에 없던 규칙입니다. 설치한 프로그램이 만든 것인지 확인하세요. 설정은 바꾸지 않았습니다.', { rule: name }));
}

export function ipsFindings(baselineIds, cell) {
  if (!cell || cell.status !== 'measured') return [];
  const out = [];
  if (cell.nis === false) out.push(f('medium', 'NET-IPS-NIS-OFF', 'Defender 네트워크 검사(NIS)가 꺼져 있습니다', '호스트 침입 방지(네트워크 검사) 구성 요소가 꺼져 있습니다. 설정은 바꾸지 않았습니다.', { nis: false }));
  if (baselineIds) {
    for (const d of cell.detections) if (!baselineIds.has(d.id)) out.push(f(d.success === false ? 'critical' : 'high', 'NET-IPS-DETECTION', `Defender 새 위협 탐지(ID ${d.id})${d.success === false ? ' — 조치 실패' : ''}`, `Microsoft Defender 가 위협을 탐지했습니다${d.process ? `(프로세스 ${d.process})` : ''}. Windows 보안 앱에서 확인하세요.`, { threatId: d.id, process: d.process, actionSuccess: d.success }));
  }
  return out;
}

export function vpnFindings(previous, cell) {
  if (!previous || !cell || cell.status !== 'measured') return [];
  const now = new Map([...cell.profiles.map((p) => [`profile:${p.name}`, p.connected]), ...cell.adapters.map((a) => [`adapter:${a.name}`, a.up])]);
  const out = [];
  for (const [key, up] of previous) if (up === true && now.get(key) === false) out.push(f('medium', 'NET-VPN-DOWN', `VPN 연결이 끊어졌습니다: ${key.split(':')[1]}`, '연결돼 있던 VPN 이 끊어졌습니다. 의도한 것이 아니라면 트래픽이 VPN 밖으로 나갈 수 있습니다.', { vpn: key }));
  return out;
}
export const vpnState = (cell) => (cell && cell.status === 'measured' ? new Map([...cell.profiles.map((p) => [`profile:${p.name}`, p.connected]), ...cell.adapters.map((a) => [`adapter:${a.name}`, a.up])]) : null);

export function nacFindings(baselineMacs, cell) {
  if (!baselineMacs || !cell || cell.status !== 'measured') return [];
  const known = new Set(baselineMacs);
  return cell.neighborMacs.filter((mac) => !known.has(mac)).slice(0, 5).map((mac) => f('low', 'NET-NAC-NEWDEVICE', `새 장치가 네트워크에서 발견됨(MAC 끝자리 ${maskMac(mac).slice(9)})`, '시작 시점에 없던 장치입니다. 휴대폰·IoT 기기일 수 있습니다. 이 앱은 장치를 차단·격리하지 않습니다.', { device: maskMac(mac) }));
}

export function iamFindings(baseline, cell) {
  if (!cell || cell.status !== 'measured') return [];
  const out = [];
  const guest = cell.users.find((u) => u.name.toLowerCase() === 'guest' || u.name === '손님');
  if (guest && guest.enabled) out.push(f('high', 'IAM-GUEST-ENABLED', '게스트 계정이 활성화돼 있습니다', '게스트 계정은 누구나 쓸 수 있는 기본 계정입니다. 설정은 바꾸지 않았습니다.', { account: guest.name }));
  const noPw = cell.users.filter((u) => u.enabled && !u.pwRequired).map((u) => u.name);
  if (noPw.length > 0) out.push(f('medium', 'IAM-NO-PWREQ', `빈 비밀번호가 허용된 활성 계정 ${noPw.length}개: ${noPw.join(', ')}`, 'Windows 계정 옵션 중 "암호 필요"가 꺼져 있어, 이 계정은 비밀번호를 아예 비워 둘 수 있습니다. 지금 실제로 비밀번호가 비어 있는지는 이 앱이 읽지 않아 모릅니다. 비밀번호를 쓰고 있다면 위험은 낮고, 비어 있다면 PC를 만질 수 있는 누구나 로그인할 수 있습니다. 의도한 설정이면 「수용」을 누르세요.', { accounts: noPw }));
  if (cell.autoLogon) out.push(f('medium', 'IAM-AUTOLOGON', '자동 로그인(AutoAdminLogon)이 켜져 있습니다', '부팅하면 비밀번호 없이 자동으로 로그인됩니다. PC에 물리적으로 접근하는 사람이 같은 권한을 얻을 수 있습니다. 비밀번호 값은 읽지 않았습니다. 개인 PC에서 의도한 설정이면 "오탐/수용"으로 처리하세요.', { autoLogon: true }));
  if (cell.uac === false) out.push(f('high', 'IAM-UAC-OFF', '사용자 계정 컨트롤(UAC)이 꺼져 있습니다', '권한 상승 확인 창이 꺼져 있습니다. 설정은 바꾸지 않았습니다.', { uac: false }));
  if (cell.elevated) out.push(f('medium', 'IAM-ELEVATED', '이 관제 앱이 관리자 권한으로 실행 중입니다', '이 앱은 관리자 권한 없이 쓰도록 설계됐습니다. 일반 권한으로 다시 실행하세요.', { elevated: true }));
  if (baseline) {
    const knownUsers = new Set(baseline.users);
    for (const u of cell.users) if (!knownUsers.has(u.name)) out.push(f('high', 'IAM-NEW-ACCOUNT', `새 로컬 계정이 생겼습니다: ${u.name}`, '시작 시점에 없던 계정입니다. 만든 기억이 없다면 확인하세요.', { account: u.name, enabled: u.enabled }));
    const knownAdmins = new Set(baseline.admins);
    for (const name of cell.admins) if (!knownAdmins.has(name)) out.push(f('critical', 'IAM-ADMIN-ADDED', `Administrators 그룹에 구성원이 추가됐습니다: ${name}`, '시작 시점에 없던 관리자입니다. 만든 기억이 없다면 즉시 확인하세요.', { account: name }));
  }
  return out;
}
export const iamBaseline = (cell) => (cell && cell.status === 'measured' ? { users: cell.users.map((u) => u.name), admins: cell.admins.slice() } : null);
export { maskMac };
