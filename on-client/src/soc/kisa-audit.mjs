// PC 보안 점검기: KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」(2026) PC 분야 PC-01~PC-18.
// 항목·판단 기준은 수업 워크시트(PC보안점검_워크시트.xlsx, 「점검표」 시트)를 그대로 옮겼다.
//
// 점검: 일반 권한으로 설정을 읽기만 한다. 관리자 권한이 있어야 읽히는 항목(PC-02 복잡성, PC-08 멀티 부팅)은 "수동 확인"으로 둔다.
// 조치: 사용자가 화면에서 고르고 확인 창에서 다시 승인한 것만 실행한다. 실행할 명령은 이 파일에 고정돼 있고(입력값을 끼워 넣지 않음),
//       관리자 권한이 필요한 조치는 Windows UAC 창에서 사용자가 한 번 더 허락해야 실행된다. 조치 전 값을 기록해 두어 되돌릴 수 있다.
import { execFile, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const SOURCE = 'KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) PC 분야 · 수업 워크시트 기준';

export const ITEMS = Object.freeze([
  { code: 'PC-01', category: '계정 관리', title: '비밀번호의 주기적 변경', importance: '상', good: '최대 암호 사용 기간이 90일 이하', bad: '최대 암호 사용 기간이 "제한 없음"이거나 90일 초과' },
  { code: 'PC-02', category: '계정 관리', title: '비밀번호 관리정책 설정', importance: '상', good: '복잡성을 만족하는 비밀번호 정책 설정', bad: '비밀번호 미사용 또는 짧고 추측하기 쉬운 비밀번호 허용' },
  { code: 'PC-03', category: '계정 관리', title: '복구 콘솔에서 자동 로그온 금지', importance: '중', good: '복구 콘솔 자동 로그온 허용 "사용 안 함"', bad: '복구 콘솔 자동 로그온 허용 "사용"' },
  { code: 'PC-04', category: '서비스 관리', title: '공유 폴더 제거', importance: '상', good: '불필요한 공유 폴더 없음, 또는 접근 권한·비밀번호 설정', bad: '불필요한 공유 폴더 존재, 또는 권한·비밀번호 없이 공유' },
  { code: 'PC-05', category: '서비스 관리', title: '불필요한 서비스 제거', importance: '상', good: '불필요한 서비스(원격 레지스트리·UPnP·단순 TCP/IP·인쇄 스풀러 등) 중지', bad: '불필요한 서비스가 실행 중' },
  { code: 'PC-06', category: '서비스 관리', title: '비인가 상용 메신저 사용 금지', importance: '상', good: '상용 메신저 미설치·미실행', bad: '상용 메신저 설치 또는 실행' },
  { code: 'PC-07', category: '서비스 관리', title: '파일 시스템 NTFS 사용', importance: '중', good: '모든 디스크 볼륨이 NTFS', bad: 'FAT32 볼륨 사용' },
  { code: 'PC-08', category: '서비스 관리', title: '멀티 부팅 금지', importance: '중', good: 'PC에 OS 하나만 설치', bad: 'OS 2개 이상 설치' },
  { code: 'PC-09', category: '서비스 관리', title: '브라우저 종료 시 임시 인터넷 파일 삭제', importance: '하', good: '브라우저를 닫을 때 임시 파일(캐시) 비우기 사용', bad: '사용 안 함' },
  { code: 'PC-10', category: '패치 관리', title: '주기적 보안 패치 적용', importance: '상', good: '보안 업데이트 설치·자동 업데이트 사용', bad: '보안 업데이트 미설치 또는 업데이트 중지' },
  { code: 'PC-11', category: '패치 관리', title: '지원이 종료되지 않은 Windows 빌드 사용', importance: '상', good: '지원 중인 빌드', bad: '지원이 끝난 빌드' },
  { code: 'PC-12', category: '보안 관리', title: 'Windows 자동 로그인 점검', importance: '중', good: '자동 로그인 비활성화', bad: '자동 로그인 활성화' },
  { code: 'PC-13', category: '보안 관리', title: '백신 설치 및 주기적 업데이트', importance: '상', good: '백신 설치, 최신 업데이트 적용', bad: '백신 미설치 또는 업데이트 오래됨' },
  { code: 'PC-14', category: '보안 관리', title: '백신 실시간 감시 활성화', importance: '상', good: '실시간 감시 켜짐', bad: '백신 없음 또는 실시간 감시 꺼짐' },
  { code: 'PC-15', category: '보안 관리', title: 'OS 방화벽 활성화', importance: '상', good: 'Windows 방화벽(또는 다른 방화벽) 사용', bad: '방화벽 사용 안 함' },
  { code: 'PC-16', category: '보안 관리', title: '화면보호기 대기 시간·재시작 시 암호 보호', importance: '상', good: '대기 시간 10분 이하 + 다시 시작할 때 로그온 화면', bad: '10분 초과 또는 암호 보호 없음' },
  { code: 'PC-17', category: '보안 관리', title: '이동식 미디어 자동 실행 방지', importance: '상', good: '미디어를 넣어도 자동 실행되지 않음', bad: '자동 실행됨' },
  { code: 'PC-18', category: '보안 관리', title: '원격 지원 금지', importance: '중', good: '원격 지원 "사용 안 함"', bad: '원격 지원 "사용"' },
]);

export const VERDICT = Object.freeze({ good: '양호', vuln: '취약', review: '판단 필요', manual: '수동 확인', na: '해당 없음' });

// 워크시트 「안내」 시트의 Windows 지원 종료일(2026-10 확인, 출처: Microsoft Windows 11 수명 주기 정리)
const WIN11 = { 22631: ['23H2', '2025-11-11', '2026-11-10'], 26100: ['24H2', '2026-10-13', '2027-10-12'], 26200: ['25H2', '2027-10-12', '2028-10-10'] };
const WIN10_END = '2025-10-14';
const WIN10_ESU_END = '2026-10-13';

const MESSENGER = '^(KakaoTalk|카카오톡|Telegram|Discord|LINE|WhatsApp|Signal|WeChat|Skype|NateOn|네이트온)';
const RISKY_SERVICES = ['RemoteRegistry', 'upnphost', 'simptcp', 'SSDPSRV'];

// 점검에 쓰는 사실을 한 번에 읽는다(읽기 전용). 출력은 JSON 한 덩어리.
const FACTS_SCRIPT = String.raw`[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
function RegVal($p, $n) { try { $v = (Get-ItemProperty -LiteralPath $p -Name $n -ErrorAction Stop).$n; if ($null -eq $v) { $null } else { [string]$v } } catch { $null } }
$o = [ordered]@{}
# net accounts 는 일반 권한으로 읽힌다. 항목 이름은 언어마다 다르지만 순서는 같아서 줄 번호로 읽는다(3번째 줄 최대 사용 기간, 4번째 줄 최소 길이).
$na = @(net accounts 2>$null); if ($LASTEXITCODE -eq 0 -and $na.Count -ge 5) { $o.maxPwAge = ($na[2] -split ":")[-1].Trim(); $o.minPwLen = ($na[3] -split ":")[-1].Trim() }
try { $tmp = Join-Path $env:TEMP ('soc-secpol-' + [guid]::NewGuid().ToString() + '.inf'); $null = secedit /export /cfg $tmp /areas SECURITYPOLICY 2>&1; if (Test-Path $tmp) { $t = Get-Content -LiteralPath $tmp -Raw; Remove-Item -LiteralPath $tmp -Force; if ($t -match 'PasswordComplexity\s*=\s*(\d)') { $o.pwComplexity = $Matches[1] } } } catch {}
$o.recoveryLevel = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' 'SecurityLevel'
$o.shares = @(Get-CimInstance Win32_Share | ForEach-Object { [ordered]@{ name = [string]$_.Name; type = [int64]$_.Type } })
$o.autoShareWks = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'
$o.services = @(Get-Service -Name RemoteRegistry, upnphost, simptcp, SSDPSRV, Spooler -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ name = [string]$_.Name; display = [string]$_.DisplayName; status = [string]$_.Status; start = [string]$_.StartType } })
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
$o.messengers = @(Get-ItemProperty $keys | Where-Object { [string]$_.DisplayName -match '${MESSENGER}' } | ForEach-Object { [string]$_.DisplayName } | Sort-Object -Unique)
$o.messengerProcs = @(Get-Process | Where-Object { $_.ProcessName -match '^(KakaoTalk|Telegram|Discord|LINE|WhatsApp|Signal|WeChat|Skype|NateOnMain)$' } | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
$o.volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ id = [string]$_.DeviceID; fs = [string]$_.FileSystem } })
$bcd = (bcdedit /enum OSLOADER 2>&1 | Out-String); if ($LASTEXITCODE -eq 0) { $o.bootEntries = ([regex]::Matches($bcd, '(?m)^-{5,}')).Count }
$o.iePersistent = RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache' 'Persistent'
$o.edgePolicy = @((RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ClearCachedImagesAndFilesOnExit'), (RegVal 'HKCU:\SOFTWARE\Policies\Microsoft\Edge' 'ClearCachedImagesAndFilesOnExit')) | Where-Object { $_ }
$o.chromePolicy = @('HKLM:\SOFTWARE\Policies\Google\Chrome\ClearBrowsingDataOnExitList', 'HKCU:\SOFTWARE\Policies\Google\Chrome\ClearBrowsingDataOnExitList' | ForEach-Object { $k = Get-Item -LiteralPath $_; if ($k) { $k.GetValueNames() | ForEach-Object { [string]$k.GetValue($_) } } })
try { $s = New-Object -ComObject Microsoft.Update.Session; $h = $s.CreateUpdateSearcher(); $n = $h.GetTotalHistoryCount(); if ($n -gt 0) { $o.wuHistory = @($h.QueryHistory(0, [Math]::Min($n, 80)) | Where-Object { $_.ResultCode -eq 2 -and $_.Operation -eq 1 } | Select-Object -First 40 | ForEach-Object { [ordered]@{ title = [string]$_.Title; at = $_.Date.ToUniversalTime().ToString('o') } }) } else { $o.wuHistory = @() } } catch { $o.wuError = $_.Exception.GetType().Name }
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($hf) { $o.hotfix = [ordered]@{ id = [string]$hf.HotFixID; at = $hf.InstalledOn.ToUniversalTime().ToString('o') } }
$o.wuPauseUntil = RegVal 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
$cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$o.os = [ordered]@{ product = RegVal $cv 'ProductName'; display = RegVal $cv 'DisplayVersion'; build = RegVal $cv 'CurrentBuild'; ubr = RegVal $cv 'UBR'; edition = RegVal $cv 'EditionID' }
$o.autoAdminLogon = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
try { $m = Get-MpComputerStatus -ErrorAction Stop; $o.defender = [ordered]@{ av = [bool]$m.AntivirusEnabled; rt = [bool]$m.RealTimeProtectionEnabled; ageDays = [int]$m.AntivirusSignatureAge; at = if ($m.AntivirusSignatureLastUpdated) { $m.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { $null } } } catch {}
$o.avProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int64]$_.productState } })
$o.fwProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int64]$_.productState } })
$o.fwProfiles = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } })
$d = 'HKCU:\Control Panel\Desktop'; $pd = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
$o.screen = [ordered]@{ active = RegVal $d 'ScreenSaveActive'; timeout = RegVal $d 'ScreenSaveTimeOut'; secure = RegVal $d 'ScreenSaverIsSecure'; exe = RegVal $d 'SCRNSAVE.EXE'; pActive = RegVal $pd 'ScreenSaveActive'; pTimeout = RegVal $pd 'ScreenSaveTimeOut'; pSecure = RegVal $pd 'ScreenSaverIsSecure'; pExe = RegVal $pd 'SCRNSAVE.EXE'; inactivity = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' }
$o.autoplay = [ordered]@{ disable = RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay'; hklm = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'; hkcu = RegVal 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' }
$o.remoteAssist = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
$o.remoteAssistPolicy = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp'
$o.elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$o | ConvertTo-Json -Compress -Depth 5`;

// net accounts 의 최대 암호 사용 기간: 숫자면 일수, 그 밖(Unlimited·무제한 등)은 제한 없음, 값이 없으면 null
const maxAgeDays = (v) => (v === null || v === undefined || v === '' ? null : /^\d+$/.test(String(v)) ? (Number(v) === 0 ? Infinity : Number(v)) : Infinity);
const arr = (v) => (Array.isArray(v) ? v : v === null || v === undefined || v === '' ? [] : [v]);
const num = (v) => (v === null || v === undefined || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
const days = (ms) => Math.floor(ms / 86400000);
const ymd = (iso) => (iso ? String(iso).slice(0, 10) : '?');

// productState(보안 센터): 둘째 바이트 0x10·0x11 = 켜짐, 마지막 바이트 0x00 = 최신
const productOn = (state) => [0x10, 0x11].includes((Number(state) >> 8) & 0xff);
const productFresh = (state) => (Number(state) & 0xff) === 0x00;

export function evaluate(f, now = new Date()) {
  const out = new Map();
  const set = (code, verdict, evidence, reason = '') => out.set(code, { verdict, evidence, reason });
  const today = now.getTime();

  // PC-01 최대 암호 사용 기간
  const maxDays = maxAgeDays(f.maxPwAge);
  if (maxDays === null) set('PC-01', 'manual', '읽지 못함', '로컬 암호 정책을 읽지 못했습니다. 명령 프롬프트에서 net accounts 로 확인하세요.');
  else set('PC-01', maxDays <= 90 ? 'good' : 'vuln', `최대 암호 사용 기간: ${maxDays === Infinity ? '제한 없음' : `${maxDays}일`}`, 'Microsoft 계정으로 로그인하는 경우 이 로컬 정책이 적용되지 않을 수 있습니다.');

  // PC-02 복잡성·최소 길이
  const minLen = num(f.minPwLen);
  const lenText = minLen === null ? '최소 길이 읽지 못함' : `최소 암호 길이 ${minLen}자`;
  if (f.pwComplexity === '1' && minLen !== null && minLen >= 8) set('PC-02', 'good', `복잡성 사용 · ${lenText}`);
  else if (f.pwComplexity === '0') set('PC-02', 'vuln', `복잡성 사용 안 함 · ${lenText}`);
  else if (minLen !== null && minLen < 8) set('PC-02', 'vuln', `${lenText} · 복잡성은 관리자 권한이 있어야 읽힘`, '짧은 비밀번호(8자 미만)를 허용하는 상태입니다.');
  else set('PC-02', 'manual', `${lenText} · 복잡성은 관리자 권한이 있어야 읽힘`, 'secpol.msc → 계정 정책 > 암호 정책에서 "암호는 복잡성을 만족해야 함"을 확인하세요(Home 에디션은 없음).');

  // PC-03 복구 콘솔
  const rc = f.recoveryLevel;
  set('PC-03', rc === '1' ? 'vuln' : 'good', rc === null || rc === undefined ? 'RecoveryConsole SecurityLevel 값 없음(사용 안 함과 같음)' : `RecoveryConsole SecurityLevel = ${rc}`);

  // PC-04 공유 폴더
  const shares = arr(f.shares).filter((s) => s && typeof s.name === 'string');
  const userShares = shares.filter((s) => s.type === 0);
  const adminDisk = shares.filter((s) => s.type === 2147483648);
  const shareText = shares.length ? shares.map((s) => s.name).join(', ') : '공유 없음';
  if (userShares.length) set('PC-04', 'review', `공유: ${shareText}`, `일반 공유 ${userShares.map((s) => s.name).join(', ')}가 있습니다. Everyone 권한 여부는 관리자 권한이 있어야 읽혀서, 폴더 속성 > 공유 > 고급 공유 > 권한에서 직접 확인하세요.`);
  else if (adminDisk.length && f.autoShareWks !== '0') set('PC-04', 'vuln', `기본 공유: ${adminDisk.map((s) => s.name).join(', ')}`, '기본 관리 공유(C$, ADMIN$)가 켜져 있습니다. 관리자 계정으로만 열리지만 가이드는 제거를 권고합니다.');
  else set('PC-04', 'good', `공유: ${shareText}`);

  // PC-05 불필요한 서비스
  const svc = arr(f.services).filter((s) => s && typeof s.name === 'string');
  const active = svc.filter((s) => s.status === 'Running' || s.start === 'Automatic');
  const risky = active.filter((s) => s.name !== 'Spooler');
  const svcText = svc.length ? svc.map((s) => `${s.display || s.name}: ${s.status === 'Running' ? '실행 중' : '중지'}·${{ Automatic: '자동', Manual: '수동', Disabled: '사용 안 함' }[s.start] || s.start}`).join(' / ') : '대상 서비스 없음';
  if (risky.length) set('PC-05', 'vuln', svcText, `${risky.map((s) => s.display || s.name).join(', ')}이(가) 켜져 있습니다.`);
  else if (active.some((s) => s.name === 'Spooler')) set('PC-05', 'review', svcText, '인쇄 스풀러만 켜져 있습니다. 프린터를 쓰면 필요한 서비스이므로 쓰지 않을 때만 끄세요.');
  else set('PC-05', 'good', svcText);

  // PC-06 상용 메신저
  const msgs = arr(f.messengers), procs = arr(f.messengerProcs);
  if (msgs.length || procs.length) set('PC-06', 'vuln', `설치: ${msgs.join(', ') || '없음'} · 실행 중: ${procs.join(', ') || '없음'}`, '회사·기관이 허가한 메신저라면 "판단 필요"로 기록하세요.');
  else set('PC-06', 'good', '알려진 상용 메신저 설치·실행 없음', '목록에 없는 메신저는 찾지 못합니다.');

  // PC-07 파일 시스템
  const vols = arr(f.volumes).filter((v) => v && v.id);
  const weak = vols.filter((v) => !['NTFS', 'ReFS'].includes(v.fs));
  if (!vols.length) set('PC-07', 'manual', '고정 디스크를 읽지 못함');
  else set('PC-07', weak.length ? 'vuln' : 'good', vols.map((v) => `${v.id} ${v.fs || '알 수 없음'}`).join(' · '));

  // PC-08 멀티 부팅
  if (Number.isInteger(f.bootEntries)) set('PC-08', f.bootEntries <= 1 ? 'good' : 'vuln', `부팅 항목 ${f.bootEntries}개`);
  else set('PC-08', 'manual', '부팅 목록은 관리자 권한이 있어야 읽힘', 'Win+R → msconfig → 부팅 탭에서 운영체제 개수를 확인하세요.');

  // PC-09 브라우저 종료 시 캐시 삭제
  const edge = arr(f.edgePolicy).includes('1');
  const chrome = arr(f.chromePolicy).some((v) => /cached_images_and_files/.test(v));
  if (edge || chrome) set('PC-09', 'good', `정책으로 설정됨: ${[edge && 'Edge', chrome && 'Chrome'].filter(Boolean).join(', ')}`);
  else if (f.iePersistent === '0') set('PC-09', 'good', '인터넷 옵션: 닫을 때 임시 인터넷 파일 비우기 사용');
  else set('PC-09', 'review', '정책으로 설정된 것 없음', '브라우저 안의 개인 설정은 이 앱이 읽지 않습니다(브라우저 저장소를 열지 않기 위해). Edge: 설정 > 개인 정보 > "브라우저를 닫을 때마다 지울 항목 선택"에서 캐시된 이미지 및 파일이 켜져 있는지 확인하세요.');

  // PC-10 보안 패치
  // 품질(보안) 업데이트만 본다: KB 번호가 있고 백신 정의·악성 코드 제거 도구가 아닌 것(스토어 앱 업데이트 제외)
  const history = arr(f.wuHistory).filter((h) => h && h.at && /KB\d{6,}/i.test(h.title) && !/Defender|보안 인텔리전스|Security Intelligence|악성 소프트웨어 제거|Malicious Software Removal/i.test(h.title));
  const latest = history.map((h) => ({ ...h, t: Date.parse(h.at) })).filter((h) => !Number.isNaN(h.t)).sort((a, b) => b.t - a.t)[0]
    || (f.hotfix && f.hotfix.at ? { title: f.hotfix.id, at: f.hotfix.at, t: Date.parse(f.hotfix.at) } : null);
  const pauseUntil = f.wuPauseUntil ? Date.parse(f.wuPauseUntil) : NaN;
  const paused = !Number.isNaN(pauseUntil) && pauseUntil > today;
  if (!latest) set('PC-10', 'manual', '업데이트 기록을 읽지 못함', '설정 > Windows 업데이트 > 업데이트 기록에서 최근 설치일을 확인하세요.');
  else {
    const age = days(today - latest.t);
    set('PC-10', age <= 45 && !paused ? 'good' : 'vuln', `최근 업데이트: ${ymd(latest.at)}(${age}일 전) ${String(latest.title).slice(0, 80)}${paused ? ` · 업데이트 일시 중지(${ymd(f.wuPauseUntil)}까지)` : ''}`, age > 45 ? '45일 넘게 품질(보안) 업데이트가 설치되지 않았습니다.' : paused ? '업데이트가 일시 중지돼 있습니다.' : '');
  }

  // PC-11 지원 종료
  const os = f.os || {};
  const build = num(os.build);
  const homePro = /^(Core|CoreSingleLanguage|CoreN|Professional|ProfessionalN|ProfessionalWorkstation|ProfessionalEducation)$/i.test(os.edition || '');
  const entEdu = /^(Enterprise|EnterpriseN|Education|EducationN)$/i.test(os.edition || '');
  const osText = `Windows ${build >= 22000 ? '11' : '10'} ${os.edition || ''} ${os.display || ''} (빌드 ${os.build || '?'}.${os.ubr || '?'})`.replace(/\s+/g, ' ');
  if (build === null) set('PC-11', 'manual', 'Windows 버전을 읽지 못함');
  else if (build < 22000) {
    const end = Date.parse(WIN10_ESU_END);
    set('PC-11', 'vuln', osText, `Windows 10은 ${WIN10_END}에 지원이 끝났습니다(개인용 유료 연장도 ${WIN10_ESU_END} 종료).${today <= end ? ' 유료 연장(ESU)에 가입했다면 판단 필요.' : ''}`);
  } else if (WIN11[build] && (homePro || entEdu)) {
    const [name, hp, ee] = WIN11[build];
    const end = homePro ? hp : ee;
    const left = days(Date.parse(end) - today);
    set('PC-11', left >= 0 ? 'good' : 'vuln', `${osText} · ${name} 지원 종료일 ${end}`, left >= 0 ? `지원 종료까지 ${left}일 남았습니다.` : `${name}(${homePro ? 'Home/Pro' : 'Enterprise/Education'})은 ${end}에 지원이 끝났습니다. Windows 업데이트에서 최신 버전(25H2)으로 올리세요.`);
  } else if (build < 22631) set('PC-11', 'vuln', osText, '23H2 이전 Windows 11 은 지원이 끝났습니다.');
  else set('PC-11', 'review', osText, '워크시트 표에 없는 빌드·에디션입니다. Microsoft 수명 주기 페이지에서 지원 종료일을 확인하세요.');

  // PC-12 자동 로그인
  set('PC-12', f.autoAdminLogon === '1' ? 'vuln' : 'good', `AutoAdminLogon = ${f.autoAdminLogon ?? '없음'}`);

  // PC-13·14 백신
  const avs = arr(f.avProducts).filter((a) => a && a.name);
  const thirdParty = avs.filter((a) => !/Defender/i.test(a.name));
  const d = f.defender;
  const avText = `${avs.map((a) => a.name).join(', ') || '보안 센터에 등록된 백신 없음'}${d ? ` · Defender 서명 ${d.ageDays}일 전(${ymd(d.at)})` : ''}`;
  if (d && d.av && d.ageDays <= 7) set('PC-13', 'good', avText);
  else if (thirdParty.some((a) => productOn(a.state) && productFresh(a.state))) set('PC-13', 'good', avText);
  else if (!avs.length && !d) set('PC-13', 'manual', '백신 상태를 읽지 못함');
  else set('PC-13', 'vuln', avText, '백신이 꺼져 있거나 7일 넘게 업데이트되지 않았습니다.');
  if ((d && d.rt) || thirdParty.some((a) => productOn(a.state))) set('PC-14', 'good', `실시간 감시 켜짐(${d && d.rt ? 'Defender' : thirdParty.filter((a) => productOn(a.state)).map((a) => a.name).join(', ')})`);
  else if (!avs.length && !d) set('PC-14', 'manual', '백신 상태를 읽지 못함');
  else set('PC-14', 'vuln', '실시간 감시 꺼짐');

  // PC-15 방화벽
  const profiles = arr(f.fwProfiles).filter((p) => p && p.name);
  const off = profiles.filter((p) => p.enabled !== 'True');
  const otherFw = arr(f.fwProducts).filter((p) => p && p.name && !/Windows/i.test(p.name) && productOn(p.state));
  if (!profiles.length) set('PC-15', 'manual', '방화벽 상태를 읽지 못함');
  else if (!off.length) set('PC-15', 'good', `Windows 방화벽: ${profiles.map((p) => p.name).join('·')} 모두 켜짐`);
  else if (otherFw.length) set('PC-15', 'good', `다른 방화벽 사용: ${otherFw.map((p) => p.name).join(', ')}`, `Windows 방화벽 ${off.map((p) => p.name).join('·')} 꺼짐`);
  else set('PC-15', 'vuln', `Windows 방화벽 꺼짐: ${off.map((p) => p.name).join(', ')}`);

  // PC-16 화면보호기(정책 값이 있으면 그것이 우선)
  const s = f.screen || {};
  const pick = (p, u) => (p !== null && p !== undefined ? p : u);
  const active2 = pick(s.pActive, s.active), timeout = num(pick(s.pTimeout, s.timeout)), secure = pick(s.pSecure, s.secure), exe = pick(s.pExe, s.exe);
  const scrText = `화면보호기 ${active2 === '1' && exe ? '사용' : '사용 안 함'} · 대기 ${timeout === null ? '?' : `${Math.round(timeout / 60)}분`} · 다시 시작할 때 로그온 ${secure === '1' ? '예' : '아니요'}`;
  const inactivity = num(s.inactivity);
  if (active2 === '1' && exe && timeout !== null && timeout <= 600 && secure === '1') set('PC-16', 'good', scrText);
  else if (inactivity !== null && inactivity > 0 && inactivity <= 600) set('PC-16', 'review', `${scrText} · 컴퓨터 비활성 한도 ${inactivity}초`, '화면보호기 대신 잠금 정책으로 대체 통제하고 있습니다(기준 해석 차이).');
  else set('PC-16', 'vuln', scrText, '대기 시간 10분 이하와 "다시 시작할 때 로그온 화면 표시"가 모두 필요합니다.');

  // PC-17 자동 실행
  const ap = f.autoplay || {};
  const noDrive = num(pick(ap.hklm, ap.hkcu));
  if (ap.disable === '1' || noDrive === 255) set('PC-17', 'good', `자동 실행 ${ap.disable === '1' ? '꺼짐' : '정책으로 모든 드라이브 차단'}`, '내부 관리 절차 수립 여부는 직접 기록하세요.');
  else set('PC-17', 'vuln', '모든 미디어 및 장치에 자동 실행 사용(켜짐)');

  // PC-18 원격 지원(정책 우선)
  const ra = f.remoteAssistPolicy ?? f.remoteAssist;
  if (ra === null || ra === undefined) set('PC-18', 'review', '원격 지원 설정 값 없음', 'sysdm.cpl → 원격 탭에서 "이 컴퓨터에 대한 원격 지원 연결 허용"을 확인하세요.');
  else set('PC-18', ra === '0' ? 'good' : 'vuln', `원격 지원 연결 허용: ${ra === '0' ? '꺼짐' : '켜짐'}${f.remoteAssistPolicy != null ? '(정책)' : ''}`);

  return ITEMS.map((item) => { const r = out.get(item.code); return { ...item, ...r, fixes: fixesFor(item.code, f).filter((fix) => r.verdict !== 'good' || SHOW_WHEN_GOOD.has(fix.id)).map(({ id, label, admin, warn }) => ({ id, label, admin, warn })), opens: OPENS_FOR[item.code] || [] }; });
}

// ---------- 조치 ----------
// 레지스트리 값 쓰기/되돌리기 명령. 경로·이름은 이 파일의 상수이고 값은 숫자 또는 검사한 짧은 문자열만 쓴다.
const safeStr = (v) => (typeof v === 'string' && /^[\w .:\\-]{0,200}$/.test(v) ? v : null);
const q = (v) => `'${String(v).replace(/'/g, "''")}'`;
function regSet(path, name, type, value) {
  const v = type === 'DWord' ? String(Number.parseInt(value, 10)) : q(value);
  return `if (-not (Test-Path -LiteralPath ${q(path)})) { New-Item -Path ${q(path)} -Force | Out-Null }; Set-ItemProperty -LiteralPath ${q(path)} -Name ${q(name)} -Value ${v} -Type ${type}`;
}
function regRestore(path, name, type, prev) {
  if (prev === null || prev === undefined) return `Remove-ItemProperty -LiteralPath ${q(path)} -Name ${q(name)} -ErrorAction SilentlyContinue`;
  if (type === 'DWord' && !/^-?\d{1,10}$/.test(String(prev))) return null;
  if (type === 'String' && safeStr(String(prev)) === null) return null;
  return regSet(path, name, type, prev);
}
const reg = (path, name, type, value, prevOf) => ({ apply: () => regSet(path, name, type, value), undo: (f) => regRestore(path, name, type, prevOf(f)), prevOf });

const SCR = 'HKCU:\\Control Panel\\Desktop';
const FIXES = {
  'PC-01': [{ id: 'maxpwage-90', label: '최대 암호 사용 기간을 90일로', admin: true, warn: '90일이 지나면 로컬 계정 비밀번호를 바꾸라는 요구가 나옵니다.',
    apply: () => 'net accounts /maxpwage:90', undo: (f) => { const d = maxAgeDays(f.maxPwAge); return d === null ? null : d === Infinity ? 'net accounts /maxpwage:UNLIMITED' : `net accounts /maxpwage:${d}`; }, prevOf: (f) => f.maxPwAge }],
  'PC-02': [{ id: 'minpwlen-8', label: '최소 암호 길이를 8자로', admin: true, warn: '지금보다 짧은 비밀번호는 다음에 바꿀 때부터 쓸 수 없습니다. 복잡성 설정은 secpol.msc 에서 직접 켜세요.',
    apply: () => 'net accounts /minpwlen:8', undo: (f) => { const n = num(f.minPwLen); return n === null ? null : `net accounts /minpwlen:${n}`; }, prevOf: (f) => f.minPwLen }],
  'PC-03': [{ id: 'recovery-off', label: '복구 콘솔 자동 로그온 끄기', admin: true, warn: '', ...reg('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole', 'SecurityLevel', 'DWord', 0, (f) => f.recoveryLevel) }],
  'PC-04': [{ id: 'autoshare-off', label: '기본 관리 공유(C$, ADMIN$) 끄기', admin: true, warn: '다시 시작한 뒤 적용됩니다. 다른 PC에서 이 PC 드라이브를 관리 공유로 여는 원격 관리 도구가 동작하지 않을 수 있습니다.', ...reg('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 'AutoShareWks', 'DWord', 0, (f) => f.autoShareWks) }],
  'PC-05': [{ id: 'services-off', label: '원격 레지스트리·UPnP·단순 TCP/IP·SSDP 서비스 끄기', admin: true, warn: '인쇄 스풀러는 끄지 않습니다(프린터용). UPnP·SSDP 를 끄면 네트워크 장치 자동 찾기가 안 될 수 있습니다.',
    applyF: (f) => arr(f.services).filter((s) => RISKY_SERVICES.includes(s.name) && (s.status === 'Running' || s.start !== 'Disabled')).map((s) => `Stop-Service -Name ${q(s.name)} -Force -ErrorAction SilentlyContinue; Set-Service -Name ${q(s.name)} -StartupType Disabled`).join('; ') || null,
    undo: (f) => arr(f.services).filter((s) => RISKY_SERVICES.includes(s.name) && (s.status === 'Running' || s.start !== 'Disabled')).map((s) => { const start = { Automatic: 'Automatic', Manual: 'Manual', Disabled: 'Disabled' }[s.start] || 'Manual'; return `Set-Service -Name ${q(s.name)} -StartupType ${start}${s.status === 'Running' ? `; Start-Service -Name ${q(s.name)} -ErrorAction SilentlyContinue` : ''}`; }).join('; ') || null,
    prevOf: (f) => arr(f.services).filter((s) => RISKY_SERVICES.includes(s.name)) }],
  'PC-09': [{ id: 'edge-clear-cache', label: 'Edge 를 닫을 때 캐시 지우기(정책)', admin: true, warn: 'Edge 설정 화면에 "조직에서 관리하는 브라우저" 표시가 생깁니다.', ...reg('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge', 'ClearCachedImagesAndFilesOnExit', 'DWord', 1, (f) => (arr(f.edgePolicy)[0] ?? null)) }],
  'PC-12': [{ id: 'autologon-off', label: '자동 로그인 끄기', admin: true, warn: '다음 부팅부터 비밀번호를 입력해야 로그인됩니다. 비밀번호를 알고 있는지 먼저 확인하세요. 저장된 자동 로그인 비밀번호 지우기는 netplwiz 에서 하세요.', ...reg('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AutoAdminLogon', 'String', '0', (f) => f.autoAdminLogon) }],
  'PC-13': [{ id: 'defender-update', label: 'Defender 업데이트 받기', admin: true, warn: '인터넷에서 최신 백신 서명을 받습니다. 되돌릴 것이 없는 조치입니다.', apply: () => 'Update-MpSignature', undo: () => null, prevOf: () => null }],
  'PC-15': [{ id: 'firewall-on', label: '꺼진 Windows 방화벽 프로필 켜기', admin: true, warn: '',
    applyF: (f) => { const off = arr(f.fwProfiles).filter((p) => p.enabled !== 'True' && ['Domain', 'Private', 'Public'].includes(p.name)); return off.length ? `Set-NetFirewallProfile -Profile ${off.map((p) => p.name).join(',')} -Enabled True` : null; },
    undo: (f) => { const off = arr(f.fwProfiles).filter((p) => p.enabled !== 'True' && ['Domain', 'Private', 'Public'].includes(p.name)); return off.length ? `Set-NetFirewallProfile -Profile ${off.map((p) => p.name).join(',')} -Enabled False` : null; }, prevOf: (f) => f.fwProfiles }],
  'PC-16': [{ id: 'screensaver-10', label: '화면보호기 10분 + 다시 시작할 때 로그온', admin: false, warn: '현재 사용자에게만 적용됩니다. 회사 정책(그룹 정책)이 있으면 그 값이 우선합니다.',
    apply: () => [regSet(SCR, 'ScreenSaveActive', 'String', '1'), regSet(SCR, 'ScreenSaveTimeOut', 'String', '600'), regSet(SCR, 'ScreenSaverIsSecure', 'String', '1'), `if (-not (Get-ItemProperty -LiteralPath ${q(SCR)} -Name 'SCRNSAVE.EXE' -ErrorAction SilentlyContinue).'SCRNSAVE.EXE') { ${regSet(SCR, 'SCRNSAVE.EXE', 'String', 'C:\\Windows\\system32\\scrnsave.scr')} }`, 'rundll32.exe user32.dll,UpdatePerUserSystemParameters'].join('; '),
    undo: (f) => { const s = f.screen || {}; const parts = [regRestore(SCR, 'ScreenSaveActive', 'String', s.active), regRestore(SCR, 'ScreenSaveTimeOut', 'String', s.timeout), regRestore(SCR, 'ScreenSaverIsSecure', 'String', s.secure), regRestore(SCR, 'SCRNSAVE.EXE', 'String', s.exe)]; return parts.includes(null) ? null : [...parts, 'rundll32.exe user32.dll,UpdatePerUserSystemParameters'].join('; '); },
    prevOf: (f) => f.screen }],
  'PC-17': [{ id: 'autoplay-off', label: '모든 미디어 자동 실행 끄기', admin: false, warn: '현재 사용자에게만 적용됩니다.', ...reg('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers', 'DisableAutoplay', 'DWord', 1, (f) => (f.autoplay || {}).disable) }],
  'PC-18': [{ id: 'remote-assist-off', label: '원격 지원 연결 허용 끄기', admin: true, warn: '다른 사람이 원격 지원으로 이 PC를 도와줄 수 없게 됩니다(원격 데스크톱 설정과는 별개).', ...reg('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance', 'fAllowToGetHelp', 'DWord', 0, (f) => f.remoteAssist) }],
};
// 점검 결과가 양호면 자동 조치를 내놓지 않는다(PC-13 업데이트는 언제나 가능).
const SHOW_WHEN_GOOD = new Set(['defender-update']);
function fixesFor(code, f) {
  return (FIXES[code] || []).filter((fix) => (fix.applyF ? fix.applyF(f) !== null : true));
}
const scriptOf = (fix, f) => (fix.applyF ? fix.applyF(f) : fix.apply(f));

// 설정 화면 열기(바꾸지 않고 해당 Windows 화면만 연다). 대상은 고정 목록.
export const OPENS = Object.freeze({
  secpol: { label: '로컬 보안 정책', cmd: "Start-Process secpol.msc" },
  netaccounts: { label: '계정 화면', cmd: "Start-Process ms-settings:yourinfo" },
  fsmgmt: { label: '공유 폴더 관리', cmd: "Start-Process fsmgmt.msc" },
  services: { label: '서비스', cmd: "Start-Process services.msc" },
  apps: { label: '설치된 앱', cmd: "Start-Process ms-settings:appsfeatures" },
  drives: { label: '내 PC(드라이브)', cmd: "Start-Process explorer.exe -ArgumentList 'shell:MyComputerFolder'" },
  msconfig: { label: '시스템 구성(msconfig)', cmd: "Start-Process msconfig.exe" },
  edgeclear: { label: 'Edge 닫을 때 지울 항목', cmd: "Start-Process msedge.exe -ArgumentList 'edge://settings/clearBrowsingDataOnClose'" },
  update: { label: 'Windows 업데이트', cmd: "Start-Process ms-settings:windowsupdate" },
  netplwiz: { label: '사용자 계정(netplwiz)', cmd: "Start-Process netplwiz.exe" },
  defender: { label: '바이러스 및 위협 방지', cmd: "Start-Process windowsdefender://threat" },
  firewall: { label: '방화벽 및 네트워크 보호', cmd: "Start-Process windowsdefender://network" },
  screensaver: { label: '화면 보호기 설정', cmd: "Start-Process control.exe -ArgumentList 'desk.cpl,,@screensaver'" },
  autoplay: { label: '자동 실행 설정', cmd: "Start-Process ms-settings:autoplay" },
  remote: { label: '원격 설정(sysdm.cpl)', cmd: "Start-Process SystemPropertiesRemote.exe" },
});
const OPENS_FOR = { 'PC-01': ['secpol'], 'PC-02': ['secpol'], 'PC-03': ['secpol'], 'PC-04': ['fsmgmt'], 'PC-05': ['services'], 'PC-06': ['apps'], 'PC-07': ['drives'], 'PC-08': ['msconfig'], 'PC-09': ['edgeclear'], 'PC-10': ['update'], 'PC-11': ['update'], 'PC-12': ['netplwiz'], 'PC-13': ['defender'], 'PC-14': ['defender'], 'PC-15': ['firewall'], 'PC-16': ['screensaver'], 'PC-17': ['autoplay'], 'PC-18': ['remote'] };

function defaultExec(script, { timeoutMs = 60000 } = {}) {
  return new Promise((resolve) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { timeout: timeoutMs, windowsHide: true, maxBuffer: 2097152, encoding: 'utf8' },
      (error, stdout) => resolve({ code: error ? (typeof error.code === 'number' ? error.code : error.killed ? 'TIMEOUT' : 'FAILED') : 0, stdout: String(stdout ?? '') }));
  });
}

// 관리자 조치: UAC 창으로 권한을 받은 PowerShell 에서 실행한다. 사용자가 UAC 를 거절하면 1223 으로 끝난다.
export function elevatedWrapper(script) {
  const encoded = Buffer.from(`$ErrorActionPreference = 'Stop'; try { ${script}; exit 0 } catch { exit 1 }`, 'utf16le').toString('base64');
  return `try { $p = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','${encoded}'; exit $p.ExitCode } catch { exit 1223 }`;
}

export function createKisaAudit({ exec = defaultExec, logFile = null, now = () => new Date(), tokenTtlMs = 120000, fs = { readFileSync, writeFileSync, renameSync, mkdirSync } } = {}) {
  let facts = null;
  let result = null;
  let running = null;
  const tokens = new Map();

  const readLog = () => { if (!logFile) return []; try { const v = JSON.parse(fs.readFileSync(logFile, 'utf8')); return Array.isArray(v) ? v : []; } catch { return []; } };
  const writeLog = (list) => { if (!logFile) return; fs.mkdirSync(dirname(logFile), { recursive: true }); fs.writeFileSync(`${logFile}.tmp`, JSON.stringify(list.slice(-200), null, 1), 'utf8'); fs.renameSync(`${logFile}.tmp`, logFile); };

  async function run() {
    if (running) return running;
    running = (async () => {
      const startedAt = now();
      const out = await exec(FACTS_SCRIPT, { timeoutMs: 90000 });
      let data = null;
      try { data = JSON.parse(out.stdout.trim()); } catch { data = null; }
      if (!data || typeof data !== 'object') { result = { status: 'unavailable', at: startedAt.toISOString(), reason: out.code === 'TIMEOUT' ? '제한 시간 안에 읽지 못했습니다.' : '점검 결과를 읽지 못했습니다.', items: [] }; return result; }
      facts = data;
      const items = evaluate(data, now());
      const counts = Object.fromEntries(Object.keys(VERDICT).map((k) => [k, items.filter((i) => i.verdict === k).length]));
      result = { status: 'measured', at: startedAt.toISOString(), durationMs: now() - startedAt, elevated: Boolean(data.elevated), source: SOURCE, counts, items };
      return result;
    })().finally(() => { running = null; });
    return running;
  }

  const findFix = (code, fixId) => (FIXES[code] || []).find((fix) => fix.id === fixId) || null;

  return Object.freeze({
    run,
    state: () => ({ result, history: readLog().slice(-30).reverse().map(({ prevFacts, ...rest }) => rest) }),
    // 조치 전 확인: 무엇을 어떻게 바꾸는지, 되돌릴 수 있는지 보여 주고 2분짜리 승인 표를 준다.
    preview({ code, fixId, undoId } = {}) {
      if (!facts) return { error: '먼저 점검을 실행하세요.' };
      if (undoId) {
        const entry = readLog().find((e) => e.id === undoId);
        if (!entry || entry.undoneAt) return { error: '되돌릴 기록이 없거나 이미 되돌렸습니다.' };
        const fix = findFix(entry.code, entry.fixId);
        const script = fix && fix.undo(entry.prevFacts || {});
        if (!script) return { error: '이 조치는 자동으로 되돌릴 수 없습니다(원래 값을 안전하게 복원할 수 없음).' };
        const token = randomUUID();
        tokens.set(token, { kind: 'undo', entryId: entry.id, code: entry.code, fixId: entry.fixId, script, admin: fix.admin, expires: now().getTime() + tokenTtlMs });
        return { token, code: entry.code, label: `되돌리기: ${fix.label}`, admin: fix.admin, warn: '조치하기 전 값으로 돌려놓습니다.', script };
      }
      const fix = findFix(code, fixId);
      if (!fix) return { error: '지원하지 않는 조치입니다.' };
      const script = scriptOf(fix, facts);
      if (!script) return { error: '지금 상태에서는 바꿀 것이 없습니다.' };
      const undoScript = fix.undo(facts);
      const token = randomUUID();
      tokens.set(token, { kind: 'apply', code, fixId, script, admin: fix.admin, prevFacts: facts, expires: now().getTime() + tokenTtlMs });
      return { token, code, label: fix.label, admin: fix.admin, warn: fix.warn, script, undoable: Boolean(undoScript) };
    },
    // 승인 표로만 실행한다. 표는 한 번 쓰면 없어진다.
    async apply(token) {
      const t = tokens.get(token);
      tokens.delete(token);
      if (!t || t.expires < now().getTime()) return { error: '확인 시간이 지났습니다. 다시 눌러 주세요.' };
      const out = await exec(t.admin ? elevatedWrapper(t.script) : `$ErrorActionPreference = 'Stop'; ${t.script}`, { timeoutMs: 180000 });
      const outcome = out.code === 0 ? 'done' : out.code === 1223 ? 'cancelled' : 'failed';
      const log = readLog();
      if (outcome === 'done') {
        if (t.kind === 'apply') log.push({ id: randomUUID(), at: now().toISOString(), code: t.code, fixId: t.fixId, label: (findFix(t.code, t.fixId) || {}).label, admin: t.admin, prevFacts: pickPrev(t.code, t.fixId, t.prevFacts), undoneAt: null });
        else { const e = log.find((x) => x.id === t.entryId); if (e) e.undoneAt = now().toISOString(); }
        try { writeLog(log); } catch { /* 기록 실패는 결과에 알린다 */ }
      }
      const after = await run();
      return { outcome, code: t.code, message: outcome === 'done' ? '적용했습니다. 아래 결과는 다시 점검한 값입니다.' : outcome === 'cancelled' ? 'Windows 권한 확인 창에서 취소했습니다. 바뀐 것은 없습니다.' : '실행하지 못했습니다(권한이나 정책 때문일 수 있음). 바뀐 것이 없는지 다시 점검한 결과를 확인하세요.', item: after.items ? after.items.find((i) => i.code === t.code) : null };
    },
    async open(target) {
      const o = OPENS[target];
      if (!o) return { error: '지원하지 않는 화면입니다.' };
      const out = await exec(o.cmd, { timeoutMs: 15000 });
      return { opened: out.code === 0, label: o.label };
    },
  });
}

// 되돌리기에 필요한 조치 전 값만 남긴다(점검 사실 전체를 저장하지 않음).
function pickPrev(code, fixId, f) {
  const keep = { 'PC-01': ['maxPwAge'], 'PC-02': ['minPwLen'], 'PC-03': ['recoveryLevel'], 'PC-04': ['autoShareWks'], 'PC-05': ['services'], 'PC-09': ['edgePolicy'], 'PC-12': ['autoAdminLogon'], 'PC-15': ['fwProfiles'], 'PC-16': ['screen'], 'PC-17': ['autoplay'], 'PC-18': ['remoteAssist'] }[code] || [];
  return Object.fromEntries(keep.map((k) => [k, f ? f[k] ?? null : null]));
}
