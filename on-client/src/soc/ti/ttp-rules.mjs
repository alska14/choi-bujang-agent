// TTP(전술·기법·절차) 탐지 규칙. 명령줄·에이전트 명령 문자열에서 알려진 공격 절차의 패턴을 찾는다.
// 규칙마다 ATT&CK 기법, 심각도, 신뢰도(오탐 가능성 반영)를 가진다. 패턴은 길이가 제한된 입력에만 적용해 정규식 폭주를 막는다.
import { attackRefs } from './attack.mjs';

const MAX_INPUT = 1200;

export const TTP_RULES = Object.freeze([
  { id: 'TTP-PS-ENCODED', name: '인코딩된 PowerShell 명령 실행', attack: ['T1059.001', 'T1027'], severity: 'high', confidence: 70, pattern: /powershell(?:\.exe)?\b[^\n]{0,200}?\s-(?:e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{20,}/i, description: 'PowerShell에 Base64로 인코딩된 명령을 넘기는 절차입니다. 정상 관리 스크립트에도 쓰여 오탐 가능성이 있습니다.' },
  { id: 'TTP-CERTUTIL-DOWNLOAD', name: 'certutil 로 파일 내려받기', attack: ['T1105'], severity: 'high', confidence: 80, pattern: /certutil(?:\.exe)?\b[^\n]{0,200}?\s-(?:urlcache|split)\b/i, description: 'certutil 을 도구 전송에 쓰는 절차입니다.' },
  { id: 'TTP-MSHTA-REMOTE', name: 'mshta 로 원격·스크립트 실행', attack: ['T1218.005'], severity: 'high', confidence: 80, pattern: /mshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)/i, description: 'mshta 가 원격 주소나 스크립트를 실행하는 절차입니다.' },
  { id: 'TTP-REGSVR32-REMOTE', name: 'regsvr32 로 원격 스크립틀릿 실행', attack: ['T1218.010'], severity: 'high', confidence: 80, pattern: /regsvr32(?:\.exe)?\b[^\n]{0,100}?(?:\/i:\s*https?:\/\/|scrobj\.dll)/i, description: 'regsvr32 가 원격 스크립틀릿을 불러오는 절차입니다.' },
  { id: 'TTP-BITS-TRANSFER', name: 'bitsadmin 전송', attack: ['T1197'], severity: 'medium', confidence: 50, pattern: /bitsadmin(?:\.exe)?\b[^\n]{0,100}?\/transfer/i, description: 'BITS 작업으로 파일을 전송하는 절차입니다. 정상 업데이트에도 쓰일 수 있습니다.' },
  { id: 'TTP-DOWNLOAD-EXEC', name: '내려받아 바로 실행', attack: ['T1105', 'T1059.001'], severity: 'high', confidence: 65, pattern: /(?:curl|wget|invoke-webrequest|iwr)\b[^\n|]{0,200}\|\s*(?:sh|bash|iex|invoke-expression|powershell)\b/i, description: '내려받은 내용을 파이프로 곧장 인터프리터에 넘기는 절차입니다. 설치 안내에도 흔해 오탐 가능성이 있습니다.' },
  { id: 'TTP-SCHTASK-CREATE', name: '예약 작업 생성', attack: ['T1053.005'], severity: 'medium', confidence: 40, pattern: /schtasks(?:\.exe)?\b[^\n]{0,100}?\/create/i, description: '예약 작업을 만드는 절차입니다. 정상 설치 프로그램도 사용합니다.' },
  { id: 'TTP-RUNKEY-ADD', name: '자동 실행(Run) 레지스트리 추가', attack: ['T1547.001'], severity: 'high', confidence: 60, pattern: /\breg(?:\.exe)?\s+add\s+[^\n]{0,80}?\\currentversion\\run/i, description: '로그인 때마다 실행되도록 Run 키에 값을 추가하는 절차입니다.' },
  { id: 'TTP-DEFENDER-DISABLE', name: 'Defender 보호 기능 끄기', attack: ['T1685'], severity: 'critical', confidence: 85, pattern: /set-mppreference\b[^\n]{0,120}?-disable\w+\s+(?:\$true|1)\b|disablerealtimemonitoring/i, description: 'Microsoft Defender 의 실시간 보호 등을 끄는 명령입니다.' },
  { id: 'TTP-FIREWALL-DISABLE', name: 'Windows 방화벽 끄기', attack: ['T1686.003'], severity: 'critical', confidence: 85, pattern: /netsh\s+(?:adv)?firewall\b[^\n]{0,80}?state\s+off|set-netfirewallprofile\b[^\n]{0,100}?-enabled\s+false/i, description: 'Windows 방화벽 프로필을 끄는 명령입니다.' },
  { id: 'TTP-LSASS-DUMP', name: 'LSASS 메모리 덤프', attack: ['T1003.001'], severity: 'critical', confidence: 85, pattern: /(?:procdump|rundll32)\b[^\n]{0,160}?(?:lsass|minidump)|sekurlsa|comsvcs\.dll[^\n]{0,60}?minidump/i, description: '로그인 자격 증명이 있는 LSASS 프로세스 메모리를 덤프하는 절차입니다.' },
  { id: 'TTP-SHADOW-DELETE', name: '복구 수단(섀도 복사본) 삭제', attack: ['T1490'], severity: 'critical', confidence: 85, pattern: /vssadmin\b[^\n]{0,60}?delete\s+shadows|wmic\b[^\n]{0,60}?shadowcopy[^\n]{0,30}?delete|bcdedit\b[^\n]{0,80}?recoveryenabled\s+no/i, description: '시스템 복구를 막기 위해 섀도 복사본이나 복구 설정을 지우는 절차입니다.' },
  { id: 'TTP-CLEAR-EVENTLOG', name: 'Windows 이벤트 로그 삭제', attack: ['T1685.005'], severity: 'high', confidence: 75, pattern: /wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog\b/i, description: '흔적을 지우기 위해 Windows 이벤트 로그를 지우는 명령입니다.' },
]);

export const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

// 문자열 하나에 모든 규칙을 적용한다. 반환: [{ rule, attack:[…], snippet }]
export function evaluateTtp(text, { rules = TTP_RULES } = {}) {
  const input = String(text ?? '').slice(0, MAX_INPUT);
  if (input.length < 6) return [];
  const found = [];
  for (const rule of rules) {
    const match = rule.pattern.exec(input);
    if (match) found.push({ rule, attack: attackRefs(rule.attack.map((id) => [id, rule.confidence])), snippet: match[0].slice(0, 160) });
  }
  return found;
}

// 어떤 기법을 어떤 규칙이 덮는지(탐지 범위). 화면의 ATT&CK 표가 쓴다.
export function coverage(rules = TTP_RULES) {
  const map = {};
  for (const rule of rules) for (const id of rule.attack) (map[id] ??= []).push(rule.id);
  return map;
}
