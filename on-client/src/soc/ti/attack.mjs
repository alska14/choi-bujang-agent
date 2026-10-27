// MITRE ATT&CK 기법 목록. 2026-10-27에 attack.mitre.org(ATT&CK v20)에서 ID와 이름, 전술을 직접 확인한 것만 넣었다.
// v20에서 "Defense Evasion"이 "Stealth"(TA0005)와 "Defense Impairment"(TA0112)로 나뉘었고, 방화벽·보안 도구·이벤트 로그 관련 기법의 ID가 바뀌었다.
// 목록에 없는 기법은 이 앱이 만들어 내지 않는다. 새 버전이 나오면 이 파일을 갱신해야 한다.
export const ATTACK_VERSION = 'v20';
export const ATTACK_CHECKED_ON = '2026-10-27';

export const TACTICS = Object.freeze({
  TA0001: 'Initial Access', TA0002: 'Execution', TA0003: 'Persistence', TA0004: 'Privilege Escalation', TA0005: 'Stealth', TA0112: 'Defense Impairment',
  TA0006: 'Credential Access', TA0007: 'Discovery', TA0009: 'Collection', TA0010: 'Exfiltration', TA0011: 'Command and Control', TA0040: 'Impact',
});

const t = (id, name, tactics) => [id, { id, name, tactics, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` }];
export const TECHNIQUES = Object.freeze(Object.fromEntries([
  t('T1059.001', 'Command and Scripting Interpreter: PowerShell', ['TA0002']),
  t('T1053.005', 'Scheduled Task/Job: Scheduled Task', ['TA0002', 'TA0003', 'TA0004']),
  t('T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', ['TA0003', 'TA0004']),
  t('T1027', 'Obfuscated Files or Information', ['TA0005']),
  t('T1218.005', 'System Binary Proxy Execution: Mshta', ['TA0005']),
  t('T1218.010', 'System Binary Proxy Execution: Regsvr32', ['TA0005']),
  t('T1197', 'BITS Jobs', ['TA0005', 'TA0003', 'TA0002']),
  t('T1686.003', 'Disable or Modify System Firewall: Windows Host Firewall', ['TA0112']),
  t('T1685', 'Disable or Modify Tools', ['TA0112']),
  t('T1685.005', 'Disable or Modify Tools: Clear Windows Event Logs', ['TA0112']),
  t('T1552.001', 'Unsecured Credentials: Credentials In Files', ['TA0006']),
  t('T1552.004', 'Unsecured Credentials: Private Keys', ['TA0006']),
  t('T1555.003', 'Credentials from Password Stores: Credentials from Web Browsers', ['TA0006']),
  t('T1003.001', 'OS Credential Dumping: LSASS Memory', ['TA0006']),
  t('T1083', 'File and Directory Discovery', ['TA0007']),
  t('T1005', 'Data from Local System', ['TA0009']),
  t('T1052.001', 'Exfiltration Over Physical Medium: Exfiltration over USB', ['TA0010']),
  t('T1105', 'Ingress Tool Transfer', ['TA0011']),
  t('T1571', 'Non-Standard Port', ['TA0011']),
  t('T1490', 'Inhibit System Recovery', ['TA0040']),
  t('T1496.001', 'Resource Hijacking: Compute Hijacking', ['TA0040']),
  t('T1136.001', 'Create Account: Local Account', ['TA0003']),
  t('T1098', 'Account Manipulation', ['TA0003', 'TA0004']),
  t('T1078.001', 'Valid Accounts: Default Accounts', ['TA0005', 'TA0003', 'TA0004', 'TA0001']),
  t('T1078.003', 'Valid Accounts: Local Accounts', ['TA0005', 'TA0003', 'TA0004', 'TA0001']),
]));

export const techniqueInfo = (id) => (TECHNIQUES[id] ? { id, name: TECHNIQUES[id].name, tactics: TECHNIQUES[id].tactics.map((tactic) => ({ id: tactic, name: TACTICS[tactic] })) } : null);
export const isKnownTechnique = (id) => Object.hasOwn(TECHNIQUES, id);

// 이 앱의 탐지 규칙이 어떤 ATT&CK 기법과 관련될 수 있는지. 연결은 "가능성"이며 확정이 아니다(confidence 0~100).
export const RULE_TO_ATTACK = Object.freeze({
  'FW-OFF-ALL': [['T1686.003', 70]],
  'FW-OFF': [['T1686.003', 50]],
  'DEF-RT-OFF': [['T1685', 70]],
  'DEF-AV-OFF': [['T1685', 70]],
  'AGENT-BURST': [['T1083', 40], ['T1005', 40]],
  'PORT-NEW-EXPOSED': [['T1571', 25]],
  'CPU-CRIT': [['T1496.001', 20]],
  'NET-FWRULE-NEW': [['T1686.003', 50]],
  'IAM-NEW-ACCOUNT': [['T1136.001', 70]],
  'IAM-ADMIN-ADDED': [['T1098', 70]],
  'IAM-GUEST-ENABLED': [['T1078.001', 60]],
  'IAM-NO-PWREQ': [['T1078.003', 30]],
  'IAM-AUTOLOGON': [['T1078.003', 30]],
  'INV-NEW-TASK': [['T1053.005', 40]],
  'INV-NEW-TASK-SCRIPT': [['T1053.005', 60]],
  'USB-NEW-STORAGE': [['T1052.001', 20]],
});

// 민감 경로의 종류에 따라 자격 증명 접근 기법을 고른다.
export function attackForSensitivePath(path) {
  const p = String(path ?? '').replace(/\\/g, '/').toLowerCase();
  if (/\/\.ssh\/|id_(rsa|ed25519|ecdsa|dsa)|\.(pem|pfx|p12|keystore|jks)$|\.kdbx$/.test(p)) return [['T1552.004', 70]];
  if (/\/user data\/|\/firefox\/profiles\/|login data|cookies/.test(p)) return [['T1555.003', 70]];
  if (/\.env|credentials|\.aws\/|\.netrc|\.npmrc|\.pypirc|secrets?(\.|$)|\.azure\/|\.kube\/|gcloud/.test(p)) return [['T1552.001', 70]];
  return [['T1552.001', 40]];
}

export function attackRefs(pairs) {
  return pairs.filter(([id]) => isKnownTechnique(id)).map(([id, confidence]) => ({ id, name: TECHNIQUES[id].name, tactics: TECHNIQUES[id].tactics.map((x) => TACTICS[x]), confidence, url: TECHNIQUES[id].url }));
}
