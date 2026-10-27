// 설치 프로그램·예약 작업·USB 저장장치 감시. 모두 일반 사용자 권한으로 읽기만 하며 아무것도 지우거나 막지 않는다.
// - 설치 프로그램: 레지스트리 Uninstall 목록(이 PC 전체 + 현재 사용자). Windows 제어판 「프로그램 추가/제거」와 같은 출처다.
// - 예약 작업: Get-ScheduledTask. 일반 권한으로 보이는 작업만 읽힌다(관리자만 볼 수 있는 일부 작업은 빠질 수 있다).
// - USB 저장장치: Win32_DiskDrive(USB 연결) + 이동식 드라이브. 장치 일련번호는 화면·사건에 내보내지 않고 짧은 지문으로만 구분한다.
// 프로그램·예약 작업의 기준 목록은 파일에 남겨 두어, 서버가 꺼져 있는 동안 새로 생긴 것도 다음 실행 때 알린다.
// 첫 실행에는 기준 목록만 만들고 알리지 않는다(이미 있던 것을 새것으로 오인하지 않기 위해).
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { runPowerShell } from '../pc-status/security-reader.mjs';
import { attackRefs } from './ti/attack.mjs';

export const RULES = Object.freeze({
  'INV-NEW-PROGRAM': '기준 목록에 없던 프로그램이 새로 설치됨',
  'INV-NEW-TASK': '기준 목록에 없던 예약 작업이 새로 생기거나 실행 대상이 바뀜',
  'INV-NEW-TASK-SCRIPT': '새 예약 작업이 스크립트 실행기(PowerShell·cmd·mshta 등)를 실행함',
  'USB-NEW-STORAGE': '새 USB·이동식 저장장치가 연결됨',
});

const CATCH = "catch { [ordered]@{ error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }";

const PROGRAMS_SCRIPT = `try { $keys = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
$p = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher; installDate = [string]$_.InstallDate; scope = if ([string]$_.PSPath -like '*HKEY_CURRENT_USER*') { 'user' } else { 'machine' } } })
ConvertTo-Json -InputObject $p -Compress } ${CATCH}`;

const TASKS_SCRIPT = `try { $t = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object { $a = @($_.Actions | Where-Object { $_.Execute } | Select-Object -First 1); [ordered]@{ path = [string]$_.TaskPath; name = [string]$_.TaskName; state = [string]$_.State; author = [string]$_.Author; exec = if ($a.Count) { [string]$a[0].Execute } else { '' }; args = if ($a.Count) { [string]$a[0].Arguments } else { '' } } })
ConvertTo-Json -InputObject $t -Compress } ${CATCH}`;

const USB_SCRIPT = `try { $d = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.InterfaceType -eq 'USB' -or [string]$_.PNPDeviceID -like 'USBSTOR*' } | ForEach-Object { $letters = @(Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_DiskPartition -ErrorAction SilentlyContinue | ForEach-Object { Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_LogicalDisk -ErrorAction SilentlyContinue } | ForEach-Object { [string]$_.DeviceID }); [ordered]@{ id = [string]$_.PNPDeviceID; model = [string]$_.Model; size = [double]$_.Size; letters = $letters } })
$r = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ letter = [string]$_.DeviceID; label = [string]$_.VolumeName; size = [double]$_.Size } })
[ordered]@{ disks = $d; removable = $r } | ConvertTo-Json -Compress -Depth 4 } ${CATCH}`;

const SCRIPT_RUNNER = /(^|[\\/])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)(\.exe)?$/i;
const USER_WRITABLE = /\\(appdata|temp|downloads|users\\public|programdata)\\/i;

const parse = (text) => { try { return JSON.parse(String(text).trim()); } catch { return undefined; } };
const arr = (value) => (Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : []);
const str = (value, max) => (typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '');
const fp = (value) => createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
const gb = (bytes) => (Number.isFinite(bytes) && bytes > 0 ? Math.round((bytes / 1073741824) * 10) / 10 : null);

export const programKey = (p) => `${p.scope}|${p.name.toLowerCase()}|${p.publisher.toLowerCase()}`;
export const taskKey = (t) => `${t.path}${t.name}|${t.exec.toLowerCase()}`.toLowerCase();

export function parsePrograms(data) {
  const seen = new Map();
  for (const x of arr(data)) {
    const p = { name: str(x && x.name, 120), version: str(x && x.version, 40), publisher: str(x && x.publisher, 80), installDate: str(x && x.installDate, 8), scope: x && x.scope === 'user' ? 'user' : 'machine' };
    if (p.name) seen.set(programKey(p), p);
  }
  return [...seen.values()];
}

export function parseTasks(data) {
  const seen = new Map();
  for (const x of arr(data)) {
    const t = { path: str(x && x.path, 200) || '\\', name: str(x && x.name, 120), state: str(x && x.state, 20), author: str(x && x.author, 80), exec: str(x && x.exec, 260), args: str(x && x.args, 200) };
    if (t.name) seen.set(taskKey(t), t);
  }
  return [...seen.values()];
}

export function parseUsb(data) {
  const devices = [];
  const lettersOnDisks = new Set();
  for (const x of arr(data && data.disks)) {
    const letters = arr(x && x.letters).filter((l) => typeof l === 'string').map((l) => l.slice(0, 3));
    letters.forEach((l) => lettersOnDisks.add(l));
    devices.push({ key: `usb:${fp(str(x && x.id, 300) || str(x && x.model, 120))}`, kind: 'usb', model: str(x && x.model, 80) || '(이름 없음)', sizeGb: gb(Number(x && x.size)), letters });
  }
  for (const x of arr(data && data.removable)) {
    const letter = str(x && x.letter, 3);
    if (!letter || lettersOnDisks.has(letter)) continue;
    devices.push({ key: `vol:${letter}:${fp(str(x && x.label, 60))}`, kind: 'removable', model: str(x && x.label, 60) || '이동식 드라이브', sizeGb: gb(Number(x && x.size)), letters: [letter] });
  }
  return devices;
}

// 새 예약 작업의 위험도: 스크립트 실행기를 부르면 높음, 그 밖에는 주의.
export function taskFinding(task) {
  const script = SCRIPT_RUNNER.test(task.exec.replace(/"/g, ''));
  const writable = USER_WRITABLE.test(task.exec);
  const where = `${task.path}${task.name}`;
  return {
    ruleId: script ? 'INV-NEW-TASK-SCRIPT' : 'INV-NEW-TASK',
    severity: script ? 'high' : 'medium',
    title: `새 예약 작업: ${where}`,
    detail: `실행 대상: ${task.exec || '(프로그램이 아닌 작업)'}${task.args ? ` ${task.args.slice(0, 120)}` : ''}${task.author ? ` · 만든 이: ${task.author}` : ''}.${script ? ' 스크립트 실행기를 부르는 작업은 악성 코드가 자리 잡을 때 자주 쓰는 방식입니다.' : writable ? ' 사용자 폴더(AppData·Temp 등)에 있는 프로그램을 실행합니다.' : ''} 직접 설치한 프로그램이 만든 것인지 확인하세요.`,
    evidence: { task: where, exec: task.exec, state: task.state },
    attack: attackRefs([['T1053.005', script ? 60 : 40]]),
  };
}

export function createInventory({ store, file = null, run = runPowerShell, now = () => new Date(), softwareMs = 300000, usbMs = 15000, fs = { readFileSync, writeFileSync, renameSync, mkdirSync } } = {}) {
  let baseline = null; // { programs: string[], tasks: string[], createdAt }
  let softwareTimer = null;
  let usbTimer = null;
  let softwareBusy = false;
  let usbBusy = false;
  let usbPrevious = null; // Map(key → device)
  const state = {
    programs: { status: 'pending', count: null, added: [], measuredAt: null, reason: null },
    tasks: { status: 'pending', count: null, added: [], measuredAt: null, reason: null },
    usb: { status: 'pending', devices: [], measuredAt: null, reason: null },
    baseline: { createdAt: null, firstRun: false, error: null },
  };

  async function read(script, timeoutMs) {
    let output;
    try { output = await run(script, { timeoutMs }); } catch (error) { return { error: error && error.code === 'TIMEOUT' ? '제한 시간 안에 읽지 못했습니다.' : '읽는 도중 오류가 났습니다.' }; }
    const data = parse(output);
    if (data === undefined) return { error: '응답 형식을 확인할 수 없습니다.' };
    if (data && !Array.isArray(data) && typeof data === 'object' && typeof data.error === 'string') {
      return { error: /^(UnauthorizedAccess|Security|Access)/.test(data.error) ? '이 계정 권한으로는 읽을 수 없습니다(관리자 권한이 필요한 항목은 읽지 않습니다).' : '읽지 못했습니다.' };
    }
    return { data };
  }

  function loadBaseline() {
    if (!file) return null;
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (Array.isArray(data.programs) && Array.isArray(data.tasks)) return { programs: data.programs.filter((x) => typeof x === 'string'), tasks: data.tasks.filter((x) => typeof x === 'string'), createdAt: typeof data.createdAt === 'string' ? data.createdAt : null };
    } catch { /* 없거나 깨졌으면 새로 만든다 */ }
    return null;
  }

  function saveBaseline() {
    if (!file || !baseline) return;
    try {
      fs.mkdirSync(dirname(file), { recursive: true });
      fs.writeFileSync(`${file}.tmp`, JSON.stringify({ version: 1, createdAt: baseline.createdAt, updatedAt: now().toISOString(), programs: baseline.programs, tasks: baseline.tasks }), 'utf8');
      fs.renameSync(`${file}.tmp`, file);
      state.baseline.error = null;
    } catch { state.baseline.error = '기준 목록 파일을 쓰지 못했습니다. 서버를 다시 켜면 그동안 생긴 것을 알리지 못할 수 있습니다.'; }
  }

  async function scanSoftware() {
    if (softwareBusy) return;
    softwareBusy = true;
    try {
      const [programsRead, tasksRead] = await Promise.all([read(PROGRAMS_SCRIPT, 30000), read(TASKS_SCRIPT, 40000)]);
      const at = now().toISOString();
      if (baseline === null) {
        baseline = loadBaseline();
        if (baseline === null) { baseline = { programs: null, tasks: null, createdAt: at }; state.baseline.firstRun = true; }
        state.baseline.createdAt = baseline.createdAt;
      }
      let changed = false;
      if (programsRead.error) Object.assign(state.programs, { status: 'unavailable', reason: programsRead.error, measuredAt: at });
      else {
        const programs = parsePrograms(programsRead.data);
        const keys = programs.map(programKey);
        if (baseline.programs) {
          const known = new Set(baseline.programs);
          const added = programs.filter((p) => !known.has(programKey(p)));
          for (const p of added) {
            store.add({
              severity: 'medium', source: 'inventory', title: `새 프로그램 설치됨: ${p.name}${p.version ? ` ${p.version}` : ''}`,
              detail: `${p.publisher ? `배포자: ${p.publisher} · ` : ''}${p.scope === 'user' ? '현재 사용자에게만 설치됨(관리자 권한 없이 설치 가능한 위치)' : '이 PC 전체에 설치됨'}. 직접 설치한 것이 아니라면 확인하세요.`,
              evidence: { name: p.name, version: p.version, publisher: p.publisher, scope: p.scope }, rule: { id: 'INV-NEW-PROGRAM', text: RULES['INV-NEW-PROGRAM'] }, key: `INV-NEW-PROGRAM:${programKey(p)}`,
            });
          }
          state.programs.added = [...added.map((p) => ({ name: p.name, version: p.version, at })), ...state.programs.added].slice(0, 10);
        }
        baseline.programs = keys;
        changed = true;
        Object.assign(state.programs, { status: 'measured', count: programs.length, measuredAt: at, reason: null });
      }
      if (tasksRead.error) Object.assign(state.tasks, { status: 'unavailable', reason: tasksRead.error, measuredAt: at });
      else {
        const tasks = parseTasks(tasksRead.data);
        if (baseline.tasks) {
          const known = new Set(baseline.tasks);
          const added = tasks.filter((t) => !known.has(taskKey(t)));
          for (const t of added) {
            const f = taskFinding(t);
            store.add({ severity: f.severity, source: 'inventory', title: f.title, detail: f.detail, evidence: f.evidence, rule: { id: f.ruleId, text: RULES[f.ruleId] }, key: `INV-NEW-TASK:${taskKey(t)}`, attack: f.attack });
          }
          state.tasks.added = [...added.map((t) => ({ name: `${t.path}${t.name}`, exec: t.exec, at })), ...state.tasks.added].slice(0, 10);
        }
        baseline.tasks = tasks.map(taskKey);
        changed = true;
        Object.assign(state.tasks, { status: 'measured', count: tasks.length, measuredAt: at, reason: null });
      }
      if (changed && baseline.programs && baseline.tasks) saveBaseline();
    } finally { softwareBusy = false; }
  }

  async function scanUsb() {
    if (usbBusy) return;
    usbBusy = true;
    try {
      const result = await read(USB_SCRIPT, 15000);
      const at = now().toISOString();
      if (result.error) { Object.assign(state.usb, { status: 'unavailable', reason: result.error, measuredAt: at }); return; }
      const devices = parseUsb(result.data);
      const current = new Map(devices.map((d) => [d.key, d]));
      if (usbPrevious) {
        for (const d of devices) {
          if (usbPrevious.has(d.key)) continue;
          store.add({
            severity: 'medium', source: 'usb', title: `USB 저장장치 연결됨: ${d.model}${d.letters.length ? ` (${d.letters.join(', ')})` : ''}`,
            detail: `${d.sizeGb !== null ? `용량 ${d.sizeGb}GB. ` : ''}직접 꽂은 장치가 아니라면 확인하세요. USB 저장장치는 자료를 빼 가거나 악성 파일을 들여오는 경로로 쓰일 수 있습니다.`,
            evidence: { model: d.model, letters: d.letters, sizeGb: d.sizeGb, kind: d.kind }, rule: { id: 'USB-NEW-STORAGE', text: RULES['USB-NEW-STORAGE'] }, key: `USB-NEW-STORAGE:${d.key}`, attack: attackRefs([['T1052.001', 20]]),
          });
        }
        for (const [key, d] of usbPrevious) if (!current.has(key)) store.add({ severity: 'info', source: 'usb', title: `USB 저장장치 분리됨: ${d.model}`, detail: '', evidence: { model: d.model, letters: d.letters }, rule: null });
      }
      usbPrevious = current;
      Object.assign(state.usb, { status: 'measured', devices: devices.map(({ key, ...rest }) => rest), measuredAt: at, reason: null });
    } finally { usbBusy = false; }
  }

  return Object.freeze({
    scanSoftware, scanUsb,
    start() {
      scanSoftware().catch(() => {});
      scanUsb().catch(() => {});
      softwareTimer = setInterval(() => { scanSoftware().catch(() => {}); }, softwareMs); softwareTimer.unref?.();
      usbTimer = setInterval(() => { scanUsb().catch(() => {}); }, usbMs); usbTimer.unref?.();
    },
    stop() { clearInterval(softwareTimer); clearInterval(usbTimer); },
    status: () => ({
      programs: { ...state.programs, added: state.programs.added.slice() }, tasks: { ...state.tasks, added: state.tasks.added.slice() },
      usb: { ...state.usb, devices: state.usb.devices.slice() }, baseline: { ...state.baseline }, intervals: { softwareSeconds: softwareMs / 1000, usbSeconds: usbMs / 1000 },
    }),
  });
}
