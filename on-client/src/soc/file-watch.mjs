// 지정한 폴더의 파일 생성·수정·삭제·이름 변경을 감시한다. 읽기(열람)는 Windows가 알려 주지 않아 감지하지 못한다.
// 민감 폴더(.ssh, .aws)의 변경은 긴급, 시작 프로그램 폴더·hosts 파일의 변경은 높음(자동 실행·접속 주소 바꿔치기에 쓰이는 곳),
// 그 밖의 감시 폴더는 짧은 시간의 대량 변경만 높음으로 알린다. 모든 Windows PC에 있는 시작 프로그램 폴더와 hosts 폴더는 기본으로 감시한다.
import { watch as fsWatch, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const RULES = Object.freeze({
  'FILE-SENSITIVE-CHANGE': '민감한 폴더(키·인증 정보)의 파일이 생성·수정·삭제·이름 변경됨',
  'FILE-BURST': '감시 폴더에서 10초 안에 파일 변경이 200건 이상 발생함',
  'FILE-STARTUP-CHANGE': '로그인할 때 자동으로 실행되는 시작 프로그램 폴더에 파일이 생기거나 바뀜',
  'FILE-HOSTS-CHANGE': '도메인을 다른 주소로 돌릴 수 있는 hosts 파일이 바뀜',
});

export function defaultWatchTargets({ home = homedir(), exists = existsSync, extra = [], appData = process.env.APPDATA, systemRoot = process.env.SystemRoot } = {}) {
  const sensitive = [join(home, '.ssh'), join(home, '.aws')].filter((dir) => exists(dir)).map((dir) => ({ dir, sensitive: true, kind: 'keys' }));
  const system = [];
  if (appData) system.push({ dir: join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), sensitive: false, kind: 'startup' });
  if (systemRoot) system.push({ dir: join(systemRoot, 'System32', 'drivers', 'etc'), sensitive: false, kind: 'hosts' });
  return [...sensitive, ...system.filter((t) => exists(t.dir)), ...extra.filter((dir) => exists(dir)).map((dir) => ({ dir, sensitive: false, kind: 'custom' }))];
}

// 시작 프로그램 폴더·hosts 는 Windows가 읽기만 해도 변경 알림을 보내는 경우가 있어서, 알리기 전에 실제 내용이 바뀌었는지 지문으로 확인한다.
function defaultFingerprint(target) {
  try {
    if (target.kind === 'hosts') return createHash('sha256').update(readFileSync(join(target.dir, 'hosts'))).digest('hex');
    if (target.kind === 'startup') return readdirSync(target.dir).sort().map((name) => { try { const st = statSync(join(target.dir, name)); return `${name}:${st.size}:${Math.round(st.mtimeMs)}`; } catch { return `${name}:?`; } }).join('|');
  } catch { return null; }
  return null;
}

export function createFileWatcher({ targets = [], store, watch = fsWatch, now = () => Date.now(), burstLimit = 200, burstWindowMs = 10000, fingerprint = defaultFingerprint } = {}) {
  const prints = new Map();
  // 지문이 그대로면 false(알리지 않음). 지문을 못 구하면 알린다(확인할 수 없는 것을 정상으로 넘기지 않음).
  const changedFor = (target) => { const next = fingerprint(target); if (next === null) return true; const before = prints.get(target.dir); prints.set(target.dir, next); return before !== next; };
  // 시작 프로그램 폴더는 Windows가 알려 주는 파일 이름(desktop.ini 등)이 실제로 바뀐 파일과 다를 수 있어, 목록 지문을 비교해 바뀐 파일을 직접 찾는다.
  const listing = (print) => new Map(String(print ?? '').split('|').filter(Boolean).map((entry) => { const i = entry.indexOf(':'); return i < 0 ? [entry, ''] : [entry.slice(0, i), entry.slice(i + 1)]; }));
  const startupChanges = (target) => {
    const next = fingerprint(target);
    if (next === null) return null; // 확인할 수 없으면 알린다
    const before = prints.get(target.dir);
    prints.set(target.dir, next);
    if (before === next) return [];
    const a = listing(before), b = listing(next);
    return [...new Set([...a.keys(), ...b.keys()])].filter((n) => a.get(n) !== b.get(n)).slice(0, 5).map((n) => `${n}(${!a.has(n) ? '새로 생김' : !b.has(n) ? '삭제됨' : '바뀜'})`);
  };
  const handles = [];
  const bursts = new Map();
  const lastSeen = new Map();
  const stats = { watching: [], events: 0, errors: 0 };

  function onChange(target, type, filename) {
    const t = now();
    const name = typeof filename === 'string' ? filename.slice(0, 200) : '(이름 확인 불가)';
    const dedupeKey = `${target.dir}\u0000${name}`;
    if (t - (lastSeen.get(dedupeKey) ?? -Infinity) < 1000) return; // Windows는 한 번의 쓰기에 이벤트를 여러 번 보낸다
    lastSeen.set(dedupeKey, t);
    if (lastSeen.size > 5000) lastSeen.clear();
    stats.events += 1;
    if (target.sensitive) {
      store.add({ severity: 'critical', source: 'files', title: `민감 폴더의 파일이 변경됨: ${name}`, detail: `${target.dir} 안에서 ${type === 'rename' ? '생성·삭제·이름 변경' : '수정'}이 감지됐습니다. 열람은 감지하지 못합니다.`, evidence: { dir: target.dir, file: name, type }, rule: { id: 'FILE-SENSITIVE-CHANGE', text: RULES['FILE-SENSITIVE-CHANGE'] }, key: `FILE-SENSITIVE-CHANGE:${target.dir}` });
    }
    const changes = target.kind === 'startup' ? startupChanges(target) : [];
    if (target.kind === 'startup' && (changes === null || changes.length > 0)) {
      const what = changes ? changes.join(', ') : name;
      store.add({ severity: 'high', source: 'files', title: `시작 프로그램 폴더 변경: ${what}`, detail: `${target.dir} 안에서 바뀐 파일: ${what}. 직접 설치하거나 설정한 것이 아니라면 확인하세요(로그인할 때마다 자동 실행됨).`, evidence: { dir: target.dir, files: changes ?? [name], type }, rule: { id: 'FILE-STARTUP-CHANGE', text: RULES['FILE-STARTUP-CHANGE'] }, key: `FILE-STARTUP-CHANGE:${what}` });
    }
    if (target.kind === 'hosts' && name.toLowerCase() === 'hosts' && changedFor(target)) {
      store.add({ severity: 'high', source: 'files', title: 'hosts 파일이 변경됨', detail: `${target.dir}\\hosts 가 바뀌었습니다. 특정 사이트 주소를 다른 곳으로 돌리는 데 쓰일 수 있으니 직접 바꾼 것인지 확인하세요.`, evidence: { dir: target.dir, file: name, type }, rule: { id: 'FILE-HOSTS-CHANGE', text: RULES['FILE-HOSTS-CHANGE'] }, key: 'FILE-HOSTS-CHANGE' });
    }
    const list = (bursts.get(target.dir) ?? []).filter((time) => t - time < burstWindowMs);
    list.push(t);
    bursts.set(target.dir, list);
    if (list.length >= burstLimit) {
      store.add({ severity: 'high', source: 'files', title: `감시 폴더에서 파일 변경이 ${list.length}건 발생`, detail: `${target.dir}: 10초 안의 대량 변경입니다. 의도한 작업인지 확인하세요.`, evidence: { dir: target.dir, count: list.length, windowSeconds: burstWindowMs / 1000 }, rule: { id: 'FILE-BURST', text: RULES['FILE-BURST'] }, key: `FILE-BURST:${target.dir}` });
    }
  }

  return Object.freeze({
    start() {
      for (const target of targets) {
        try {
          if (target.kind === 'startup' || target.kind === 'hosts') prints.set(target.dir, fingerprint(target));
          const handle = watch(target.dir, { recursive: true, persistent: false }, (type, filename) => onChange(target, type, filename));
          handle.on('error', () => { stats.errors += 1; });
          handles.push(handle);
          stats.watching.push({ dir: target.dir, sensitive: target.sensitive, kind: target.kind ?? 'custom' });
        } catch { stats.errors += 1; }
      }
    },
    stop() { for (const handle of handles.splice(0)) { try { handle.close(); } catch { /* 이미 닫힘 */ } } },
    status: () => ({ watching: stats.watching.slice(), events: stats.events, errors: stats.errors, note: '변경(생성·수정·삭제·이름 변경)만 감지하며 파일 열람은 감지하지 못합니다.' }),
    onChange,
  });
}
