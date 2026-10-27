// 사건 기록 보관: 서버를 껐다 켜도 지난 사건을 다시 볼 수 있게 사건 목록을 파일 하나(JSON)에 저장한다.
// 저장 위치는 저장소 밖(기본: %LOCALAPPDATA%\djokovic-soc\events.json)이고, maxAgeDays 보다 오래된 사건과 max 건을 넘는 사건은 지운다.
// 사건이 생기거나 바뀔 때마다 바로 쓰지 않고 delayMs 동안 모아서 한 번에 쓴다. 임시 파일에 쓴 뒤 이름을 바꿔 반쯤 쓰인 파일이 남지 않게 한다.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function createEventLog({ file, store, maxAgeDays = 30, max = 2000, delayMs = 1500, now = () => Date.now(), fs = { readFileSync, writeFileSync, renameSync, mkdirSync } } = {}) {
  let timer = null;
  let unsubscribe = null;
  const info = { file: file ?? null, restored: 0, savedAt: null, error: null };

  const fresh = (event) => now() - Date.parse(event.lastAt || event.at) <= maxAgeDays * 86400000;

  function load() {
    if (!file) return 0;
    let data;
    try { data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) {
      if (error && error.code !== 'ENOENT') info.error = '사건 기록 파일을 읽지 못해 새로 시작했습니다.';
      return 0;
    }
    const list = Array.isArray(data && data.events) ? data.events.filter((e) => e && typeof e.at === 'string' && fresh(e)).slice(-max) : [];
    info.restored = store.restore(list);
    return info.restored;
  }

  function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!file) return false;
    const events = store.all().filter(fresh).slice(-max);
    const tmp = `${file}.tmp`;
    try {
      fs.mkdirSync(dirname(file), { recursive: true });
      fs.writeFileSync(tmp, JSON.stringify({ version: 1, savedAt: new Date(now()).toISOString(), events }), 'utf8');
      fs.renameSync(tmp, file);
      info.savedAt = new Date(now()).toISOString();
      info.error = null;
      return true;
    } catch {
      info.error = '사건 기록을 파일에 쓰지 못했습니다(화면의 사건은 그대로 남아 있습니다).';
      return false;
    }
  }

  const schedule = () => { if (!timer) { timer = setTimeout(flush, delayMs); timer.unref?.(); } };

  return Object.freeze({
    load,
    flush,
    start() { if (!unsubscribe) unsubscribe = store.subscribe(schedule); },
    stop() { if (unsubscribe) { unsubscribe(); unsubscribe = null; } if (timer) flush(); },
    status: () => ({ ...info, maxAgeDays, max }),
  });
}
