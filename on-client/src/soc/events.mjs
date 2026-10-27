import { domainOf } from './domains.mjs';

// 관제 사건 저장소. 최근 max 건을 메모리에 둔다. 파일 보관은 event-log.mjs 가 맡는다(이 모듈은 파일에 쓰지 않는다).
export const SEVERITY = Object.freeze({
  critical: { rank: 4, label: '긴급' },
  high: { rank: 3, label: '높음' },
  medium: { rank: 2, label: '주의' },
  low: { rank: 1, label: '낮음' },
  info: { rank: 0, label: '정보' },
});

const clip = (value, max) => (typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max) : '');

export function createEventStore({ max = 500, now = () => new Date(), cooldownMs = 60000 } = {}) {
  const events = [];
  const listeners = new Set();
  let nextId = 1;

  const emit = (type, payload) => { for (const listener of listeners) { try { listener(type, payload); } catch { /* 한 구독자의 오류가 저장소를 멈추지 않게 한다 */ } } };

  return Object.freeze({
    // key 가 같고 확인 전이며 쿨다운 안이면 새 사건을 만들지 않고 횟수만 올린다(경보 반복 방지).
    add({ severity, source, title, detail = '', evidence = null, rule = null, test = false, key = null, attack = [], quietMs = 0 }) {
      if (!SEVERITY[severity]) throw Error('INVALID_SEVERITY');
      const clock = now();
      const at = clock.toISOString();
      // 사용자가 확인(ack)한 같은 사건은 quietMs 동안 다시 경보를 만들지 않는다(계속 이어지는 연결이 확인 직후 다시 울리는 것을 막는다).
      if (key && quietMs > 0) {
        const acked = [...events].reverse().find((event) => event.key === key && event.ack && event.ackAt && clock.getTime() - Date.parse(event.ackAt) < quietMs);
        if (acked) return { event: acked, created: false, suppressed: true };
      }
      if (key) {
        // 되살린 미확인 사건(서버 재시작 전 것)도 같은 문제가 이어지는 것이므로 새로 만들지 않고 이어 센다.
        const existing = [...events].reverse().find((event) => event.key === key && !event.ack && (event.restored || clock.getTime() - Date.parse(event.lastAt) < cooldownMs));
        if (existing) {
          existing.count += 1;
          existing.lastAt = at;
          if (detail) existing.detail = clip(detail, 400);
          emit('updated', existing);
          return { event: existing, created: false };
        }
      }
      const event = {
        id: nextId++, at, lastAt: at, severity, source: clip(source, 40), title: clip(title, 160), detail: clip(detail, 400),
        evidence, rule: rule ? { id: clip(rule.id, 40), text: clip(rule.text, 200) } : null, test: Boolean(test), key, count: 1, ack: false, ackAt: null,
        attack: Array.isArray(attack) ? attack.slice(0, 6) : [], verdict: null, domain: domainOf({ source, rule, evidence }),
      };
      events.push(event);
      while (events.length > max) events.shift();
      emit('created', event);
      return { event, created: true };
    },
    ack(id) {
      const event = events.find((item) => item.id === id);
      if (!event || event.ack) return false;
      event.ack = true;
      event.ackAt = now().toISOString();
      emit('ack', [event.id]);
      return true;
    },
    ackAll(minRank = 0) {
      const ids = [];
      for (const event of events) if (!event.ack && SEVERITY[event.severity].rank >= minRank) { event.ack = true; event.ackAt = now().toISOString(); ids.push(event.id); }
      if (ids.length > 0) emit('ack', ids);
      return ids;
    },
    // 파일에 남겨 둔 지난 사건을 되살린다(서버 재시작 뒤). 'created'를 내보내지 않아 지난 사건으로 팝업·소리가 다시 나지 않는다.
    restore(list) {
      let restored = 0;
      for (const raw of Array.isArray(list) ? list : []) {
        if (!raw || typeof raw !== 'object' || !Number.isInteger(raw.id) || raw.id < 1 || !SEVERITY[raw.severity] || typeof raw.at !== 'string' || Number.isNaN(Date.parse(raw.at)) || events.some((e) => e.id === raw.id)) continue;
        const rule = raw.rule && typeof raw.rule === 'object' ? { id: clip(raw.rule.id, 40), text: clip(raw.rule.text, 200) } : null;
        events.push({
          id: raw.id, at: raw.at, lastAt: typeof raw.lastAt === 'string' && !Number.isNaN(Date.parse(raw.lastAt)) ? raw.lastAt : raw.at, severity: raw.severity,
          source: clip(raw.source, 40), title: clip(raw.title, 160), detail: clip(raw.detail, 400), evidence: raw.evidence ?? null, rule, test: Boolean(raw.test),
          key: typeof raw.key === 'string' ? raw.key.slice(0, 400) : null, count: Number.isInteger(raw.count) && raw.count > 0 ? raw.count : 1,
          ack: Boolean(raw.ack), ackAt: typeof raw.ackAt === 'string' ? raw.ackAt : null, attack: Array.isArray(raw.attack) ? raw.attack.slice(0, 6) : [],
          verdict: typeof raw.verdict === 'string' ? raw.verdict.slice(0, 20) : null, domain: domainOf({ source: raw.source, rule, evidence: raw.evidence }), restored: true,
        });
        restored += 1;
      }
      events.sort((a, b) => a.id - b.id);
      while (events.length > max) events.shift();
      nextId = Math.max(nextId, ...events.map((e) => e.id + 1));
      return restored;
    },
    all() { return events.slice(); },
    get(id) { return events.find((item) => item.id === id) ?? null; },
    setVerdict(id, verdict) { const event = events.find((item) => item.id === id); if (!event) return false; event.verdict = verdict; emit('updated', event); return true; },
    list(limit = 200) { return events.slice(-limit).reverse(); },
    counts() {
      const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unackedCritical: 0, total: events.length };
      for (const event of events) { counts[event.severity] += 1; if (event.severity === 'critical' && !event.ack) counts.unackedCritical += 1; }
      return counts;
    },
    unackedCritical() { return events.filter((event) => event.severity === 'critical' && !event.ack); },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
  });
}
