// IOC(침해지표) 저장소. 형식을 검증해 저장하고, 관측값(IP, 도메인, 해시, 프로세스 이름, 경로)과 대조한다.
// 파일에는 IOC와 허용 목록(오탐 처리)만 저장한다. 탐지 기록(sightings)과 사건은 메모리에만 둔다.
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { isKnownTechnique } from './attack.mjs';

export const IOC_TYPES = Object.freeze(['ipv4', 'cidr4', 'domain', 'sha256', 'process', 'path']);
export const TLP = Object.freeze(['clear', 'green', 'amber', 'red']);
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const MAX_IOCS = 5000;
const MAX_ALLOW = 1000;

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const DOMAIN = /^(?:\*\.)?(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const PROCESS = /^[a-z0-9][a-z0-9 ._()-]{0,62}$/;

const ipToInt = (ip) => ip.split('.').reduce((acc, octet) => (acc * 256) + Number(octet), 0);
export const isPrivateOrLocal = (ip) => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip);

// 유형별로 값을 정규화하고 검증한다. 실패하면 { error } 를 돌려준다.
export function normalizeIndicator(type, raw) {
  const value = String(raw ?? '').trim();
  if (!IOC_TYPES.includes(type)) return { error: '지원하지 않는 유형입니다(ipv4, cidr4, domain, sha256, process, path).' };
  if (value.length === 0 || value.length > 300) return { error: '값이 비었거나 너무 깁니다.' };
  if (type === 'ipv4') return IPV4.test(value) ? { value } : { error: 'IPv4 주소 형식이 아닙니다.' };
  if (type === 'cidr4') {
    const [ip, bits, extra] = value.split('/');
    const prefix = Number(bits);
    if (extra !== undefined || !IPV4.test(ip ?? '') || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return { error: 'CIDR 형식이 아닙니다(예: 203.0.113.0/24).' };
    if (prefix < 8) return { error: '범위가 너무 넓습니다(/8 이상만 허용). 정상 트래픽을 대량으로 오탐할 수 있습니다.' };
    return { value: `${ip}/${prefix}` };
  }
  if (type === 'domain') { const v = value.toLowerCase(); return DOMAIN.test(v) ? { value: v } : { error: '도메인 형식이 아닙니다(와일드카드는 *.example.com 형태만).' }; }
  if (type === 'sha256') { const v = value.toLowerCase(); return SHA256.test(v) ? { value: v } : { error: 'SHA-256(64자리 16진수)이 아닙니다.' }; }
  if (type === 'process') { const v = value.toLowerCase(); return PROCESS.test(v) ? { value: v } : { error: '프로세스 이름 형식이 아닙니다.' }; }
  const v = value.replace(/\\/g, '/').toLowerCase();
  return v.length >= 6 && /[a-z0-9]/.test(v) ? { value: v } : { error: '경로 조각은 6자 이상이어야 합니다.' };
}

function cidrContains(cidr, ip) {
  const [base, bits] = cidr.split('/');
  const prefix = Number(bits);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((ipToInt(base) & mask) >>> 0) === ((ipToInt(ip) & mask) >>> 0);
}

export function createIocStore({ file = null, now = () => new Date(), fsApi = { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } } = {}) {
  let iocs = [];
  let allow = [];
  const loadInfo = { loaded: false, skipped: 0, error: null };
  const ttlOk = (ioc) => !ioc.validUntil || Date.parse(ioc.validUntil) > now().getTime();

  function persist() {
    if (!file) return;
    try {
      fsApi.mkdirSync(dirname(file), { recursive: true });
      const temp = `${file}.tmp`;
      fsApi.writeFileSync(temp, JSON.stringify({ version: 1, savedAt: now().toISOString(), iocs, allow }, null, 1), 'utf8');
      fsApi.renameSync(temp, file);
    } catch (error) { loadInfo.error = String(error && error.code ? error.code : 'SAVE_FAILED'); }
  }

  function clean(input, defaults = {}) {
    const normalized = normalizeIndicator(input.type, input.value);
    if (normalized.error) return { error: normalized.error };
    const severity = SEVERITIES.includes(input.severity) ? input.severity : defaults.severity ?? 'high';
    const tlp = TLP.includes(input.tlp) ? input.tlp : defaults.tlp ?? 'amber';
    const confidence = Number.isInteger(input.confidence) && input.confidence >= 0 && input.confidence <= 100 ? input.confidence : defaults.confidence ?? 60;
    const ttps = Array.isArray(input.ttps) ? input.ttps.filter(isKnownTechnique).slice(0, 8) : [];
    let validUntil = null;
    if (input.validUntil) { const t = Date.parse(input.validUntil); if (Number.isNaN(t)) return { error: '만료 시각 형식이 올바르지 않습니다.' }; validUntil = new Date(t).toISOString(); }
    // 공유 기본값: 네트워크·해시 지표만. 프로세스 이름·경로는 내 PC 정보가 들어 있어 기본적으로 공유하지 않는다.
    const shareable = typeof input.shareable === 'boolean' ? input.shareable : ['ipv4', 'cidr4', 'domain', 'sha256'].includes(input.type);
    return {
      ioc: {
        id: input.id && typeof input.id === 'string' ? input.id.slice(0, 80) : `ioc-${randomUUID()}`,
        type: input.type, value: normalized.value, source: String(input.source ?? 'manual').slice(0, 60), tlp, confidence, severity,
        description: String(input.description ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200), ttps,
        createdAt: input.createdAt && !Number.isNaN(Date.parse(input.createdAt)) ? new Date(input.createdAt).toISOString() : now().toISOString(),
        validUntil, shareable, test: Boolean(input.test), hits: 0, lastHit: null,
      },
    };
  }

  const store = {
    load() {
      if (!file || !fsApi.existsSync(file)) { loadInfo.loaded = true; return loadInfo; }
      try {
        const data = JSON.parse(fsApi.readFileSync(file, 'utf8'));
        for (const item of Array.isArray(data.iocs) ? data.iocs : []) {
          const result = clean(item);
          if (result.error) { loadInfo.skipped += 1; continue; }
          iocs.push({ ...result.ioc, hits: Number.isInteger(item.hits) ? item.hits : 0, lastHit: item.lastHit ?? null });
        }
        allow = (Array.isArray(data.allow) ? data.allow : []).filter((a) => a && typeof a.key === 'string').slice(0, MAX_ALLOW);
      } catch (error) { loadInfo.error = 'LOAD_FAILED'; }
      loadInfo.loaded = true;
      return loadInfo;
    },
    add(input, defaults) {
      const result = clean(input, defaults);
      if (result.error) return result;
      const existing = iocs.find((x) => x.type === result.ioc.type && x.value === result.ioc.value);
      if (existing) return { ioc: existing, duplicate: true };
      if (iocs.length >= MAX_IOCS) return { error: `IOC는 최대 ${MAX_IOCS}개까지 저장합니다.` };
      iocs.push(result.ioc);
      persist();
      return { ioc: result.ioc };
    },
    addMany(list, defaults) {
      const summary = { added: 0, duplicates: 0, rejected: [] };
      for (const item of list) {
        const result = clean(item, defaults);
        if (result.error) { if (summary.rejected.length < 20) summary.rejected.push({ value: String(item.value ?? '').slice(0, 80), reason: result.error }); continue; }
        if (iocs.some((x) => x.type === result.ioc.type && x.value === result.ioc.value)) { summary.duplicates += 1; continue; }
        if (iocs.length >= MAX_IOCS) { summary.rejected.push({ value: result.ioc.value, reason: `최대 ${MAX_IOCS}개 초과` }); break; }
        iocs.push(result.ioc); summary.added += 1;
      }
      if (summary.added > 0) persist();
      return summary;
    },
    remove(id) { const before = iocs.length; iocs = iocs.filter((x) => x.id !== id); if (iocs.length !== before) persist(); return iocs.length !== before; },
    list() { return iocs.map((x) => ({ ...x, active: ttlOk(x) })); },
    exportable() { return iocs.filter((x) => x.shareable && !x.test && ttlOk(x)); },
    // 관측값 하나를 활성 IOC 와 대조한다. observable: { type:'ip'|'domain'|'sha256'|'process'|'text', value }
    match(observable) {
      const value = String(observable.value ?? '').toLowerCase();
      const found = [];
      for (const ioc of iocs) {
        if (!ttlOk(ioc)) continue;
        if (observable.type === 'ip' && ioc.type === 'ipv4' && ioc.value === value) found.push(ioc);
        else if (observable.type === 'ip' && ioc.type === 'cidr4' && IPV4.test(value) && cidrContains(ioc.value, value)) found.push(ioc);
        else if (observable.type === 'domain' && ioc.type === 'domain' && (ioc.value === value || (ioc.value.startsWith('*.') && value.endsWith(ioc.value.slice(1))))) found.push(ioc);
        else if (observable.type === 'sha256' && ioc.type === 'sha256' && ioc.value === value) found.push(ioc);
        else if (observable.type === 'process' && ioc.type === 'process' && (ioc.value === value || ioc.value === value.replace(/\.exe$/, ''))) found.push(ioc);
        else if (observable.type === 'text' && ioc.type === 'path' && value.replace(/\\/g, '/').includes(ioc.value)) found.push(ioc);
      }
      return found;
    },
    recordHit(id) { const ioc = iocs.find((x) => x.id === id); if (ioc) { ioc.hits += 1; ioc.lastHit = now().toISOString(); persist(); } },
    // 오탐 처리: 같은 키의 탐지는 더 이상 사건으로 올리지 않는다.
    allowKey(key, reason) { if (!allow.some((a) => a.key === key) && allow.length < MAX_ALLOW) { allow.push({ key: String(key).slice(0, 200), reason: String(reason ?? '').slice(0, 120), at: now().toISOString() }); persist(); } },
    isAllowed(key) { return allow.some((a) => a.key === key); },
    allowList() { return allow.slice(); },
    stats() {
      const active = iocs.filter(ttlOk);
      const bySource = {};
      for (const ioc of active) bySource[ioc.source] = (bySource[ioc.source] ?? 0) + 1;
      const byType = {};
      for (const ioc of active) byType[ioc.type] = (byType[ioc.type] ?? 0) + 1;
      return { total: iocs.length, active: active.length, expired: iocs.length - active.length, bySource, byType, allow: allow.length, file, loadError: loadInfo.error, skippedOnLoad: loadInfo.skipped };
    },
  };
  return Object.freeze(store);
}
