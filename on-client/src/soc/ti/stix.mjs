// STIX 2.1 가져오기·내보내기와 일반 텍스트(줄 단위) 가져오기. 공유는 파일 교환 방식이다(TAXII 서버 연동은 하지 않는다).
// 확인한 근거: STIX 2.1 Indicator 필수 속성(type, spec_version, id, created, modified, pattern, pattern_type, valid_from),
// 패턴 `[ipv4-addr:value = '…']`, `[file:hashes.'SHA-256' = '…']`, TLP 표시 정의 ID(공식 stix2 구현체).
// CIDR 의 ISSUBSET 연산자는 구현체에서 존재만 확인했고 스펙 문구는 확인하지 못했다.
import { createHash, randomUUID } from 'node:crypto';
import { TECHNIQUES, TACTICS } from './attack.mjs';
import { normalizeIndicator, TLP } from './ioc-store.mjs';

export const TLP_MARKINGS = Object.freeze({
  clear: { id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9', name: 'TLP:WHITE', tlp: 'white' },
  green: { id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', name: 'TLP:GREEN', tlp: 'green' },
  amber: { id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82', name: 'TLP:AMBER', tlp: 'amber' },
  red: { id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed', name: 'TLP:RED', tlp: 'red' },
});
const TLP_BY_ID = Object.fromEntries(Object.entries(TLP_MARKINGS).map(([key, value]) => [value.id, key]));
const MAX_IMPORT = 5000;

const stixTime = (iso) => new Date(iso).toISOString().replace(/\.(\d{3})Z$/, '.$1Z');
function stableUuid(seed) {
  const hex = createHash('sha256').update(seed).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}
const quote = (text) => String(text).replace(/\\/g, '\\\\').replace(/'/g, "\\'");

export function patternFor(ioc) {
  if (ioc.type === 'ipv4') return `[ipv4-addr:value = '${quote(ioc.value)}']`;
  if (ioc.type === 'cidr4') return `[ipv4-addr:value ISSUBSET '${quote(ioc.value)}']`;
  if (ioc.type === 'domain' && !ioc.value.startsWith('*.')) return `[domain-name:value = '${quote(ioc.value)}']`;
  if (ioc.type === 'sha256') return `[file:hashes.'SHA-256' = '${quote(ioc.value)}']`;
  return null; // process, path, 와일드카드 도메인은 검증한 STIX 패턴으로 표현하지 않는다(내보내지 않음)
}

export function exportBundle(iocs, { now = () => new Date(), creator = 'Djoković SOC (로컬 관제)', installId = 'local' } = {}) {
  const created = stixTime(now().toISOString());
  const identityId = `identity--${stableUuid(`djokovic-soc:${installId}`)}`;
  const objects = [];
  const usedTlp = new Set();
  const usedTechniques = new Set();
  const skipped = [];
  const indicators = [];

  for (const ioc of iocs) {
    const pattern = patternFor(ioc);
    if (!pattern) { skipped.push({ type: ioc.type, value: ioc.value, reason: '검증한 STIX 패턴으로 표현할 수 없는 유형' }); continue; }
    usedTlp.add(ioc.tlp);
    const indicator = {
      type: 'indicator', spec_version: '2.1', id: `indicator--${stableUuid(`${ioc.type}:${ioc.value}`)}`, created: stixTime(ioc.createdAt), modified: created,
      created_by_ref: identityId, name: `${ioc.type}: ${ioc.value}`, description: ioc.description || undefined, indicator_types: ['malicious-activity'],
      pattern, pattern_type: 'stix', valid_from: stixTime(ioc.createdAt), ...(ioc.validUntil ? { valid_until: stixTime(ioc.validUntil) } : {}),
      confidence: ioc.confidence, object_marking_refs: [TLP_MARKINGS[ioc.tlp].id],
    };
    for (const technique of ioc.ttps) usedTechniques.add(technique);
    indicators.push({ indicator, ttps: ioc.ttps });
  }

  for (const key of usedTlp) objects.push({ type: 'marking-definition', spec_version: '2.1', id: TLP_MARKINGS[key].id, created: '2017-01-20T00:00:00.000Z', definition_type: 'tlp', name: TLP_MARKINGS[key].name, definition: { tlp: TLP_MARKINGS[key].tlp } });
  objects.push({ type: 'identity', spec_version: '2.1', id: identityId, created, modified: created, name: creator, identity_class: 'system' });
  for (const id of usedTechniques) {
    const technique = TECHNIQUES[id];
    objects.push({ type: 'attack-pattern', spec_version: '2.1', id: `attack-pattern--${stableUuid(`mitre-attack:${id}`)}`, created, modified: created, name: technique.name, external_references: [{ source_name: 'mitre-attack', external_id: id, url: technique.url }] });
  }
  for (const { indicator, ttps } of indicators) {
    objects.push(indicator);
    for (const id of ttps) objects.push({ type: 'relationship', spec_version: '2.1', id: `relationship--${stableUuid(`${indicator.id}:indicates:${id}`)}`, created, modified: created, relationship_type: 'indicates', source_ref: indicator.id, target_ref: `attack-pattern--${stableUuid(`mitre-attack:${id}`)}` });
  }
  return { bundle: { type: 'bundle', id: `bundle--${randomUUID()}`, objects }, exported: indicators.length, skipped };
}

// ---- 가져오기 ----
const PATTERNS = [
  [/^\[ipv4-addr:value\s*=\s*'([0-9.]+)'\]$/i, 'ipv4'],
  [/^\[ipv4-addr:value\s+ISSUBSET\s+'([0-9./]+)'\]$/i, 'cidr4'],
  [/^\[domain-name:value\s*=\s*'([^']+)'\]$/i, 'domain'],
  [/^\[file:hashes\.(?:'SHA-256'|"SHA-256"|SHA-256)\s*=\s*'([0-9a-f]{64})'\]$/i, 'sha256'],
];

export function parseStix(text) {
  let data;
  try { data = JSON.parse(text); } catch { return { error: 'JSON 형식이 아닙니다.' }; }
  const objects = data && data.type === 'bundle' && Array.isArray(data.objects) ? data.objects : null;
  if (!objects) return { error: 'STIX 번들(type: bundle, objects 배열)이 아닙니다.' };
  const patternsById = new Map(objects.filter((o) => o && o.type === 'attack-pattern').map((o) => [o.id, ((o.external_references || []).find((r) => r.source_name === 'mitre-attack') || {}).external_id]));
  const ttpsByIndicator = new Map();
  for (const o of objects) if (o && o.type === 'relationship' && o.relationship_type === 'indicates' && patternsById.has(o.target_ref)) (ttpsByIndicator.get(o.source_ref) ?? ttpsByIndicator.set(o.source_ref, []).get(o.source_ref)).push(patternsById.get(o.target_ref));
  const items = [];
  const rejected = [];
  for (const o of objects) {
    if (!o || o.type !== 'indicator') continue;
    if (items.length >= MAX_IMPORT) { rejected.push({ value: '(이하 생략)', reason: `한 번에 ${MAX_IMPORT}개까지 가져옵니다` }); break; }
    if (o.pattern_type !== 'stix' || typeof o.pattern !== 'string') { rejected.push({ value: String(o.name ?? o.id).slice(0, 80), reason: 'pattern_type 이 stix 가 아님' }); continue; }
    const hit = PATTERNS.map(([regex, type]) => [regex.exec(o.pattern.trim()), type]).find(([match]) => match);
    if (!hit) { rejected.push({ value: o.pattern.slice(0, 80), reason: '지원하지 않는 패턴(단일 비교만 가져옵니다)' }); continue; }
    const tlpKey = (o.object_marking_refs || []).map((ref) => TLP_BY_ID[ref]).find(Boolean);
    items.push({ type: hit[1], value: hit[0][1], description: o.description || o.name || '', confidence: Number.isInteger(o.confidence) ? o.confidence : undefined, tlp: tlpKey, validUntil: o.valid_until, createdAt: o.valid_from || o.created, ttps: ttpsByIndicator.get(o.id) || [], shareable: true });
  }
  return { items, rejected };
}

export function parseText(text) {
  const items = [];
  const rejected = [];
  const lines = String(text).split(/\r?\n/).slice(0, 20000);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (items.length >= MAX_IMPORT) { rejected.push({ value: '(이하 생략)', reason: `한 번에 ${MAX_IMPORT}개까지 가져옵니다` }); break; }
    const parts = line.split(/[,\t]/).map((part) => part.trim());
    const explicit = IOC_TYPE_WORDS.has(parts[0].toLowerCase()) && parts.length >= 2;
    const value = explicit ? parts[1] : parts[0];
    const type = explicit ? parts[0].toLowerCase() : guessType(value);
    if (!type) { rejected.push({ value: value.slice(0, 80), reason: '유형을 알 수 없습니다' }); continue; }
    const check = normalizeIndicator(type, value);
    if (check.error) { rejected.push({ value: value.slice(0, 80), reason: check.error }); continue; }
    items.push({ type, value, severity: ['low', 'medium', 'high', 'critical'].includes(parts[explicit ? 2 : 1]) ? parts[explicit ? 2 : 1] : undefined, description: parts.slice(explicit ? 3 : 2).join(' ').slice(0, 200) });
  }
  return { items, rejected };
}
const IOC_TYPE_WORDS = new Set(['ipv4', 'cidr4', 'domain', 'sha256', 'process', 'path']);
function guessType(value) {
  if (/^[0-9a-f]{64}$/i.test(value)) return 'sha256';
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value)) return 'cidr4';
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return 'ipv4';
  if (/^(?:\*\.)?[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return 'domain';
  return null;
}

export function parseAuto(text) {
  const trimmed = String(text).trim();
  return trimmed.startsWith('{') ? { format: 'stix', ...parseStix(trimmed) } : { format: 'text', ...parseText(trimmed) };
}

export { TLP, TACTICS };
