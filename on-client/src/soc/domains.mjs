// 사건을 세 보안 영역으로 나눈다: 네트워크 보안, 엔드포인트 보안, 계정·접근 관리. 규칙 id 접두어와 지표 유형으로 정한다.
export const DOMAINS = Object.freeze({ network: '네트워크 보안', endpoint: '엔드포인트 보안', iam: '계정·접근 관리' });

export function domainOf({ source, rule, evidence } = {}) {
  const id = rule && rule.id ? String(rule.id) : '';
  if (source === 'test') return 'test';
  if (/^(NET-|FW-|PORT-)/.test(id)) return 'network';
  if (/^(IAM-|AGENT-)/.test(id)) return 'iam';
  if (id === 'IOC-MATCH') return ['ipv4', 'cidr4', 'domain'].includes(evidence && evidence.ioc && evidence.ioc.type) ? 'network' : 'endpoint';
  return 'endpoint';
}
