// 관제 감시 루프. 서버가 계속 돌며 (1) 2초마다 CPU·메모리·디스크를 재고 이상을 판정하고
// (2) 60초마다 방화벽·Defender·수신 포트·Windows 기록을 읽기만 해서 규칙에 맞으면 사건을 만든다.
// 값은 서버 메모리에만 두며, 읽지 못한 값은 예시로 채우지 않고 확인 불가로 둔다.
import { RULES as ANOMALY_RULES } from './anomaly.mjs';
import { attackRefs, RULE_TO_ATTACK } from './ti/attack.mjs';
import { RULES as HOST_RULES, fwRuleFindings, ipsFindings, vpnFindings, vpnState, nacFindings, iamFindings, iamBaseline } from './host-checks.mjs';
import { firewallFindings, defenderFindings, newExposedPorts, eventLogFindings, countErrors, RULES as CHECK_RULES } from './checks.mjs';

const METRIC_LABEL = { cpu: 'CPU 사용률', memory: '메모리 사용량', disk: '디스크 남은 공간' };
const SEVERITY_OF_LEVEL = { warn: 'medium', critical: 'high' };

export function createMonitor({
  sampler, store, anomaly, securityReader, checks, agentAudit = null, fileWatcher = null, alerter = null, intel = null, hostChecks = null, inventory = null, eventLog = null,
  fastMs = 2000, slowMs = 60000, intelMs = 15000, pointsMax = 150, now = () => new Date(),
} = {}) {
  const points = [];
  const listeners = new Set();
  const levels = { cpu: 'unknown', memory: 'unknown', disk: 'unknown' };
  let anomalyState = null;
  let security = { readAt: null, firewall: null, defender: null, ports: null, network: null, events: null };
  let portBaseline = null;
  let fwRuleBaseline = null;
  let ipsBaseline = null;
  let vpnPrevious = null;
  let nacBaseline = null;
  let iamBase = null;
  let errorBaseline = null;
  let fastTimer = null;
  let slowTimer = null;
  let intelTimer = null;
  let intelBusy = false;
  let slowBusy = false;
  let lastTestAt = -Infinity;

  const emit = (type, payload) => { for (const listener of listeners) { try { listener(type, payload); } catch { /* 한 구독자의 오류가 감시를 멈추지 않게 한다 */ } } };

  store.subscribe((type, event) => { if (type === 'created' && alerter) alerter.alert(event); });

  function describe(metric, entry) {
    const first = entry.reasons[0];
    if (!first) return '';
    const e = first.evidence;
    const unit = metric === 'disk' ? 'GB' : '%';
    return e.baseline !== undefined ? `${first.text} (현재 ${e.value}${unit}, 직전 평균 ${e.baseline}${unit})` : `${first.text} (현재 ${e.value}${unit})`;
  }

  function judge(result) {
    for (const metric of ['cpu', 'memory', 'disk']) {
      const entry = result[metric];
      const before = levels[metric];
      levels[metric] = entry.level;
      if (entry.level === 'warn' || entry.level === 'critical') {
        const first = entry.reasons[0];
        store.add({
          severity: SEVERITY_OF_LEVEL[entry.level], source: 'metrics',
          title: `${METRIC_LABEL[metric]} 이상: ${first.ruleId}`, detail: describe(metric, entry),
          evidence: first.evidence, rule: { id: first.ruleId, text: first.text }, key: `anomaly:${metric}:${first.ruleId}`, attack: attackRefs(RULE_TO_ATTACK[first.ruleId] ?? []),
        });
      } else if ((before === 'warn' || before === 'critical') && entry.level === 'normal') {
        store.add({ severity: 'info', source: 'metrics', title: `${METRIC_LABEL[metric]}이(가) 정상 범위로 돌아왔습니다`, detail: '', evidence: null, rule: null });
      }
    }
  }

  function tick() {
    const at = now().toISOString();
    const sample = sampler.sample();
    const diskFreePercent = sample.disk.status === 'measured' ? Math.round((sample.disk.value / sample.disk.totalGb) * 1000) / 10 : null;
    const values = {
      cpu: sample.cpu.status === 'measured' ? sample.cpu.value : null,
      memoryPercent: sample.memory.status === 'measured' ? sample.memory.percent : null,
      memoryGb: sample.memory.status === 'measured' ? sample.memory.value : null,
      diskFreePercent,
      diskFreeGb: sample.disk.status === 'measured' ? sample.disk.value : null,
    };
    anomalyState = anomaly.update({ cpu: values.cpu, memoryPercent: values.memoryPercent, diskFreePercent, diskFreeGb: values.diskFreeGb });
    judge(anomalyState);
    const point = { at, ...values, cpuReason: sample.cpu.status === 'measured' ? null : sample.cpu.reason, memoryTotalGb: sample.memory.totalGb ?? null, diskTotalGb: sample.disk.totalGb ?? null };
    points.push(point);
    while (points.length > pointsMax) points.shift();
    if (agentAudit) agentAudit.poll();
    emit('metrics', { point, anomaly: anomalyState, counts: store.counts() });
  }

  async function slowTick() {
    if (slowBusy) return security;
    slowBusy = true;
    try {
      const [firewall, events, defender, ports] = await Promise.all([securityReader.readFirewall(), securityReader.readEvents(), checks.readDefender(), checks.readPorts()]);
      const network = securityReader.readNetwork();
      const host = hostChecks ? await readHost() : { net: null, iam: null };
      security = { readAt: now().toISOString(), firewall, defender, ports, network, events, net: host.net, iam: host.iam };
      for (const finding of [...firewallFindings(firewall), ...defenderFindings(defender)]) addFinding(finding, 'security');
      if (ports.status === 'measured') {
        if (portBaseline === null) portBaseline = ports.ports;
        else for (const finding of newExposedPorts(portBaseline, ports)) addFinding(finding, 'ports');
      }
      const errors = countErrors(events);
      if (errorBaseline === null && errors !== null) errorBaseline = errors;
      else for (const finding of eventLogFindings(errorBaseline, events)) addFinding(finding, 'winlog');
      emit('security', { security, counts: store.counts() });
      return security;
    } finally { slowBusy = false; }
  }

  // 네트워크(방화벽 규칙·IPS·VPN·NAC)와 계정·접근 상태를 읽고, 시작 시점 기준선과 달라진 것만 사건으로 올린다.
  async function readHost() {
    const [fwRules, ips, vpn, nac, accounts] = await Promise.all([hostChecks.readFirewallRules(), hostChecks.readIps(), hostChecks.readVpn(), hostChecks.readNac(), hostChecks.readAccounts()]);
    for (const finding of fwRuleFindings(fwRuleBaseline, fwRules)) addFinding(finding, 'network');
    if (fwRuleBaseline === null && fwRules.status === 'measured') fwRuleBaseline = fwRules.names;
    for (const finding of ipsFindings(ipsBaseline, ips)) addFinding(finding, 'network');
    if (ipsBaseline === null && ips.status === 'measured') ipsBaseline = new Set(ips.detections.map((d) => d.id));
    for (const finding of vpnFindings(vpnPrevious, vpn)) addFinding(finding, 'network');
    if (vpn.status === 'measured') vpnPrevious = vpnState(vpn);
    for (const finding of nacFindings(nacBaseline, nac)) addFinding(finding, 'network');
    if (nacBaseline === null && nac.status === 'measured') nacBaseline = nac.neighborMacs;
    for (const finding of iamFindings(iamBase, accounts)) addFinding(finding, 'iam');
    if (iamBase === null) iamBase = iamBaseline(accounts);
    // 화면과 사건에는 장치의 전체 MAC 주소를 내보내지 않는다.
    const publicNac = nac.status === 'measured' ? { ...nac, neighborMacs: undefined } : nac;
    return { net: { fwRules: fwRules.status === 'measured' ? { ...fwRules, names: undefined } : fwRules, ips, vpn, nac: publicNac }, iam: accounts };
  }

  function addFinding(finding, source) {
    store.add({ severity: finding.severity, source, title: finding.title, detail: finding.detail, evidence: finding.evidence, rule: { id: finding.ruleId, text: CHECK_RULES[finding.ruleId] ?? HOST_RULES[finding.ruleId] }, key: `${finding.ruleId}:${JSON.stringify(finding.evidence)}`, attack: attackRefs(RULE_TO_ATTACK[finding.ruleId] ?? []) });
  }

  async function intelTick() {
    if (!intel || intelBusy) return;
    intelBusy = true;
    try { await intel.scanNetwork(); await intel.scanProcesses(); } catch { /* 한 번의 스캔 실패는 다음 주기에 다시 시도한다 */ } finally { intelBusy = false; }
  }

  return Object.freeze({
    start() {
      tick();
      slowTick().catch(() => {});
      intelTick();
      if (intel) { intelTimer = setInterval(intelTick, intelMs); intelTimer.unref?.(); }
      fastTimer = setInterval(tick, fastMs); fastTimer.unref?.();
      slowTimer = setInterval(() => { slowTick().catch(() => {}); }, slowMs); slowTimer.unref?.();
      fileWatcher?.start();
      inventory?.start();
    },
    stop() { clearInterval(fastTimer); clearInterval(slowTimer); clearInterval(intelTimer); fileWatcher?.stop(); inventory?.stop(); eventLog?.stop(); },
    tick, slowTick, intelTick,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    // 시험 경보: 경보 화면·소리·알림·Windows 팝업이 동작하는지 확인하는 용도. 실제 사건과 섞이지 않게 test 표시를 붙인다.
    testAlert() {
      const t = now().getTime();
      if (t - lastTestAt < 5000) return null;
      lastTestAt = t;
      return store.add({ severity: 'critical', source: 'test', title: '시험 경보입니다. 실제 보안 사건이 아닙니다', detail: '경보 화면, 소리, 바탕화면 알림, Windows 팝업이 동작하는지 확인하는 시험입니다.', evidence: null, rule: { id: 'TEST-ALERT', text: '사용자가 시험 경보 버튼을 누름' }, test: true }).event;
    },
    snapshot() {
      return {
        serverTime: now().toISOString(), points: points.slice(-60), anomaly: anomalyState, security,
        events: store.list(400), counts: store.counts(),
        collectors: { agent: agentAudit ? agentAudit.status() : { state: 'not_configured' }, files: fileWatcher ? fileWatcher.status() : { watching: [], events: 0, errors: 0 }, native: alerter ? alerter.status() : { enabled: false }, inventory: inventory ? inventory.status() : null, history: eventLog ? eventLog.status() : null },
        intel: intel && intel.summary ? intel.summary() : null,
        rules: { anomaly: ANOMALY_RULES, checks: CHECK_RULES },
      };
    },
  });
}
