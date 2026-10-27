// CPU·메모리·디스크의 갑작스러운 변화와 지속적인 고부하를 규칙으로 판정한다. 규칙마다 id와 글, 근거 값을 함께 돌려준다.
// 기준선(baseline)은 직전 표본의 중앙값이다. 표본이 모이기 전에는 급증·급감 규칙을 평가하지 않고 '기준 수집 중'으로 표시한다.
export const LEVEL = Object.freeze({ UNKNOWN: 'unknown', NORMAL: 'normal', WARN: 'warn', CRITICAL: 'critical' });
const ORDER = { unknown: 0, normal: 1, warn: 2, critical: 3 };

export const RULES = Object.freeze({
  'CPU-HIGH': 'CPU 사용률이 85% 이상으로 2회 연속 유지됨',
  'CPU-CRIT': 'CPU 사용률이 95% 이상으로 3회 연속 유지됨',
  'CPU-SPIKE': 'CPU 사용률이 직전 평균보다 30%p 이상 갑자기 높아짐(현재 40% 이상)',
  'MEM-HIGH': '메모리 사용률이 85% 이상',
  'MEM-CRIT': '메모리 사용률이 92% 이상',
  'MEM-SURGE': '메모리 사용률이 직전 평균보다 8%p 이상 갑자기 높아짐',
  'DISK-LOW': '디스크 남은 공간이 전체의 15% 미만',
  'DISK-CRIT': '디스크 남은 공간이 전체의 8% 미만',
  'DISK-DROP': '디스크 남은 공간이 직전 평균보다 5 GB 이상 갑자기 줄어듦',
});

const finite = (value) => typeof value === 'number' && Number.isFinite(value);
const round1 = (value) => Math.round(value * 10) / 10;

export function median(values) {
  const sorted = values.filter(finite).slice().sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function worst(reasons) {
  return reasons.reduce((level, reason) => (ORDER[reason.level] > ORDER[level] ? reason.level : level), LEVEL.NORMAL);
}

export function createAnomalyDetector({ window = 30, minBaseline = 6, baselineSize = 10 } = {}) {
  const series = { cpu: [], memory: [], disk: [], diskGb: [] };

  const push = (key, value) => { series[key].push(finite(value) ? value : null); while (series[key].length > window) series[key].shift(); };
  const tail = (key, count) => series[key].slice(-count);
  const previous = (key) => series[key].slice(0, -1).slice(-baselineSize);
  const reason = (ruleId, level, evidence) => ({ ruleId, text: RULES[ruleId], level, evidence });

  function evaluateCpu() {
    const reasons = [];
    const last = series.cpu[series.cpu.length - 1];
    if (!finite(last)) return { level: LEVEL.UNKNOWN, reasons, learning: false, baseline: null };
    if (tail('cpu', 3).length === 3 && tail('cpu', 3).every((v) => finite(v) && v >= 95)) reasons.push(reason('CPU-CRIT', LEVEL.CRITICAL, { value: last, samples: tail('cpu', 3) }));
    else if (tail('cpu', 2).length === 2 && tail('cpu', 2).every((v) => finite(v) && v >= 85)) reasons.push(reason('CPU-HIGH', LEVEL.WARN, { value: last, samples: tail('cpu', 2) }));
    const base = previous('cpu').filter(finite);
    const learning = base.length < minBaseline;
    const baseline = learning ? null : median(base);
    if (baseline !== null && last >= 40 && last >= baseline + 30) reasons.push(reason('CPU-SPIKE', LEVEL.WARN, { value: last, baseline: round1(baseline), delta: round1(last - baseline) }));
    return { level: worst(reasons), reasons, learning, baseline: baseline === null ? null : round1(baseline), baselineCount: base.length };
  }

  function evaluateMemory() {
    const reasons = [];
    const last = series.memory[series.memory.length - 1];
    if (!finite(last)) return { level: LEVEL.UNKNOWN, reasons, learning: false, baseline: null };
    if (last >= 92) reasons.push(reason('MEM-CRIT', LEVEL.CRITICAL, { value: last }));
    else if (last >= 85) reasons.push(reason('MEM-HIGH', LEVEL.WARN, { value: last }));
    const base = previous('memory').filter(finite);
    const learning = base.length < minBaseline;
    const baseline = learning ? null : median(base);
    if (baseline !== null && last >= baseline + 8) reasons.push(reason('MEM-SURGE', LEVEL.WARN, { value: last, baseline: round1(baseline), delta: round1(last - baseline) }));
    return { level: worst(reasons), reasons, learning, baseline: baseline === null ? null : round1(baseline), baselineCount: base.length };
  }

  function evaluateDisk() {
    const reasons = [];
    const last = series.disk[series.disk.length - 1];
    if (!finite(last)) return { level: LEVEL.UNKNOWN, reasons, learning: false, baseline: null };
    if (last < 8) reasons.push(reason('DISK-CRIT', LEVEL.CRITICAL, { value: last }));
    else if (last < 15) reasons.push(reason('DISK-LOW', LEVEL.WARN, { value: last }));
    const lastGb = series.diskGb[series.diskGb.length - 1];
    const base = previous('diskGb').filter(finite);
    const learning = base.length < minBaseline;
    const baseline = learning ? null : median(base);
    if (finite(lastGb) && baseline !== null && lastGb <= baseline - 5) reasons.push(reason('DISK-DROP', LEVEL.WARN, { value: round1(lastGb), baseline: round1(baseline), delta: round1(lastGb - baseline) }));
    return { level: worst(reasons), reasons, learning, baseline: baseline === null ? null : round1(baseline), baselineCount: base.length };
  }

  return Object.freeze({
    // 입력: cpu(%), memoryPercent(%), diskFreePercent(%), diskFreeGb(GB). 읽지 못한 값은 null.
    update({ cpu = null, memoryPercent = null, diskFreePercent = null, diskFreeGb = null } = {}) {
      push('cpu', cpu); push('memory', memoryPercent); push('disk', diskFreePercent); push('diskGb', diskFreeGb);
      const result = { cpu: evaluateCpu(), memory: evaluateMemory(), disk: evaluateDisk() };
      const levels = Object.values(result).map((entry) => entry.level);
      result.overall = levels.reduce((level, next) => (ORDER[next] > ORDER[level] ? next : level), LEVEL.NORMAL);
      return result;
    },
  });
}
