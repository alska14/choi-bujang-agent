// 최근 측정 N회를 서버 메모리에만 보관한다. 파일에 쓰지 않으며 서버를 끄면 사라진다.
const METRICS = ['cpu', 'memory', 'disk'];

export function createHistory({ max = 20 } = {}) {
  const rows = [];

  const valueOf = (row, metric) => (row[metric] && row[metric].status === 'measured' ? row[metric].value : null);

  function trendFor(metric) {
    const values = rows.map((row) => valueOf(row, metric));
    const measuredValues = values.filter((value) => value !== null);
    const latest = values.length > 0 ? values[values.length - 1] : null;
    // 직전 값이 확인 불가였으면 비교하지 않는다. 더 오래된 값을 직전 값으로 쓰지 않는다.
    const previous = values.length > 1 ? values[values.length - 2] : null;
    const delta = latest !== null && previous !== null ? Math.round((latest - previous) * 10) / 10 : null;
    return {
      latest,
      previous,
      delta,
      direction: delta === null ? 'unknown' : delta > 0 ? 'up' : delta < 0 ? 'down' : 'same',
      min: measuredValues.length > 0 ? Math.min(...measuredValues) : null,
      max: measuredValues.length > 0 ? Math.max(...measuredValues) : null,
      measuredCount: measuredValues.length,
      series: values,
    };
  }

  return Object.freeze({
    add(sample) {
      rows.push({ measuredAt: sample.measuredAt, cpu: sample.cpu, memory: sample.memory, disk: sample.disk });
      while (rows.length > max) rows.shift();
    },
    snapshot() {
      return {
        max,
        count: rows.length,
        rows: rows.map((row) => ({
          measuredAt: row.measuredAt,
          cpu: valueOf(row, 'cpu'),
          memory: valueOf(row, 'memory'),
          disk: valueOf(row, 'disk'),
        })),
        trend: Object.fromEntries(METRICS.map((metric) => [metric, trendFor(metric)])),
      };
    },
  });
}
