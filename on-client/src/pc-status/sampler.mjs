// 이 PC의 CPU 사용률·메모리 사용량·디스크 남은 공간을 일반 권한으로 읽는다. 읽기 전용이며 설정을 바꾸지 않는다.
// 읽지 못한 값은 예시 값으로 채우지 않고 status:'unavailable'과 이유를 돌려준다.
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

const GB = 2 ** 30;
const round1 = (value) => Math.round(value * 10) / 10;
const finite = (value) => typeof value === 'number' && Number.isFinite(value);

const measured = (fields, measuredAt) => ({ status: 'measured', measuredAt, ...fields });
const unavailable = (reason, measuredAt, unit, code = 'READ_FAILED') => ({ status: 'unavailable', measuredAt, unit, reason, code });

function cpuTotals(cpus) {
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    const times = cpu && cpu.times;
    if (!times || ![times.user, times.nice, times.sys, times.idle, times.irq].every(finite)) return null;
    idle += times.idle;
    total += times.user + times.nice + times.sys + times.idle + times.irq;
  }
  return cpus.length > 0 ? { idle, total } : null;
}

// 의존 객체(os, fs, 시계)를 바꿔 끼울 수 있게 해서 읽기 실패 경로를 시험할 수 있다.
export function createSampler({ osModule = os, fsModule = fs, now = () => new Date(), diskPath = path.parse(process.cwd()).root } = {}) {
  let previousCpu = null;

  function readCpu(at, atMs) {
    let totals;
    try { totals = cpuTotals(osModule.cpus()); } catch { totals = null; }
    if (!totals) return unavailable('CPU 시간 정보를 읽지 못했습니다.', at, '%');
    const before = previousCpu;
    previousCpu = { ...totals, atMs };
    if (!before) return unavailable('첫 측정이라 비교할 이전 측정이 없습니다. 한 번 더 측정하면 표시됩니다.', at, '%', 'FIRST_SAMPLE');
    const totalDelta = totals.total - before.total;
    const idleDelta = totals.idle - before.idle;
    if (!(totalDelta > 0) || idleDelta < 0 || idleDelta > totalDelta) {
      return unavailable('직전 측정과의 간격이 너무 짧거나 값이 맞지 않아 계산할 수 없습니다.', at, '%', 'SHORT_INTERVAL');
    }
    return measured({
      value: round1((1 - idleDelta / totalDelta) * 100),
      unit: '%',
      windowSeconds: round1(Math.max(0, atMs - before.atMs) / 1000),
      basis: '직전 측정 이후 구간의 평균',
    }, at);
  }

  function readMemory(at) {
    let total;
    let free;
    try { total = osModule.totalmem(); free = osModule.freemem(); } catch { return unavailable('메모리 정보를 읽지 못했습니다.', at, 'GB'); }
    if (!finite(total) || !finite(free) || total <= 0 || free < 0 || free > total) {
      return unavailable('메모리 값이 올바르지 않아 계산할 수 없습니다.', at, 'GB');
    }
    return measured({
      value: round1((total - free) / GB),
      unit: 'GB',
      totalGb: round1(total / GB),
      percent: round1(((total - free) / total) * 100),
      basis: '전체 물리 메모리 − 운영체제가 알려 주는 여유 메모리',
    }, at);
  }

  function readDisk(at) {
    let stat;
    try { stat = fsModule.statfsSync(diskPath); } catch (error) {
      return unavailable(`디스크 정보를 읽지 못했습니다(${error && error.code ? error.code : '원인 불명'}).`, at, 'GB');
    }
    const free = stat.bavail * stat.bsize;
    const total = stat.blocks * stat.bsize;
    if (!finite(free) || !finite(total) || total <= 0 || free < 0 || free > total) {
      return unavailable('디스크 값이 올바르지 않아 계산할 수 없습니다.', at, 'GB');
    }
    return measured({
      value: round1(free / GB),
      unit: 'GB',
      totalGb: round1(total / GB),
      drive: path.parse(diskPath).root || diskPath,
      basis: '앱이 실행 중인 드라이브의 일반 사용자 기준 남은 공간',
    }, at);
  }

  return Object.freeze({
    sample() {
      const clock = now();
      const at = clock.toISOString();
      const atMs = clock.getTime();
      return { measuredAt: at, cpu: readCpu(at, atMs), memory: readMemory(at), disk: readDisk(at) };
    },
  });
}
