import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAgentHooks } from '../src/soc/agent-hooks.mjs';

const setup = () => {
  const home = mkdtempSync(join(tmpdir(), 'hooks-home-'));
  const dataDir = join(home, 'data');
  return { home, dataDir, done: () => rmSync(home, { recursive: true, force: true }) };
};

test('감사 훅 연결: 기존 Claude 설정을 지키며 한 항목만 더하고, 원본을 백업하며, 다시 눌러도 겹치지 않는다', () => {
  const { home, dataDir, done } = setup();
  try {
    mkdirSync(join(home, '.claude'));
    const original = { model: 'opus', permissions: { allow: ['Bash(git *)'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'other-tool' }] }], Stop: [{ hooks: [] }] } };
    writeFileSync(join(home, '.claude', 'settings.json'), JSON.stringify(original));
    const hooks = createAgentHooks({ home, dataDir, findNode: () => 'C:\\node\\node.exe', appExe: null });
    const r = hooks.install();
    assert.equal(r.results.find((x) => x.agent === 'Claude Code').ok, true);
    assert.equal(r.results.find((x) => x.agent === 'Codex CLI').ok, false); // .codex 없음 → 건너뜀
    hooks.install();
    const saved = JSON.parse(readFileSync(join(home, '.claude', 'settings.json'), 'utf8'));
    assert.equal(saved.model, 'opus');
    assert.deepEqual(saved.permissions, original.permissions);
    assert.deepEqual(saved.hooks.Stop, original.hooks.Stop);
    assert.equal(saved.hooks.PreToolUse.length, 2, '다른 훅은 남기고 이 앱 항목은 하나만');
    assert.equal(saved.hooks.PreToolUse[0].hooks[0].command, 'other-tool');
    assert.deepEqual(saved.hooks.PreToolUse[1].hooks[0].args, [join(dataDir, 'hooks', 'agent-audit-hook.mjs'), 'claude']);
    assert.deepEqual(JSON.parse(readFileSync(join(home, '.claude', 'settings.json.djokovic-backup'), 'utf8')), original);
    assert.ok(existsSync(join(dataDir, 'hooks', 'agent-audit-hook.mjs')));
    assert.equal(hooks.status().claude.connected, true);
  } finally { done(); }
});

test('감사 훅 연결: Node.js 가 없으면 Claude 는 앱 실행 파일로, Codex 는 건너뛰고, 깨진 설정 파일은 건드리지 않는다', () => {
  const { home, dataDir, done } = setup();
  try {
    mkdirSync(join(home, '.claude'));
    mkdirSync(join(home, '.codex'));
    writeFileSync(join(home, '.codex', 'hooks.json'), '{ broken');
    const hooks = createAgentHooks({ home, dataDir, findNode: () => null, appExe: 'C:\\App\\Djokovic SOC.exe' });
    const r = hooks.install();
    const claude = JSON.parse(readFileSync(join(home, '.claude', 'settings.json'), 'utf8')).hooks.PreToolUse[0].hooks[0];
    assert.equal(claude.command, 'C:\\App\\Djokovic SOC.exe');
    assert.deepEqual(claude.args, ['--audit-hook', 'claude']);
    assert.equal(r.results.find((x) => x.agent === 'Codex CLI').ok, false);
    assert.equal(readFileSync(join(home, '.codex', 'hooks.json'), 'utf8'), '{ broken');
  } finally { done(); }
});

test('감사 훅 연결: Codex 는 PATH 의 node 로 부르고 /hooks 신뢰 안내를 준다', () => {
  const { home, dataDir, done } = setup();
  try {
    mkdirSync(join(home, '.codex'));
    const hooks = createAgentHooks({ home, dataDir, findNode: () => 'C:\\node\\node.exe', appExe: null });
    const r = hooks.install({ claude: false });
    const entry = JSON.parse(readFileSync(join(home, '.codex', 'hooks.json'), 'utf8')).hooks.PreToolUse[0];
    assert.match(entry.hooks[0].command, /^node .*agent-audit-hook\.mjs codex$/);
    assert.match(r.results[0].message, /\/hooks/);
  } finally { done(); }
});
