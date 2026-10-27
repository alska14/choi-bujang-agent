// LLM 에이전트 훅 스크립트(Claude Code·Codex CLI 공용): 도구를 쓸 때마다 대상 경로·명령 일부를 감사 파일에 한 줄 남긴다.
// 에이전트의 동작을 막거나 바꾸지 않는다(항상 종료 코드 0, 출력 없음). 비밀로 보이는 값은 지우고 저장한다.
// 감사 파일은 저장소 밖(기본: %LOCALAPPDATA%\djokovic-soc\agent-audit.jsonl)에 쓰며 5MB를 넘으면 .1 로 넘긴다.
// 사용: node agent-audit-hook.mjs            → Claude Code 기록
//       node agent-audit-hook.mjs codex      → Codex CLI 기록(apply_patch 는 패치 내용 대신 바뀌는 파일 경로만 남긴다)
import { appendFileSync, mkdirSync, statSync, renameSync } from 'node:fs';
import { join, dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const file = process.env.ON_SOC_AUDIT_FILE || join(process.env.LOCALAPPDATA || process.env.TEMP || '.', 'djokovic-soc', 'agent-audit.jsonl');
const AGENTS = { claude: 'claude-code', codex: 'codex-cli' };
const agentArg = String(process.argv[2] ?? 'claude').toLowerCase();

const SECRET = [/\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, /\bAKIA[0-9A-Z]{12,}\b/g, /(authorization:\s*bearer\s+)\S+/gi, /((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*)\S+/gi, /(--(?:password|token|api-key)\s+)\S+/gi];
const redact = (text) => SECRET.reduce((value, pattern) => value.replace(pattern, (match, prefix) => `${typeof prefix === 'string' ? prefix : ''}[삭제됨]`), String(text));
const str = (value, max) => (typeof value === 'string' ? value.slice(0, max) : undefined);

// Codex apply_patch 본문에서 바뀌는 파일 경로만 뽑는다. 상대 경로는 작업 폴더 기준으로 바꾼다.
export function patchTargets(patch, cwd) {
  const found = [];
  for (const match of String(patch ?? '').matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm)) {
    const path = (match[1] ?? match[2]).trim();
    if (path) found.push(isAbsolute(path) || !cwd ? path : join(cwd, path));
  }
  return [...new Set(found)].slice(0, 8).map((value) => value.slice(0, 400));
}

function readStdin() {
  return new Promise((done) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; if (data.length > 1_000_000) data = data.slice(0, 1_000_000); });
    process.stdin.on('end', () => done(data));
    process.stdin.on('error', () => done(data));
    setTimeout(() => done(data), 3000).unref();
  });
}

async function main() {
  const input = JSON.parse((await readStdin()).replace(/^﻿/, ''));
  const toolInput = input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};
  const tool = str(input.tool_name, 40) || 'unknown';
  const cwd = str(input.cwd, 400);
  const rawCommand = Array.isArray(toolInput.command) ? toolInput.command.filter((x) => typeof x === 'string').join(' ') : toolInput.command;
  const isPatch = tool === 'apply_patch';
  const targets = isPatch ? patchTargets(rawCommand ?? toolInput.patch, cwd)
    : [toolInput.file_path, toolInput.path, toolInput.notebook_path].filter((value) => typeof value === 'string').map((value) => str(value, 400));
  const record = {
    at: new Date().toISOString(),
    agent: AGENTS[agentArg] ?? 'claude-code',
    session: str(input.session_id, 64),
    event: str(input.hook_event_name, 40),
    tool,
    cwd,
    targets,
    ...(!isPatch && typeof rawCommand === 'string' ? { command: redact(str(rawCommand, 300)) } : {}),
  };
  mkdirSync(dirname(file), { recursive: true });
  try { if (statSync(file).size > 5 * 1024 * 1024) renameSync(file, `${file}.1`); } catch { /* 파일이 아직 없으면 넘어간다 */ }
  appendFileSync(file, `${JSON.stringify(record)}\n`, 'utf8');
}

// 테스트가 patchTargets 만 가져다 쓸 때는 실행하지 않는다.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await main(); } catch { /* 감사 기록 실패가 에이전트 동작을 막으면 안 된다 */ }
  process.exit(0);
}
