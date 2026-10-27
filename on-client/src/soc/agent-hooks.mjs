// AI 에이전트 감사 훅 연결: 이 PC의 Claude Code·Codex CLI 설정에 감사 훅을 등록한다(사용자가 화면에서 누를 때만).
// - 훅 스크립트를 %LOCALAPPDATA%\djokovic-soc\hooks 에 복사하고 그 복사본을 가리키게 한다(앱을 업데이트·이동해도 경로가 그대로).
// - Claude Code: %USERPROFILE%\.claude\settings.json 의 hooks.PreToolUse 에 한 항목을 더한다. 다른 설정은 건드리지 않고, 처음 바꾸기 전 원본을 .djokovic-backup 으로 남긴다.
// - Codex CLI: %USERPROFILE%\.codex\hooks.json 에 같은 방식으로 더한다. Codex 는 새 훅을 /hooks 에서 신뢰로 표시해야 실행한다.
// - 실행기: Node.js 가 있으면 node 로, 없으면(Claude Code 만) 데스크톱 앱 실행 파일의 --audit-hook 으로 실행한다.
// 이미 이 앱이 넣은 항목(agent-audit-hook 또는 --audit-hook 을 부르는 것)은 새 항목으로 바꾼다. 설정 파일을 읽지 못하면(JSON 오류) 건드리지 않는다.
import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HOOK_SRC = fileURLToPath(new URL('../../tools/agent-audit-hook.mjs', import.meta.url));
const CLAUDE_MATCHER = 'Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|Bash|PowerShell';
const isOurs = (entry) => JSON.stringify(entry ?? '').match(/agent-audit-hook|--audit-hook/) !== null;

function defaultFindNode() {
  try {
    const out = execFileSync('where.exe', ['node'], { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    return out.split(/\r?\n/).map((l) => l.trim()).find((l) => /node\.exe$/i.test(l) && existsSync(l)) || null;
  } catch { return null; }
}

function readJson(file) {
  if (!existsSync(file)) return { data: {} };
  try {
    const text = readFileSync(file, 'utf8').replace(/^﻿/, '');
    return { data: text.trim() ? JSON.parse(text) : {} };
  } catch { return { error: `${file} 을(를) 읽지 못해(JSON 형식 오류) 건드리지 않았습니다.` }; }
}

function writeJsonWithBackup(file, data) {
  const backup = `${file}.djokovic-backup`;
  if (existsSync(file) && !existsSync(backup)) copyFileSync(file, backup);
  writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

function hasOurHook(file, event = 'PreToolUse') {
  const { data } = readJson(file);
  return Boolean(data && data.hooks && Array.isArray(data.hooks[event]) && data.hooks[event].some(isOurs));
}

export function createAgentHooks({ home = homedir(), dataDir, appExe = process.versions.electron ? process.execPath : null, findNode = defaultFindNode, hookSource = HOOK_SRC } = {}) {
  const claudeDir = join(home, '.claude');
  const codexDir = join(home, '.codex');
  const claudeFile = join(claudeDir, 'settings.json');
  const codexFile = join(codexDir, 'hooks.json');
  const hookDir = join(dataDir, 'hooks');
  const hookCopy = join(hookDir, 'agent-audit-hook.mjs');

  function status() {
    const node = findNode();
    return {
      claude: { found: existsSync(claudeDir), connected: hasOurHook(claudeFile), file: claudeFile },
      codex: { found: existsSync(codexDir), connected: hasOurHook(codexFile), file: codexFile },
      runner: node ? 'node' : appExe ? 'app' : 'none',
    };
  }

  function install({ claude = true, codex = true } = {}) {
    const node = findNode();
    mkdirSync(hookDir, { recursive: true });
    copyFileSync(hookSource, hookCopy);
    const results = [];

    if (claude) {
      if (!existsSync(claudeDir)) results.push({ agent: 'Claude Code', ok: false, message: 'Claude Code 설정 폴더(.claude)가 없어 건너뛰었습니다(설치돼 있지 않거나 한 번도 실행하지 않음).' });
      else if (!node && !appExe) results.push({ agent: 'Claude Code', ok: false, message: 'Node.js 를 찾지 못했고 앱 실행 파일도 없어 연결하지 못했습니다.' });
      else {
        const { data, error } = readJson(claudeFile);
        if (error) results.push({ agent: 'Claude Code', ok: false, message: error });
        else {
          const handler = node ? { type: 'command', command: node, args: [hookCopy, 'claude'], timeout: 10 } : { type: 'command', command: appExe, args: ['--audit-hook', 'claude'], timeout: 15 };
          data.hooks = data.hooks && typeof data.hooks === 'object' ? data.hooks : {};
          data.hooks.PreToolUse = [...(Array.isArray(data.hooks.PreToolUse) ? data.hooks.PreToolUse.filter((e) => !isOurs(e)) : []), { matcher: CLAUDE_MATCHER, hooks: [handler] }];
          writeJsonWithBackup(claudeFile, data);
          results.push({ agent: 'Claude Code', ok: true, message: `연결했습니다(${node ? 'Node.js' : '앱'}으로 실행). 새로 여는 Claude Code 세션부터 기록됩니다.` });
        }
      }
    }

    if (codex) {
      if (!existsSync(codexDir)) results.push({ agent: 'Codex CLI', ok: false, message: 'Codex 설정 폴더(.codex)가 없어 건너뛰었습니다.' });
      else if (!node) results.push({ agent: 'Codex CLI', ok: false, message: 'Node.js 를 찾지 못해 Codex 는 연결하지 않았습니다(Codex CLI 는 보통 Node.js 와 함께 설치됩니다).' });
      else {
        const { data, error } = readJson(codexFile);
        if (error) results.push({ agent: 'Codex CLI', ok: false, message: error });
        else {
          const q = (p) => (/\s/.test(p) ? `"${p}"` : p);
          // Codex 가 어떤 셸로 실행하든 되도록 PATH 의 node 를 그대로 부른다(전체 경로의 공백·따옴표 문제를 피함).
          const command = `node ${q(hookCopy.replace(/\\/g, '/'))} codex`;
          data.hooks = data.hooks && typeof data.hooks === 'object' ? data.hooks : {};
          data.hooks.PreToolUse = [...(Array.isArray(data.hooks.PreToolUse) ? data.hooks.PreToolUse.filter((e) => !isOurs(e)) : []), { matcher: '*', hooks: [{ type: 'command', command, timeout: 10 }] }];
          writeJsonWithBackup(codexFile, data);
          results.push({ agent: 'Codex CLI', ok: true, message: '연결했습니다. Codex 를 열고 /hooks 에서 이 훅을 신뢰(trust)로 한 번 표시해야 기록이 시작됩니다.' });
        }
      }
    }
    return { results, status: status() };
  }

  return Object.freeze({ status, install });
}
