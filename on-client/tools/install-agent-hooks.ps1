<#
  Codex CLI 감사 훅 설치 도구: Codex 가 도구(명령 실행·파일 수정)를 쓸 때마다 대상 경로를 관제 앱의 감사 파일에 남기게 합니다.

  하는 일
   - 훅 스크립트(tools\agent-audit-hook.mjs)를 %LOCALAPPDATA%\djokovic-soc\hooks 에 복사합니다(공백 없는 경로라 어떤 셸에서도 그대로 실행됨).
   - %USERPROFILE%\.codex\hooks.json 을 만듭니다. 이미 다른 내용이 있으면 덮어쓰지 않고 멈춥니다.
   - Codex 의 동작은 막거나 바꾸지 않습니다(훅은 기록만 하고 항상 성공으로 끝남).

  하지 않는 일
   - 관리자 권한을 쓰지 않고, Codex 설정(config.toml)·로그인 정보를 읽거나 바꾸지 않습니다.

  설치 뒤 한 번 해야 할 일
   - Codex 는 새 훅을 사용자가 확인(trust)해야 실행합니다. Codex 를 열고 /hooks 에서 이 훅을 신뢰로 표시해 주세요.

  사용 (앱 폴더에서)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install-agent-hooks.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install-agent-hooks.ps1 -Uninstall
#>
[CmdletBinding()]
param([switch]$Uninstall)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$marker = 'djokovic-soc'
$source = Join-Path $PSScriptRoot 'agent-audit-hook.mjs'
$hookDir = Join-Path $env:LOCALAPPDATA 'djokovic-soc\hooks'
$hookCopy = Join-Path $hookDir 'agent-audit-hook.mjs'
$codexDir = Join-Path $env:USERPROFILE '.codex'
$hooksJson = Join-Path $codexDir 'hooks.json'
$utf8 = [Text.UTF8Encoding]::new($false)

function Is-Ours([string]$path) { (Test-Path -LiteralPath $path) -and ((Get-Content -LiteralPath $path -Raw -Encoding UTF8) -match [regex]::Escape($marker)) }

if ($Uninstall) {
  if (Is-Ours $hooksJson) { Remove-Item -LiteralPath $hooksJson; Write-Host "Codex 훅 설정을 지웠습니다: $hooksJson" }
  elseif (Test-Path -LiteralPath $hooksJson) { Write-Host "hooks.json 에 이 앱이 만든 내용이 없어 그대로 둡니다: $hooksJson" -ForegroundColor Yellow }
  else { Write-Host 'Codex 훅 설정이 없습니다.' }
  if (Test-Path -LiteralPath $hookCopy) { Remove-Item -LiteralPath $hookCopy; Write-Host "훅 스크립트 복사본을 지웠습니다: $hookCopy" }
  exit 0
}

if (-not (Test-Path -LiteralPath $source)) { Write-Host "훅 스크립트가 없습니다: $source" -ForegroundColor Yellow; exit 1 }
if (-not (Get-Command node -CommandType Application -ErrorAction SilentlyContinue)) { Write-Host 'node 를 찾지 못했습니다. Node.js 를 설치한 뒤 다시 실행해 주세요.' -ForegroundColor Yellow; exit 1 }
if ($hookCopy -match '\s') { Write-Host "복사 경로에 공백이 있어 Codex 가 실행하지 못할 수 있습니다: $hookCopy" -ForegroundColor Yellow }
if ((Test-Path -LiteralPath $hooksJson) -and -not (Is-Ours $hooksJson)) {
  Write-Host "이미 다른 Codex 훅 설정이 있어 덮어쓰지 않았습니다: $hooksJson" -ForegroundColor Yellow
  Write-Host "직접 합치려면 PreToolUse 에 다음 명령을 추가하세요: node $($hookCopy -replace '\\','/') codex"
  exit 1
}

New-Item -ItemType Directory -Force -Path $hookDir | Out-Null
Copy-Item -LiteralPath $source -Destination $hookCopy -Force
New-Item -ItemType Directory -Force -Path $codexDir | Out-Null
$command = "node $($hookCopy -replace '\\','/') codex"
# Codex 가 모르는 키를 넣지 않는다. 이 앱이 만든 설정인지는 명령 경로의 djokovic-soc 로 알아본다.
$json = [ordered]@{
  hooks =[ordered]@{ PreToolUse = @([ordered]@{ matcher = '*'; hooks = @([ordered]@{ type = 'command'; command = $command; timeout = 10 }) }) }
} | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($hooksJson, $json, $utf8)
Write-Host "Codex 훅을 설치했습니다: $hooksJson"
Write-Host "실행 명령: $command"
Write-Host '마지막 단계: Codex 를 열고 /hooks 에서 이 훅을 신뢰(trust)로 표시해야 기록이 시작됩니다.' -ForegroundColor Cyan
