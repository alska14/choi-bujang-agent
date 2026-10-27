<#
  최종 앱 실행 도구: 보안 앱과 「내 PC 상태」(/pc-status)를 같은 포트에서 켭니다.

  하는 일
   - 이 파일이 들어 있는 앱 폴더(on-client)의 src\final-app.mjs 하나만 실행합니다.
   - 실행 전에 Node.js 버전, 폴더 구성, 포트 사용 여부를 확인합니다.
   - 서버가 뜨면 보안 앱 주소와 내 PC 상태 주소를 알려 줍니다.

  하지 않는 일
   - 프로그램 설치, 전역 실행 정책 변경, 관리자 권한 요청을 하지 않습니다.
   - 이미 포트를 쓰는 다른 프로그램을 종료하지 않습니다.
   - 열쇠·토큰 같은 비밀 환경변수를 서버에 넘기지 않습니다.
   - SDP·계정 연결 설정 파일 옵션은 받지 않습니다. 그 연결이 필요하면 기존 start-alekov.ps1 을 씁니다.

  사용 (앱 폴더에서)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-final.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-final.ps1 -Port 5190
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-final.ps1 -Demo
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-final.ps1 -Background
#>
[CmdletBinding()]
param(
  [ValidateRange(1024, 65535)][int]$Port = 5189,
  [switch]$Demo,
  [switch]$Background,
  [ValidateRange(1, 120)][int]$WaitSeconds = 20
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function Say([string]$text) { Write-Host $text }
function Stop-With([string]$text, [int]$code = 1) { Write-Host $text -ForegroundColor Yellow; exit $code }

# 1) 폴더 확인: 이 스크립트가 있는 tools 의 상위가 앱 폴더여야 합니다.
$root = Split-Path -Parent $PSScriptRoot
$entry = Join-Path $root 'src\final-app.mjs'
$package = Join-Path $root 'package.json'
foreach ($path in @($root, $entry, $package)) {
  if (-not (Test-Path -LiteralPath $path)) { Stop-With "앱 폴더가 아닙니다. 저장소의 on-client 폴더 안에서 tools\start-final.ps1 을 실행해 주세요. (없는 파일: $path)" }
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-With "바로가기(링크)로 연결된 폴더나 파일에서는 실행하지 않습니다. 실제 앱 폴더(on-client)에서 실행해 주세요. ($path)" }
}
try { $meta = Get-Content -LiteralPath $package -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Stop-With 'package.json 을 읽지 못했습니다.' }
if ($meta.name -ne 'alekov-client-starter') { Stop-With '앱 폴더가 아닙니다. 저장소의 on-client 폴더에서 실행해 주세요.' }

# 2) Node.js 확인: 설치하지 않고 안내만 합니다.
$node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $node) { Stop-With 'Node.js 가 없습니다. https://nodejs.org 에서 Node.js 24.19.0(LTS)을 설치한 뒤 새 PowerShell 창에서 다시 실행해 주세요.' }
$versionText = (& $node.Source --version 2>$null | Out-String).Trim()
if ($versionText -notmatch '^v(\d+)\.(\d+)\.(\d+)$') { Stop-With "Node.js 버전을 확인하지 못했습니다($versionText). Node.js 24.19.0 을 설치해 주세요." }
$major = [int]$Matches[1]
if ($major -lt 22 -or $major -gt 24) { Stop-With "지금 Node.js 는 $versionText 입니다. 앱은 Node.js 22~24 에서 실행합니다. Node.js 24.19.0 을 권장합니다." }
if ($versionText -ne 'v24.19.0') { Say "참고: 지금 Node.js 는 $versionText 입니다. 수업 기준은 v24.19.0 입니다." }

# 3) 포트 확인: 사용 중이면 다른 프로그램을 끄지 않고 다른 번호를 안내합니다.
$busy = $false
try {
  $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
  $probe.Start(); $probe.Stop()
} catch { $busy = $true }
if ($busy) { Stop-With "포트 $Port 를 다른 프로그램이 쓰고 있습니다. 그 프로그램은 그대로 두고, 다른 번호로 실행해 주세요. 예: -Port $($Port + 1)" }

# 4) 실행: 셸을 거치지 않고 node 를 직접 실행합니다. 비밀로 보이는 환경변수는 넘기지 않습니다.
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = $node.Source
$info.WorkingDirectory = $root
$info.UseShellExecute = $false
$info.Arguments = '"' + $entry + '"' + $(if ($Demo) { ' --demo' } else { '' })
$secret = '(?i)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|^ON_AI_|^OPENAI|^ANTHROPIC|^SUPABASE)'
foreach ($name in @($info.EnvironmentVariables.Keys)) { if ($name -match $secret) { $info.EnvironmentVariables.Remove($name) } }
$info.EnvironmentVariables['ON_PORT'] = [string]$Port
if ($Background) {
  $info.CreateNoWindow = $true
  $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
}
$process = [Diagnostics.Process]::Start($info)
$base = "http://127.0.0.1:$Port"

# 5) 보안 앱 화면과 내 PC 상태 화면이 모두 응답할 때까지 기다립니다. 서버가 응답한 것만 확인하며 AI 연결 성공을 뜻하지 않습니다.
$ready = $false
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
  try {
    $main = Invoke-WebRequest -UseBasicParsing -Uri "$base/" -TimeoutSec 2
    $pc = Invoke-WebRequest -UseBasicParsing -Uri "$base/pc-status" -TimeoutSec 2
    if ($main.StatusCode -eq 200 -and $pc.StatusCode -eq 200) { $ready = $true; break }
  } catch { Start-Sleep -Milliseconds 300 }
}
if (-not $ready) {
  if (-not $process.HasExited) { $process.Kill() }
  Stop-With "앱 서버가 $WaitSeconds 초 안에 뜨지 않았습니다. 이 창의 메시지를 확인하세요."
}
Say "보안 앱: $base/"
Say "내 PC 상태: $base/pc-status"
Say '서버가 응답한 것만 확인했습니다. AI 연결 상태나 측정값은 화면에서 따로 확인해 주세요.'
if ($Background) {
  Say "뒤에서 실행 중입니다(프로세스 번호 $($process.Id)). 끄려면 이 번호의 node 를 작업 관리자에서 종료하세요."
  exit 0
}
Say '끄려면 이 창에서 Ctrl+C 를 누르세요.'
$process.WaitForExit()
exit $process.ExitCode
