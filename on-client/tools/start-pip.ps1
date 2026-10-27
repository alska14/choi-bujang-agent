<#
  보안 관제 미니 창(막대 없는 항상 위 창)을 켭니다.

  하는 일
   - pip-desktop 폴더의 Electron 창을 띄워 관제 서버의 미니 화면(/pc-status#pip-desktop)을 보여 줍니다.
   - 관제 서버가 꺼져 있으면 안내만 하고 끝냅니다(서버는 tools\start-final.ps1 로 켭니다).
   - -Install 을 붙이면 처음 한 번 Electron(약 370MB)을 pip-desktop\node_modules 에 내려받습니다.

  하지 않는 일
   - 관리자 권한을 요청하지 않고, 전역 설치를 하지 않으며, 제공 서버·설정 파일을 바꾸지 않습니다.

  사용 (앱 폴더 on-client 에서)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-pip.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-pip.ps1 -Install
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-pip.ps1 -Port 5190
#>
[CmdletBinding()]
param(
  [ValidateRange(1024, 65535)][int]$Port = 5189,
  [switch]$Install
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root 'pip-desktop'
$exe = Join-Path $app 'node_modules\electron\dist\electron.exe'

if (-not (Test-Path -LiteralPath (Join-Path $app 'main.js'))) { Write-Host "pip-desktop 폴더를 찾지 못했습니다: $app" -ForegroundColor Yellow; exit 1 }
if (-not (Test-Path -LiteralPath $exe)) {
  if (-not $Install) { Write-Host 'Electron 이 아직 없습니다. 처음 한 번은 -Install 을 붙여 실행하세요(약 370MB 내려받음).' -ForegroundColor Yellow; exit 1 }
  Push-Location $app
  try { npm install --no-fund --no-audit } finally { Pop-Location }
  if (-not (Test-Path -LiteralPath $exe)) { Write-Host 'Electron 설치에 실패했습니다. 네트워크 연결을 확인하세요.' -ForegroundColor Yellow; exit 1 }
}

try { $null = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$Port/pc-status" }
catch { Write-Host "관제 서버(http://127.0.0.1:$Port)가 꺼져 있습니다. 먼저 tools\start-final.ps1 로 켜세요. 미니 창은 서버가 켜지면 자동으로 다시 연결합니다." -ForegroundColor Yellow }

$env:SOC_PORT = "$Port"
Start-Process -FilePath $exe -ArgumentList "`"$app`"" -WorkingDirectory $app
Write-Host '보안 관제 미니 창을 켰습니다. 판 아무 곳이나 끌어 옮기고, 위쪽에 마우스를 올리면 투명도·닫기 버튼이 나옵니다.'
