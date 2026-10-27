<#
  로그인할 때 실행되는 도구: 관제 서버를 창 없이 켜고, 서버가 응답하면 막대 없는 미니 창을 띄웁니다.
  autostart.ps1 -Enable 이 만든 바로가기가 이 파일을 부릅니다. 직접 실행해도 됩니다.

  하는 일
   - 포트(기본 5189)에서 관제 서버가 이미 응답하면 서버를 또 켜지 않습니다.
   - 서버가 없으면 start-final.ps1 -Background 로 켭니다(관리자 권한·설치 없음).
   - 서버가 응답하면 start-pip.ps1 로 미니 창을 띄웁니다(-NoPip 이면 띄우지 않음).
   - 기록은 %LOCALAPPDATA%\djokovic-soc\autostart.log 에 남깁니다.
#>
[CmdletBinding()]
param(
  [ValidateRange(1024, 65535)][int]$Port = 5189,
  [switch]$NoPip,
  [ValidateRange(5, 300)][int]$WaitSeconds = 60
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$logDir = Join-Path $env:LOCALAPPDATA 'djokovic-soc'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'autostart.log'
function Log([string]$text) { Add-Content -LiteralPath $log -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $text) -Encoding UTF8 }

function Test-Soc {
  try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri "http://127.0.0.1:$Port/api/soc/snapshot"; return $r.StatusCode -eq 200 } catch { return $false }
}

try {
  if (Test-Soc) { Log "관제 서버가 이미 켜져 있음(포트 $Port)" }
  else {
    Log "관제 서버 켜는 중(포트 $Port)"
    # Windows PowerShell 5.1 의 Start-Process 는 인수를 따옴표로 감싸 주지 않는다. 폴더 이름에 공백이 있어도 되게 직접 감싼다.
    $starter = Join-Path $PSScriptRoot 'start-final.ps1'
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$starter`" -Port $Port -Background" | Out-Null
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while (-not (Test-Soc) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    if (Test-Soc) { Log '관제 서버 응답 확인' } else { Log "관제 서버가 ${WaitSeconds}초 안에 응답하지 않음"; exit 1 }
  }
  if (-not $NoPip) {
    if (Get-Process -Name electron -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like '*PiP*' -or $_.MainWindowTitle -like '*미니 창*' }) { Log '미니 창이 이미 떠 있음' }
    else { & (Join-Path $PSScriptRoot 'start-pip.ps1') -Port $Port; Log '미니 창 실행' }
  }
} catch { Log "오류: $($_.Exception.Message)"; exit 1 }
