<#
  PC 켤 때 자동 실행 설정 도구: 로그인하면 관제 서버와 미니 창이 저절로 켜지게 합니다.

  하는 일
   - 현재 사용자의 시작 프로그램 폴더에 바로가기 「Djokovic 보안 관제.lnk」 하나를 만들거나 지웁니다.
     (관리자 권한 없음. 작업 스케줄러·레지스트리는 건드리지 않습니다.)
   - 바로가기는 tools\start-at-login.ps1 을 창 없이 실행합니다.

  참고
   - 관제 앱은 시작 프로그램 폴더를 감시하므로, 켜거나 끌 때 「시작 프로그램 폴더 변경」 알림이 한 번 뜹니다.
     이 도구로 직접 바꾼 것이면 확인(또는 오탐 표시)하면 됩니다.

  사용 (앱 폴더에서)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\autostart.ps1 -Enable
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\autostart.ps1 -Enable -NoPip    # 미니 창 없이 서버만
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\autostart.ps1 -Disable
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\autostart.ps1                   # 지금 상태 보기
#>
[CmdletBinding()]
param(
  [switch]$Enable,
  [switch]$Disable,
  [switch]$NoPip,
  [ValidateRange(1024, 65535)][int]$Port = 5189
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$startup = [Environment]::GetFolderPath('Startup')
$link = Join-Path $startup 'Djokovic 보안 관제.lnk'
$script = Join-Path $PSScriptRoot 'start-at-login.ps1'

if ($Enable -and $Disable) { Write-Host '-Enable 과 -Disable 중 하나만 쓰세요.' -ForegroundColor Yellow; exit 1 }

if ($Enable) {
  if (-not (Test-Path -LiteralPath $script)) { Write-Host "실행 파일이 없습니다: $script" -ForegroundColor Yellow; exit 1 }
  $shell = New-Object -ComObject WScript.Shell
  $shortcut = $shell.CreateShortcut($link)
  $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $shortcut.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`" -Port $Port$(if ($NoPip) { ' -NoPip' } else { '' })"
  $shortcut.WorkingDirectory = Split-Path -Parent $PSScriptRoot
  $shortcut.WindowStyle = 7
  $shortcut.Description = 'Djokovic 보안 관제: 로그인할 때 관제 서버와 미니 창을 켭니다'
  $shortcut.Save()
  Write-Host "자동 실행을 켰습니다: $link"
  Write-Host "다음 로그인부터 관제 서버$(if ($NoPip) { '' } else { '와 미니 창' })이 저절로 켜집니다. 기록: %LOCALAPPDATA%\djokovic-soc\autostart.log"
  exit 0
}
if ($Disable) {
  if (Test-Path -LiteralPath $link) { Remove-Item -LiteralPath $link; Write-Host "자동 실행을 껐습니다(바로가기 삭제): $link" } else { Write-Host '자동 실행이 이미 꺼져 있습니다.' }
  exit 0
}
if (Test-Path -LiteralPath $link) {
  $target = (New-Object -ComObject WScript.Shell).CreateShortcut($link)
  Write-Host "자동 실행: 켜짐`n바로가기: $link`n실행 인수: $($target.Arguments)"
} else { Write-Host "자동 실행: 꺼짐 (켜려면 -Enable)" }
