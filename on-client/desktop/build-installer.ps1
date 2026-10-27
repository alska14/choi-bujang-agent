<#
  비밀번호 암호화 설치 파일 만들기.

  하는 일
   1) electron-builder 로 앱 폴더(dist\win-unpacked)를 만든다(설치 파일은 만들지 않음).
   2) 그 폴더 전체를 설치 비밀번호로 7z AES-256 암호화한다(-mhe=on: 파일 이름까지 암호화).
   3) installer\djokovic.nsi 로 설치 파일(dist\Djokovic 보안 관제 Setup <버전>.exe)을 만든다.
   4) 중간 산출물(payload.7z)은 지운다.

  비밀번호는 저장소·설치 파일 어디에도 남기지 않는다. 실행할 때 입력하거나 환경 변수 DJK_INSTALLER_PASSWORD 로 넘긴다.

  사용 (desktop 폴더에서)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\build-installer.ps1
#>
[CmdletBinding()]
param()
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$pkg = Get-Content -LiteralPath (Join-Path $here 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$version = [string]$pkg.version
$sevenZip = Join-Path $here 'node_modules\7zip-bin\win\x64\7za.exe'
$makensis = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'electron-builder\Cache\nsis') -Recurse -Filter makensis.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not (Test-Path -LiteralPath $sevenZip)) { throw "7za.exe 가 없습니다. desktop 폴더에서 npm install 을 먼저 하세요." }

$password = $env:DJK_INSTALLER_PASSWORD
if (-not $password) {
  $secure = Read-Host '설치 비밀번호' -AsSecureString
  $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if ($password.Length -lt 8) { throw '설치 비밀번호는 8자 이상이어야 합니다.' }
if ($password -match '"') { throw '설치 비밀번호에 큰따옴표(")는 쓸 수 없습니다.' }

Push-Location $here
try {
  Write-Host '1/3 앱 폴더 만드는 중(electron-builder --dir)…'
  $env:CSC_IDENTITY_AUTO_DISCOVERY = 'false'
  # electron-builder 가 stderr 로 내는 경고(DeprecationWarning)를 Windows PowerShell 이 오류로 바꾸지 않게 이 구간만 Continue 로 둔다.
  $ErrorActionPreference = 'Continue'
  & npx electron-builder --win dir 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match 'packaging|⨯' } | ForEach-Object { Write-Host "  $_" }
  $ErrorActionPreference = 'Stop'
  $unpacked = Join-Path $here 'dist\win-unpacked'
  if (-not (Test-Path -LiteralPath (Join-Path $unpacked 'Djokovic SOC.exe'))) { throw '앱 폴더를 만들지 못했습니다.' }
  if (-not $makensis) { throw 'NSIS(makensis.exe)를 찾지 못했습니다. electron-builder 로 nsis 대상을 한 번 만들면 내려받아집니다.' }

  Write-Host '2/3 프로그램 파일 암호화 중(7z AES-256, 파일 이름 포함)…'
  $payload = Join-Path $here 'dist\payload.7z'
  if (Test-Path -LiteralPath $payload) { Remove-Item -LiteralPath $payload }
  & $sevenZip a -t7z -mx=7 -mhe=on "-p$password" $payload (Join-Path $unpacked '*') -bso0 -bsp0
  if ($LASTEXITCODE -ne 0) { throw "암호화에 실패했습니다(코드 $LASTEXITCODE)." }

  Write-Host '3/3 설치 파일 만드는 중(NSIS)…'
  $out = Join-Path $here "dist\Djokovic 보안 관제 Setup $version.exe"
  & $makensis.FullName /V2 /INPUTCHARSET UTF8 "/DVERSION=$version" "/DOUTFILE=$out" "/DPAYLOAD=$payload" "/DSEVENZIP=$sevenZip" "/DICON=$(Join-Path $here 'assets\icon.ico')" (Join-Path $here 'installer\djokovic.nsi')
  if ($LASTEXITCODE -ne 0) { throw "설치 파일을 만들지 못했습니다(코드 $LASTEXITCODE)." }
  Remove-Item -LiteralPath $payload
  Write-Host "완료: $out"
} finally {
  $password = $null
  Pop-Location
}
