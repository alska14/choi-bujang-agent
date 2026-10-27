<#
  업데이트 배포: 만든 설치 파일을 GitHub Releases 에 올려, 이미 설치한 앱이 자동으로 새 버전을 찾게 한다.

  하는 일
   1) dist 의 설치 파일을 영문 이름(Djokovic-SOC-Setup-<버전>.exe)으로 복사한다.
   2) latest.json(버전·파일 주소·SHA-256·크기·바뀐 점)을 만들고, 업데이트 서명 개인 열쇠(Ed25519)로 서명해 latest.json.sig 를 만든다.
   3) gh 로 Release v<버전> 을 만들고 세 파일을 올린다.

  개인 열쇠는 이 PC의 %LOCALAPPDATA%\djokovic-soc-release\update-signing-key.pem 에만 있다(저장소에 넣지 않음).
  이 열쇠를 잃어버리면 이미 설치된 앱에 업데이트를 보낼 수 없으니 안전한 곳에 따로 백업한다.
  앱에는 짝이 되는 공개 열쇠(desktop\update-key.pub.pem)만 들어간다.

  사용 (desktop 폴더에서, 먼저 package.json 의 version 을 올리고 build-installer.ps1 로 설치 파일을 만든 뒤)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\publish-release.ps1 -Notes "바뀐 점 한두 줄"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Notes,
  [string]$Repo = 'alska14/choi-bujang-agent',
  [string]$Target = 'final-app',
  [switch]$DryRun
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$version = [string](Get-Content -LiteralPath (Join-Path $here 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json).version
$source = Join-Path $here "dist\Djokovic 보안 관제 Setup $version.exe"
$key = Join-Path $env:LOCALAPPDATA 'djokovic-soc-release\update-signing-key.pem'
if (-not (Test-Path -LiteralPath $source)) { throw "설치 파일이 없습니다: $source (build-installer.ps1 을 먼저 실행하세요)" }
if (-not (Test-Path -LiteralPath $key)) { throw "업데이트 서명 개인 열쇠가 없습니다: $key" }

$out = Join-Path $here "dist\release-$version"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$file = "Djokovic-SOC-Setup-$version.exe"
Copy-Item -LiteralPath $source -Destination (Join-Path $out $file) -Force
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out $file)).Hash.ToLower()
$size = (Get-Item -LiteralPath (Join-Path $out $file)).Length
$manifest = [ordered]@{
  version = $version
  file = $file
  url = "https://github.com/$Repo/releases/download/v$version/$file"
  sha256 = $sha
  size = $size
  publishedAt = (Get-Date).ToUniversalTime().ToString('o')
  notes = $Notes
} | ConvertTo-Json -Compress
$manifestPath = Join-Path $out 'latest.json'
[IO.File]::WriteAllText($manifestPath, $manifest, [Text.UTF8Encoding]::new($false))
& node -e "const c=require('crypto'),f=require('fs');const sig=c.sign(null,f.readFileSync(process.argv[1]),c.createPrivateKey(f.readFileSync(process.argv[2])));f.writeFileSync(process.argv[3],sig.toString('base64'));" $manifestPath $key "$manifestPath.sig"
if ($LASTEXITCODE -ne 0) { throw '서명하지 못했습니다.' }
# 앱과 같은 방법으로 서명을 다시 검사한다.
& node -e "const {verifyManifest}=require(process.argv[1]);const f=require('fs');const r=verifyManifest(f.readFileSync(process.argv[2],'utf8'),f.readFileSync(process.argv[3],'utf8'),f.readFileSync(process.argv[4],'utf8'));if(!r.ok){console.error(r.error);process.exit(1)}" (Join-Path $here 'updater.js') $manifestPath "$manifestPath.sig" (Join-Path $here 'update-key.pub.pem')
if ($LASTEXITCODE -ne 0) { throw '서명 검사에 실패했습니다.' }
Write-Host "준비됨: v$version ($file, $([math]::Round($size/1MB,1))MB, sha256 $sha)"
if ($DryRun) { Write-Host "-DryRun: 올리지 않았습니다. $out"; exit 0 }

& gh release create "v$version" (Join-Path $out $file) $manifestPath "$manifestPath.sig" --repo $Repo --target $Target --title "Djokovic 보안 관제 $version" --notes "$Notes`n`n설치 파일은 설치 비밀번호로 암호화돼 있습니다. 이미 설치한 앱(1.0.1 이상)은 알림 영역 아이콘 메뉴에서 업데이트를 받습니다." --latest
if ($LASTEXITCODE -ne 0) { throw 'Release 를 만들지 못했습니다.' }
Write-Host "올림: https://github.com/$Repo/releases/tag/v$version"
